//! A JSON Schema validator for exactly the dialect this repo emits
//! (#305, DESIGN.md §5).
//!
//! Not a general one, and deliberately so. `config_schema.zig` renders
//! the schema by reflecting over the loader's own DTOs, so the set of
//! keywords that can appear in it is closed and known — `census` below
//! walks a rendered document and fails on any keyword this file does not
//! implement, which is what keeps "we validate the schema we emit" a
//! fact rather than a hope. A general validator would be a dependency
//! (§4) or a second implementation of a spec nobody here is reading.
//!
//! What it exists for: the differential gate. `zig build schema` says
//! what a config may look like and the loader says what it may *mean*,
//! and until now nothing checked that the two agree. A config the schema
//! admits and the loader refuses is a cross-field rule that should have
//! been a shape (#305 Part 1's whole argument); a config the schema
//! refuses and the loader accepts is a schema that lies to every editor
//! that reads it.
//!
//! Allocation: none. Both the schema and the instance arrive as parsed
//! `std.json.Value` trees the caller owns, and validation is a walk over
//! them — this runs in tests and in the schema tool, never on the loop
//! (§3), but the discipline is free here so it is kept.

const std = @import("std");

const assert = std.debug.assert;

/// Every keyword this validator understands. Two kinds: the ones that
/// constrain an instance, and the annotations that describe it for a
/// human or an editor and constrain nothing. Both are listed, because
/// `census` has to tell "implemented" from "unrecognised" and an
/// annotation left out would read as the latter.
pub const Keyword = enum {
    // Annotations — carried in the document, ignored here.
    @"$schema",
    @"$id",
    title,
    description,
    default,

    // Constraints.
    type,
    properties,
    required,
    additionalProperties,
    items,
    @"enum",
    @"const",
    oneOf,
    anyOf,
    minimum,
    maximum,
    minLength,
    maxLength,
    minItems,
    maxItems,
    minProperties,

    /// Whether this keyword's value is itself a schema, a map of
    /// schemas, or a list of schemas — which is what lets `census`
    /// recurse without guessing, and what keeps a property named `type`
    /// from being read as the keyword `type`.
    pub const Shape = enum { annotation, scalar, schema, schema_map, schema_list };

    pub fn shape(keyword: Keyword) Shape {
        return switch (keyword) {
            .@"$schema", .@"$id", .title, .description, .default => .annotation,
            .type,
            .required,
            .@"enum",
            .@"const",
            .minimum,
            .maximum,
            .minLength,
            .maxLength,
            .minItems,
            .maxItems,
            .minProperties,
            => .scalar,
            // `additionalProperties` is `false` in everything this repo
            // emits; the schema form is legal in the dialect and costs
            // nothing to accept.
            .items, .additionalProperties => .schema,
            .properties => .schema_map,
            .oneOf, .anyOf => .schema_list,
        };
    }
};

/// Why an instance failed, as a path and a reason — enough for a gate to
/// say which config and which field rather than just "no".
pub const Failure = struct {
    /// Dotted path to the offending value, `""` at the root. Written
    /// into caller storage so this allocates nothing.
    path: []const u8,
    reason: Reason,

    pub const Reason = enum {
        type_mismatch,
        missing_required,
        unknown_property,
        not_in_enum,
        not_const,
        below_minimum,
        above_maximum,
        too_short,
        too_long,
        too_few_items,
        too_few_properties,
        too_many_items,
        no_branch_matched,
        many_branches_matched,
    };
};

/// How deep a schema may nest before this file refuses to walk it.
///
/// TIGER_STYLE forbids unbounded recursion, and a schema is a tree, so
/// the walk carries its depth and asserts against this rather than
/// trusting the document. The emitted schema nests about six deep
/// (root → listeners → items → http → request_filters → items →
/// match); 32 is room for the shape to grow several times over without
/// being room for a cycle to hide in.
pub const depth_max = 32;

/// The longest dotted path a failure can name. The emitted schema nests
/// a handful deep and every segment is a DTO field name, so this is
/// generous rather than tight — and it is a test-path bound, not a §5
/// one.
pub const path_bytes_max = 512;

/// Validate `instance` against `schema`, both already parsed. Null is a
/// pass; a `Failure` names the first thing wrong, in document order.
///
/// `path_storage` is where the failure's path is written — the caller
/// owns it, and it must outlive the returned failure.
pub fn validate(
    schema: std.json.Value,
    instance: std.json.Value,
    path_storage: *[path_bytes_max]u8,
) ?Failure {
    var path: Path = .{ .storage = path_storage, .len = 0 };
    return check(schema, instance, &path, 0);
}

/// A dotted path built as the walk descends and truncated as it returns
/// — one buffer for the whole validation, so a deep tree costs no more
/// than a shallow one.
const Path = struct {
    storage: *[path_bytes_max]u8,
    len: u16,

    fn push(path: *Path, segment: []const u8) u16 {
        const saved = path.len;
        // A path past the bound is a schema deeper than this file is
        // built for, and silently truncating it would name the wrong
        // field in a failure. Nothing here recurses without a schema
        // that produced it, so the bound is checkable rather than
        // hopeful.
        assert(path.len + segment.len + 1 <= path_bytes_max);
        if (path.len >= 1) {
            path.storage[path.len] = '.';
            path.len += 1;
        }
        @memcpy(path.storage[path.len..][0..segment.len], segment);
        path.len += @intCast(segment.len);
        return saved;
    }

    fn pushIndex(path: *Path, index: usize) u16 {
        var digits: [24]u8 = undefined;
        const rendered = std.fmt.bufPrint(&digits, "[{d}]", .{index}) catch unreachable;
        const saved = path.len;
        assert(path.len + rendered.len <= path_bytes_max);
        @memcpy(path.storage[path.len..][0..rendered.len], rendered);
        path.len += @intCast(rendered.len);
        return saved;
    }

    fn restore(path: *Path, saved: u16) void {
        assert(saved <= path.len);
        path.len = saved;
    }

    fn fail(path: *const Path, reason: Failure.Reason) Failure {
        return .{ .path = path.storage[0..path.len], .reason = reason };
    }
};

fn check(
    schema: std.json.Value,
    instance: std.json.Value,
    path: *Path,
    depth: u8,
) ?Failure {
    // The one bound this walk has. A schema deeper than `depth_max` is
    // one this file was not built for, and descending anyway is how a
    // cyclic or hostile document turns a validator into a stack
    // overflow — the emitter's own output is checked against it by the
    // census, so a breach here is a document from somewhere else.
    assert(depth < depth_max);
    // A schema that is not an object constrains nothing in this dialect;
    // the emitter never writes one, and the census proves it.
    const object = switch (schema) {
        .object => |map| map,
        else => return null,
    };
    if (object.get("type")) |wanted| {
        if (!typeMatches(wanted, instance)) {
            return path.fail(.type_mismatch);
        }
    }
    if (object.get("const")) |wanted| {
        if (!valuesEqual(wanted, instance)) {
            return path.fail(.not_const);
        }
    }
    if (object.get("enum")) |choices| {
        if (!inEnum(choices, instance)) {
            return path.fail(.not_in_enum);
        }
    }
    if (checkNumeric(object, instance, path)) |failure| {
        return failure;
    }
    if (checkString(object, instance, path)) |failure| {
        return failure;
    }
    if (checkArray(object, instance, path, depth)) |failure| {
        return failure;
    }
    if (checkObject(object, instance, path, depth)) |failure| {
        return failure;
    }
    return checkCombinators(object, instance, path, depth);
}

fn checkNumeric(
    object: std.json.ObjectMap,
    instance: std.json.Value,
    path: *Path,
) ?Failure {
    const observed = numberOf(instance) orelse return null;
    if (object.get("minimum")) |bound| {
        if (observed < numberOf(bound).?) {
            return path.fail(.below_minimum);
        }
    }
    if (object.get("maximum")) |bound| {
        if (observed > numberOf(bound).?) {
            return path.fail(.above_maximum);
        }
    }
    return null;
}

fn checkString(
    object: std.json.ObjectMap,
    instance: std.json.Value,
    path: *Path,
) ?Failure {
    const text = switch (instance) {
        .string => |value| value,
        else => return null,
    };
    if (object.get("minLength")) |bound| {
        if (@as(f64, @floatFromInt(text.len)) < numberOf(bound).?) {
            return path.fail(.too_short);
        }
    }
    if (object.get("maxLength")) |bound| {
        if (@as(f64, @floatFromInt(text.len)) > numberOf(bound).?) {
            return path.fail(.too_long);
        }
    }
    return null;
}

fn checkArray(
    object: std.json.ObjectMap,
    instance: std.json.Value,
    path: *Path,
    depth: u8,
) ?Failure {
    assert(depth < depth_max);
    const items = switch (instance) {
        .array => |value| value,
        else => return null,
    };
    if (object.get("minItems")) |bound| {
        if (@as(f64, @floatFromInt(items.items.len)) < numberOf(bound).?) {
            return path.fail(.too_few_items);
        }
    }
    if (object.get("maxItems")) |bound| {
        if (@as(f64, @floatFromInt(items.items.len)) > numberOf(bound).?) {
            return path.fail(.too_many_items);
        }
    }
    if (object.get("items")) |item_schema| {
        for (items.items, 0..) |element, index| {
            const saved = path.pushIndex(index);
            defer path.restore(saved);
            if (check(item_schema, element, path, depth + 1)) |failure| {
                return failure;
            }
        }
    }
    return null;
}

fn checkObject(
    object: std.json.ObjectMap,
    instance: std.json.Value,
    path: *Path,
    depth: u8,
) ?Failure {
    assert(depth < depth_max);
    const members = switch (instance) {
        .object => |value| value,
        else => return null,
    };
    if (object.get("minProperties")) |bound| {
        if (@as(f64, @floatFromInt(members.count())) < numberOf(bound).?) {
            return path.fail(.too_few_properties);
        }
    }
    if (object.get("required")) |names| {
        for (names.array.items) |name| {
            if (members.get(name.string) == null) {
                const saved = path.push(name.string);
                defer path.restore(saved);
                return path.fail(.missing_required);
            }
        }
    }
    const properties = object.get("properties");
    // `additionalProperties` carries both jobs this dialect needs, and
    // conflating them is easy to do and expensive to miss. As `false` it
    // closes the object: an unknown key is a typo the loader would
    // reject anyway, and saying so in the schema is what makes an editor
    // catch it first. As a *schema* it types every member a `properties`
    // map does not name — which is how a table keyed by operator-chosen
    // names is described at all, and `clusters`, `bodies` and
    // `error_pages` are all that shape.
    const additional = object.get("additionalProperties");
    const closed = if (additional) |value| value == .bool and value.bool == false else false;
    const member_default: ?std.json.Value = if (additional) |value|
        (if (value == .object) value else null)
    else
        null;
    var it = members.iterator();
    while (it.next()) |entry| {
        const named = if (properties) |map| map.object.get(entry.key_ptr.*) else null;
        const member_schema = named orelse member_default;
        if (member_schema) |sub| {
            const saved = path.push(entry.key_ptr.*);
            defer path.restore(saved);
            if (check(sub, entry.value_ptr.*, path, depth + 1)) |failure| {
                return failure;
            }
        } else if (closed) {
            const saved = path.push(entry.key_ptr.*);
            defer path.restore(saved);
            return path.fail(.unknown_property);
        }
    }
    return null;
}

fn checkCombinators(
    object: std.json.ObjectMap,
    instance: std.json.Value,
    path: *Path,
    depth: u8,
) ?Failure {
    assert(depth < depth_max);
    if (object.get("anyOf")) |branches| {
        var matched = false;
        for (branches.array.items) |branch| {
            if (check(branch, instance, path, depth + 1) == null) {
                matched = true;
            }
        }
        if (!matched) {
            return path.fail(.no_branch_matched);
        }
    }
    if (object.get("oneOf")) |branches| {
        var matches: u32 = 0;
        for (branches.array.items) |branch| {
            if (check(branch, instance, path, depth + 1) == null) {
                matches += 1;
            }
        }
        if (matches == 0) {
            return path.fail(.no_branch_matched);
        }
        // Exactly one, which is what makes `oneOf` the "exactly one of"
        // the loader used to enforce in prose (#305 Part 1).
        if (matches > 1) {
            return path.fail(.many_branches_matched);
        }
    }
    return null;
}

fn typeMatches(wanted: std.json.Value, instance: std.json.Value) bool {
    return switch (wanted) {
        .string => |name| typeNameMatches(name, instance),
        // The union form: any one of the listed types will do.
        .array => |names| {
            for (names.items) |name| {
                if (typeNameMatches(name.string, instance)) return true;
            }
            return false;
        },
        else => true,
    };
}

fn typeNameMatches(name: []const u8, instance: std.json.Value) bool {
    if (std.mem.eql(u8, name, "object")) return instance == .object;
    if (std.mem.eql(u8, name, "array")) return instance == .array;
    if (std.mem.eql(u8, name, "string")) return instance == .string;
    if (std.mem.eql(u8, name, "boolean")) return instance == .bool;
    if (std.mem.eql(u8, name, "null")) return instance == .null;
    if (std.mem.eql(u8, name, "integer")) {
        return switch (instance) {
            .integer => true,
            // JSON has one number type, so an integral float is an
            // integer — `1.0` and `1` are the same value, and rejecting
            // the first would fail a config no human wrote differently.
            .float => |value| @floor(value) == value,
            else => false,
        };
    }
    if (std.mem.eql(u8, name, "number")) {
        return instance == .integer or instance == .float;
    }
    // An unrecognised type name is a keyword the census should have
    // caught; treating it as satisfied here would hide that.
    unreachable;
}

fn numberOf(value: std.json.Value) ?f64 {
    return switch (value) {
        .integer => |number| @floatFromInt(number),
        .float => |number| number,
        else => null,
    };
}

fn inEnum(choices: std.json.Value, instance: std.json.Value) bool {
    for (choices.array.items) |choice| {
        if (valuesEqual(choice, instance)) return true;
    }
    return false;
}

fn valuesEqual(a: std.json.Value, b: std.json.Value) bool {
    return switch (a) {
        .null => b == .null,
        .bool => |value| b == .bool and b.bool == value,
        .integer, .float => blk: {
            const other = numberOf(b) orelse break :blk false;
            break :blk numberOf(a).? == other;
        },
        .string => |value| b == .string and std.mem.eql(u8, b.string, value),
        // The emitter writes no composite `enum` or `const` values, and
        // comparing them structurally would be a feature nothing asks
        // for — the census is what keeps that true.
        else => false,
    };
}

/// Walk a rendered schema and fail on the first keyword this file does
/// not implement.
///
/// This is the half that makes the validator trustworthy. A validator
/// that silently ignores what it does not know is worse than none: it
/// reports "valid" for a document whose constraints it never read, and
/// the gate built on it would pass by not looking. So the emitter and
/// this file are held together — teach the emitter a keyword and this
/// census fails until the validator learns it too.
pub fn census(schema: std.json.Value) ?[]const u8 {
    return censusAt(schema, 0);
}

fn censusAt(schema: std.json.Value, depth: u8) ?[]const u8 {
    // Same bound as the validation walk, and for the same reason: this
    // one runs over a document the emitter produced, so a breach is a
    // shape nobody meant to write.
    assert(depth < depth_max);
    const object = switch (schema) {
        .object => |map| map,
        else => return null,
    };
    var it = object.iterator();
    while (it.next()) |entry| {
        const keyword = std.meta.stringToEnum(Keyword, entry.key_ptr.*) orelse {
            return entry.key_ptr.*;
        };
        switch (keyword.shape()) {
            .annotation, .scalar => {},
            .schema => {
                if (censusAt(entry.value_ptr.*, depth + 1)) |unknown| return unknown;
            },
            .schema_map => {
                var members = entry.value_ptr.object.iterator();
                while (members.next()) |member| {
                    if (censusAt(member.value_ptr.*, depth + 1)) |unknown| return unknown;
                }
            },
            .schema_list => {
                for (entry.value_ptr.array.items) |branch| {
                    if (censusAt(branch, depth + 1)) |unknown| return unknown;
                }
            },
        }
    }
    return null;
}

const testing = std.testing;

fn parse(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, testing.allocator, text, .{});
}

fn expectValid(schema_text: []const u8, instance_text: []const u8) !void {
    var schema = try parse(schema_text);
    defer schema.deinit();
    var instance = try parse(instance_text);
    defer instance.deinit();
    var storage: [path_bytes_max]u8 = undefined;
    const failure = validate(schema.value, instance.value, &storage);
    if (failure) |found| {
        std.debug.print(
            "\nunexpected failure at '{s}': {t}\n",
            .{ found.path, found.reason },
        );
        return error.TestUnexpectedResult;
    }
}

fn expectInvalid(
    schema_text: []const u8,
    instance_text: []const u8,
    reason: Failure.Reason,
    path: []const u8,
) !void {
    var schema = try parse(schema_text);
    defer schema.deinit();
    var instance = try parse(instance_text);
    defer instance.deinit();
    var storage: [path_bytes_max]u8 = undefined;
    const failure = validate(schema.value, instance.value, &storage) orelse {
        return error.TestExpectedError;
    };
    try testing.expectEqual(reason, failure.reason);
    try testing.expectEqualStrings(path, failure.path);
}

test "json schema: types, and an integral float is an integer" {
    const schema =
        \\{"type":"object","properties":{"n":{"type":"integer"},"s":{"type":"string"}}}
    ;
    try expectValid(schema, "{\"n\":7,\"s\":\"x\"}");
    // JSON has one number type: `1.0` and `1` are the same value, and a
    // config nobody wrote differently must not fail on the spelling.
    try expectValid(schema, "{\"n\":1.0}");
    try expectInvalid(schema, "{\"n\":1.5}", .type_mismatch, "n");
    try expectInvalid(schema, "{\"n\":\"7\"}", .type_mismatch, "n");
}

test "json schema: required, closed objects, and the path names the field" {
    const schema =
        \\{"type":"object","required":["bind"],"additionalProperties":false,
        \\ "properties":{"bind":{"type":"string"},"mode":{"type":"string"}}}
    ;
    try expectValid(schema, "{\"bind\":\"x\"}");
    try expectValid(schema, "{\"bind\":\"x\",\"mode\":\"0660\"}");
    try expectInvalid(schema, "{\"mode\":\"0660\"}", .missing_required, "bind");
    // The typo an editor should catch before the loader does.
    try expectInvalid(schema, "{\"bind\":\"x\",\"bnid\":1}", .unknown_property, "bnid");
}

test "json schema: additionalProperties types a table keyed by operator names" {
    // How `clusters`, `bodies` and `error_pages` are described: no
    // `properties` at all, every member typed by one schema. A validator
    // that read this keyword only as the closed-object flag would walk
    // straight past every cluster in the file and call it valid.
    const schema =
        \\{"type":"object","minProperties":1,"additionalProperties":
        \\ {"type":"object","required":["endpoints"],"properties":
        \\  {"endpoints":{"type":"array","minItems":1}}}}
    ;
    try expectValid(schema, "{\"api\":{\"endpoints\":[\"a\"]}}");
    try expectInvalid(schema, "{}", .too_few_properties, "");
    try expectInvalid(schema, "{\"api\":{\"endpoints\":[]}}", .too_few_items, "api.endpoints");
    try expectInvalid(schema, "{\"api\":{}}", .missing_required, "api.endpoints");
}

test "json schema: nested paths name the whole route to the value" {
    const schema =
        \\{"type":"object","properties":{"listeners":{"type":"array","items":
        \\ {"type":"object","properties":{"http":{"type":"object","properties":
        \\ {"cluster":{"type":"string"}}}}}}}}
    ;
    try expectValid(schema, "{\"listeners\":[{\"http\":{\"cluster\":\"a\"}}]}");
    try expectInvalid(
        schema,
        "{\"listeners\":[{\"http\":{\"cluster\":\"a\"}},{\"http\":{\"cluster\":7}}]}",
        .type_mismatch,
        "listeners[1].http.cluster",
    );
}

test "json schema: oneOf is exactly one, which is the whole point of it" {
    // The shape #305 Part 1 gave the listener: a tagged body, where
    // naming both or neither is a document error rather than a loader
    // rule stated in prose.
    const schema =
        \\{"type":"object","oneOf":[
        \\ {"required":["http"]},
        \\ {"required":["l4"]}],
        \\ "properties":{"http":{"type":"object"},"l4":{"type":"object"}}}
    ;
    try expectValid(schema, "{\"http\":{}}");
    try expectValid(schema, "{\"l4\":{}}");
    try expectInvalid(schema, "{}", .no_branch_matched, "");
    try expectInvalid(schema, "{\"http\":{},\"l4\":{}}", .many_branches_matched, "");
}

test "json schema: bounds, enums and item counts" {
    const schema =
        \\{"type":"object","properties":{
        \\ "weight":{"type":"integer","minimum":0,"maximum":256},
        \\ "mode":{"enum":["replace","append"]},
        \\ "names":{"type":"array","minItems":1,"maxItems":2},
        \\ "name":{"type":"string","minLength":1}}}
    ;
    try expectValid(schema, "{\"weight\":256,\"mode\":\"append\",\"names\":[\"a\"],\"name\":\"n\"}");
    try expectInvalid(schema, "{\"weight\":257}", .above_maximum, "weight");
    try expectInvalid(schema, "{\"weight\":-1}", .below_minimum, "weight");
    try expectInvalid(schema, "{\"mode\":\"trust\"}", .not_in_enum, "mode");
    try expectInvalid(schema, "{\"names\":[]}", .too_few_items, "names");
    try expectInvalid(schema, "{\"names\":[\"a\",\"b\",\"c\"]}", .too_many_items, "names");
    try expectInvalid(schema, "{\"name\":\"\"}", .too_short, "name");
}

test "json schema: the census names a keyword the validator does not implement" {
    // The property *named* like a keyword must not be read as one — a
    // config DTO is free to have a field called `type`, and the census
    // only looks at schema positions.
    var honest = try parse(
        \\{"type":"object","properties":{"type":{"type":"string"},"pattern":{"type":"integer"}}}
    );
    defer honest.deinit();
    try testing.expect(census(honest.value) == null);

    // And a real unimplemented keyword is caught wherever it sits,
    // including inside a branch — silently ignoring it would make the
    // validator report "valid" for a constraint it never read.
    var nested = try parse(
        \\{"oneOf":[{"type":"object"},{"type":"object","patternProperties":{"^x":{}}}]}
    );
    defer nested.deinit();
    try testing.expectEqualStrings("patternProperties", census(nested.value).?);
}
