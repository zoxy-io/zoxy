//! JSON Schema (draft 2020-12) for the startup config, emitted by reflecting
//! over the very `*Json` DTOs the loader parses (see `config.zig`). Structure
//! comes from `@typeInfo`; the un-reflectable parts — prose, numeric bounds,
//! and the closed vocabularies (`protocol`, `pick`, filter `method` tokens,
//! filter `reject` statuses) — come from the DTOs' co-located `schema_doc`/
//! `schema_fields` metadata, cross-checked against the fields at comptime by
//! `config.assert_meta_matches`. Bounds trace to `constants.zig` and vocab to
//! the same Zig enums/arrays the loader validates against, so the schema
//! cannot drift from the code. `zig build schema` writes it to
//! `zig-out/config.schema.json`; the release workflow ships it as an asset.
//!
//! What JSON Schema *can* express is emitted: structure, `required`,
//! `additionalProperties: false` (the parser rejects unknown fields), enums,
//! and numeric ranges. What it *cannot* — the loader's semantic validations
//! (canonical route prefixes/hosts, IP:port literal parsing, reserved header
//! names, endpoint port != 0) and the "exactly one of" forks (listener
//! cluster/routes, header-match kind, action kind) — stays the loader's job.
//! A config that passes this schema is well-shaped, not necessarily accepted.

const std = @import("std");

const config = @import("config.zig");
const constants = @import("constants.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");

const assert = std.debug.assert;

const Writer = std.Io.Writer;
const Stringify = std.json.Stringify;
const Protocol = config.Config.Listener.Protocol;
const Pick = config.Config.Cluster.Pick;

/// Emit the whole schema document, pretty-printed (it is a shipped,
/// human-read artifact). `std.json.Stringify` owns all punctuation, quoting,
/// and escaping; this file only decides structure. Deterministic: every loop
/// walks fields/enums in declaration order.
pub fn writeSchema(w: *Writer) Writer.Error!void {
    // The generated vocabularies are closed and non-empty; an empty enum
    // could never be satisfied, so guard the shapes at comptime.
    comptime assert(@typeInfo(Protocol).@"enum".fields.len >= 1);
    comptime assert(@typeInfo(Pick).@"enum".fields.len >= 1);
    comptime assert(filter.reject_statuses.len >= 1);

    var out: Stringify = .{ .writer = w, .options = .{ .whitespace = .indent_2 } };
    try out.beginObject();
    try out.objectField("$schema");
    try out.write("https://json-schema.org/draft/2020-12/schema");
    try out.objectField("$id");
    try out.write("https://zoxy.io/schema/config.schema.json");
    try out.objectField("title");
    try out.write("zoxy configuration");
    // The root object's own body (type/description/properties/...) is
    // appended into the still-open object begun above.
    try writeObjectBody(&out, config.ConfigJson, true);
    try out.endObject();
    try w.writeByte('\n');
}

/// Append an object schema's body — `type`, optional `description`,
/// `properties`, `required`, `additionalProperties: false` — into the
/// currently-open object. `with_doc` emits `T.schema_doc` as the
/// description; callers that supply their own description (a named field or
/// map value) pass `false`. `required` is exactly the fields with no Zig
/// default, so the schema's required set is derived, never hand-listed.
fn writeObjectBody(out: *Stringify, comptime T: type, comptime with_doc: bool) Writer.Error!void {
    comptime config.assert_meta_matches(T);
    const fields = @typeInfo(T).@"struct".fields;
    comptime assert(fields.len >= 1);

    try out.objectField("type");
    try out.write("object");
    if (with_doc) {
        try out.objectField("description");
        try out.write(T.schema_doc);
    }

    try out.objectField("properties");
    try out.beginObject();
    inline for (fields) |field| {
        try out.objectField(field.name);
        try writeFieldSchema(out, T, field);
    }
    try out.endObject();

    try out.objectField("required");
    try out.beginArray();
    inline for (fields) |field| {
        if (comptime field.defaultValue() == null) try out.write(field.name);
    }
    try out.endArray();

    try out.objectField("additionalProperties");
    try out.write(false);
}

/// Emit one field's schema object: its `description` (from metadata),
/// its type-derived shape, and a scalar `default` when the Zig field has a
/// non-optional default (optionals default to null — noise we omit).
fn writeFieldSchema(
    out: *Stringify,
    comptime T: type,
    comptime field: std.builtin.Type.StructField,
) Writer.Error!void {
    const meta = @field(T.schema_fields, field.name);
    const Base = comptime optionalChild(field.type);

    try out.beginObject();
    try out.objectField("description");
    try out.write(meta.desc);

    switch (@typeInfo(Base)) {
        .@"struct" => if (Base == config.ClustersJson)
            try writeClustersMap(out)
        else
            // Nested object; its description is the field's, written above.
            try writeObjectBody(out, Base, false),
        else => try writeShape(out, Base, meta),
    }

    if (comptime @typeInfo(field.type) != .optional) {
        if (comptime field.defaultValue()) |default| {
            switch (@typeInfo(Base)) {
                .int => {
                    try out.objectField("default");
                    try out.write(default);
                },
                .pointer => |ptr| if (comptime ptr.child == u8) {
                    try out.objectField("default");
                    try out.write(default);
                },
                else => {},
            }
        }
    }

    try out.endObject();
}

/// Emit the type-derived shape keys (everything but `description`) for a
/// scalar/array field into the currently-open field object. Struct-typed
/// fields never reach here — `writeFieldSchema` routes them to
/// `writeObjectBody`/`writeClustersMap`.
fn writeShape(out: *Stringify, comptime Base: type, comptime meta: anytype) Writer.Error!void {
    switch (@typeInfo(Base)) {
        .bool => {
            if (comptime @hasField(@TypeOf(meta), "const_true")) {
                comptime assert(meta.const_true);
                try out.objectField("const");
                try out.write(true);
            } else {
                try out.objectField("type");
                try out.write("boolean");
            }
        },
        .int => {
            if (comptime @hasField(@TypeOf(meta), "int_values")) {
                try out.objectField("enum");
                try out.beginArray();
                for (meta.int_values) |value| try out.write(value);
                try out.endArray();
            } else {
                comptime assert(meta.minimum <= meta.maximum);
                try out.objectField("type");
                try out.write("integer");
                try out.objectField("minimum");
                try out.write(meta.minimum);
                try out.objectField("maximum");
                try out.write(meta.maximum);
            }
        },
        .pointer => |ptr| if (comptime ptr.child == u8)
            try writeStringShape(out, meta)
        else
            try writeArrayShape(out, ptr.child, meta),
        else => comptime unreachable,
    }
}

/// A `[]const u8` field: a plain string, or a closed enum when the metadata
/// names a source enum (`protocol`, `pick`).
fn writeStringShape(out: *Stringify, comptime meta: anytype) Writer.Error!void {
    if (comptime @hasField(@TypeOf(meta), "enum_type")) {
        try writeEnum(out, meta.enum_type);
        return;
    }
    try out.objectField("type");
    try out.write("string");
    if (comptime @hasField(@TypeOf(meta), "min_length")) {
        comptime assert(meta.min_length >= 1);
        try out.objectField("minLength");
        try out.write(meta.min_length);
    }
}

/// A slice field (`[]const Child`): an array with optional length bounds and
/// an `items` schema for the element type.
fn writeArrayShape(out: *Stringify, comptime Child: type, comptime meta: anytype) Writer.Error!void {
    try out.objectField("type");
    try out.write("array");
    if (comptime @hasField(@TypeOf(meta), "min_items")) {
        comptime assert(meta.min_items >= 1); // a minItems of 0 is vacuous — a typo, not a bound
        try out.objectField("minItems");
        try out.write(meta.min_items);
    }
    if (comptime @hasField(@TypeOf(meta), "max_items")) {
        try out.objectField("maxItems");
        try out.write(meta.max_items);
    }
    if (comptime @hasField(@TypeOf(meta), "min_items") and @hasField(@TypeOf(meta), "max_items")) {
        comptime assert(meta.min_items <= meta.max_items);
    }
    try out.objectField("items");
    try out.beginObject();
    try writeItems(out, Child, meta);
    try out.endObject();
}

/// Emit an array's `items` body into the currently-open items object: a
/// nested object schema for struct elements, the method-token enum when the
/// metadata marks it, or a plain string otherwise.
fn writeItems(out: *Stringify, comptime Child: type, comptime meta: anytype) Writer.Error!void {
    switch (@typeInfo(Child)) {
        .@"struct" => try writeObjectBody(out, Child, true),
        .pointer => |ptr| {
            comptime assert(ptr.child == u8);
            if (comptime @hasField(@TypeOf(meta), "items")) {
                comptime assert(meta.items == .http_method); // the only marker we define
                try writeMethodEnum(out);
            } else {
                try out.objectField("type");
                try out.write("string");
            }
        },
        else => comptime unreachable,
    }
}

/// An `"enum"` array of an enum type's field names — the same closed
/// vocabulary the loader accepts, since the field names ARE the JSON tokens
/// (`protocol` via a literal match, `pick` via `std.meta.stringToEnum`).
fn writeEnum(out: *Stringify, comptime Enum: type) Writer.Error!void {
    const fields = @typeInfo(Enum).@"enum".fields;
    comptime assert(fields.len >= 1);
    try out.objectField("enum");
    try out.beginArray();
    inline for (fields) |field| try out.write(field.name);
    try out.endArray();
}

/// The filter `method` vocabulary as an `"enum"` array: the registered
/// request-method tokens, which are exactly the uppercased `parser.Method`
/// field names minus the `extension` catch-all (which names no token). A
/// test pins this against `parser.methodFromToken`.
fn writeMethodEnum(out: *Stringify) Writer.Error!void {
    try out.objectField("enum");
    try out.beginArray();
    comptime var emitted = false;
    inline for (@typeInfo(parser.Method).@"enum".fields) |field| {
        if (comptime std.mem.eql(u8, field.name, "extension")) continue;
        try out.write(upperToken(field.name));
        emitted = true;
    }
    try out.endArray();
    comptime assert(emitted); // at least one real method token exists
}

/// The clusters map: a name-keyed object whose values are cluster schemas,
/// bounded by `clusters_max`. The DTO is a custom parser (not a plain
/// struct), so its shape is emitted here rather than reflected.
fn writeClustersMap(out: *Stringify) Writer.Error!void {
    comptime assert(constants.clusters_max >= constants.clusters_min);
    try out.objectField("type");
    try out.write("object");
    try out.objectField("minProperties");
    try out.write(constants.clusters_min);
    try out.objectField("maxProperties");
    try out.write(constants.clusters_max);
    try out.objectField("additionalProperties");
    try out.beginObject();
    try writeObjectBody(out, config.ClusterJson, true);
    try out.endObject();
}

/// The non-optional element type of `T`, or `T` itself if it is not an
/// optional. Optionality only affects `required`, never the field's shape.
fn optionalChild(comptime T: type) type {
    return switch (@typeInfo(T)) {
        .optional => |opt| opt.child,
        else => T,
    };
}

/// Uppercase a method enum field name into its wire token. `name` is
/// comptime (it fixes the array length), but the body runs at either phase,
/// so the method-enum test can call it at runtime too.
fn upperToken(comptime name: []const u8) [name.len]u8 {
    var buffer: [name.len]u8 = undefined;
    for (name, 0..) |byte, index| buffer[index] = std.ascii.toUpper(byte);
    return buffer;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Render the schema into `buffer` and return the written slice. The document
/// is a few KiB; callers size their buffers well above that. A too-small
/// buffer fails the render with `error.WriteFailed` (a fixed writer does not
/// spill), so truncation surfaces as a test failure rather than silent loss.
fn renderInto(buffer: []u8) Writer.Error![]const u8 {
    var w = Writer.fixed(buffer);
    try writeSchema(&w);
    return w.buffered();
}

test "config_schema: the emitted document is valid, documented JSON" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();
    const root = parsed.value;
    try std.testing.expect(root == .object);
    try std.testing.expect(root.object.get("$schema") != null);
    try std.testing.expect(root.object.get("$id") != null);
    // A draft-2020-12 object schema that names its fields — the shape every
    // consumer keys off. `additionalProperties: false` mirrors the strict
    // parser (`ignore_unknown_fields = false`).
    try std.testing.expectEqualStrings("object", root.object.get("type").?.string);
    try std.testing.expect(root.object.get("properties").?.object.count() >= 1);
    try std.testing.expectEqual(false, root.object.get("additionalProperties").?.bool);
}

test "config_schema: the `$schema` editor hint is a declared root property" {
    // `additionalProperties: false` is what makes the schema mirror the
    // strict loader, so the key an editor writes to *find* this schema has
    // to be declared here too — otherwise pointing at it flags the pointer.
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const properties = parsed.value.object.get("properties").?.object;
    const hint = properties.get("$schema").?.object;
    try std.testing.expectEqualStrings("string", hint.get("type").?.string);
    // Optional, exactly as the loader has it: a config without the hint is
    // still valid.
    for (parsed.value.object.get("required").?.array.items) |name| {
        try std.testing.expect(!std.mem.eql(u8, name.string, "$schema"));
    }
}

test "config_schema: emission is deterministic" {
    var buffer_a: [64 * 1024]u8 = undefined;
    var buffer_b: [64 * 1024]u8 = undefined;
    // Same inputs, twice: field/enum order is declaration order, so the two
    // renders must be byte-identical (the release asset is reproducible).
    try std.testing.expectEqualStrings(try renderInto(&buffer_a), try renderInto(&buffer_b));
}

test "config_schema: the shipped example's top-level keys are all declared" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var schema = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer schema.deinit();
    const properties = schema.value.object.get("properties").?.object;

    const example = @embedFile("example_config");
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, example, .{});
    defer parsed.deinit();
    var it = parsed.value.object.iterator();
    while (it.next()) |entry| {
        try std.testing.expect(properties.get(entry.key_ptr.*) != null);
    }
}

test "config_schema: the method enum matches what the parser accepts" {
    // Every token the schema emits must be one the loader resolves, and no
    // more than the registered methods (extension names no token).
    var accepted: u32 = 0;
    inline for (@typeInfo(parser.Method).@"enum".fields) |field| {
        if (comptime std.mem.eql(u8, field.name, "extension")) continue;
        const token = upperToken(field.name);
        try std.testing.expect(parser.methodFromToken(&token) != null);
        accepted += 1;
    }
    try std.testing.expectEqual(@as(u32, @typeInfo(parser.Method).@"enum".fields.len - 1), accepted);
    try std.testing.expect(parser.methodFromToken("NOTAMETHOD") == null);
}
