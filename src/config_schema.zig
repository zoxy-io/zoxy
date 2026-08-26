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
//! numeric ranges, and the "exactly one of" forks — listener
//! `cluster`/`routes`, header-match kind, action kind — as `oneOf`
//! (`writeOneOf`, #305). What it *cannot* is the loader's semantic
//! validation: canonical route prefixes and hosts, IP:port literal parsing,
//! reserved header names, endpoint port != 0. Those stay the loader's job,
//! so a config that passes this schema is well-shaped, not necessarily
//! accepted — but the gap is now only what is genuinely semantic.

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

    try writeOneOf(out, T);
}

/// Emit a DTO's "exactly one of these fields" fork as `oneOf`, one
/// `required` branch per name.
///
/// `oneOf` means *exactly* one branch matches, which is the rule itself:
/// a config naming two of the fields satisfies two branches and a config
/// naming none satisfies none, so both are rejected without the schema
/// having to describe why. Three DTOs share this shape — the listener's
/// `cluster`/`routes`, a header predicate's kind, a filter action's kind
/// — and each used to concede the rule in prose ("enforced by the
/// loader, not this schema"). They are the cheap third of #305's eight
/// admissions: expressible all along, just never expressed.
///
/// The branches carry no `properties` of their own, so the enclosing
/// `additionalProperties: false` is unaffected — in draft 2020-12 that
/// keyword only considers `properties` declared in the same schema
/// object, never a sibling subschema's.
fn writeOneOf(out: *Stringify, comptime T: type) Writer.Error!void {
    if (!@hasDecl(T, "schema_one_of")) return;
    // `assertOneOfMatches` proved this at comptime; restated where the
    // loop below depends on it.
    comptime assert(T.schema_one_of.len >= 2);
    try out.objectField("oneOf");
    try out.beginArray();
    inline for (T.schema_one_of) |name| {
        try out.beginObject();
        try out.objectField("required");
        try out.beginArray();
        try out.write(name);
        try out.endArray();
        try out.endObject();
    }
    try out.endArray();
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
        .@"struct" => if (Base == config.ClustersJson) {
            try writeClustersMap(out);
        } else {
            if (Base == config.PickJson) {
                try writePickField(out);
            } else {
                if (Base == config.BodiesJson) {
                    try writeNamedMap(out, config.BodyJson);
                } else {
                    if (Base == config.ErrorPagesJson) {
                        try writeNamedMap(out, null);
                    } else {
                        // Nested object; its description is the field's,
                        // written above.
                        try writeObjectBody(out, Base, false);
                    }
                }
            }
        },
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
        .@"struct" => if (Child == config.EndpointJson)
            try writeEndpointItems(out)
        else
            try writeObjectBody(out, Child, true),
        .pointer => |ptr| {
            comptime assert(ptr.child == u8);
            if (comptime @hasField(@TypeOf(meta), "items")) {
                switch (meta.items) {
                    .http_method => try writeMethodEnum(out),
                    .upgrade_token => try writeUpgradeEnum(out),
                }
            } else {
                try out.objectField("type");
                try out.write("string");
            }
        },
        // An integer element (the response-match `status` list, #175):
        // the bounds come from the field's own metadata, exactly as a
        // scalar integer field's do.
        .int => {
            comptime assert(meta.minimum <= meta.maximum);
            try out.objectField("type");
            try out.write("integer");
            try out.objectField("minimum");
            try out.write(meta.minimum);
            try out.objectField("maximum");
            try out.write(meta.maximum);
        },
        else => comptime unreachable,
    }
}

/// A cluster endpoint accepts two spellings (#174) — the bare `IP:port`
/// string every existing config writes, or the `{address, weight}` object
/// — so its items schema is the document's one `anyOf`. Emitted here
/// rather than reflected because reflection sees only the resolved DTO
/// (`EndpointJson`), whose custom `jsonParse` is where the string form
/// lives; the two arms below mirror that parser exactly.
fn writeEndpointItems(out: *Stringify) Writer.Error!void {
    try out.objectField("anyOf");
    try out.beginArray();
    try out.beginObject();
    try out.objectField("type");
    try out.write("string");
    try out.objectField("description");
    try out.write("IP:port endpoint literal (port must be non-zero) — weight 1.");
    try out.endObject();
    try out.beginObject();
    try writeObjectBody(out, config.EndpointJson, true);
    try out.endObject();
    try out.endArray();
}

/// A cluster's pick accepts two spellings (#178) — the bare policy string
/// (`p2c`, `rr`; a bare `hash` is rejected because its key must be named)
/// or the `{policy, key, name}` object — so its schema is an `anyOf`,
/// emitted by hand for the same reason `writeEndpointItems` is: the
/// resolved DTO (`PickJson`) hides the string form inside its custom
/// `jsonParse`. The string arm's vocabulary is deliberately narrower than
/// `Pick`: hash without a key never resolves, so the schema must not
/// advertise it.
fn writePickField(out: *Stringify) Writer.Error!void {
    try out.objectField("anyOf");
    try out.beginArray();
    try out.beginObject();
    try out.objectField("type");
    try out.write("string");
    try out.objectField("enum");
    try out.beginArray();
    try out.write("p2c");
    try out.write("rr");
    try out.endArray();
    try out.objectField("description");
    try out.write("A keyless pick policy; hash takes the object form, which names its key.");
    try out.endObject();
    try out.beginObject();
    try writeObjectBody(out, config.PickJson, true);
    try out.endObject();
    try out.endArray();
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

/// The #180 upgrade vocabulary as an `"enum"` array, read off the
/// `Upgrades` set's own field names — which *are* the JSON tokens, the
/// same one-source-of-truth `protocol` and `pick` get from their enums.
/// The set is a struct rather than an enum because membership is what
/// the config expresses, so this walks fields where `writeEnum` walks
/// variants; the closedness it publishes is the same, and it is the
/// point: a token absent from here is one no rule could catch after 101.
fn writeUpgradeEnum(out: *Stringify) Writer.Error!void {
    const fields = @typeInfo(config.Config.Listener.Upgrades).@"struct".fields;
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

/// The clusters map: a name-keyed object whose values are cluster schemas.
/// The DTO is a custom parser (not a plain struct), so its shape is
/// emitted here rather than reflected.
///
/// `minProperties` only: there is no `maxProperties` because there is no
/// cluster ceiling left to emit. The loader's one remaining rejection is
/// the `u16` index type's edge, which is not a number worth putting in a
/// schema an editor uses for completion.
fn writeClustersMap(out: *Stringify) Writer.Error!void {
    comptime assert(constants.clusters_min >= 1);
    try out.objectField("type");
    try out.write("object");
    try out.objectField("minProperties");
    try out.write(constants.clusters_min);
    try out.objectField("additionalProperties");
    try out.beginObject();
    try writeObjectBody(out, config.ClusterJson, true);
    try out.endObject();
}

/// A #159 map field: string keys to either a nested object schema
/// (`bodies`, whose values are `BodyJson`) or bare strings
/// (`error_pages`, whose values are body names). Like `ClustersJson`,
/// the maps carry custom `jsonParse`s the reflection cannot see, so
/// their shapes are emitted by hand.
fn writeNamedMap(out: *Stringify, comptime Value: ?type) Writer.Error!void {
    try out.objectField("type");
    try out.write("object");
    try out.objectField("additionalProperties");
    if (Value) |ValueType| {
        try out.beginObject();
        try writeObjectBody(out, ValueType, true);
        try out.endObject();
    } else {
        try out.beginObject();
        try out.objectField("type");
        try out.write("string");
        try out.objectField("description");
        try out.write("Name of a configured body.");
        try out.endObject();
    }
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

test "config_schema: endpoint items accept both spellings" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const clusters = parsed.value.object.get("properties").?.object.get("clusters").?.object;
    const cluster_schema = clusters.get("additionalProperties").?.object;
    const endpoints = cluster_schema.get("properties").?.object.get("endpoints").?.object;
    const arms = endpoints.get("items").?.object.get("anyOf").?.array;

    // Exactly the loader's two spellings: a bare literal, or the object.
    try std.testing.expectEqual(@as(usize, 2), arms.items.len);
    try std.testing.expectEqualStrings("string", arms.items[0].object.get("type").?.string);
    const object_arm = arms.items[1].object;
    try std.testing.expectEqualStrings("object", object_arm.get("type").?.string);
    // `address` is the one required key — `weight` defaults — and the
    // emitted weight ceiling is the loader's own constant, so the schema
    // cannot promise a weight the loader would then reject.
    const required = object_arm.get("required").?.array;
    try std.testing.expectEqual(@as(usize, 1), required.items.len);
    try std.testing.expectEqualStrings("address", required.items[0].string);
    const weight = object_arm.get("properties").?.object.get("weight").?.object;
    try std.testing.expectEqual(
        @as(i64, constants.endpoint_weight_max),
        weight.get("maximum").?.integer,
    );
    try std.testing.expectEqual(@as(i64, 0), weight.get("minimum").?.integer);
}

test "config_schema: pick accepts both spellings, and only the object names hash" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const clusters = parsed.value.object.get("properties").?.object.get("clusters").?.object;
    const cluster_schema = clusters.get("additionalProperties").?.object;
    const pick = cluster_schema.get("properties").?.object.get("pick").?.object;
    const arms = pick.get("anyOf").?.array;
    try std.testing.expectEqual(@as(usize, 2), arms.items.len);

    // The string arm must not advertise `hash`: a bare hash never
    // resolves (#178 — its key is the operator's to name).
    const string_arm = arms.items[0].object;
    try std.testing.expectEqualStrings("string", string_arm.get("type").?.string);
    const literals = string_arm.get("enum").?.array;
    try std.testing.expectEqual(@as(usize, 2), literals.items.len);
    for (literals.items) |literal| {
        try std.testing.expect(!std.mem.eql(u8, literal.string, "hash"));
    }

    // The object arm requires exactly `policy` and closes both
    // vocabularies: every `Pick` policy, every `HashKey` key.
    const object_arm = arms.items[1].object;
    try std.testing.expectEqualStrings("object", object_arm.get("type").?.string);
    const required = object_arm.get("required").?.array;
    try std.testing.expectEqual(@as(usize, 1), required.items.len);
    try std.testing.expectEqualStrings("policy", required.items[0].string);
    const properties = object_arm.get("properties").?.object;
    const policies = properties.get("policy").?.object.get("enum").?.array;
    try std.testing.expectEqual(
        @typeInfo(config.Config.Cluster.Pick).@"enum".fields.len,
        policies.items.len,
    );
    const keys = properties.get("key").?.object.get("enum").?.array;
    try std.testing.expectEqual(
        @typeInfo(std.meta.Tag(config.Config.Cluster.HashKey)).@"enum".fields.len,
        keys.items.len,
    );
}

test "config_schema: response filter status bounds and class vocabulary" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const listener = parsed.value.object.get("properties").?.object
        .get("listeners").?.object.get("items").?.object;
    const response_filters = listener.get("properties").?.object
        .get("response_filters").?.object;
    const match = response_filters.get("items").?.object.get("properties").?.object
        .get("match").?.object;
    // The status list's items carry the loader's own bounds — the schema
    // cannot promise a status the parser can never produce.
    const status_items = match.get("properties").?.object
        .get("status").?.object.get("items").?.object;
    try std.testing.expectEqualStrings("integer", status_items.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 100), status_items.get("minimum").?.integer);
    try std.testing.expectEqual(@as(i64, 599), status_items.get("maximum").?.integer);
    // The class vocabulary is the closed enum, "1xx" through "5xx".
    const class_values = match.get("properties").?.object
        .get("status_class").?.object.get("enum").?.array;
    try std.testing.expectEqual(@as(usize, 5), class_values.items.len);
    try std.testing.expectEqualStrings("1xx", class_values.items[0].string);
    try std.testing.expectEqualStrings("5xx", class_values.items[4].string);
}

test "config_schema: every exactly-one-of fork is emitted, and names real properties" {
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
    defer parsed.deinit();

    const listener = parsed.value.object.get("properties").?.object
        .get("listeners").?.object.get("items").?.object;
    try expectOneOf(&listener, config.ListenerJson.schema_one_of.len);

    const filter_item = listener.get("properties").?.object
        .get("request_filters").?.object.get("items").?.object;
    const action = filter_item.get("properties").?.object
        .get("actions").?.object.get("items").?.object;
    try expectOneOf(&action, config.ActionJson.schema_one_of.len);
    const header_match = filter_item.get("properties").?.object
        .get("match").?.object.get("properties").?.object
        .get("headers").?.object.get("items").?.object;
    try expectOneOf(&header_match, config.HeaderMatchJson.schema_one_of.len);
}

/// One fork, checked the way a validator would read it: an arm per
/// declared name, each arm requiring exactly that one field, and every
/// named field actually declared as a property of the same object.
///
/// The last part is the one worth the code. A `oneOf` naming a field the
/// object does not declare is not an error in JSON Schema — combined
/// with `additionalProperties: false` it is a branch nothing can ever
/// satisfy, so the fork would silently reject every config instead of
/// forking them.
fn expectOneOf(object: *const std.json.ObjectMap, arms_expected: usize) !void {
    const arms = object.get("oneOf").?.array;
    try std.testing.expectEqual(arms_expected, arms.items.len);
    const properties = object.get("properties").?.object;
    for (arms.items) |arm| {
        const required = arm.object.get("required").?.array;
        try std.testing.expectEqual(@as(usize, 1), required.items.len);
        const name = required.items[0].string;
        try std.testing.expect(properties.contains(name));
        // And it must not *also* be in the object's own `required`: a
        // field required outright is set in every config, so every arm
        // would match at once and "exactly one" would reject them all.
        for (object.get("required").?.array.items) |already| {
            try std.testing.expect(!std.mem.eql(u8, already.string, name));
        }
    }
}

test "config_schema: no DTO concedes a rule the schema now expresses" {
    // #305's measurable definition of done, held at the count it is
    // actually at. Every "enforced by the loader" sentence in the emitted
    // document is a cross-field rule a shape could have carried instead —
    // the forks were the expressible third and are gone, so what is left
    // must be genuinely semantic. A new concession has to move this
    // number deliberately rather than accumulate quietly.
    var buffer: [64 * 1024]u8 = undefined;
    const text = try renderInto(&buffer);
    try std.testing.expectEqual(@as(usize, 0), countOccurrences(text, "enforced by the loader, not this schema"));
    try std.testing.expectEqual(@as(usize, 0), countOccurrences(text, "that fork is enforced by the loader"));
    // The one remaining, and it is the honest one: the root's note that
    // canonical prefixes, address literals and reserved header names are
    // semantic checks no JSON Schema can carry.
    try std.testing.expectEqual(@as(usize, 1), countOccurrences(text, "enforced by the loader"));
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    assert(needle.len >= 1);
    var count: usize = 0;
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, offset, needle)) |at| {
        assert(at >= offset);
        count += 1;
        offset = at + needle.len;
    }
    return count;
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
