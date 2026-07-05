//! JSON Schema (draft 2020-12) generator for the proxy config, derived by
//! comptime reflection from `config.Dto` — the single source of truth, so the
//! schema can never drift from the parser (docs/DESIGN.md §7 Phase 6, slice 1).
//! Descriptions/enum values/formats come from each DTO struct's co-located
//! `schema_doc`/`schema_fields` metadata, which `config.assert_meta_matches`
//! pins to the field set at comptime. The output is deterministic (declaration
//! field order, no maps, fixed 2-space indent, LF newlines) so a byte-compare
//! against the committed `config.schema.json` is a stable drift gate.
//!
//! Emits the object schema for every DTO struct: `type`/`properties`/`required`
//! (fields with no default)/`additionalProperties:false`, integer `minimum`/
//! `maximum` from the exact Zig int type (or a metadata override), string/array
//! shapes, `?T` as a nullable `type` array or an `anyOf` with `{"type":"null"}`,
//! and `default` from the field's default value.

const std = @import("std");
const config = @import("config.zig");

const Dto = config.Dto;
const Error = std.Io.Writer.Error;

/// Re-export so a CLI that imports only this module can still parse/validate a
/// config file (`config_schema.config_zig.parse_diagnostic`).
pub const config_zig = config;

/// Write the full JSON Schema document for the proxy config to `w`.
pub fn write(w: *std.Io.Writer) Error!void {
    try w.writeAll("{\n");
    try pad(w, 1);
    try w.writeAll("\"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n");
    try pad(w, 1);
    try w.writeAll("\"title\": \"zoxy configuration\",\n");
    try write_object_body(w, Dto, 1);
    try w.writeAll("\n}\n");
}

/// A complete object schema `{ … }` (used for nested objects and array items).
fn write_object(w: *std.Io.Writer, comptime T: type, comptime indent: usize) Error!void {
    try w.writeAll("{\n");
    try write_object_body(w, T, indent + 1);
    try w.writeAll("\n");
    try pad(w, indent);
    try w.writeAll("}");
}

/// The keys of an object schema (no enclosing braces), each indented at
/// `indent`. Calls the metadata drift check so a nested struct forgotten in
/// `config.dto_types` is still caught the moment it is emitted.
fn write_object_body(w: *std.Io.Writer, comptime T: type, comptime indent: usize) Error!void {
    comptime config.assert_meta_matches(T);
    const fields = @typeInfo(T).@"struct".fields;

    try pad(w, indent);
    try w.writeAll("\"type\": \"object\",\n");
    if (@hasDecl(T, "schema_doc")) {
        try pad(w, indent);
        try w.writeAll("\"description\": ");
        try json_string(w, T.schema_doc);
        try w.writeAll(",\n");
    }
    try pad(w, indent);
    try w.writeAll("\"properties\": {\n");
    inline for (fields, 0..) |field, i| {
        try pad(w, indent + 1);
        try json_string(w, field.name);
        try w.writeAll(": ");
        try write_field(w, T, field, indent + 1);
        if (i + 1 < fields.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try pad(w, indent);
    try w.writeAll("},\n");

    try pad(w, indent);
    try w.writeAll("\"required\": [");
    comptime var wrote_required = false;
    inline for (fields) |field| {
        if (field.defaultValue() == null) {
            if (wrote_required) try w.writeAll(", ");
            try json_string(w, field.name);
            wrote_required = true;
        }
    }
    try w.writeAll("],\n");

    try pad(w, indent);
    try w.writeAll("\"additionalProperties\": false");
}

/// One field's schema value: shape from the type, overlaid with metadata, then
/// a `default` from the field's default value (null defaults are elided).
fn write_field(
    w: *std.Io.Writer,
    comptime T: type,
    comptime field: std.builtin.Type.StructField,
    comptime indent: usize,
) Error!void {
    const meta = @field(T.schema_fields, field.name);
    const Meta = @TypeOf(meta);
    const info = @typeInfo(field.type);
    const nullable = info == .optional;
    const Base = if (nullable) info.optional.child else field.type;

    try w.writeAll("{");
    var first = true;

    if (@hasField(Meta, "desc")) {
        try key(w, indent, &first, "description");
        try json_string(w, meta.desc);
    }
    try write_shape(w, Base, nullable, meta, indent, &first);
    if (@hasField(Meta, "format")) {
        try key(w, indent, &first, "format");
        try json_string(w, meta.format);
    }
    if (@hasField(Meta, "pattern")) {
        try key(w, indent, &first, "pattern");
        try json_string(w, meta.pattern);
    }
    if (@hasField(Meta, "units")) {
        try key(w, indent, &first, "x-units");
        try json_string(w, meta.units);
    }
    if (@hasField(Meta, "enum_type")) try write_enum(w, meta, indent, &first);
    if (@hasField(Meta, "example")) {
        try key(w, indent, &first, "examples");
        try w.writeAll("[");
        try json_string(w, meta.example);
        try w.writeAll("]");
    }
    if (field.defaultValue()) |default| {
        const is_null = nullable and default == null;
        if (!is_null) {
            try key(w, indent, &first, "default");
            try write_default(w, field.type, default);
        }
    }

    if (!first) {
        try w.writeAll("\n");
        try pad(w, indent);
    }
    try w.writeAll("}");
}

/// The `type` (and `minimum`/`maximum` or `items`/`anyOf`) keys for `Base`.
fn write_shape(
    w: *std.Io.Writer,
    comptime Base: type,
    comptime nullable: bool,
    meta: anytype,
    comptime indent: usize,
    first: *bool,
) Error!void {
    const Meta = @TypeOf(meta);
    switch (@typeInfo(Base)) {
        .bool => try type_key(w, indent, first, "boolean", nullable),
        .int => {
            try type_key(w, indent, first, "integer", nullable);
            const lo = if (@hasField(Meta, "minimum")) meta.minimum else std.math.minInt(Base);
            const hi = if (@hasField(Meta, "maximum")) meta.maximum else std.math.maxInt(Base);
            try key(w, indent, first, "minimum");
            try w.print("{d}", .{lo});
            try key(w, indent, first, "maximum");
            try w.print("{d}", .{hi});
        },
        .pointer => |ptr| {
            if (ptr.child == u8) {
                try type_key(w, indent, first, "string", nullable);
            } else {
                try type_key(w, indent, first, "array", nullable);
                try key(w, indent, first, "items");
                try write_items(w, ptr.child, indent + 1);
            }
        },
        .@"struct" => {
            try key(w, indent, first, if (nullable) "anyOf" else "allOf");
            try w.writeAll("[\n");
            try pad(w, indent + 2);
            try write_object(w, Base, indent + 2);
            if (nullable) {
                try w.writeAll(",\n");
                try pad(w, indent + 2);
                try w.writeAll("{ \"type\": \"null\" }");
            }
            try w.writeAll("\n");
            try pad(w, indent + 1);
            try w.writeAll("]");
        },
        else => @compileError("config_schema: unsupported field type " ++ @typeName(Base)),
    }
}

/// The `items` schema of an array: an object for struct elements, a plain
/// string schema for `[]const []const u8`.
fn write_items(w: *std.Io.Writer, comptime Child: type, comptime indent: usize) Error!void {
    switch (@typeInfo(Child)) {
        .@"struct" => try write_object(w, Child, indent),
        .pointer => |ptr| {
            if (ptr.child != u8) @compileError("config_schema: unsupported array element");
            try w.writeAll("{ \"type\": \"string\" }");
        },
        else => @compileError("config_schema: unsupported array element " ++ @typeName(Child)),
    }
}

/// `"enum": [...]` from the metadata's `enum_type`, plus a per-value
/// `x-enumDescriptions` object when `enum_docs` is present. Values come from the
/// real enum, and `@field(enum_docs, name)` forces a doc for every value — both
/// drift-proof against the enum.
fn write_enum(w: *std.Io.Writer, meta: anytype, comptime indent: usize, first: *bool) Error!void {
    const E = meta.enum_type;
    const values = @typeInfo(E).@"enum".fields;
    try key(w, indent, first, "enum");
    try w.writeAll("[");
    inline for (values, 0..) |value, i| {
        if (i != 0) try w.writeAll(", ");
        try json_string(w, value.name);
    }
    try w.writeAll("]");
    if (@hasField(@TypeOf(meta), "enum_docs")) {
        try key(w, indent, first, "x-enumDescriptions");
        try w.writeAll("{");
        inline for (values, 0..) |value, i| {
            if (i != 0) try w.writeAll(",");
            try w.writeAll(" ");
            try json_string(w, value.name);
            try w.writeAll(": ");
            try json_string(w, @field(meta.enum_docs, value.name));
        }
        try w.writeAll(" }");
    }
}

/// Emit a field's default value as JSON.
fn write_default(w: *std.Io.Writer, comptime T: type, value: T) Error!void {
    switch (@typeInfo(T)) {
        .bool => try w.writeAll(if (value) "true" else "false"),
        .int => try w.print("{d}", .{value}),
        .optional => |opt| if (value) |inner|
            try write_default(w, opt.child, inner)
        else
            try w.writeAll("null"),
        .pointer => |ptr| if (ptr.child == u8)
            try json_string(w, value)
        else
            try w.writeAll("[]"), // the only slice default is an empty list
        else => @compileError("config_schema: unsupported default type " ++ @typeName(T)),
    }
}

/// Open a new key line inside a field object: newline for the first key,
/// comma-newline for the rest, then indent and `"name": `.
fn key(
    w: *std.Io.Writer,
    comptime indent: usize,
    first: *bool,
    comptime name: []const u8,
) Error!void {
    if (first.*) {
        try w.writeAll("\n");
        first.* = false;
    } else {
        try w.writeAll(",\n");
    }
    try pad(w, indent + 1);
    try json_string(w, name);
    try w.writeAll(": ");
}

/// The `type` key, as a bare string or a `["<name>", "null"]` union.
fn type_key(
    w: *std.Io.Writer,
    comptime indent: usize,
    first: *bool,
    comptime name: []const u8,
    comptime nullable: bool,
) Error!void {
    try key(w, indent, first, "type");
    if (nullable) {
        try w.writeAll("[");
        try json_string(w, name);
        try w.writeAll(", ");
        try json_string(w, "null");
        try w.writeAll("]");
    } else {
        try json_string(w, name);
    }
}

fn pad(w: *std.Io.Writer, comptime indent: usize) Error!void {
    const spaces = " " ** 40;
    var remaining: usize = indent * 2;
    while (remaining > 0) {
        const take = @min(remaining, spaces.len);
        try w.writeAll(spaces[0..take]);
        remaining -= take;
    }
}

/// Write `bytes` as a JSON string literal, escaping per RFC 8259.
fn json_string(w: *std.Io.Writer, bytes: []const u8) Error!void {
    const hex = "0123456789abcdef";
    try w.writeByte('"');
    for (bytes) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => if (c < 0x20) {
            try w.writeAll("\\u00");
            try w.writeByte(hex[(c >> 4) & 0xf]);
            try w.writeByte(hex[c & 0xf]);
        } else try w.writeByte(c),
    };
    try w.writeByte('"');
}

// ---- tests ----------------------------------------------------------------

test "config_schema: emits valid, strict, documented JSON Schema" {
    var buf: [64 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try write(&writer);
    const out = writer.buffered();

    // Structural spot-checks on the raw text.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"additionalProperties\": false") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        out,
        "\"$schema\": \"https://json-schema.org/draft/2020-12/schema\"",
    ) != null);
    // Enum values are sourced from the real enums, and units annotate ms fields.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"reuseport\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"maglev\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"milliseconds\"") != null);

    // The output must be valid JSON, and required-ness must follow field defaults.
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, out, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("object", root.get("type").?.string);
    try std.testing.expectEqual(false, root.get("additionalProperties").?.bool);

    const properties = root.get("properties").?.object;
    try std.testing.expect(properties.get("listen") != null);
    try std.testing.expect(properties.get("admin") != null);

    var required_listen = false;
    var required_admin = false;
    for (root.get("required").?.array.items) |item| {
        if (std.mem.eql(u8, item.string, "listen")) required_listen = true;
        if (std.mem.eql(u8, item.string, "admin")) required_admin = true;
    }
    try std.testing.expect(required_listen); // no default
    try std.testing.expect(!required_admin); // defaults to null

    // accept_mode carries the enum drawn from `config.AcceptMode`.
    const accept_mode = properties.get("accept_mode").?.object;
    var saw_shared = false;
    for (accept_mode.get("enum").?.array.items) |item| {
        if (std.mem.eql(u8, item.string, "shared")) saw_shared = true;
    }
    try std.testing.expect(saw_shared);
}

test "config_schema: generated schema is deterministic" {
    var buf_a: [64 * 1024]u8 = undefined;
    var buf_b: [64 * 1024]u8 = undefined;
    var writer_a = std.Io.Writer.fixed(&buf_a);
    var writer_b = std.Io.Writer.fixed(&buf_b);
    try write(&writer_a);
    try write(&writer_b);
    try std.testing.expectEqualStrings(writer_a.buffered(), writer_b.buffered());
}
