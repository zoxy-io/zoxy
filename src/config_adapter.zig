//! Zoxyfile → JSON config adapter (docs/DESIGN.md §7 Phase 6, slice 3): a
//! terse, human-authored surface that *lowers to* the JSON `config.zig` already
//! parses — JSON stays the single source of truth, the sugar never becomes a
//! second one. Modelled on Caddy's config adapter (`caddy adapt`): this module
//! only understands the surface syntax and emits JSON text; every semantic
//! check (unknown keys, ms→ns, address parsing, bounds) stays downstream in
//! `config.parse_diagnostic`, which consumes the emitted JSON unchanged.
//!
//! `config.Dto` stays authoritative for the *field names* too, enforced at
//! compile time: every emitted JSON key goes through `dto_field` (asserts the
//! field exists on its DTO struct) and the resilience `Field` tables through
//! `assert_table` (existence + full coverage + type/kind match). A renamed or
//! removed DTO field is a build error here, not a silent runtime rejection —
//! the same "can't drift from the parser" guarantee `config_schema.zig` gives
//! the JSON Schema via `assert_meta_matches`. Only the DSL *directive* names
//! (the human vocabulary, e.g. `backoff_base` for `backoff_base_ms`) are free.
//!
//! Startup/reload only (the JSON parse is the allocation island), so the
//! emitted document is accumulated with an allocating writer — no hot path.
//!
//! Grammar (line-oriented, `#` starts a comment, `{`/`}` open/close blocks):
//!
//!   listen 127.0.0.1:8080
//!   admin  127.0.0.1:9901
//!   handoff /run/zoxy.sock
//!   accept_mode shared            # reuseport | shared
//!   workers 4                     # fixed worker count; omit = one per CPU
//!
//!   tls {
//!       certificate cert.pem
//!       key         key.pem
//!       http2                     # flag: presence = true
//!       kernel_offload off        # on/off/true/false/yes/no
//!       identity {                # repeatable → additional_identities[]
//!           server_names a.example.com b.example.com
//!           certificate a.pem
//!           key         a-key.pem
//!       }
//!   }
//!
//!   route api.example.com /v1 -> api   # [host] [path] -> cluster
//!   route /static -> assets            # one match token: /… = path, else host
//!   route -> default                   # host=*, path=/
//!
//!   cluster api {
//!       endpoints 127.0.0.1:9001 127.0.0.1:9002
//!       lb maglev header x-user-id   # least_request | maglev [target|header <name>]
//!       per_try_timeout 1500ms
//!       retry {                      # one directive per line; `}` on its own line
//!           max 2
//!           backoff_base 25ms
//!       }
//!       outlier {
//!           consecutive_failures 5
//!           ejection 30s
//!       }
//!   }
//!
//! One directive per line; a block's opening `{` may trail its directive, its
//! `}` sits alone. Durations accept a `ms`/`s` suffix (bare number =
//! milliseconds) and lower to the DTO's `*_ms` fields.

const std = @import("std");
const constants = @import("constants.zig");
const config = @import("config.zig");

const assert = std.debug.assert;
const Writer = std.Io.Writer;
const Dto = config.Dto;

/// Comptime-checked JSON key: assert `T` (a `config.Dto` struct) declares field
/// `name`, and return `name` for use as the emitted key. **This is the pin that
/// keeps `config.Dto` the single source of truth** — the adapter emits JSON that
/// the DTO parses strictly, so a renamed/removed DTO field turns every hand-
/// written emit site referencing it into a *compile error* here, not a silent
/// unknown-key rejection at runtime. (The `Field` tables are pinned the same way
/// by `assert_table`, which also enforces full coverage.)
fn dto_field(comptime T: type, comptime name: []const u8) []const u8 {
    comptime assert(@typeInfo(T) == .@"struct");
    if (!@hasField(T, name)) {
        @compileError("config_adapter: " ++ @typeName(T) ++ " has no field '" ++ name ++ "'");
    }
    return name;
}

/// Surfaced on error: the 1-based source line and a short human message. Kept
/// caller-owned so the adapter never logs (mirrors `config.Diagnostic`).
pub const Diagnostic = struct {
    line: u32 = 0,
    message: ?[]const u8 = null,
};

pub const Error = error{
    Syntax,
    UnknownDirective,
    MissingValue,
    InvalidValue,
    UnexpectedToken,
    UnterminatedBlock,
    TooManyDirectives,
    TooManyTokens,
    NoEndpoints,
} || Writer.Error || std.mem.Allocator.Error;

/// Most tokens a single line may carry (directive + values). Generous versus
/// the real limits (`endpoints_per_cluster_max` + 1); a longer line is a bug.
const tokens_max: usize = 128;
/// Directives scanned per block before bailing (TigerStyle: bound every loop).
const directives_max: u32 = 8192;

/// Lower a Zoxyfile `source` into JSON config text (allocator-owned; the caller
/// frees it or, at startup/reload, lets its arena reclaim it). On error the
/// returned bytes are undefined and `diag` names the offending line.
pub fn to_json(gpa: std.mem.Allocator, source: []const u8, diag: *Diagnostic) Error![]u8 {
    assert(diag.message == null); // fresh diagnostic

    // Top-level scalars/tls, routes, and clusters accumulate separately so the
    // input may interleave them (JSON groups them); stitched into one object
    // below. Each is a JSON object body / array body with no enclosing braces.
    var scalars: Writer.Allocating = .init(gpa);
    defer scalars.deinit();
    var routes: Writer.Allocating = .init(gpa);
    defer routes.deinit();
    var clusters: Writer.Allocating = .init(gpa);
    defer clusters.deinit();

    var parser: Parser = .{
        .lines = std.mem.splitScalar(u8, source, '\n'),
        .diag = diag,
        .gpa = gpa,
        .token_buf = undefined,
        .scalars = .{ .w = &scalars.writer },
        .routes = .{ .w = &routes.writer },
        .clusters = .{ .w = &clusters.writer },
    };
    try parser.parse_top();

    var out: Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeByte('{');
    if (scalars.written().len > 0) {
        try w.writeAll(scalars.written());
        try w.writeByte(',');
    }
    try emit_string(w, dto_field(Dto, "routes"));
    try w.writeAll(":[");
    try w.writeAll(routes.written());
    try w.writeAll("],");
    try emit_string(w, dto_field(Dto, "clusters"));
    try w.writeAll(":[");
    try w.writeAll(clusters.written());
    try w.writeAll("]}");
    return try out.toOwnedSlice();
}

/// A comma-tracked object-field / array-element writer over one output stream.
/// `field`/`elem` emit the leading separator only after the first item, so a
/// freshly opened `{`/`[` never gets a stray comma.
const Emit = struct {
    w: *Writer,
    first: bool = true,

    fn field(e: *Emit, name: []const u8) Writer.Error!void {
        if (!e.first) try e.w.writeByte(',');
        e.first = false;
        try emit_string(e.w, name);
        try e.w.writeByte(':');
    }

    fn elem(e: *Emit) Writer.Error!void {
        if (!e.first) try e.w.writeByte(',');
        e.first = false;
    }
};

/// One tokenized, comment-stripped, non-blank source line.
const Line = struct {
    tokens: []const []const u8,

    fn directive(l: Line) []const u8 {
        assert(l.tokens.len > 0);
        return l.tokens[0];
    }

    fn is_close(l: Line) bool {
        return l.tokens.len == 1 and eq(l.tokens[0], "}");
    }

    fn opens_block(l: Line) bool {
        assert(l.tokens.len > 0);
        return eq(l.tokens[l.tokens.len - 1], "{");
    }

    /// Tokens excluding a trailing `{` — the directive and its own arguments.
    fn head(l: Line) []const []const u8 {
        return if (l.opens_block()) l.tokens[0 .. l.tokens.len - 1] else l.tokens;
    }
};

const Parser = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    line_number: u32 = 0,
    diag: *Diagnostic,
    gpa: std.mem.Allocator,
    token_buf: [tokens_max][]const u8,
    scalars: Emit,
    routes: Emit,
    clusters: Emit,

    /// Next non-blank logical line, or null at end of input. Tokens point into
    /// `source` (stable) but live in `token_buf` (reused per call): a caller
    /// must copy out the individual token slices it needs before advancing.
    fn next_line(p: *Parser) Error!?Line {
        while (p.lines.next()) |raw| {
            p.line_number += 1;
            const stripped = strip_comment(raw);
            var count: usize = 0;
            var it = std.mem.tokenizeAny(u8, stripped, " \t\r");
            while (it.next()) |tok| {
                if (count >= tokens_max) {
                    return p.fail(error.TooManyTokens, "too many tokens on a line");
                }
                p.token_buf[count] = tok;
                count += 1;
            }
            if (count == 0) continue; // blank or comment-only
            return Line{ .tokens = p.token_buf[0..count] };
        }
        return null;
    }

    fn fail(p: *Parser, err: Error, message: []const u8) Error {
        assert(message.len > 0);
        p.diag.line = p.line_number;
        p.diag.message = message;
        return err;
    }

    /// Count one directive against the per-block bound (TigerStyle: every loop
    /// is bounded). Errors past the limit so a pathological file cannot spin.
    fn bump(p: *Parser, seen: *u32) Error!void {
        seen.* += 1;
        if (seen.* > directives_max) return p.fail(error.TooManyDirectives, "too many directives");
    }

    /// Top level: scalars/tls into `scalars`, routes into `routes`, clusters
    /// into `clusters`. A stray `}` here closes nothing.
    fn parse_top(p: *Parser) Error!void {
        var seen: u32 = 0;
        while (try p.next_line()) |line| {
            try p.bump(&seen);
            if (line.is_close()) return p.fail(error.UnexpectedToken, "unexpected '}'");
            const d = line.directive();
            if (eq(d, "listen")) {
                try p.scalar(line, &p.scalars, dto_field(Dto, "listen"));
            } else if (eq(d, "admin")) {
                try p.scalar(line, &p.scalars, dto_field(Dto, "admin"));
            } else if (eq(d, "handoff")) {
                try p.scalar(line, &p.scalars, dto_field(Dto, "handoff"));
            } else if (eq(d, "accept_mode")) {
                try p.scalar(line, &p.scalars, dto_field(Dto, "accept_mode"));
            } else if (eq(d, "workers")) {
                try p.scalar_integer(line, &p.scalars, dto_field(Dto, "workers"));
            } else if (eq(d, "tls")) {
                try p.top_tls(line);
            } else if (eq(d, "route")) {
                try p.route(line);
            } else if (eq(d, "cluster")) {
                try p.cluster(line);
            } else {
                return p.fail(error.UnknownDirective, "unknown top-level directive");
            }
        }
    }

    /// A `name value` scalar string field into the given emitter.
    fn scalar(p: *Parser, line: Line, emit: *Emit, name: []const u8) Error!void {
        if (line.opens_block()) {
            return p.fail(error.UnexpectedToken, "directive takes a value, not a block");
        }
        if (line.tokens.len != 2) {
            return p.fail(error.MissingValue, "directive needs exactly one value");
        }
        try emit.field(name);
        try emit_string(emit.w, line.tokens[1]);
    }

    /// A `name value` scalar integer field into the given emitter (unquoted).
    fn scalar_integer(p: *Parser, line: Line, emit: *Emit, name: []const u8) Error!void {
        if (line.opens_block()) {
            return p.fail(error.UnexpectedToken, "directive takes a value, not a block");
        }
        if (line.tokens.len != 2) {
            return p.fail(error.MissingValue, "directive needs exactly one value");
        }
        try emit.field(name);
        try p.emit_integer(emit.w, line.tokens[1]);
    }

    /// `tls { … }` on the listener → the `tls` object; `identity` sub-blocks
    /// collect into `additional_identities`.
    fn top_tls(p: *Parser, line: Line) Error!void {
        if (!line.opens_block()) return p.fail(error.UnexpectedToken, "tls must open a block");
        if (line.head().len != 1) return p.fail(error.Syntax, "tls takes no arguments");
        try p.scalars.field(dto_field(Dto, "tls"));
        const w = p.scalars.w;
        try w.writeByte('{');
        var emit: Emit = .{ .w = w };

        var ids: Writer.Allocating = .init(p.gpa);
        defer ids.deinit();
        var ids_emit: Emit = .{ .w = &ids.writer };

        var seen: u32 = 0;
        while (try p.next_line()) |ln| {
            try p.bump(&seen);
            if (ln.is_close()) {
                if (!ids_emit.first) {
                    try emit.field(dto_field(Dto.TlsDto, "additional_identities"));
                    try w.writeByte('[');
                    try w.writeAll(ids.written());
                    try w.writeByte(']');
                }
                try w.writeByte('}');
                return;
            }
            const d = ln.directive();
            if (eq(d, "certificate")) {
                try p.kv_string(ln, &emit, dto_field(Dto.TlsDto, "certificate_file"));
            } else if (eq(d, "key")) {
                try p.kv_string(ln, &emit, dto_field(Dto.TlsDto, "private_key_file"));
            } else if (eq(d, "http2")) {
                try p.kv_flag(ln, &emit, dto_field(Dto.TlsDto, "http2"));
            } else if (eq(d, "kernel_offload")) {
                try p.kv_bool(ln, &emit, dto_field(Dto.TlsDto, "kernel_offload"));
            } else if (eq(d, "identity")) {
                if (!ln.opens_block()) {
                    return p.fail(error.UnexpectedToken, "identity must open a block");
                }
                if (ln.head().len != 1) return p.fail(error.Syntax, "identity takes no arguments");
                try ids_emit.elem();
                try ids.writer.writeByte('{');
                try p.identity(&ids.writer);
                try ids.writer.writeByte('}');
            } else {
                return p.fail(error.UnknownDirective, "unknown tls directive");
            }
        }
        return p.fail(error.UnterminatedBlock, "unterminated tls block");
    }

    /// One SNI `identity { … }` object body.
    fn identity(p: *Parser, w: *Writer) Error!void {
        var emit: Emit = .{ .w = w };
        var seen: u32 = 0;
        while (try p.next_line()) |ln| {
            try p.bump(&seen);
            if (ln.is_close()) return;
            const d = ln.directive();
            if (eq(d, "server_names")) {
                try p.string_array(ln, &emit, dto_field(Dto.TlsIdentityDto, "server_names"));
            } else if (eq(d, "certificate")) {
                try p.kv_string(ln, &emit, dto_field(Dto.TlsIdentityDto, "certificate_file"));
            } else if (eq(d, "key")) {
                try p.kv_string(ln, &emit, dto_field(Dto.TlsIdentityDto, "private_key_file"));
            } else {
                return p.fail(error.UnknownDirective, "unknown identity directive");
            }
        }
        return p.fail(error.UnterminatedBlock, "unterminated identity block");
    }

    /// `route [host] [path] -> cluster`. Left of the arrow: 0 tokens (any host,
    /// any path), 1 token (a leading `/` is the path, else the host), or 2
    /// (host then path). Right of the arrow: exactly the cluster name.
    fn route(p: *Parser, line: Line) Error!void {
        if (line.opens_block()) return p.fail(error.UnexpectedToken, "route is not a block");
        var arrow: ?usize = null;
        for (line.tokens[1..], 1..) |tok, i| {
            if (eq(tok, "->")) {
                arrow = i;
                break;
            }
        }
        const at = arrow orelse return p.fail(error.Syntax, "route needs '-> <cluster>'");
        const match = line.tokens[1..at];
        const rhs = line.tokens[at + 1 ..];
        if (rhs.len != 1) return p.fail(error.Syntax, "route needs exactly one cluster after '->'");
        var host: []const u8 = "*";
        var path: []const u8 = "/";
        switch (match.len) {
            0 => {},
            1 => if (std.mem.startsWith(u8, match[0], "/")) {
                path = match[0];
            } else {
                host = match[0];
            },
            2 => {
                host = match[0];
                path = match[1];
            },
            else => return p.fail(error.Syntax, "route match takes at most a host and a path"),
        }
        try p.routes.elem();
        const w = p.routes.w;
        var emit: Emit = .{ .w = w };
        try w.writeByte('{');
        try emit.field(dto_field(Dto.RouteDto, "host"));
        try emit_string(w, host);
        try emit.field(dto_field(Dto.RouteDto, "path_prefix"));
        try emit_string(w, path);
        try emit.field(dto_field(Dto.RouteDto, "cluster"));
        try emit_string(w, rhs[0]);
        try w.writeByte('}');
    }

    /// `cluster <name> { … }`. Endpoints accumulate (across one or more
    /// `endpoints` lines) into a side buffer spliced in at the closing brace;
    /// other directives emit inline.
    fn cluster(p: *Parser, line: Line) Error!void {
        if (!line.opens_block()) return p.fail(error.UnexpectedToken, "cluster must open a block");
        if (line.head().len != 2) return p.fail(error.Syntax, "cluster needs exactly a name");
        const name = line.head()[1];
        try p.clusters.elem();
        const w = p.clusters.w;
        var emit: Emit = .{ .w = w };
        try w.writeByte('{');
        try emit.field(dto_field(Dto.ClusterDto, "name"));
        try emit_string(w, name);

        var eps: Writer.Allocating = .init(p.gpa);
        defer eps.deinit();
        var eps_emit: Emit = .{ .w = &eps.writer };

        var seen: u32 = 0;
        while (try p.next_line()) |ln| {
            try p.bump(&seen);
            if (ln.is_close()) {
                if (eps_emit.first) return p.fail(error.NoEndpoints, "cluster has no endpoints");
                try emit.field(dto_field(Dto.ClusterDto, "endpoints"));
                try w.writeByte('[');
                try w.writeAll(eps.written());
                try w.writeByte(']');
                try w.writeByte('}');
                return;
            }
            try p.cluster_directive(ln, &emit, &eps_emit);
        }
        return p.fail(error.UnterminatedBlock, "unterminated cluster block");
    }

    /// One directive inside a `cluster { … }` block.
    fn cluster_directive(p: *Parser, ln: Line, emit: *Emit, eps_emit: *Emit) Error!void {
        const d = ln.directive();
        if (eq(d, "endpoints")) {
            if (ln.opens_block()) return p.fail(error.UnexpectedToken, "endpoints is not a block");
            if (ln.tokens.len < 2) {
                return p.fail(error.MissingValue, "endpoints needs at least one address");
            }
            for (ln.tokens[1..]) |addr| {
                try eps_emit.elem();
                try emit_string(eps_emit.w, addr);
            }
        } else if (eq(d, "per_try_timeout")) {
            try p.kv_duration(ln, emit, dto_field(Dto.ClusterDto, "per_try_timeout_ms"));
        } else if (eq(d, "lb")) {
            try p.lb(ln, emit);
        } else if (eq(d, "retry")) {
            try p.sub_block(ln, emit, dto_field(Dto.ClusterDto, "retry"), &retry_fields);
        } else if (eq(d, "circuit_breaker")) {
            const name = dto_field(Dto.ClusterDto, "circuit_breaker");
            try p.sub_block(ln, emit, name, &circuit_breaker_fields);
        } else if (eq(d, "outlier")) {
            try p.sub_block(ln, emit, dto_field(Dto.ClusterDto, "outlier"), &outlier_fields);
        } else if (eq(d, "health_check")) {
            const name = dto_field(Dto.ClusterDto, "health_check");
            try p.sub_block(ln, emit, name, &health_check_fields);
        } else if (eq(d, "tls")) {
            try p.sub_block(ln, emit, dto_field(Dto.ClusterDto, "tls"), &cluster_tls_fields);
        } else {
            return p.fail(error.UnknownDirective, "unknown cluster directive");
        }
    }

    /// `lb <policy> [target | header <name>]` → the `lb` object.
    fn lb(p: *Parser, ln: Line, emit: *Emit) Error!void {
        if (ln.opens_block()) return p.fail(error.UnexpectedToken, "lb is not a block");
        if (ln.tokens.len < 2) return p.fail(error.MissingValue, "lb needs a policy");
        try emit.field(dto_field(Dto.ClusterDto, "lb"));
        const w = emit.w;
        try w.writeByte('{');
        var e: Emit = .{ .w = w };
        try e.field(dto_field(Dto.LbDto, "policy"));
        try emit_string(w, ln.tokens[1]);
        if (ln.tokens.len >= 3) {
            const hash = ln.tokens[2];
            try e.field(dto_field(Dto.LbDto, "hash"));
            try emit_string(w, hash);
            if (eq(hash, "header")) {
                if (ln.tokens.len != 4) {
                    return p.fail(error.Syntax, "lb header needs a header name");
                }
                try e.field(dto_field(Dto.LbDto, "header"));
                try emit_string(w, ln.tokens[3]);
            } else if (ln.tokens.len != 3) {
                return p.fail(error.Syntax, "lb takes a policy and an optional hash");
            }
        }
        try w.writeByte('}');
    }

    /// A `<name> { … }` sub-block of key/value directives described by `fields`.
    fn sub_block(
        p: *Parser,
        ln: Line,
        emit: *Emit,
        name: []const u8,
        fields: []const Field,
    ) Error!void {
        if (!ln.opens_block()) return p.fail(error.UnexpectedToken, "directive must open a block");
        if (ln.head().len != 1) return p.fail(error.Syntax, "block takes no arguments");
        try emit.field(name);
        const w = emit.w;
        try w.writeByte('{');
        try p.kv_body(w, fields);
        try w.writeByte('}');
    }

    /// The body of a key/value block: each line names a `Field` and carries its
    /// value (or nothing, for a flag). Loops until the closing brace.
    fn kv_body(p: *Parser, w: *Writer, fields: []const Field) Error!void {
        var emit: Emit = .{ .w = w };
        var seen: u32 = 0;
        while (try p.next_line()) |ln| {
            try p.bump(&seen);
            if (ln.is_close()) return;
            const f = find_field(fields, ln.directive()) orelse
                return p.fail(error.UnknownDirective, "unknown directive in block");
            if (f.kind == .flag) {
                if (ln.tokens.len != 1) return p.fail(error.UnexpectedToken, "flag takes no value");
                try emit.field(f.json);
                try w.writeAll("true");
                continue;
            }
            if (ln.opens_block()) return p.fail(error.UnexpectedToken, "directive is not a block");
            if (ln.tokens.len != 2) return p.fail(error.MissingValue, "directive needs one value");
            try emit.field(f.json);
            switch (f.kind) {
                .string => try emit_string(w, ln.tokens[1]),
                .integer => try p.emit_integer(w, ln.tokens[1]),
                .duration => try p.emit_duration(w, ln.tokens[1]),
                .boolean => try p.emit_bool(w, ln.tokens[1]),
                .flag => unreachable,
            }
        }
        return p.fail(error.UnterminatedBlock, "unterminated block");
    }

    // -- value helpers -----------------------------------------------------

    fn kv_string(p: *Parser, ln: Line, emit: *Emit, name: []const u8) Error!void {
        if (ln.opens_block()) return p.fail(error.UnexpectedToken, "directive is not a block");
        if (ln.tokens.len != 2) return p.fail(error.MissingValue, "directive needs one value");
        try emit.field(name);
        try emit_string(emit.w, ln.tokens[1]);
    }

    fn kv_flag(p: *Parser, ln: Line, emit: *Emit, name: []const u8) Error!void {
        if (ln.tokens.len != 1) return p.fail(error.UnexpectedToken, "flag takes no value");
        try emit.field(name);
        try emit.w.writeAll("true");
    }

    fn kv_bool(p: *Parser, ln: Line, emit: *Emit, name: []const u8) Error!void {
        if (ln.tokens.len != 2) return p.fail(error.MissingValue, "directive needs one value");
        try emit.field(name);
        try p.emit_bool(emit.w, ln.tokens[1]);
    }

    fn kv_duration(p: *Parser, ln: Line, emit: *Emit, name: []const u8) Error!void {
        if (ln.opens_block()) return p.fail(error.UnexpectedToken, "directive is not a block");
        if (ln.tokens.len != 2) return p.fail(error.MissingValue, "directive needs one value");
        try emit.field(name);
        try p.emit_duration(emit.w, ln.tokens[1]);
    }

    fn string_array(p: *Parser, ln: Line, emit: *Emit, name: []const u8) Error!void {
        if (ln.opens_block()) return p.fail(error.UnexpectedToken, "directive is not a block");
        if (ln.tokens.len < 2) {
            return p.fail(error.MissingValue, "directive needs at least one value");
        }
        try emit.field(name);
        const w = emit.w;
        try w.writeByte('[');
        for (ln.tokens[1..], 0..) |tok, i| {
            if (i != 0) try w.writeByte(',');
            try emit_string(w, tok);
        }
        try w.writeByte(']');
    }

    fn emit_integer(p: *Parser, w: *Writer, text: []const u8) Error!void {
        const n = std.fmt.parseInt(u64, text, 10) catch
            return p.fail(error.InvalidValue, "expected a non-negative integer");
        try emit_number(w, n);
    }

    fn emit_duration(p: *Parser, w: *Writer, text: []const u8) Error!void {
        const ms = parse_duration_ms(text) orelse
            return p.fail(error.InvalidValue, "expected a duration (e.g. 500ms, 30s, or 100)");
        try emit_number(w, ms);
    }

    fn emit_bool(p: *Parser, w: *Writer, text: []const u8) Error!void {
        if (eq(text, "on") or eq(text, "true") or eq(text, "yes")) {
            try w.writeAll("true");
        } else if (eq(text, "off") or eq(text, "false") or eq(text, "no")) {
            try w.writeAll("false");
        } else {
            return p.fail(error.InvalidValue, "expected on/off, true/false, or yes/no");
        }
    }
};

/// The value kind a key/value directive carries. `flag` is a valueless boolean
/// that emits `true` by its presence.
const Kind = enum { string, integer, duration, boolean, flag };

/// A key/value directive → JSON field mapping for a `kv_body` block.
const Field = struct {
    key: []const u8,
    json: []const u8,
    kind: Kind,
};

const retry_fields = [_]Field{
    .{ .key = "max", .json = "max", .kind = .integer },
    .{ .key = "backoff_base", .json = "backoff_base_ms", .kind = .duration },
    .{ .key = "backoff_cap", .json = "backoff_cap_ms", .kind = .duration },
    .{ .key = "budget_percent", .json = "budget_percent", .kind = .integer },
    .{ .key = "budget_min", .json = "budget_min", .kind = .integer },
};

const circuit_breaker_fields = [_]Field{
    .{ .key = "max_connections", .json = "max_connections", .kind = .integer },
    .{ .key = "max_pending", .json = "max_pending", .kind = .integer },
    .{ .key = "max_requests", .json = "max_requests", .kind = .integer },
    .{ .key = "max_retries", .json = "max_retries", .kind = .integer },
};

const outlier_fields = [_]Field{
    .{ .key = "consecutive_failures", .json = "consecutive_failures", .kind = .integer },
    .{ .key = "ejection", .json = "ejection_ms", .kind = .duration },
    .{ .key = "max_ejection_percent", .json = "max_ejection_percent", .kind = .integer },
};

const health_check_fields = [_]Field{
    .{ .key = "interval", .json = "interval_ms", .kind = .duration },
    .{ .key = "timeout", .json = "timeout_ms", .kind = .duration },
    .{ .key = "healthy_threshold", .json = "healthy_threshold", .kind = .integer },
    .{ .key = "unhealthy_threshold", .json = "unhealthy_threshold", .kind = .integer },
};

const cluster_tls_fields = [_]Field{
    .{ .key = "server_name", .json = "server_name", .kind = .string },
    .{ .key = "ca_file", .json = "ca_file", .kind = .string },
    .{ .key = "insecure", .json = "insecure", .kind = .flag },
};

/// Cross-check a DSL `Field` table against DTO struct `T` at comptime so it
/// cannot drift from the parser: (1) every entry's `.json` is a real field of
/// `T` whose type matches the entry's `.kind`; (2) every field of `T` is mapped
/// by exactly one entry — a new DTO knob must gain a DSL directive, a removed
/// one must lose it. The DSL *directive* names (`.key`) stay a deliberate
/// human vocabulary; only the emitted JSON keys are pinned. Mirrors config's
/// `assert_meta_matches` for the schema — `config.Dto` is the single source of
/// truth for the DSL too, enforced at compile time.
fn assert_table(comptime T: type, comptime fields: []const Field) void {
    inline for (fields) |f| {
        if (!@hasField(T, f.json)) {
            @compileError("config_adapter: " ++ @typeName(T) ++ " has no field '" ++ f.json ++ "'");
        }
        const F = @FieldType(T, f.json);
        const Base = if (@typeInfo(F) == .optional) @typeInfo(F).optional.child else F;
        const ok = switch (f.kind) {
            .integer, .duration => @typeInfo(Base) == .int,
            .string => Base == []const u8,
            .flag, .boolean => Base == bool,
        };
        if (!ok) @compileError("config_adapter: " ++ @typeName(T) ++ "." ++ f.json ++
            " type is not compatible with DSL kind ." ++ @tagName(f.kind));
    }
    inline for (@typeInfo(T).@"struct".fields) |sf| {
        comptime var count: usize = 0;
        inline for (fields) |f| {
            if (std.mem.eql(u8, f.json, sf.name)) count += 1;
        }
        if (count != 1) @compileError("config_adapter: " ++ @typeName(T) ++ "." ++ sf.name ++
            " must map to exactly one DSL directive");
    }
}

comptime {
    assert_table(Dto.RetryDto, &retry_fields);
    assert_table(Dto.CircuitBreakerDto, &circuit_breaker_fields);
    assert_table(Dto.OutlierDto, &outlier_fields);
    assert_table(Dto.HealthCheckDto, &health_check_fields);
    assert_table(Dto.ClusterTlsDto, &cluster_tls_fields);
}

fn find_field(fields: []const Field, key: []const u8) ?Field {
    for (fields) |f| {
        if (eq(f.key, key)) return f;
    }
    return null;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Drop a trailing `# comment` from a raw line (before tokenizing).
fn strip_comment(raw: []const u8) []const u8 {
    const hash = std.mem.indexOfScalar(u8, raw, '#') orelse return raw;
    return raw[0..hash];
}

/// Parse a duration token to milliseconds: `<n>ms`, `<n>s`, or a bare `<n>`
/// (milliseconds). Null on a bad number or overflow.
fn parse_duration_ms(text: []const u8) ?u64 {
    if (std.mem.endsWith(u8, text, "ms")) {
        return std.fmt.parseInt(u64, text[0 .. text.len - 2], 10) catch null;
    }
    if (std.mem.endsWith(u8, text, "s")) {
        const secs = std.fmt.parseInt(u64, text[0 .. text.len - 1], 10) catch return null;
        return std.math.mul(u64, secs, 1000) catch null;
    }
    return std.fmt.parseInt(u64, text, 10) catch null;
}

/// Emit a decimal integer as a bare JSON number.
fn emit_number(w: *Writer, n: u64) Writer.Error!void {
    var buf: [24]u8 = undefined; // u64 max is 20 digits
    const text = std.fmt.bufPrint(&buf, "{d}", .{n}) catch unreachable;
    assert(text.len > 0 and text.len <= 20);
    try w.writeAll(text);
}

/// Emit a JSON string literal, escaping per RFC 8259 (mirrors the schema
/// generator's `json_string`).
fn emit_string(w: *Writer, bytes: []const u8) Writer.Error!void {
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

// -- tests ------------------------------------------------------------------
// Self-contained: the adapter emits JSON (validated as well-formed via
// std.json here); config.zig owns the round-trip-through-parse tests, since it
// is the module that depends on this one.

const testing = std.testing;

/// Adapt `source`, parse the result as a generic JSON tree, and return it. The
/// caller owns and deinits the returned `Parsed`.
fn adapt_to_value(source: []const u8) !std.json.Parsed(std.json.Value) {
    var diag: Diagnostic = .{};
    const json = try to_json(testing.allocator, source, &diag);
    defer testing.allocator.free(json);
    return std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
}

test "adapter: minimal config lowers to the expected JSON shape" {
    const parsed = try adapt_to_value(
        \\listen 127.0.0.1:8080
        \\route -> origin
        \\cluster origin {
        \\    endpoints 127.0.0.1:9000
        \\}
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("127.0.0.1:8080", root.get("listen").?.string);

    const routes = root.get("routes").?.array;
    try testing.expectEqual(@as(usize, 1), routes.items.len);
    try testing.expectEqualStrings("*", routes.items[0].object.get("host").?.string);
    try testing.expectEqualStrings("/", routes.items[0].object.get("path_prefix").?.string);
    try testing.expectEqualStrings("origin", routes.items[0].object.get("cluster").?.string);

    const clusters = root.get("clusters").?.array;
    try testing.expectEqual(@as(usize, 1), clusters.items.len);
    try testing.expectEqualStrings("origin", clusters.items[0].object.get("name").?.string);
    const eps = clusters.items[0].object.get("endpoints").?.array;
    try testing.expectEqual(@as(usize, 1), eps.items.len);
    try testing.expectEqualStrings("127.0.0.1:9000", eps.items[0].string);
}

test "adapter: IPv6 and hostname endpoint tokens pass through verbatim" {
    // The adapter only lowers syntax; endpoint validation (and hostname
    // resolution) stays downstream in config parsing.
    const parsed = try adapt_to_value(
        \\listen 127.0.0.1:8080
        \\route -> origin
        \\cluster origin {
        \\    endpoints [::1]:9000 backend.internal:9001
        \\}
    );
    defer parsed.deinit();
    const clusters = parsed.value.object.get("clusters").?.array;
    const eps = clusters.items[0].object.get("endpoints").?.array;
    try testing.expectEqual(@as(usize, 2), eps.items.len);
    try testing.expectEqualStrings("[::1]:9000", eps.items[0].string);
    try testing.expectEqualStrings("backend.internal:9001", eps.items[1].string);
}

test "adapter: scalars, comments, and blank lines" {
    const parsed = try adapt_to_value(
        \\# a comment line
        \\listen 0.0.0.0:80   # trailing comment
        \\admin 127.0.0.1:9901
        \\handoff /run/zoxy.sock
        \\accept_mode shared
        \\workers 4
        \\
        \\route -> c
        \\cluster c {
        \\    endpoints 127.0.0.1:9000
        \\}
    );
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("0.0.0.0:80", root.get("listen").?.string);
    try testing.expectEqualStrings("127.0.0.1:9901", root.get("admin").?.string);
    try testing.expectEqualStrings("/run/zoxy.sock", root.get("handoff").?.string);
    try testing.expectEqualStrings("shared", root.get("accept_mode").?.string);
    try testing.expectEqual(@as(i64, 4), root.get("workers").?.integer);
}

test "adapter: route arrow match forms" {
    const parsed = try adapt_to_value(
        \\route api.example.com /v1 -> api
        \\route /static -> assets
        \\route example.com -> web
        \\route -> fallback
        \\cluster api {
        \\    endpoints 127.0.0.1:9001
        \\}
        \\cluster assets {
        \\    endpoints 127.0.0.1:9002
        \\}
        \\cluster web {
        \\    endpoints 127.0.0.1:9003
        \\}
        \\cluster fallback {
        \\    endpoints 127.0.0.1:9000
        \\}
    );
    defer parsed.deinit();
    const routes = parsed.value.object.get("routes").?.array.items;
    try testing.expectEqual(@as(usize, 4), routes.len);
    try testing.expectEqualStrings("api.example.com", routes[0].object.get("host").?.string);
    try testing.expectEqualStrings("/v1", routes[0].object.get("path_prefix").?.string);
    // single leading-'/' token → path, host defaults to '*'
    try testing.expectEqualStrings("*", routes[1].object.get("host").?.string);
    try testing.expectEqualStrings("/static", routes[1].object.get("path_prefix").?.string);
    // single non-'/' token → host, path defaults to '/'
    try testing.expectEqualStrings("example.com", routes[2].object.get("host").?.string);
    try testing.expectEqualStrings("/", routes[2].object.get("path_prefix").?.string);
    try testing.expectEqualStrings("fallback", routes[3].object.get("cluster").?.string);
}

test "adapter: full cluster resilience surface with durations" {
    const parsed = try adapt_to_value(
        \\route -> api
        \\cluster api {
        \\    endpoints 127.0.0.1:9001 127.0.0.1:9002
        \\    endpoints 127.0.0.1:9003
        \\    lb maglev header x-user-id
        \\    per_try_timeout 500ms
        \\    retry {
        \\        max 3
        \\        backoff_base 25ms
        \\        backoff_cap 1s
        \\    }
        \\    circuit_breaker {
        \\        max_requests 100
        \\    }
        \\    outlier {
        \\        consecutive_failures 5
        \\        ejection 30s
        \\    }
        \\    health_check {
        \\        interval 5s
        \\        timeout 2s
        \\        healthy_threshold 2
        \\    }
        \\    tls {
        \\        server_name api.internal
        \\        ca_file ca.pem
        \\    }
        \\}
    );
    defer parsed.deinit();
    const c = parsed.value.object.get("clusters").?.array.items[0].object;
    try testing.expectEqual(@as(usize, 3), c.get("endpoints").?.array.items.len);

    const lb = c.get("lb").?.object;
    try testing.expectEqualStrings("maglev", lb.get("policy").?.string);
    try testing.expectEqualStrings("header", lb.get("hash").?.string);
    try testing.expectEqualStrings("x-user-id", lb.get("header").?.string);

    try testing.expectEqual(@as(i64, 500), c.get("per_try_timeout_ms").?.integer);
    const retry = c.get("retry").?.object;
    try testing.expectEqual(@as(i64, 3), retry.get("max").?.integer);
    try testing.expectEqual(@as(i64, 25), retry.get("backoff_base_ms").?.integer);
    try testing.expectEqual(@as(i64, 1000), retry.get("backoff_cap_ms").?.integer);
    const outlier = c.get("outlier").?.object;
    try testing.expectEqual(@as(i64, 30000), outlier.get("ejection_ms").?.integer);
    const health = c.get("health_check").?.object;
    try testing.expectEqual(@as(i64, 5000), health.get("interval_ms").?.integer);

    const tls = c.get("tls").?.object;
    try testing.expectEqualStrings("api.internal", tls.get("server_name").?.string);
    try testing.expectEqualStrings("ca.pem", tls.get("ca_file").?.string);
}

test "adapter: listener tls with SNI identities and flags" {
    const parsed = try adapt_to_value(
        \\tls {
        \\    certificate cert.pem
        \\    key key.pem
        \\    http2
        \\    kernel_offload off
        \\    identity {
        \\        server_names a.example.com b.example.com
        \\        certificate a.pem
        \\        key a-key.pem
        \\    }
        \\}
        \\route -> c
        \\cluster c {
        \\    endpoints 127.0.0.1:9000
        \\}
    );
    defer parsed.deinit();
    const tls = parsed.value.object.get("tls").?.object;
    try testing.expectEqualStrings("cert.pem", tls.get("certificate_file").?.string);
    try testing.expectEqualStrings("key.pem", tls.get("private_key_file").?.string);
    try testing.expectEqual(true, tls.get("http2").?.bool);
    try testing.expectEqual(false, tls.get("kernel_offload").?.bool);
    const ids = tls.get("additional_identities").?.array.items;
    try testing.expectEqual(@as(usize, 1), ids.len);
    try testing.expectEqual(@as(usize, 2), ids[0].object.get("server_names").?.array.items.len);
    try testing.expectEqualStrings("a.pem", ids[0].object.get("certificate_file").?.string);
}

test "adapter: cluster tls insecure flag" {
    const parsed = try adapt_to_value(
        \\route -> c
        \\cluster c {
        \\    endpoints 127.0.0.1:9000
        \\    tls {
        \\        insecure
        \\    }
        \\}
    );
    defer parsed.deinit();
    const tls = parsed.value.object.get("clusters").?.array.items[0].object.get("tls").?.object;
    try testing.expectEqual(true, tls.get("insecure").?.bool);
}

fn expect_fail(source: []const u8, want: Error) !void {
    var diag: Diagnostic = .{};
    const result = to_json(testing.allocator, source, &diag);
    if (result) |json| {
        testing.allocator.free(json);
        return error.TestExpectedError;
    } else |err| {
        try testing.expectEqual(want, err);
        try testing.expect(diag.message != null);
        try testing.expect(diag.line > 0);
    }
}

test "adapter: syntax errors carry a diagnostic line" {
    try expect_fail("listen\n", error.MissingValue);
    try expect_fail("bogus 1\n", error.UnknownDirective);
    try expect_fail("route origin\n", error.Syntax); // no arrow
    try expect_fail("route a b c -> x\n", error.Syntax); // too many match tokens
    try expect_fail("cluster c {\n  endpoints 1.2.3.4:9000\n", error.UnterminatedBlock);
    try expect_fail("cluster c {\n}\n", error.NoEndpoints);
    try expect_fail("cluster c {\n  bogus 1\n}\n", error.UnknownDirective);
    try expect_fail(
        "cluster c {\n  endpoints x\n  retry {\n    max 1s\n  }\n}\n",
        error.InvalidValue,
    );
    try expect_fail("}\n", error.UnexpectedToken);
}

test "adapter: diagnostic points at the offending line" {
    var diag: Diagnostic = .{};
    const source =
        \\listen 0.0.0.0:80
        \\route -> c
        \\cluster c {
        \\    frobnicate 1
        \\}
    ;
    const result = to_json(testing.allocator, source, &diag);
    try testing.expectError(error.UnknownDirective, result);
    try testing.expectEqual(@as(u32, 4), diag.line);
}
