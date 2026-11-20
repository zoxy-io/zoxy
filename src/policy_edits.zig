//! The header edits a build's request policies make (#424): copied out of
//! each verdict when it is read, into scratch every stream slot reserves at
//! startup, and handed to the upstream render beside the filters' own.
//!
//! A policy decides at routing; the head it edits is rendered later, after
//! a dial the loop awaits. So the edit's bytes cannot stay in the policy's
//! view — they are copied, and the copy is bounded: a verdict carries at
//! most `edits_per_verdict_max` edits, their names and values within its
//! type's declared `edit_bytes_max`. A stream's scratch holds the worst
//! one request can make — every edit-making selection of its listener's
//! list and of the longest such route list — so a copy never runs out of
//! room. A build whose policies edit nothing has no table.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const extension = @import("extension.zig");
const filter = @import("http/filter.zig");
const parser = @import("http/parser.zig");
const render = @import("http/render.zig");

const assert = std.debug.assert;

const Config = config_module.Config;
const AppliedHeaderEdit = filter.AppliedHeaderEdit;

/// What one stream slot reserves: the edits one request can carry and
/// the bytes they can copy.
pub const Shape = struct {
    edits: u32 = 0,
    bytes: u32 = 0,
};

/// One request's edits so far: the listener's policies' first, then its
/// route's, laid out in that order in the slot.
pub const State = struct {
    listener_edits: u16 = 0,
    route_edits: u16 = 0,
    bytes_used: u32 = 0,
};

/// One response's edits so far (#424): its route's policies' first, then
/// its listener's — the order they run in on the way out.
pub const ResponseState = struct {
    route_edits: u16 = 0,
    listener_edits: u16 = 0,
    bytes_used: u32 = 0,
};

/// The declared `edit_bytes_max` of the type in `list` that `selection`
/// names.
fn editBytesIn(comptime list: []const type, selection: extension.Selection) u32 {
    assert(selection.index < list.len);
    inline for (list, 0..) |Policy, index| {
        if (selection.index == index) return comptime extension.editBytesOf(Policy);
    }
    unreachable;
}

fn listShapeIn(comptime list: []const type, selections: []const extension.Selection) Shape {
    assert(selections.len <= std.math.maxInt(u16));
    var shape: Shape = .{};
    for (selections) |selection| {
        const bound = editBytesIn(list, selection);
        if (bound == 0) continue;
        shape.edits += extension.edits_per_verdict_max;
        shape.bytes += bound;
    }
    return shape;
}

/// The worst one exchange can make on `config` through the lists named
/// `field`: every listener's own plus its costliest route's.
fn worstShape(comptime list: []const type, comptime field: []const u8, config: *const Config) Shape {
    var widest: Shape = .{};
    for (config.listeners) |*listener| {
        var route_worst: Shape = .{};
        for (listener.routes) |*route| {
            const shape = listShapeIn(list, @field(route, field));
            route_worst.edits = @max(route_worst.edits, shape.edits);
            route_worst.bytes = @max(route_worst.bytes, shape.bytes);
        }
        const own = listShapeIn(list, @field(listener, field));
        widest.edits = @max(widest.edits, own.edits + route_worst.edits);
        widest.bytes = @max(widest.bytes, own.bytes + route_worst.bytes);
    }
    // Every edit copies at least a one-byte name.
    assert(widest.bytes >= widest.edits / extension.edits_per_verdict_max);
    return widest;
}

fn anyEdits(comptime list: []const type) bool {
    for (list) |Policy| {
        if (extension.editBytesOf(Policy) != 0) return true;
    }
    return false;
}

pub fn Table(comptime extensions: extension.Extensions) type {
    const policies = extensions.request_policies;
    const response_policies = extensions.response_policies;
    return struct {
        const Self = @This();

        /// Whether any request-policy type the build lists edits requests.
        pub const enabled = anyEdits(policies);
        /// Whether any response-policy type it lists edits responses.
        pub const responds = anyEdits(response_policies);

        /// One stream slot's reservation; every slot's is the same.
        shape: Shape = .{},
        /// `shape.edits` per stream slot, in `streamIndex` order.
        edits: []AppliedHeaderEdit = &.{},
        /// `shape.bytes` per stream slot, the edits' names and values.
        bytes: []u8 = &.{},
        /// One per stream slot: how much of its edits and bytes are used.
        states: []State = &.{},
        /// The response side (#424): one scratch for the server, since a
        /// response's policies run and its head renders in one callback.
        response_shape: Shape = .{},
        response_edits: []AppliedHeaderEdit = &.{},
        response_bytes: []u8 = &.{},
        response_state: ResponseState = .{},

        /// The worst one request can make on this config: every listener's
        /// own list plus its costliest route's.
        pub fn shapeOf(config: *const Config) Shape {
            if (!enabled) return .{};
            return worstShape(policies, "request_policies", config);
        }

        /// The worst one response can make (#424): every listener's own
        /// response list plus its costliest route's.
        pub fn responseShapeOf(config: *const Config) Shape {
            if (!responds) return .{};
            return worstShape(response_policies, "response_policies", config);
        }

        /// The declared `edit_bytes_max` of the request-policy type
        /// `selection` names.
        pub fn editBytesOfSelection(selection: extension.Selection) u32 {
            return editBytesIn(policies, selection);
        }

        /// The declared `edit_bytes_max` of the response-policy type
        /// `selection` names.
        pub fn responseEditBytesOf(selection: extension.Selection) u32 {
            return editBytesIn(response_policies, selection);
        }

        /// What `init` takes from the startup arena: every stream slot's
        /// edits, bytes and state, and the one response scratch.
        pub fn tableBytes(config: *const Config, stream_slots: u32) u64 {
            const shape = shapeOf(config);
            const response = responseShapeOf(config);
            const per_slot: u64 = @as(u64, shape.edits) * @sizeOf(AppliedHeaderEdit) + shape.bytes + @sizeOf(State);
            const requests: u64 = if (shape.edits == 0) 0 else per_slot * stream_slots;
            return requests + @as(u64, response.edits) * @sizeOf(AppliedHeaderEdit) + response.bytes;
        }

        pub fn init(table: *Self, arena: std.mem.Allocator, config: *const Config, stream_slots: u32) error{OutOfMemory}!void {
            table.* = .{};
            const shape = shapeOf(config);
            const response = responseShapeOf(config);
            // `App` refuses a config whose lists could make more.
            assert(shape.edits <= constants.policy_edits_max);
            assert(response.edits <= constants.policy_edits_max);
            if (shape.edits != 0) {
                table.shape = shape;
                table.edits = try arena.alloc(AppliedHeaderEdit, @as(usize, shape.edits) * stream_slots);
                table.bytes = try arena.alloc(u8, @as(usize, shape.bytes) * stream_slots);
                table.states = try arena.alloc(State, stream_slots);
                @memset(table.states, .{});
            }
            table.response_shape = response;
            table.response_edits = try arena.alloc(AppliedHeaderEdit, response.edits);
            table.response_bytes = try arena.alloc(u8, response.bytes);
            // The banner's price is what was taken.
            assert(table.edits.len * @sizeOf(AppliedHeaderEdit) + table.bytes.len +
                table.states.len * @sizeOf(State) + table.response_edits.len * @sizeOf(AppliedHeaderEdit) +
                table.response_bytes.len == tableBytes(config, stream_slots));
        }

        /// A fresh request starts with no edits.
        pub fn reset(table: *Self, stream_index: u32) void {
            if (table.shape.edits == 0) return;
            assert(stream_index < table.states.len);
            table.states[stream_index] = .{};
        }

        /// One request's edits: its listener's policies', then its route's.
        pub const Edits = struct {
            listener: []const AppliedHeaderEdit = &.{},
            route: []const AppliedHeaderEdit = &.{},
        };

        /// The edits a stream's request carries so far: the listener's
        /// policies', and its route's.
        pub fn editsOf(table: *const Self, stream_index: u32) Edits {
            if (table.shape.edits == 0) return .{ .listener = &.{}, .route = &.{} };
            assert(stream_index < table.states.len);
            const state = table.states[stream_index];
            const slot = table.edits[@as(usize, stream_index) * table.shape.edits ..][0..table.shape.edits];
            assert(state.listener_edits + state.route_edits <= slot.len);
            return .{
                .listener = slot[0..state.listener_edits],
                .route = slot[state.listener_edits..][0..state.route_edits],
            };
        }

        /// Copy one verdict's edits into the stream's slot, for the phase
        /// they were made at. `error.Refused` when one names a header zoxy
        /// writes itself or carries a value that is not a field value: the
        /// request is refused, not edited.
        pub fn take(
            table: *Self,
            stream_index: u32,
            route_phase: bool,
            verdict_edits: []const extension.Edit,
            bound: u32,
        ) error{Refused}!void {
            // The verdict's own contract, which its type declared.
            assert(verdict_edits.len <= extension.edits_per_verdict_max);
            assert(verdict_edits.len == 0 or bound >= 1);
            var verdict_bytes: u32 = 0;
            for (verdict_edits) |edit| {
                if (!editAcceptable(edit)) return error.Refused;
                verdict_bytes += edit.bytes();
            }
            assert(verdict_bytes <= bound);
            if (verdict_edits.len == 0) return;
            assert(table.shape.edits >= 1);
            const state = &table.states[stream_index];
            // The route phase's edits follow the listener's, which are
            // final once routing runs.
            if (!route_phase) assert(state.route_edits == 0);
            const used: u32 = state.listener_edits + state.route_edits;
            assert(used + verdict_edits.len <= table.shape.edits);
            assert(state.bytes_used + verdict_bytes <= table.shape.bytes);
            const slot = table.edits[@as(usize, stream_index) * table.shape.edits ..][0..table.shape.edits];
            const bytes = table.bytes[@as(usize, stream_index) * table.shape.bytes ..][0..table.shape.bytes];
            for (verdict_edits, slot[used..][0..verdict_edits.len]) |edit, *applied| {
                applied.* = copyEdit(edit, bytes, &state.bytes_used);
            }
            if (route_phase) {
                state.route_edits += @intCast(verdict_edits.len);
            } else {
                state.listener_edits += @intCast(verdict_edits.len);
            }
        }

        /// A response head is met with no policy edits yet (#424).
        pub fn resetResponse(table: *Self) void {
            assert(table.response_edits.len == table.response_shape.edits);
            table.response_state = .{};
        }

        /// One response's edits: its route's policies', then its
        /// listener's.
        pub const ResponseEdits = struct {
            route: []const AppliedHeaderEdit = &.{},
            listener: []const AppliedHeaderEdit = &.{},
        };

        /// The edits the response being rendered carries: its route's
        /// policies', then its listener's.
        pub fn responseEditsOf(table: *const Self) ResponseEdits {
            const state = table.response_state;
            assert(state.route_edits + state.listener_edits <= table.response_edits.len);
            return .{
                .route = table.response_edits[0..state.route_edits],
                .listener = table.response_edits[state.route_edits..][0..state.listener_edits],
            };
        }

        /// Copy one response verdict's edits (#424): the route's policies
        /// run first on the way out, so theirs lead. `error.Refused` on an
        /// edit a request's would be refused for.
        pub fn takeResponse(
            table: *Self,
            route_phase: bool,
            verdict_edits: []const extension.Edit,
            bound: u32,
        ) error{Refused}!void {
            assert(verdict_edits.len <= extension.edits_per_verdict_max);
            assert(verdict_edits.len == 0 or bound >= 1);
            var verdict_bytes: u32 = 0;
            for (verdict_edits) |edit| {
                if (!editAcceptable(edit)) return error.Refused;
                verdict_bytes += edit.bytes();
            }
            assert(verdict_bytes <= bound);
            if (verdict_edits.len == 0) return;
            const state = &table.response_state;
            if (route_phase) assert(state.listener_edits == 0);
            const used: u32 = state.route_edits + state.listener_edits;
            assert(used + verdict_edits.len <= table.response_shape.edits);
            assert(state.bytes_used + verdict_bytes <= table.response_shape.bytes);
            for (verdict_edits, table.response_edits[used..][0..verdict_edits.len]) |edit, *applied| {
                applied.* = copyEdit(edit, table.response_bytes, &state.bytes_used);
            }
            if (route_phase) {
                state.route_edits += @intCast(verdict_edits.len);
            } else {
                state.listener_edits += @intCast(verdict_edits.len);
            }
        }
    };
}

/// A name a request may be edited at, and a value it may carry: the
/// filter compiler's rules, applied at runtime because a policy's value
/// may come from the request.
fn editAcceptable(edit: extension.Edit) bool {
    const name, const value = switch (edit) {
        .set, .add => |header| .{ header.name, header.value },
        .remove => |name| .{ name, "" },
    };
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!parser.isTokenByte(byte)) return false;
    }
    if (render.isReservedEditName(name)) return false;
    for (value) |byte| {
        if (!parser.isForwardableByte(byte)) return false;
    }
    return true;
}

fn copyEdit(edit: extension.Edit, bytes: []u8, used: *u32) AppliedHeaderEdit {
    const kind: filter.AppliedHeaderEdit.Kind, const name, const value = switch (edit) {
        .set => |header| .{ .set, header.name, header.value },
        .add => |header| .{ .add, header.name, header.value },
        .remove => |name| .{ .remove, name, "" },
    };
    const name_copy = copyInto(bytes, used, name);
    const value_copy = copyInto(bytes, used, value);
    return .{ .kind = kind, .name = name_copy, .value = value_copy };
}

fn copyInto(bytes: []u8, used: *u32, source: []const u8) []const u8 {
    assert(used.* + source.len <= bytes.len);
    const copy = bytes[used.*..][0..source.len];
    @memcpy(copy, source);
    used.* += @intCast(source.len);
    return copy;
}

/// The request's edits in the order their deciders ran — the listener's
/// policies', the filters', the route's policies' — with each later `set`
/// or `remove` of a name dropping every earlier edit of that name, so the
/// render's suppress-and-append writes exactly what the last word said.
/// Laid out in `out`, which holds all three. Only a request a policy
/// edited comes through here, so only on one do two filter rules that
/// `set` one name collapse to the later; a request no policy edited keeps
/// the filters' edits exactly as they were collected.
pub fn compose(
    listener: []const AppliedHeaderEdit,
    filters: []const AppliedHeaderEdit,
    route: []const AppliedHeaderEdit,
    out: []AppliedHeaderEdit,
) []const AppliedHeaderEdit {
    const total = listener.len + filters.len + route.len;
    assert(total <= out.len);
    assert(out.len <= @max(constants.request_edits_max, constants.response_render_edits_max));
    // `filters` may already sit at its place in `out`; move it first.
    std.mem.copyBackwards(AppliedHeaderEdit, out[listener.len..][0..filters.len], filters);
    @memcpy(out[0..listener.len], listener);
    @memcpy(out[listener.len + filters.len ..][0..route.len], route);
    // Walk back from the last word, keeping an edit only while no later
    // `set` or `remove` has settled its name.
    var kept: usize = total;
    var index: usize = total;
    while (index > 0) {
        index -= 1;
        const edit = out[index];
        if (settledLater(out[kept..total], edit.name)) continue;
        kept -= 1;
        out[kept] = edit;
    }
    std.mem.copyForwards(AppliedHeaderEdit, out[0 .. total - kept], out[kept..total]);
    return out[0 .. total - kept];
}

fn settledLater(later: []const AppliedHeaderEdit, name: []const u8) bool {
    for (later) |edit| {
        if (edit.kind != .add and std.ascii.eqlIgnoreCase(edit.name, name)) return true;
    }
    return false;
}
