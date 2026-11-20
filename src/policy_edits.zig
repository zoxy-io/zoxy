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

pub fn Table(comptime extensions: extension.Extensions) type {
    const policies = extensions.request_policies;
    return struct {
        const Self = @This();

        /// Whether any policy type the build lists edits requests.
        pub const enabled = blk: {
            for (policies) |Policy| {
                if (extension.editBytesOf(Policy) != 0) break :blk true;
            }
            break :blk false;
        };

        /// One stream slot's reservation; every slot's is the same.
        shape: Shape = .{},
        /// `shape.edits` per stream slot, in `streamIndex` order.
        edits: []AppliedHeaderEdit = &.{},
        /// `shape.bytes` per stream slot, the edits' names and values.
        bytes: []u8 = &.{},
        /// One per stream slot: how much of its edits and bytes are used.
        states: []State = &.{},

        /// The worst one request can make on this config: every listener's
        /// own list plus its costliest route's.
        pub fn shapeOf(config: *const Config) Shape {
            if (!enabled) return .{};
            var widest: Shape = .{};
            for (config.listeners) |*listener| {
                var route_worst: Shape = .{};
                for (listener.routes) |*route| {
                    const shape = listShape(route.request_policies);
                    route_worst.edits = @max(route_worst.edits, shape.edits);
                    route_worst.bytes = @max(route_worst.bytes, shape.bytes);
                }
                const own = listShape(listener.request_policies);
                widest.edits = @max(widest.edits, own.edits + route_worst.edits);
                widest.bytes = @max(widest.bytes, own.bytes + route_worst.bytes);
            }
            return widest;
        }

        fn listShape(selections: []const extension.Selection) Shape {
            var shape: Shape = .{};
            for (selections) |selection| {
                const bound = editBytesOfSelection(selection);
                if (bound == 0) continue;
                shape.edits += extension.edits_per_verdict_max;
                shape.bytes += bound;
            }
            return shape;
        }

        /// The declared `edit_bytes_max` of the type `selection` names.
        pub fn editBytesOfSelection(selection: extension.Selection) u32 {
            assert(selection.index < policies.len);
            inline for (policies, 0..) |Policy, index| {
                if (selection.index == index) return comptime extension.editBytesOf(Policy);
            }
            unreachable;
        }

        /// What `init` takes from the startup arena: every stream slot's
        /// edits, bytes and state.
        pub fn tableBytes(config: *const Config, stream_slots: u32) u64 {
            const shape = shapeOf(config);
            if (shape.edits == 0) return 0;
            const per_slot: u64 = @as(u64, shape.edits) * @sizeOf(AppliedHeaderEdit) + shape.bytes + @sizeOf(State);
            return per_slot * stream_slots;
        }

        pub fn init(table: *Self, arena: std.mem.Allocator, config: *const Config, stream_slots: u32) error{OutOfMemory}!void {
            table.* = .{};
            const shape = shapeOf(config);
            if (shape.edits == 0) return;
            // `App` refuses a config whose lists could make more.
            assert(shape.edits <= constants.policy_edits_max);
            table.shape = shape;
            table.edits = try arena.alloc(AppliedHeaderEdit, @as(usize, shape.edits) * stream_slots);
            table.bytes = try arena.alloc(u8, @as(usize, shape.bytes) * stream_slots);
            table.states = try arena.alloc(State, stream_slots);
            @memset(table.states, .{});
            // The banner's price is what was taken.
            assert(table.edits.len * @sizeOf(AppliedHeaderEdit) + table.bytes.len +
                table.states.len * @sizeOf(State) == tableBytes(config, stream_slots));
        }

        /// A fresh request starts with no edits.
        pub fn reset(table: *Self, stream_index: u32) void {
            if (table.shape.edits == 0) return;
            assert(stream_index < table.states.len);
            table.states[stream_index] = .{};
        }

        /// The edits a stream's request carries so far: the listener's
        /// policies', and its route's.
        /// One request's edits: its listener's policies', then its route's.
        pub const Edits = struct {
            listener: []const AppliedHeaderEdit = &.{},
            route: []const AppliedHeaderEdit = &.{},
        };

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
    assert(out.len <= constants.request_edits_max);
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
