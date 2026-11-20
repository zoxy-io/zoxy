//! A cluster's endpoint set, changed while serving (#428). An update is a
//! whole new set, applied on the loop thread into slots reserved at
//! startup, all at once or not at all:
//!
//! - an endpoint already in the set keeps its slot — its health, its
//!   in-flight work, its parked connections — and takes its new weight
//!   and tier in place;
//! - one that leaves drains: weight 0, never picked or probed again, its
//!   parked connections closed, its in-flight work running to its end;
//! - one that arrives takes a free slot, or rejoins the draining slot it
//!   left, unhealthy until its first probe passes on a checked cluster.
//!
//! A slot that drained stays draining: making one free again, once
//! nothing references it, is the issue's next slice. Until then a cluster
//! needs a slot for every endpoint it has ever held.
//!
//! An update compares each endpoint it names with every slot: bounded by
//! the capacity squared, which a control-plane call pays once.

const std = @import("std");

const constants = @import("constants.zig");
const extension = @import("extension.zig");
const config_module = @import("config.zig");

const assert = std.debug.assert;

const Endpoint = extension.EndpointSet.Endpoint;
const UpdateError = extension.EndpointSet.UpdateError;

/// Make `wanted` the set of `server`'s cluster `cluster_index`.
pub fn replace(server: anytype, cluster_index: u16, wanted: []const Endpoint) UpdateError!void {
    assert(cluster_index < server.config.clusters.len);
    const cluster = &server.config.clusters[cluster_index];
    const slots = cluster.slots.?;
    try validate(wanted, slots.states.len);
    // Room first: refused before anything is written.
    var arrivals: u32 = 0;
    for (wanted) |*entry| {
        if (slotHolding(slots, &entry.address) == null) arrivals += 1;
    }
    if (arrivals > countState(slots, .free)) return error.SlotsExhausted;

    departLeavers(server, cluster_index, wanted);
    for (wanted) |*entry| {
        if (slotHolding(slots, &entry.address)) |index| {
            keep(server, cluster_index, index, entry);
        } else {
            const index = firstFree(slots).?;
            arriveInto(server, cluster_index, index, entry);
        }
    }
    assert(countState(slots, .live) == wanted.len);
}

fn validate(wanted: []const Endpoint, capacity: usize) UpdateError!void {
    assert(capacity >= 1);
    if (wanted.len == 0) return error.EndpointsEmpty;
    if (wanted.len > capacity) return error.EndpointsOverSlots;
    var weight_sum: u64 = 0;
    for (wanted, 0..) |*entry, index| {
        if (entry.address.getPort() == 0) return error.EndpointInvalid;
        if (entry.weight > constants.endpoint_weight_max) return error.EndpointInvalid;
        if (entry.priority > constants.endpoint_priority_max) return error.EndpointInvalid;
        for (wanted[0..index]) |*earlier| {
            if (earlier.address.eql(&entry.address)) return error.EndpointDuplicate;
        }
        weight_sum += entry.weight;
    }
    // A set with no weight anywhere sends the cluster nowhere — refused as
    // the loader refuses `EndpointWeightsAllZero`.
    if (weight_sum == 0) return error.EndpointsEmpty;
}

/// Every live slot the new set does not name drains.
fn departLeavers(server: anytype, cluster_index: u16, wanted: []const Endpoint) void {
    const slots = server.config.clusters[cluster_index].slots.?;
    assert(slots.states.len == slots.addresses.len);
    for (slots.states, 0..) |state, index| {
        if (state != .live) continue;
        const address = slots.addresses[index];
        // A socket endpoint the cluster started with leaves at the first
        // update: an update names IP endpoints alone.
        const stays = address == .ip and for (wanted) |*entry| {
            if (entry.address.eql(&address.ip)) break true;
        } else false;
        if (stays) continue;
        slots.states[index] = .draining;
        slots.weights[index] = 0;
        assert(!server.config.clusters[cluster_index].liveAt(index));
        const endpoint_index: u16 = @intCast(index);
        server.health.depart(cluster_index, endpoint_index);
        server.health.closeParkedOf(cluster_index, endpoint_index);
        server.counters.increment("endpoints_departed");
    }
}

/// An endpoint the set already holds, in its slot: its weight and tier in
/// place, and — if it was draining — back in the set, probed afresh.
fn keep(server: anytype, cluster_index: u16, index: u16, entry: *const Endpoint) void {
    const slots = server.config.clusters[cluster_index].slots.?;
    assert(index < slots.states.len);
    assert(slots.states[index] != .free);
    assert(entry.weight <= constants.endpoint_weight_max);
    const rejoins = slots.states[index] == .draining;
    // A draining slot was drained to weight 0 as it left.
    if (rejoins) assert(slots.weights[index] == 0);
    if (!rejoins and (slots.weights[index] != entry.weight or slots.priorities[index] != entry.priority)) {
        server.counters.increment("endpoints_reweighted");
    }
    slots.weights[index] = entry.weight;
    slots.priorities[index] = entry.priority;
    if (!rejoins) return;
    slots.states[index] = .live;
    server.health.arrive(cluster_index, index);
    server.counters.increment("endpoints_arrived");
}

/// An endpoint new to the set, into free slot `index`: its address, its
/// identity, its label and series, and its health from the start.
fn arriveInto(server: anytype, cluster_index: u16, index: u16, entry: *const Endpoint) void {
    const cluster = &server.config.clusters[cluster_index];
    const slots = cluster.slots.?;
    assert(index < slots.states.len);
    assert(slots.states[index] == .free);
    slots.addresses[index] = .{ .ip = entry.address };
    slots.weights[index] = entry.weight;
    slots.priorities[index] = entry.priority;
    slots.states[index] = .live;
    server.balancer.arrive(cluster_index, index);
    server.labeled.relabel(server.upstreams.keys.key(cluster_index, index), cluster, index);
    server.health.arrive(cluster_index, index);
    server.counters.increment("endpoints_arrived");
}

/// The occupied slot — live or draining — holding `address`, if any.
fn slotHolding(slots: *const config_module.Config.Slots, address: *const std.Io.net.IpAddress) ?u16 {
    assert(slots.states.len == slots.addresses.len);
    for (slots.states, slots.addresses, 0..) |state, *held, index| {
        if (state == .free) continue;
        if (held.* != .ip) continue;
        if (held.ip.eql(address)) return @intCast(index);
    }
    return null;
}

fn firstFree(slots: *const config_module.Config.Slots) ?u16 {
    assert(slots.states.len >= 1);
    const index = std.mem.indexOfScalar(config_module.Config.EndpointState, slots.states, .free) orelse return null;
    assert(slots.states[index] == .free);
    return @intCast(index);
}

fn countState(slots: *const config_module.Config.Slots, wanted: config_module.Config.EndpointState) u32 {
    var count: u32 = 0;
    for (slots.states) |state| {
        if (state == wanted) count += 1;
    }
    assert(count <= slots.states.len);
    return count;
}
