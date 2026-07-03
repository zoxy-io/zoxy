//! Per-worker mutable resilience state (Phase 2, docs/DESIGN.md §7): request,
//! attempt, dial, and connection accounting per cluster and per endpoint —
//! the inputs to least-request balancing, circuit breaking, outlier
//! detection, and the retry budget. Share-nothing: each worker owns one
//! `Resilience` and nothing here is synchronized. The data path talks to it
//! through this narrow API at fixed points (admission, endpoint pick, dial,
//! outcome) — the DESIGN §1.5 "filter seam" in callback-I/O form. Every
//! table is statically sized (`clusters_max` x `endpoints_per_cluster_max`);
//! nothing allocates.
//!
//! A *request* spans admission to final outcome; an *attempt* spans an
//! endpoint pick to that attempt's outcome. Retries are new attempts under
//! one request.

const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// How an attempt ended. `failure` is an endpoint-health signal (feeds
/// outlier detection); `failure_stale_pool` (a parked keep-alive connection
/// the upstream closed — normal churn) and `aborted` (the client vanished —
/// not the endpoint's fault) are neutral.
pub const AttemptOutcome = enum { success, failure, failure_stale_pool, aborted };

pub const EndpointState = struct {
    /// Attempts issued to this endpoint with no outcome yet — the
    /// least-request balancer input.
    in_flight: u32 = 0,
    /// Consecutive `failure` outcomes; a `success` resets it (outlier
    /// detection input).
    consecutive_failures: u32 = 0,
    /// Absolute ns deadline while ejected by outlier detection; 0 = not
    /// ejected. Un-ejection is lazy: the balancer treats an expired deadline
    /// as available and clears it.
    ejected_until_ns: u64 = 0,
    /// The active health checker's verdict. Endpoints start healthy so a
    /// restarting proxy serves immediately.
    healthy: bool = true,
    /// Current probe streak (one of the two is always 0).
    probe_successes: u16 = 0,
    probe_failures: u16 = 0,
};

pub const ClusterState = struct {
    /// Admitted requests currently in flight (admission -> final outcome).
    requests_active: u32 = 0,
    /// Upstream connects currently in flight.
    pending_dials: u32 = 0,
    /// Upstream sockets currently held for this cluster (dialing or
    /// serving). Idle pooled connections are not counted — they are bounded
    /// separately by `upstream_idle_max`.
    connections_active: u32 = 0,
    /// Retries currently in flight (retry budget input).
    retries_active: u32 = 0,
    /// Endpoints currently ejected by outlier detection.
    ejected_count: u32 = 0,
    endpoints: [constants.endpoints_per_cluster_max]EndpointState = @splat(.{}),
};

pub const Resilience = struct {
    clusters: [constants.clusters_max]ClusterState = @splat(.{}),

    pub fn cluster_state(resilience: *Resilience, cluster_index: u32) *ClusterState {
        assert(cluster_index < constants.clusters_max); // enforced by config.parse
        const cluster = &resilience.clusters[cluster_index];
        // Endpoint state never outnumbers its static reservation.
        assert(cluster.ejected_count <= constants.endpoints_per_cluster_max);
        return cluster;
    }

    pub fn endpoint_state(
        resilience: *Resilience,
        cluster_index: u32,
        endpoint_index: u32,
    ) *EndpointState {
        assert(endpoint_index < constants.endpoints_per_cluster_max); // enforced by config.parse
        return &resilience.cluster_state(cluster_index).endpoints[endpoint_index];
    }

    pub fn request_start(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        cluster.requests_active += 1;
        // Bounded by the downstream connection pool: one request per slot.
        assert(cluster.requests_active <= constants.connections_max);
    }

    pub fn request_finish(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        assert(cluster.requests_active > 0); // finish never precedes start
        cluster.requests_active -= 1;
    }

    pub fn attempt_start(resilience: *Resilience, cluster_index: u32, endpoint_index: u32) void {
        const endpoint = resilience.endpoint_state(cluster_index, endpoint_index);
        endpoint.in_flight += 1;
        // One attempt at a time per request, one request per connection slot.
        assert(endpoint.in_flight <= constants.connections_max);
    }

    pub fn attempt_finish(
        resilience: *Resilience,
        cluster_index: u32,
        endpoint_index: u32,
        outcome: AttemptOutcome,
    ) void {
        const endpoint = resilience.endpoint_state(cluster_index, endpoint_index);
        assert(endpoint.in_flight > 0); // finish never precedes start
        endpoint.in_flight -= 1;
        // Outcomes drive outlier detection (Phase 2 slice 7); accounted, not
        // yet acted upon.
        _ = outcome;
    }

    pub fn dial_start(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        cluster.pending_dials += 1;
        assert(cluster.pending_dials <= constants.connections_max);
    }

    pub fn dial_finish(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        assert(cluster.pending_dials > 0); // finish never precedes start
        cluster.pending_dials -= 1;
    }

    pub fn connection_open(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        cluster.connections_active += 1;
        assert(cluster.connections_active <= constants.connections_max);
    }

    pub fn connection_close(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        assert(cluster.connections_active > 0); // close never precedes open
        cluster.connections_active -= 1;
    }

    /// Every live counter must return to zero once a worker drains. The
    /// simulator checks this after every iteration — the accounting leak
    /// detector for the whole resilience layer.
    pub fn is_idle(resilience: *const Resilience) bool {
        for (&resilience.clusters) |*cluster| {
            if (cluster.requests_active != 0) return false;
            if (cluster.pending_dials != 0) return false;
            if (cluster.connections_active != 0) return false;
            if (cluster.retries_active != 0) return false;
            for (&cluster.endpoints) |*endpoint| {
                if (endpoint.in_flight != 0) return false;
            }
        }
        return true;
    }
};

// ---- tests ----------------------------------------------------------------

test "resilience: request/attempt/dial/connection cycles return to idle" {
    var resilience = Resilience{};
    try std.testing.expect(resilience.is_idle());

    resilience.request_start(3);
    resilience.attempt_start(3, 1);
    resilience.dial_start(3);
    resilience.connection_open(3);
    try std.testing.expect(!resilience.is_idle());
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[3].requests_active);
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[3].endpoints[1].in_flight);
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[3].pending_dials);
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[3].connections_active);

    resilience.dial_finish(3);
    resilience.connection_close(3);
    resilience.attempt_finish(3, 1, .success);
    resilience.request_finish(3);
    try std.testing.expect(resilience.is_idle());
}

test "resilience: a retried request stacks attempts on the same request" {
    var resilience = Resilience{};
    resilience.request_start(0);
    resilience.attempt_start(0, 0);
    resilience.attempt_finish(0, 0, .failure_stale_pool);
    resilience.attempt_start(0, 0); // the replay, same endpoint
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[0].endpoints[0].in_flight);
    resilience.attempt_finish(0, 0, .success);
    resilience.request_finish(0);
    try std.testing.expect(resilience.is_idle());
}

test "resilience: endpoints start healthy and un-ejected" {
    var resilience = Resilience{};
    const endpoint = resilience.endpoint_state(0, 0);
    try std.testing.expect(endpoint.healthy);
    try std.testing.expectEqual(@as(u64, 0), endpoint.ejected_until_ns);
    try std.testing.expectEqual(@as(u32, 0), endpoint.consecutive_failures);
}
