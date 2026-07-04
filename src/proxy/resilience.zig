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
const config = @import("../config.zig");
const ResiliencePolicy = config.ResiliencePolicy;

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

    /// Circuit-breaker admission for a new request (`max_requests`). An
    /// unconfigured limit is `limit_none` and never trips.
    pub fn admit_request(
        resilience: *Resilience,
        cluster_index: u32,
        policy: *const ResiliencePolicy,
    ) bool {
        assert(policy.max_requests > 0); // zero limits are rejected at parse
        const cluster = resilience.cluster_state(cluster_index);
        return cluster.requests_active < policy.max_requests;
    }

    /// Circuit-breaker admission for a fresh upstream dial (`max_pending`
    /// on concurrent connects, `max_connections` on held sockets). Pooled
    /// checkouts bypass this: they consume no dial, and idle pooled fds are
    /// bounded separately by `upstream_idle_max` (a documented delta from
    /// Envoy, which attributes pool slots to the cluster).
    pub fn admit_dial(
        resilience: *Resilience,
        cluster_index: u32,
        policy: *const ResiliencePolicy,
    ) bool {
        assert(policy.max_pending > 0); // zero limits are rejected at parse
        assert(policy.max_connections > 0);
        const cluster = resilience.cluster_state(cluster_index);
        if (cluster.pending_dials >= policy.max_pending) return false;
        return cluster.connections_active < policy.max_connections;
    }

    /// Retry admission: the Envoy-style budget (retries may run up to
    /// `budget_percent` of active requests, with a `budget_min` floor so a
    /// quiet cluster can still retry) and the `max_retries` breaker limit.
    pub fn admit_retry(
        resilience: *Resilience,
        cluster_index: u32,
        policy: *const ResiliencePolicy,
    ) bool {
        assert(policy.retry_budget_percent > 0); // zero percent is rejected at parse
        assert(policy.retry_budget_percent <= 100);
        const cluster = resilience.cluster_state(cluster_index);
        if (cluster.retries_active >= policy.max_retries) return false;
        const budget = @max(
            @as(u64, policy.retry_budget_min),
            @as(u64, cluster.requests_active) * policy.retry_budget_percent / 100,
        );
        return cluster.retries_active < budget;
    }

    pub fn retry_start(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        cluster.retries_active += 1;
        // At most one scheduled retry per request, one request per slot.
        assert(cluster.retries_active <= constants.connections_max);
    }

    pub fn retry_finish(resilience: *Resilience, cluster_index: u32) void {
        const cluster = resilience.cluster_state(cluster_index);
        assert(cluster.retries_active > 0); // finish never precedes start
        cluster.retries_active -= 1;
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

    /// Settle an attempt and run passive outlier detection on its outcome:
    /// a `failure` extends the endpoint's consecutive-failure streak and, at
    /// the policy threshold, ejects it for `outlier_ejection_ns` (unless the
    /// cluster is already at its ejection ceiling); `success` resets the
    /// streak; `failure_stale_pool` and `aborted` are neutral. Returns true
    /// when this call ejected the endpoint (callers count the metric).
    pub fn attempt_finish(
        resilience: *Resilience,
        cluster_index: u32,
        endpoint_index: u32,
        outcome: AttemptOutcome,
        policy: *const ResiliencePolicy,
        endpoints_total: u32,
        now_ns: u64,
    ) bool {
        assert(endpoints_total <= constants.endpoints_per_cluster_max);
        assert(endpoint_index < endpoints_total);
        const endpoint = resilience.endpoint_state(cluster_index, endpoint_index);
        assert(endpoint.in_flight > 0); // finish never precedes start
        endpoint.in_flight -= 1;
        switch (outcome) {
            .success => endpoint.consecutive_failures = 0,
            .failure => {
                if (policy.outlier_consecutive_failures == 0) return false; // outlier off
                endpoint.consecutive_failures += 1;
                if (endpoint.consecutive_failures < policy.outlier_consecutive_failures) {
                    return false;
                }
                return resilience.maybe_eject(cluster_index, endpoint_index, policy, //
                    endpoints_total, now_ns);
            },
            .failure_stale_pool, .aborted => {}, // not endpoint-health signals
        }
        return false;
    }

    /// Eject the endpoint unless the cluster would exceed its ejection
    /// ceiling. Expired ejections are swept out of the count first (lazy
    /// un-ejection: the balancer already treats them as available; the
    /// bookkeeping catches up here, exactly where the count matters).
    fn maybe_eject(
        resilience: *Resilience,
        cluster_index: u32,
        endpoint_index: u32,
        policy: *const ResiliencePolicy,
        endpoints_total: u32,
        now_ns: u64,
    ) bool {
        assert(policy.outlier_ejection_ns > 0); // enforced at parse
        assert(policy.outlier_ejection_percent_max <= 100);
        const cluster = resilience.cluster_state(cluster_index);
        for (cluster.endpoints[0..endpoints_total]) |*swept| {
            if (swept.ejected_until_ns == 0 or now_ns < swept.ejected_until_ns) continue;
            swept.ejected_until_ns = 0;
            assert(cluster.ejected_count > 0); // every set deadline was counted
            cluster.ejected_count -= 1;
        }
        const endpoint = &cluster.endpoints[endpoint_index];
        if (endpoint.ejected_until_ns != 0) return false; // already ejected
        const ceiling = @as(u64, endpoints_total) * policy.outlier_ejection_percent_max;
        if (@as(u64, cluster.ejected_count + 1) * 100 > ceiling) return false;
        endpoint.ejected_until_ns = now_ns + policy.outlier_ejection_ns;
        cluster.ejected_count += 1;
        // A fresh slate once the ejection expires: re-ejection requires a
        // full new streak (a per-repeat multiplier is deferred).
        endpoint.consecutive_failures = 0;
        return true;
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
    _ = resilience.attempt_finish(3, 1, .success, &ResiliencePolicy{}, 2, 0);
    resilience.request_finish(3);
    try std.testing.expect(resilience.is_idle());
}

test "resilience: a retried request stacks attempts on the same request" {
    var resilience = Resilience{};
    const off = ResiliencePolicy{};
    resilience.request_start(0);
    resilience.attempt_start(0, 0);
    _ = resilience.attempt_finish(0, 0, .failure_stale_pool, &off, 1, 0);
    resilience.attempt_start(0, 0); // the replay, same endpoint
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[0].endpoints[0].in_flight);
    _ = resilience.attempt_finish(0, 0, .success, &off, 1, 0);
    resilience.request_finish(0);
    try std.testing.expect(resilience.is_idle());
}

test "resilience: consecutive failures eject, success and neutral outcomes do not" {
    var resilience = Resilience{};
    const policy = ResiliencePolicy{
        .outlier_consecutive_failures = 2,
        .outlier_ejection_ns = 1000,
        .outlier_ejection_percent_max = 50,
    };
    const total: u32 = 4;
    const endpoint = &resilience.clusters[0].endpoints[0];

    // Neutral outcomes leave the streak alone; success resets it.
    resilience.attempt_start(0, 0);
    try std.testing.expect(
        !resilience.attempt_finish(0, 0, .failure_stale_pool, &policy, total, 0),
    );
    resilience.attempt_start(0, 0);
    try std.testing.expect(!resilience.attempt_finish(0, 0, .failure, &policy, total, 0));
    try std.testing.expectEqual(@as(u32, 1), endpoint.consecutive_failures);
    resilience.attempt_start(0, 0);
    try std.testing.expect(!resilience.attempt_finish(0, 0, .success, &policy, total, 0));
    try std.testing.expectEqual(@as(u32, 0), endpoint.consecutive_failures);

    // Two straight failures eject: deadline set, count bumped, streak reset.
    for (0..2) |i| {
        resilience.attempt_start(0, 0);
        const ejected = resilience.attempt_finish(0, 0, .failure, &policy, total, 100);
        try std.testing.expectEqual(i == 1, ejected);
    }
    try std.testing.expectEqual(@as(u64, 1100), endpoint.ejected_until_ns);
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[0].ejected_count);
    try std.testing.expectEqual(@as(u32, 0), endpoint.consecutive_failures);
}

test "resilience: the ejection ceiling holds until an expired ejection is swept" {
    var resilience = Resilience{};
    const policy = ResiliencePolicy{
        .outlier_consecutive_failures = 1,
        .outlier_ejection_ns = 1000,
        .outlier_ejection_percent_max = 50,
    };
    const total: u32 = 2; // ceiling: at most 1 of 2 ejected

    resilience.attempt_start(0, 0);
    try std.testing.expect(resilience.attempt_finish(0, 0, .failure, &policy, total, 0));
    // Endpoint 1 fails at t=500: the ceiling refuses a second ejection.
    resilience.attempt_start(0, 1);
    try std.testing.expect(!resilience.attempt_finish(0, 1, .failure, &policy, total, 500));
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[0].ejected_count);
    // At t=2000 endpoint 0's ejection has expired: the sweep frees the slot
    // and endpoint 1 (streak intact from the refused attempt) ejects.
    resilience.attempt_start(0, 1);
    try std.testing.expect(resilience.attempt_finish(0, 1, .failure, &policy, total, 2000));
    try std.testing.expectEqual(@as(u64, 0), resilience.clusters[0].endpoints[0].ejected_until_ns);
    try std.testing.expectEqual(
        @as(u64, 3000),
        resilience.clusters[0].endpoints[1].ejected_until_ns,
    );
    try std.testing.expectEqual(@as(u32, 1), resilience.clusters[0].ejected_count);
}

test "resilience: admission gates trip at their limits and never below" {
    var resilience = Resilience{};
    const unbounded = ResiliencePolicy{};
    const tight = ResiliencePolicy{ .max_requests = 2, .max_pending = 1, .max_connections = 2 };

    // Unconfigured limits (limit_none) never trip.
    resilience.request_start(0);
    resilience.dial_start(0);
    resilience.connection_open(0);
    try std.testing.expect(resilience.admit_request(0, &unbounded));
    try std.testing.expect(resilience.admit_dial(0, &unbounded));

    // requests_active = 1 < 2 admits; = 2 rejects.
    try std.testing.expect(resilience.admit_request(0, &tight));
    resilience.request_start(0);
    try std.testing.expect(!resilience.admit_request(0, &tight));

    // pending_dials = 1 trips max_pending = 1.
    try std.testing.expect(!resilience.admit_dial(0, &tight));
    resilience.dial_finish(0);
    // connections_active = 1 < 2 admits; = 2 rejects.
    try std.testing.expect(resilience.admit_dial(0, &tight));
    resilience.connection_open(0);
    try std.testing.expect(!resilience.admit_dial(0, &tight));
}

test "resilience: retry budget scales with active requests above its floor" {
    var resilience = Resilience{};
    const policy = ResiliencePolicy{ .retry_budget_percent = 20, .retry_budget_min = 2 };

    // Quiet cluster: the floor (2) admits the first two retries.
    try std.testing.expect(resilience.admit_retry(0, &policy));
    resilience.retry_start(0);
    try std.testing.expect(resilience.admit_retry(0, &policy));
    resilience.retry_start(0);
    try std.testing.expect(!resilience.admit_retry(0, &policy)); // floor reached

    // 20 active requests raise the budget to 4.
    for (0..20) |_| resilience.request_start(0);
    try std.testing.expect(resilience.admit_retry(0, &policy));
    resilience.retry_start(0);
    resilience.retry_start(0);
    try std.testing.expect(!resilience.admit_retry(0, &policy)); // 4 of 4 in flight

    // The max_retries breaker caps below the budget when configured tighter.
    const tight = ResiliencePolicy{ .retry_budget_min = 100, .max_retries = 4 };
    try std.testing.expect(!resilience.admit_retry(0, &tight));
}

test "resilience: endpoints start healthy and un-ejected" {
    var resilience = Resilience{};
    const endpoint = resilience.endpoint_state(0, 0);
    try std.testing.expect(endpoint.healthy);
    try std.testing.expectEqual(@as(u64, 0), endpoint.ejected_until_ns);
    try std.testing.expectEqual(@as(u32, 0), endpoint.consecutive_failures);
}
