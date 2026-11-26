//! zoxy's stock values (#417): what the stock binary's JSON applies where
//! a key is absent. Options written in code state every choice; a build
//! that wants the stock one names it here — `.timeouts =
//! zoxy.defaults.timeouts` — rather than copying a number that would then
//! drift from the stock binary's. The JSON front-end's own field defaults
//! are written in terms of these, so the two cannot disagree.
//!
//! The numbers themselves live in `constants.zig`, beside the relations
//! the rest of the §5 closed form asserts of them; this file states them
//! in the shapes `Options` takes.

const std = @import("std");

const constants = @import("constants.zig");
const Options = @import("Options.zig");

const assert = std.debug.assert;

/// The stock deadlines (§4, §6, §8): a dial in single-digit seconds as
/// HAProxy's `timeout connect` is conventionally set, a minute of quiet
/// as nginx's own keep-alive and header budgets give, an hour for a
/// tunnel, HAProxy's `inter` between probe sweeps, the head budget derived
/// from the two it sits between, and every optional cap off.
pub const timeouts: Options.Timeouts = .{
    .connect_ms = constants.connect_ms_default,
    .idle_ms = constants.idle_ms_default,
    .head_ms = headMs(constants.connect_ms_default, constants.idle_ms_default),
    .tunnel_ms = constants.tunnel_ms_default,
    .health_interval_ms = constants.health_interval_ms_default,
};

/// The #235 head-read budget for a dial budget and an idle window: what
/// the stock binary gives a config that names none.
///
/// Derived rather than fixed, and that is what keeps every config written
/// before the field existed behaving exactly as it did. A flat ten
/// seconds would break two shapes: a config whose whole `idle_ms` is
/// smaller than the default (the head budget must never exceed the idle
/// window it tightens), and — the one that would have been a silent
/// regression rather than a load error — a config with a `connect_ms`
/// *above* ten seconds, whose dial budget would quietly have been cut to
/// the head budget, since the lazy timer cannot move later at the
/// re-base. So the default is the ten seconds clamped into the band the
/// two neighbours leave: strictly above the dial, at or below the idle.
///
/// Total, because the JSON front-end fills an absent key before the
/// options are judged. Where the band is empty — `connect_ms` at or above
/// `idle_ms` — what it returns is moot, since resolving refuses that pair
/// before it looks at the head budget.
pub fn headMs(connect_ms: u32, idle_ms: u32) u32 {
    const floored = @max(constants.head_ms_default, connect_ms +| 1);
    const derived = @min(floored, idle_ms);
    assert(derived <= idle_ms);
    if (connect_ms < idle_ms) assert(derived > connect_ms);
    return derived;
}

/// Every pool sized by zoxy's own rule for the config (§5): what the
/// stock binary gives a config with no `limits` block, and what the banner
/// prints the sizes of.
pub const limits: Options.Limits = .{};

/// The stock cap on one request body (#236): a mebibyte, so an upload
/// past it is refused with `413` before the origin is dialed when its
/// length was declared.
pub const max_body_bytes: u64 = constants.request_body_bytes_default;

/// Requests one connection serves before the response that announces its
/// close (#237): nginx's `keepalive_requests`.
pub const keepalive_requests: u32 = constants.keepalive_requests_default;

/// The stock pick (§7): the power of two choices.
pub const pick: Options.Cluster.Pick = .p2c;

/// The stock pace for a cluster that follows names (#481): a refresh at
/// most once a second and at least once a minute, whatever the TTL says,
/// and sixteen addresses per name and family.
pub const dns = struct {
    pub const refresh_min_ms: u32 = constants.dns_refresh_min_ms_default;
    pub const refresh_max_ms: u32 = constants.dns_refresh_max_ms_default;
    pub const addresses_max: u16 = constants.dns_addresses_max_default;
};

/// One query's stock budget at one nameserver (#481).
pub const resolver_timeout_ms: u32 = constants.dns_timeout_ms_default;

/// A health check's stock kind, thresholds and verdict (§7) — a TCP
/// connect, HAProxy's `fall` and `rise`, and a `200` for an http probe. Its stock budget is the connect timeout: one
/// probe is a dial and an answer, and a check that gave up sooner than a
/// dial does would call an endpoint down that traffic still reaches.
pub const check = struct {
    pub const kind: Options.Cluster.Check.Kind = .tcp;
    pub const fall: u8 = constants.health_probe_fall_default;
    pub const rise: u8 = constants.health_probe_rise_default;
    pub const expect_status: u16 = 200;
};

/// Passive ejection's stock thresholds (#230): five consecutive failures
/// the endpoint caused, and half a minute out before traffic judges it
/// again, with every cooldown the same length.
pub const passive_ejection: Options.Cluster.PassiveEjection = .{
    .fall = constants.passive_ejection_fall_default,
    .recovery_ms = constants.passive_ejection_recovery_ms_default,
};

/// Mutual TLS's stock verdict on a client with no certificate (#304):
/// refused, since asking for one and admitting its absence is a policy
/// an operator should state.
pub const client_verify: Options.Listener.ClientVerify = .required;

/// A `redirect` action's stock status (#176): permanent, as a redirect
/// most often is.
pub const redirect_status: u16 = 301;

/// A `respond` action's stock status (#159): a page that answers.
pub const respond_status: u16 = 200;

comptime {
    // What resolving holds every set of timeouts to, held of the stock
    // set here so a changed constant fails the build rather than every
    // config that leaves the block out.
    assert(timeouts.connect_ms < timeouts.head_ms);
    assert(timeouts.head_ms <= timeouts.idle_ms);
    assert(passive_ejection.fall >= 1);
    assert(check.fall >= 1);
    assert(check.rise >= 1);
}

test "defaults: the derived head budget is total over every timeout pair (#417)" {
    // It runs before validation, so it meets pairs validation would
    // refuse; none of them may trap, and every pair validation accepts
    // must land strictly above the dial and at or below the idle window.
    const max = std.math.maxInt(u32);
    const pairs = [_][2]u32{
        .{ 0, 0 },          .{ max, 0 },         .{ max, max }, .{ 0, max },
        .{ 5_000, 60_000 }, .{ 20_000, 60_000 }, .{ 1, 2 },     .{ 60_000, 5_000 },
    };
    for (pairs) |pair| {
        const head_ms = headMs(pair[0], pair[1]);
        try std.testing.expect(head_ms <= pair[1]);
        if (pair[0] < pair[1]) try std.testing.expect(head_ms > pair[0]);
    }
    // The stock pair keeps the flat default; a slow dial lifts it; a
    // tight idle window caps it.
    try std.testing.expectEqual(constants.head_ms_default, headMs(5_000, 60_000));
    try std.testing.expectEqual(@as(u32, 20_001), headMs(20_000, 60_000));
    try std.testing.expectEqual(@as(u32, 2), headMs(1, 2));
}

test "defaults: the stock values resolve (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const bind = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080");
    const options: Options = .{
        .listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .http = .{
            .target = .{ .cluster = "origin" },
            .max_body_bytes = max_body_bytes,
            .keepalive_requests = keepalive_requests,
        } } }},
        .clusters = &.{.{
            .name = "origin",
            .endpoints = &.{.{ .address = .{ .ip = origin } }},
            .pick = pick,
            .check = .{
                .kind = .{ .http = .{ .path = "/health", .expect_status = check.expect_status } },
                .fall = check.fall,
                .rise = check.rise,
                .timeout_ms = timeouts.connect_ms,
            },
            .passive_ejection = passive_ejection,
        }},
        .timeouts = timeouts,
        .limits = limits,
    };
    const config = try @import("config.zig").resolve(arena_state.allocator(), &options);
    try std.testing.expectEqual(timeouts.head_ms, config.head_timeout_ms);
    try std.testing.expectEqual(max_body_bytes, config.listeners[0].max_body_bytes);
}
