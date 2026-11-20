//! A request policy for the gates (#417): it rejects every request whose
//! canonical path starts with a configured prefix, proceeds with the rest —
//! tagging them, when configured to (#433) — and records what it
//! evaluated. Exported so the simulator, outside this module, can select
//! one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedPolicy = struct {
    /// The canonical-path prefix this instance refuses; empty refuses
    /// nothing.
    reject_prefix: []const u8 = "",
    status: extension.RejectStatus = .forbidden,
    /// The tag it sets on every request it hands on (#433), through
    /// `proceed_with`; null hands them on with a bare `proceed`.
    tag: ?u64 = null,
    /// The tag every request must arrive with, when configured: an
    /// earlier phase's, held to reaching this one. A request that does
    /// not carry it stops the run, so the simulator replays its seed.
    expect_tag: ?u64 = null,
    /// The tag the last request arrived with.
    seen_tag: u64 = 0,
    /// Startup binds received, one per listener or route that selected
    /// the instance.
    binds: u32 = 0,
    /// Requests evaluated, and of those, rejected.
    evaluated: u32 = 0,
    rejected: u32 = 0,
    /// Whether the last request it saw had been routed: the route phase's
    /// view carries the cluster, the listener phase's does not.
    routed: bool = false,
    /// The last request's path, copied out — the view is valid only for
    /// the call.
    path: [path_bytes_max]u8 = @splat(0),
    path_len: u8 = 0,

    pub const path_bytes_max = 64;

    pub fn bind(
        policy: *ScriptedPolicy,
        site: *const extension.PolicySite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        // A route is bound with the cluster it sends to; a listener with
        // neither.
        assert((site.route_index == null) == (site.cluster_index == null));
        assert(policy.reject_prefix.len <= path_bytes_max);
        policy.binds += 1;
    }

    pub fn evaluate(policy: *ScriptedPolicy, request: *const extension.Request) extension.Verdict {
        assert(request.path.len >= 1);
        assert(request.path[0] == '/');
        if (policy.expect_tag) |expected| assert(request.tag == expected);
        policy.evaluated += 1;
        policy.routed = request.cluster_index != null;
        policy.seen_tag = request.tag;
        const kept = @min(request.path.len, path_bytes_max);
        @memcpy(policy.path[0..kept], request.path[0..kept]);
        policy.path_len = @intCast(kept);
        if (policy.reject_prefix.len == 0) return policy.handOn();
        if (!std.mem.startsWith(u8, request.path, policy.reject_prefix)) return policy.handOn();
        policy.rejected += 1;
        return .{ .reject = policy.status };
    }

    /// Both ways of proceeding, so the gates reach both arms.
    fn handOn(policy: *const ScriptedPolicy) extension.Verdict {
        const tag = policy.tag orelse return .proceed;
        return .{ .proceed_with = .{ .tag = tag } };
    }

    /// The last request's path, as recorded.
    pub fn lastPath(policy: *const ScriptedPolicy) []const u8 {
        assert(policy.path_len <= path_bytes_max);
        assert(policy.rejected <= policy.evaluated);
        return policy.path[0..policy.path_len];
    }
};

comptime {
    extension.assertRequestPolicy(ScriptedPolicy);
}
