//! A response policy for the gates (#424): it edits every response head
//! it reads with a scripted list of edits and records what it read.
//! Exported so the simulator, outside this module, can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedResponsePolicy = struct {
    /// The edits it hands back for every response it reads.
    edits: []const extension.Edit = &.{},
    /// The tag every response must carry, when configured: the request's
    /// policies', held to reaching the response.
    expect_tag: ?u64 = null,
    /// Startup binds received, one per listener or route that selected
    /// the instance.
    binds: u32 = 0,
    /// Responses read, and the last one's status and route.
    evaluated: u32 = 0,
    last_status: u16 = 0,
    last_route: u16 = 0,

    pub const edit_bytes_max = 256;

    pub fn bind(
        policy: *ScriptedResponsePolicy,
        site: *const extension.PolicySite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        assert(site.routes.len >= 1);
        assert(policy.edits.len <= extension.edits_per_verdict_max);
        policy.binds += 1;
    }

    pub fn evaluate(policy: *ScriptedResponsePolicy, response: *const extension.Response) extension.ResponseVerdict {
        // A final response: interims and upgrades divert before policies.
        assert(response.status >= 200);
        assert(response.status != 101);
        if (policy.expect_tag) |expected| assert(response.tag == expected);
        policy.evaluated += 1;
        policy.last_status = response.status;
        policy.last_route = response.route_index;
        return .{ .edits = policy.edits };
    }
};

comptime {
    extension.assertResponsePolicy(ScriptedResponsePolicy);
}
