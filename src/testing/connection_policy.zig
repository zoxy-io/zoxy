//! A connection policy for the gates (#425): it answers every connection
//! with one scripted verdict and records what it read. Exported so the
//! simulator, outside this module, can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedConnectionPolicy = struct {
    /// What it answers every connection `refuse_network` does not claim.
    verdict: extension.ConnectionVerdict = .proceed,
    /// The tag it proceeds with (#425), through `proceed_with`, where
    /// `verdict` proceeds; null proceeds bare.
    tag: ?u64 = null,
    /// The tag the last connection arrived with: an earlier phase's.
    seen_tag: u64 = 0,
    /// An IPv4 /24 it refuses: an RST for an odd host octet, a FIN for an
    /// even one — so one instance reaches both closes. Null claims none.
    refuse_network: ?[3]u8 = null,
    /// Startup binds received, one per listener that selected the
    /// instance.
    binds: u32 = 0,
    /// Connections evaluated, and of those, refused.
    evaluated: u32 = 0,
    refused: u32 = 0,
    /// Connections that came with a client address, and the last one's
    /// port: a PROXY header's, on a listener that takes one.
    addressed: u32 = 0,
    last_client_port: u16 = 0,
    last_listener: u16 = 0,
    /// Connections it read at an SNI route's phase, and the last one's
    /// name, copied out — the view is valid only for the call.
    routed: u32 = 0,
    server_name: [64]u8 = @splat(0),
    server_name_len: u8 = 0,
    /// The loop clock the last connection was evaluated at.
    seen_now_ns: u64 = 0,
    /// Completions received (#425): one for each connection it proceeded
    /// on, once released.
    completions: u32 = 0,
    /// The last completion, copied out; its `client` cleared, since the
    /// view's address is valid only for the call.
    last: ?extension.ConnectionCompletion = null,

    pub fn bind(
        policy: *ScriptedConnectionPolicy,
        site: *const extension.PolicySite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        // A listener is bound with no route; an SNI route with its cluster.
        assert((site.route_index == null) == (site.cluster_index == null));
        policy.binds += 1;
        // A server's clock starts afresh; see `ScriptedPolicy.bind`.
        policy.seen_now_ns = 0;
    }

    pub fn evaluate(
        policy: *ScriptedConnectionPolicy,
        connection: *const extension.Connection,
    ) extension.ConnectionVerdict {
        assert(connection.now_ns >= 1);
        assert(connection.now_ns >= policy.seen_now_ns);
        policy.seen_now_ns = connection.now_ns;
        policy.evaluated += 1;
        policy.last_listener = connection.listener_index;
        policy.seen_tag = connection.tag;
        if (connection.route_index != null) policy.noteRouted(connection);
        if (connection.client) |client| {
            policy.addressed += 1;
            policy.last_client_port = client.getPort();
        }
        const verdict = policy.verdictFor(connection);
        switch (verdict) {
            .proceed, .proceed_with => {},
            .reject, .reset => policy.refused += 1,
        }
        assert(policy.refused <= policy.evaluated);
        return verdict;
    }

    /// The connections it let on: what it owes completions for.
    pub fn proceeded(policy: *const ScriptedConnectionPolicy) u32 {
        assert(policy.refused <= policy.evaluated);
        return policy.evaluated - policy.refused;
    }

    pub fn complete(policy: *ScriptedConnectionPolicy, done: *const extension.ConnectionCompletion) void {
        assert(done.done_ns >= done.started_ns);
        assert(done.started_ns >= 1);
        // One per connection it proceeded on: never one it refused.
        policy.completions += 1;
        assert(policy.completions <= policy.proceeded());
        policy.last = done.*;
        policy.last.?.client = null;
    }

    fn noteRouted(policy: *ScriptedConnectionPolicy, connection: *const extension.Connection) void {
        // A route's phase names its cluster; a listener's names neither.
        assert(connection.cluster_index != null);
        policy.routed += 1;
        const name = connection.server_name orelse "";
        const kept = @min(name.len, policy.server_name.len);
        @memcpy(policy.server_name[0..kept], name[0..kept]);
        policy.server_name_len = @intCast(kept);
    }

    /// The name the last routed connection's hello asked for.
    pub fn lastServerName(policy: *const ScriptedConnectionPolicy) []const u8 {
        assert(policy.server_name_len <= policy.server_name.len);
        return policy.server_name[0..policy.server_name_len];
    }

    fn verdictFor(
        policy: *const ScriptedConnectionPolicy,
        connection: *const extension.Connection,
    ) extension.ConnectionVerdict {
        if (policy.refusedNetwork(connection)) |verdict| return verdict;
        if (policy.verdict != .proceed) return policy.verdict;
        const tag = policy.tag orelse return .proceed;
        return .{ .proceed_with = .{ .tag = tag } };
    }

    /// The refusal `refuse_network` claims this connection for, if any.
    fn refusedNetwork(
        policy: *const ScriptedConnectionPolicy,
        connection: *const extension.Connection,
    ) ?extension.ConnectionVerdict {
        const network = policy.refuse_network orelse return null;
        const client = connection.client orelse return null;
        if (client.* != .ip4) return null;
        const bytes = client.ip4.bytes;
        if (!std.mem.eql(u8, bytes[0..3], &network)) return null;
        return if (bytes[3] % 2 == 1) .reset else .reject;
    }
};

comptime {
    extension.assertConnectionPolicy(ScriptedConnectionPolicy);
}
