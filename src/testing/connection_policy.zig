//! A connection policy for the gates (#425): it answers every connection
//! with one scripted verdict and records what it read. Exported so the
//! simulator, outside this module, can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedConnectionPolicy = struct {
    /// What it answers every connection `refuse_network` does not claim.
    verdict: extension.ConnectionVerdict = .proceed,
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
    /// The loop clock the last connection was evaluated at.
    seen_now_ns: u64 = 0,

    pub fn bind(
        policy: *ScriptedConnectionPolicy,
        site: *const extension.PolicySite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        // A connection policy sits on a listener, never on a route.
        assert(site.route_index == null);
        assert(site.cluster_index == null);
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
        if (connection.client) |client| {
            policy.addressed += 1;
            policy.last_client_port = client.getPort();
        }
        const verdict = policy.verdictFor(connection);
        if (verdict != .proceed) policy.refused += 1;
        assert(policy.refused <= policy.evaluated);
        return verdict;
    }

    fn verdictFor(
        policy: *const ScriptedConnectionPolicy,
        connection: *const extension.Connection,
    ) extension.ConnectionVerdict {
        const network = policy.refuse_network orelse return policy.verdict;
        const client = connection.client orelse return policy.verdict;
        if (client.* != .ip4) return policy.verdict;
        const bytes = client.ip4.bytes;
        if (!std.mem.eql(u8, bytes[0..3], &network)) return policy.verdict;
        return if (bytes[3] % 2 == 1) .reset else .reject;
    }
};

comptime {
    extension.assertConnectionPolicy(ScriptedConnectionPolicy);
}
