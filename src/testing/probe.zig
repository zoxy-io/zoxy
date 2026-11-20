//! A health-check kind for the gates (#436): each round sends a scripted
//! request and expects a scripted reply — by default the request itself,
//! which the gates' echo origins send back. Exported so the simulator,
//! outside this module, can select one.

const std = @import("std");

const constants = @import("../constants.zig");
const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedProbe = struct {
    /// Each round's request, in order; the last round's answer passes.
    rounds: []const []const u8 = &.{"ping\n"},
    /// What every round's reply must start with; null expects the round's
    /// own request back.
    expect: ?[]const u8 = null,
    /// Startup binds received, one per cluster that selected the instance.
    binds: u32 = 0,
    /// Requests asked for and judgements made, across every probe.
    requests: u32 = 0,
    judgements: u32 = 0,
    /// The furthest round any probe reached.
    furthest_round: u8 = 0,

    pub const reply_bytes_max = 64;

    pub fn bind(
        probe: *ScriptedProbe,
        site: *const extension.ClusterSite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        assert(site.endpoints.len >= 1);
        assert(probe.rounds.len >= 1);
        probe.binds += 1;
    }

    pub fn request(probe: *ScriptedProbe, round: u8) []const u8 {
        assert(round < constants.health_check_rounds_max);
        assert(round < probe.rounds.len);
        probe.requests += 1;
        probe.furthest_round = @max(probe.furthest_round, round);
        // Unchecked against `health_check_request_bytes_max`: a gate holds
        // zoxy to failing the probe on an oversize request.
        return probe.rounds[round];
    }

    pub fn judge(probe: *ScriptedProbe, round: u8, reply: []const u8) extension.ProbeJudgement {
        assert(round < probe.rounds.len);
        assert(reply.len <= reply_bytes_max);
        probe.judgements += 1;
        const expected = probe.expect orelse probe.rounds[round];
        if (reply.len < expected.len) {
            return if (std.mem.startsWith(u8, expected, reply)) .read_more else .fail;
        }
        if (!std.mem.startsWith(u8, reply, expected)) return .fail;
        return if (round + 1 == probe.rounds.len) .pass else .next;
    }
};

comptime {
    extension.assertProbe(ScriptedProbe);
}
