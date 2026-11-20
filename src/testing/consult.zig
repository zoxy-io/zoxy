//! A consulting policy for the gates (#437): it asks a named cluster
//! about every request under its prefix, and once answered proceeds on a
//! `200` and refuses anything else. Generic over its declared failure, so
//! the gates hold both. Exported so the simulator, outside this module,
//! can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub fn ScriptedConsult(comptime failure: extension.ConsultFailure) type {
    return struct {
        const Self = @This();

        /// The cluster it asks, by name, resolved at `bind`.
        cluster_name: []const u8 = "",
        cluster_index: ?u16 = null,
        /// The request it sends; a gate may make it too long.
        question: []const u8 = default_question,
        /// The paths it consults about, by prefix; empty is every one.
        /// Any other request it hands on untouched.
        consult_prefix: []const u8 = "",
        /// Consults it asked for, and replies it heard.
        consults: u32 = 0,
        replies: u32 = 0,
        /// The last reply's status, body length, and whether its body
        /// was cut.
        last_status: u16 = 0,
        last_body_len: u32 = 0,
        last_truncated: bool = false,

        pub const consult_failure = failure;
        pub const consult_request_bytes_max = 256;
        pub const consult_reply_bytes_max = 256;
        pub const consult_timeout_ms = 100;

        /// A bare question, framed by its head.
        pub const default_question = "GET /authz HTTP/1.1\r\nHost: authz\r\n\r\n";

        pub fn bind(
            policy: *Self,
            site: *const extension.PolicySite,
            startup: *const extension.Startup,
        ) !void {
            _ = startup;
            assert(policy.cluster_name.len >= 1);
            policy.cluster_index = site.clusterNamed(policy.cluster_name) orelse return error.ConsultClusterUnknown;
        }

        pub fn evaluate(policy: *Self, request: *const extension.Request) extension.Verdict {
            assert(request.path.len >= 1);
            assert(policy.question.len >= 1);
            if (!std.mem.startsWith(u8, request.path, policy.consult_prefix)) return .proceed;
            policy.consults += 1;
            return .{ .consult = .{ .cluster_index = policy.cluster_index.?, .request = policy.question } };
        }

        pub fn consulted(
            policy: *Self,
            request: *const extension.Request,
            reply: *const extension.ConsultReply,
        ) extension.Verdict {
            assert(request.path.len >= 1);
            assert(reply.body.len <= consult_reply_bytes_max);
            policy.replies += 1;
            assert(policy.replies <= policy.consults);
            policy.last_status = reply.status;
            policy.last_body_len = @intCast(reply.body.len);
            policy.last_truncated = reply.body_truncated;
            return if (reply.status == 200) .proceed else .{ .reject = .forbidden };
        }
    };
}

comptime {
    extension.assertRequestPolicy(ScriptedConsult(.closed));
    extension.assertRequestPolicy(ScriptedConsult(.open));
}
