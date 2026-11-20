//! A request policy for the gates (#417): it rejects every request whose
//! canonical path starts with a configured prefix, proceeds with the rest —
//! tagging them, when configured to (#433) — and records what it
//! evaluated. Exported so the simulator, outside this module, can select
//! one.

const std = @import("std");

const constants = @import("../constants.zig");
const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedPolicy = struct {
    /// The canonical-path prefix this instance refuses; empty refuses
    /// nothing.
    reject_prefix: []const u8 = "",
    status: extension.RejectStatus = .forbidden,
    /// The canonical-path prefix this instance answers with one of its
    /// own `answers` (#431); empty answers nothing.
    answer_prefix: []const u8 = "",
    /// Which of its answers it gives there.
    answer: extension.AnswerName(ScriptedPolicy) = .denied,
    /// Requests it answered with one of its own pages.
    answered: u32 = 0,
    /// The canonical-path prefix under which this instance sends the
    /// request to a route (#430); empty routes nothing.
    route_prefix: []const u8 = "",
    /// The name of the route it sends to, resolved on each listener at
    /// `bind`.
    route_name: []const u8 = "",
    /// An index to route to as given, unresolved and unchecked: how a
    /// gate holds zoxy to falling back from a route the listener lacks.
    route_raw: ?u16 = null,
    /// Requests it chose a route for.
    rerouted: u32 = 0,
    /// The URI subjectAltName every request's verified client must carry
    /// (#432); empty requires none. A request without it is rejected.
    require_client_uri: []const u8 = "",
    /// The last request's client names: how many it carried, and whether
    /// its leaf named more than the connection kept.
    seen_client_names: u8 = 0,
    seen_client_names_truncated: bool = false,
    /// The edits it hands on with every request it proceeds with (#424).
    edits: []const extension.Edit = &.{},
    /// `route_name`'s index on each listener the instance is bound to.
    route_targets: [route_listeners_max]?u16 = @splat(null),
    /// The tag it sets on every request it hands on (#433), through
    /// `proceed_with`; null hands them on with a bare `proceed`.
    tag: ?u64 = null,
    /// The tag every request must arrive with, when configured: an
    /// earlier phase's, held to reaching this one. A request that does
    /// not carry it stops the run, so the simulator replays its seed.
    expect_tag: ?u64 = null,
    /// The tag the last request arrived with.
    seen_tag: u64 = 0,
    /// The loop clock the last request was evaluated at (#429).
    seen_now_ns: u64 = 0,
    /// Completions received (#429): one for each request it handed on,
    /// so `evaluated - rejected` once the server is idle.
    completions: u32 = 0,
    /// The last completion, copied out.
    last: ?extension.RequestCompletion = null,
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
    /// The listeners one instance resolves its route on.
    pub const route_listeners_max = 4;
    /// What one verdict's edits may copy (#424).
    pub const edit_bytes_max = 256;

    /// Its own series (#435), so the gates reach every metered arm: a
    /// counter for each way a request leaves it, and a gauge.
    pub const metrics_prefix = "scripted_policy";
    pub const counters = .{
        .evaluated = "Requests the scripted policy evaluated.",
        .rejected = "Requests it rejected.",
        .tagged = "Requests it handed on with a tag.",
        .completed = "Requests it handed on that have since ended.",
        .completed_ok = "Requests it handed on that the origin answered whole.",
        .completed_refused = "Requests it handed on that something after it refused.",
        .answered = "Requests it answered with one of its own pages.",
        .rerouted = "Requests it chose a route for.",
        .edited = "Requests it handed on with header edits.",
    };
    pub const gauges = .{
        .path_bytes = "Bytes of the last request's canonical path.",
    };

    /// The body of its `denied` answer: a 403 page of its own, which a
    /// harness may configure as its 403 error page too, so every 403 a
    /// sweep sees carries one body whoever raised it.
    pub const denied_body = "scripted-policy-denied\n";

    /// Its own answers (#431): a refusal with a header of its own, a
    /// maintenance notice with a body, and a redirect.
    pub const answers = .{
        .denied = extension.Answer{
            .status = 403,
            .headers = &.{.{ .name = "X-Scripted-Policy", .value = "denied" }},
            .body = denied_body,
        },
        .maintenance = extension.Answer{
            .status = 503,
            .headers = &.{.{ .name = "Retry-After", .value = "120" }},
            .body = "back soon\n",
        },
        .login = extension.Answer{
            .status = 302,
            .headers = &.{.{ .name = "Location", .value = "/login" }},
        },
    };

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
        assert(policy.answer_prefix.len <= path_bytes_max);
        policy.binds += 1;
        // A server's clock starts afresh, and an instance a test reuses
        // across servers must not hold the last one's reading against it:
        // the clock runs forward within one server's life, not across two.
        policy.seen_now_ns = 0;
        // A route is named once, here, per listener: never on a request.
        if (site.route_index == null and policy.route_name.len != 0) {
            assert(site.listener_index < route_listeners_max);
            policy.route_targets[site.listener_index] = site.routeNamed(policy.route_name);
        }
    }

    pub fn evaluate(policy: *ScriptedPolicy, request: *const extension.Request) extension.Verdict {
        assert(request.path.len >= 1);
        assert(request.path[0] == '/');
        if (policy.expect_tag) |expected| assert(request.tag == expected);
        policy.evaluated += 1;
        policy.routed = request.cluster_index != null;
        policy.seen_tag = request.tag;
        // The loop clock runs forward: within one server's life — `bind`
        // starts each — a later evaluation never reads an earlier time.
        assert(request.now_ns >= 1);
        assert(request.now_ns >= policy.seen_now_ns);
        policy.seen_now_ns = request.now_ns;
        request.metrics.add(ScriptedPolicy, .evaluated, 1);
        request.metrics.set(ScriptedPolicy, .path_bytes, request.path.len);
        const kept = @min(request.path.len, path_bytes_max);
        @memcpy(policy.path[0..kept], request.path[0..kept]);
        policy.path_len = @intCast(kept);
        policy.seen_client_names = @intCast(request.client_cert_names.names.len);
        policy.seen_client_names_truncated = request.client_cert_names.truncated;
        if (startsWithNonEmpty(request.path, policy.answer_prefix)) {
            policy.answered += 1;
            request.metrics.add(ScriptedPolicy, .answered, 1);
            return switch (policy.answer) {
                inline else => |name| extension.respond(ScriptedPolicy, name),
            };
        }
        if (!startsWithNonEmpty(request.path, policy.reject_prefix) and policy.clientAdmitted(request)) {
            return policy.handOn(request);
        }
        policy.rejected += 1;
        request.metrics.add(ScriptedPolicy, .rejected, 1);
        return .{ .reject = policy.status };
    }

    /// Whether the request's verified client names `require_client_uri`,
    /// or nothing is required of it.
    fn clientAdmitted(policy: *const ScriptedPolicy, request: *const extension.Request) bool {
        const names = request.client_cert_names.names;
        assert(names.len <= constants.client_cert_names_max);
        if (policy.require_client_uri.len == 0) return true;
        for (names) |name| {
            assert(name.value.len >= 1);
            if (name.kind != .uri) continue;
            if (std.mem.eql(u8, name.value, policy.require_client_uri)) return true;
        }
        return false;
    }

    fn startsWithNonEmpty(path: []const u8, prefix: []const u8) bool {
        assert(path.len >= 1);
        return prefix.len != 0 and std.mem.startsWith(u8, path, prefix);
    }

    /// What it handed on: every request it neither rejected nor answered.
    pub fn handedOn(policy: *const ScriptedPolicy) u32 {
        assert(policy.rejected + policy.answered <= policy.evaluated);
        return policy.evaluated - policy.rejected - policy.answered;
    }

    /// One completion per request it handed on (#429), its times in
    /// order, and the ways a request ends after a policy counted apart.
    pub fn complete(policy: *ScriptedPolicy, done: *const extension.RequestCompletion) void {
        assert(done.done_ns >= done.started_ns);
        assert(done.started_ns >= 1);
        // A site's routed request names its cluster; a route's always is.
        if (done.route_index != null) assert(done.cluster_index != null);
        policy.completions += 1;
        assert(policy.completions <= policy.handedOn());
        policy.last = done.*;
        done.metrics.add(ScriptedPolicy, .completed, 1);
        switch (done.outcome) {
            .ok => done.metrics.add(ScriptedPolicy, .completed_ok, 1),
            .rejected => done.metrics.add(ScriptedPolicy, .completed_refused, 1),
            else => {},
        }
    }

    /// Both ways of proceeding, so the gates reach both arms: a bare
    /// `proceed`, or `proceed_with` a tag, a route, or both.
    fn handOn(policy: *ScriptedPolicy, request: *const extension.Request) extension.Verdict {
        const route = policy.routeFor(request);
        if (route != null) assert(policy.route_raw != null or policy.route_name.len != 0);
        assert(policy.edits.len <= extension.edits_per_verdict_max);
        if (policy.tag == null and policy.edits.len == 0) {
            if (route == null) return .proceed;
        }
        if (policy.tag != null) request.metrics.add(ScriptedPolicy, .tagged, 1);
        if (route != null) {
            policy.rerouted += 1;
            request.metrics.add(ScriptedPolicy, .rerouted, 1);
        }
        if (policy.edits.len != 0) request.metrics.add(ScriptedPolicy, .edited, 1);
        return .{ .proceed_with = .{ .tag = policy.tag, .route = route, .edits = policy.edits } };
    }

    /// The route it sends `request` to, if any: `route_raw` as given, or
    /// the route `route_name` names on the request's listener.
    fn routeFor(policy: *const ScriptedPolicy, request: *const extension.Request) ?u16 {
        if (!startsWithNonEmpty(request.path, policy.route_prefix)) return null;
        if (policy.route_raw) |raw| return raw;
        if (policy.route_name.len == 0) return null;
        assert(request.listener_index < route_listeners_max);
        return policy.route_targets[request.listener_index];
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
