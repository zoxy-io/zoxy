//! A handler for the gates (#434): it answers every request it is routed
//! with its path, its control-plane flag and the body it read, and a
//! `POST` flips the flag. Exported so the simulator, outside this module,
//! can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedHandler = struct {
    /// The status it answers with.
    status: u16 = 200,
    /// Misbehaviours a gate holds zoxy to refusing: a header zoxy writes
    /// itself, and an answer past what the type declares.
    framing_header: bool = false,
    overflow: bool = false,
    /// The state a `POST` changes: what a control plane is for.
    flag: bool = false,
    /// Startup binds received, one per route that selected the instance.
    binds: u32 = 0,
    /// Requests it answered, and the last one's body length.
    handled: u32 = 0,
    last_body_len: u32 = 0,

    pub const response_bytes_max = 256;

    pub fn bind(
        handler: *ScriptedHandler,
        site: *const extension.PolicySite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        // A handler sits on a route, which sends to no cluster.
        assert(site.route_index != null);
        assert(site.cluster_index == null);
        handler.binds += 1;
    }

    pub fn handle(
        handler: *ScriptedHandler,
        request: *const extension.Request,
        body: []const u8,
        response: *extension.HandlerResponse,
    ) void {
        assert(request.path.len >= 1);
        // A handler route's request names no cluster.
        assert(request.cluster_index == null);
        handler.handled += 1;
        handler.last_body_len = @intCast(body.len);
        if (request.method == .post) handler.flag = !handler.flag;
        response.status = handler.status;
        if (handler.framing_header) response.header("Content-Length", "1");
        response.header("Content-Type", "text/plain");
        response.header("X-Handled", "scripted");
        if (handler.status == 204 or handler.status == 304) return;
        response.print("{s} flag={}\n", .{ request.path, handler.flag });
        response.write(body);
        if (handler.overflow) {
            const filler: [response_bytes_max]u8 = @splat('x');
            response.write(&filler);
        }
    }
};

comptime {
    extension.assertHandler(ScriptedHandler);
}
