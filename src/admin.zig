//! The admin/metrics listener (DESIGN.md §8, PLANS.md §243): one dedicated
//! listener, off the three shared pools, that answers any request on the
//! admin port with the Prometheus rendering of the counters
//! (`counters.zig`). Exactly one scrape at a time — the "reserved slot" —
//! so a scrape and the data path can never shed one another; the fd and
//! ring budgets reserve for it unconditionally (`constants.admin_*`).
//!
//! Lifecycle of one scrape: accept → send the rendered response → lingering
//! close (half-close the write side, drain client input to EOF so the close
//! never RSTs the response away, §2) → re-arm accept. A per-scrape deadline
//! (`admin_scrape_deadline_ms`) reaps a stalled or slowloris client so it
//! cannot pin the single slot, exactly as every data-path socket is reaped
//! (§8). Drain (§8) closes the listener and tears down any in-flight scrape,
//! then the loop may stop.
//!
//! The request is never parsed: the endpoint serves the same counters
//! regardless of method or path, so there is no routing, no head buffer,
//! and no attack surface beyond a fixed-size drain. Generic over the Io
//! backend like the rest of the data path, so the simulator drives it too.

const std = @import("std");

const constants = @import("constants.zig");
const counters_module = @import("counters.zig");
const Io = @import("io/io.zig");
const shed = @import("shed.zig");

const assert = std.debug.assert;

/// Response head sent before the rendered body. `Connection: close` frames
/// the body by connection close (RFC 9112 §6.3), so no Content-Length is
/// needed — the renderer's length never has to be known before the head.
pub const response_head =
    "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/plain; version=0.0.4\r\n" ++
    "Connection: close\r\n\r\n";

/// A full response is the fixed head plus one rendering of every counter.
pub const response_bytes_max = response_head.len + counters_module.Counters.render_bytes_max;

pub fn Admin(comptime IoType: type) type {
    const ServerType = @import("Server.zig").Server(IoType);

    return struct {
        server: *ServerType,
        /// Null when no admin bind is configured — the whole plane is off
        /// and `start` opens no listener.
        bind_address: ?std.Io.net.IpAddress,
        /// Valid only while `listening`; the single dedicated listener.
        listener: IoType.Listener,
        listening: bool,
        state: State,
        /// Valid in `.sending`/`.draining`/`.closing` — the scrape client.
        socket: IoType.Socket,
        /// Absolute scrape deadline; a lazy tick-and-compare re-arms until
        /// it is due, then reaps (the §4 single-timer discipline).
        deadline_ns: u64,
        /// The rendered response and the send cursor over it (short sends
        /// resume from `sent`).
        response: [response_bytes_max]u8,
        response_len: u32,
        sent: u32,
        drain_scratch: [constants.admin_drain_scratch_bytes]u8,
        armed: Armed,
        op_accept: IoType.Completion,
        /// Backoff timer re-arming an accept that failed with kernel
        /// pressure; never armed while `accept` is (§8 tight-spin guard),
        /// so it reuses the listener's two-op ring budget.
        op_accept_retry: IoType.Completion,
        op_send: IoType.Completion,
        op_recv: IoType.Completion,
        op_deadline: IoType.Completion,
        op_deadline_cancel: IoType.Completion,
        op_close: IoType.Completion,

        const Self = @This();

        pub const State = enum(u8) {
            /// No admin bind configured.
            off,
            /// Listener armed, waiting for the next scrape.
            accepting,
            /// Writing the rendered response to the client.
            sending,
            /// Write side half-closed; discarding client input to EOF so
            /// the close does not RST the response away (§2).
            draining,
            /// Teardown: sockets shut down, data op draining, close not yet
            /// submitted (the abnormal path — deadline, error, server drain).
            tearing_down,
            /// Close submitted; the slot frees (accept re-arms) once the
            /// armed set empties (§5 release rule, single-socket form).
            closing,
        };

        /// One bit per embedded op; the slot is quiescent only when clear.
        pub const Armed = packed struct(u8) {
            accept: bool = false,
            accept_retry: bool = false,
            send: bool = false,
            recv: bool = false,
            deadline: bool = false,
            deadline_cancel: bool = false,
            close: bool = false,
            _pad: u1 = 0,
        };

        pub fn init(
            admin: *Self,
            server: *ServerType,
            bind_address: ?std.Io.net.IpAddress,
        ) void {
            admin.server = server;
            admin.bind_address = bind_address;
            admin.listening = false;
            admin.state = .off;
            admin.deadline_ns = 0;
            admin.response_len = 0;
            admin.sent = 0;
            admin.armed = .{};
            admin.op_accept = .{};
            admin.op_accept_retry = .{};
            admin.op_send = .{};
            admin.op_recv = .{};
            admin.op_deadline = .{};
            admin.op_deadline_cancel = .{};
            admin.op_close = .{};
            assert(admin.armedCount() == 0);
            assert(admin.state == .off);
        }

        /// Set the bind address before `start` (main.zig, from the env var;
        /// the simulator sets it directly). A no-op default leaves admin off.
        pub fn setBind(admin: *Self, bind_address: std.Io.net.IpAddress) void {
            assert(admin.state == .off);
            assert(!admin.listening);
            admin.bind_address = bind_address;
        }

        /// Open the listener and arm the first accept, or stay off when no
        /// bind is configured. Called from `Server.start`.
        pub fn start(admin: *Self) Io.ListenError!void {
            assert(admin.state == .off);
            assert(!admin.listening);
            const bind = admin.bind_address orelse return;
            admin.listener = try admin.server.io.listen(bind);
            admin.listening = true;
            admin.armAccept();
        }

        fn armAccept(admin: *Self) void {
            assert(admin.listening);
            assert(!admin.server.draining);
            assert(admin.armedCount() == 0);
            admin.state = .accepting;
            admin.arm("accept");
            admin.server.io.accept(admin.listener, &admin.op_accept, Self, admin, onAccept);
        }

        fn onAccept(admin: *Self, result: Io.AcceptError!IoType.Socket) void {
            assert(admin.state == .accepting);
            admin.disarm("accept");
            if (admin.server.draining) {
                // The drain reached the listener: a Canceled accept
                // (`listenClose`), or a scrape that slipped in as the drain
                // began — shed that socket, do not serve (§8). No shed
                // counter: admin accepts are outside `reconcile`'s
                // accepted/admitted/shed accounting entirely (they never
                // increment `accepted`), so counting one here would break the
                // gate identity. Either way the admin plane is done accepting
                // and now quiescent, so the drain-stop gate is re-checked.
                if (result) |socket| {
                    shed.closeQuietly(IoType, admin.server.io, socket);
                } else |_| {}
                admin.listening = false;
                admin.state = .off;
                admin.server.maybeStopAfterDrain();
                return;
            }
            const socket = result catch |err| {
                // A kernel-pressure accept failure (ENFILE/ENOMEM-class,
                // process-wide, so reachable even on a localhost listener)
                // would re-fire instantly on an immediate re-arm — a tight
                // spin starving the loop (§8). Witness it and back off through
                // the shared retry delay, exactly as `Server.onAccept` does;
                // Canceled cannot occur outside a drain, handled above.
                admin.server.witnessKernelPressure(err);
                admin.armAcceptRetry();
                return;
            };
            admin.socket = socket;
            admin.storeDeadline();
            admin.armDeadline();
            admin.renderResponse();
            admin.armSend();
            assert(admin.state == .sending);
        }

        fn armAcceptRetry(admin: *Self) void {
            assert(admin.listening);
            assert(!admin.server.draining);
            assert(admin.armedCount() == 0);
            admin.state = .accepting;
            admin.arm("accept_retry");
            admin.server.io.timerStart(
                &admin.op_accept_retry,
                @as(u64, constants.accept_retry_delay_ms) * std.time.ns_per_ms,
                Self,
                admin,
                onAcceptRetry,
            );
        }

        fn onAcceptRetry(admin: *Self, result: Io.TimerError!void) void {
            assert(admin.state == .accepting);
            admin.disarm("accept_retry");
            // Nothing ever cancels the retry timer; a drain begun while it
            // was pending is handled by cleaning up instead of re-arming.
            result catch unreachable;
            if (admin.server.draining) {
                admin.listening = false;
                admin.state = .off;
                admin.server.maybeStopAfterDrain();
                return;
            }
            admin.armAccept();
        }

        /// Build the full response once, into the fixed buffer: the static
        /// head then the counters rendering (zero-alloc, §5).
        fn renderResponse(admin: *Self) void {
            @memcpy(admin.response[0..response_head.len], response_head);
            const body = admin.server.counters.render(admin.response[response_head.len..]);
            admin.response_len = @intCast(response_head.len + body.len);
            admin.sent = 0;
            assert(admin.response_len >= response_head.len);
            assert(admin.response_len <= admin.response.len);
        }

        fn armSend(admin: *Self) void {
            assert(admin.state == .accepting or admin.state == .sending);
            assert(admin.sent < admin.response_len);
            admin.state = .sending;
            admin.arm("send");
            admin.server.io.send(
                admin.socket,
                admin.response[admin.sent..admin.response_len],
                &admin.op_send,
                Self,
                admin,
                onSend,
            );
        }

        fn onSend(admin: *Self, result: Io.SendError!u32) void {
            admin.disarm("send");
            if (admin.state == .tearing_down) {
                admin.continueTeardown();
                return;
            }
            const n = result catch |err| {
                // A reset or unexpected error mid-response: nothing left to
                // deliver, tear down. Witness kernel pressure (§8) like every
                // other data-op site.
                admin.server.witnessKernelPressure(err);
                admin.beginTeardown();
                return;
            };
            admin.sent += n;
            assert(admin.sent <= admin.response_len);
            if (admin.sent < admin.response_len) {
                admin.armSend();
                return;
            }
            // Response fully sent: half-close the write side and drain the
            // client's input to EOF so the close does not RST it away (§2).
            admin.server.counters.increment("admin_served");
            admin.state = .draining;
            admin.server.io.shutdown(admin.socket, .write);
            admin.armRecv();
        }

        fn armRecv(admin: *Self) void {
            assert(admin.state == .draining);
            admin.arm("recv");
            admin.server.io.recv(
                admin.socket,
                &admin.drain_scratch,
                &admin.op_recv,
                Self,
                admin,
                onRecv,
            );
        }

        fn onRecv(admin: *Self, result: Io.RecvError!u32) void {
            admin.disarm("recv");
            if (admin.state == .tearing_down) {
                admin.continueTeardown();
                return;
            }
            assert(admin.state == .draining);
            if (result) |_| {
                // More client input arrived; keep discarding until EOF. The
                // scrape deadline bounds a client that never closes.
                admin.armRecv();
            } else |err| switch (err) {
                // The client closed after reading the response (EndOfStream)
                // or reset — input is done, close cleanly.
                error.EndOfStream, error.Reset => admin.beginClose(),
                // Canceled cannot occur outside teardown; route through it
                // defensively.
                error.Canceled => admin.beginTeardown(),
                // Kernel pressure on the drain read (§8): witness and tear down.
                error.Unexpected => {
                    admin.server.witnessKernelPressure(err);
                    admin.beginTeardown();
                },
            }
        }

        /// The clean-completion close: no data op is armed, the write side
        /// is already half-closed, so shut the read side and close.
        fn beginClose(admin: *Self) void {
            assert(admin.state == .draining);
            assert(!admin.armed.send and !admin.armed.recv);
            admin.state = .closing;
            admin.server.io.shutdown(admin.socket, .both);
            admin.cancelDeadline();
            admin.submitClose();
        }

        /// Abnormal teardown (§5, single-socket form): deadline expiry, a
        /// send/recv error, or the server drain. Shut both sides, cancel the
        /// deadline, then close once the data op drains.
        fn beginTeardown(admin: *Self) void {
            if (admin.state == .tearing_down or admin.state == .closing) return;
            assert(admin.state == .sending or admin.state == .draining);
            admin.state = .tearing_down;
            admin.server.io.shutdown(admin.socket, .both);
            admin.cancelDeadline();
            admin.continueTeardown();
        }

        /// Drain of a torn-down scrape: submit the close once no data op is
        /// armed, then free the slot when the armed set empties.
        fn continueTeardown(admin: *Self) void {
            assert(admin.state == .tearing_down or admin.state == .closing);
            if (admin.state == .tearing_down and !admin.armed.send and !admin.armed.recv) {
                admin.state = .closing;
                admin.submitClose();
            }
            admin.maybeFinish();
        }

        fn cancelDeadline(admin: *Self) void {
            if (!admin.armed.deadline or admin.armed.deadline_cancel) return;
            admin.arm("deadline_cancel");
            admin.server.io.timerCancel(
                &admin.op_deadline,
                &admin.op_deadline_cancel,
                Self,
                admin,
                onDeadlineCancel,
            );
        }

        fn submitClose(admin: *Self) void {
            assert(admin.state == .closing);
            assert(!admin.armed.close);
            assert(!admin.armed.send and !admin.armed.recv);
            admin.arm("close");
            admin.server.io.close(admin.socket, &admin.op_close, Self, admin, onClose);
        }

        fn onClose(admin: *Self) void {
            admin.disarm("close");
            admin.maybeFinish();
        }

        fn onDeadlineCancel(admin: *Self) void {
            admin.disarm("deadline_cancel");
            admin.maybeFinish();
        }

        fn storeDeadline(admin: *Self) void {
            admin.deadline_ns = admin.server.io.nowNs() +
                @as(u64, constants.admin_scrape_deadline_ms) * std.time.ns_per_ms;
        }

        fn armDeadline(admin: *Self) void {
            const delay_ns = admin.deadline_ns -| admin.server.io.nowNs();
            admin.arm("deadline");
            admin.server.io.timerStart(&admin.op_deadline, delay_ns, Self, admin, onDeadline);
        }

        /// Lazy tick-and-compare (§4): a fire before the stored deadline is
        /// due re-arms for the remainder; a fire that is due reaps the scrape.
        fn onDeadline(admin: *Self, result: Io.TimerError!void) void {
            admin.disarm("deadline");
            if (result) |_| {
                if (admin.state == .tearing_down or admin.state == .closing) {
                    admin.continueTeardown();
                    return;
                }
                if (admin.server.io.nowNs() >= admin.deadline_ns) {
                    // The scrape overran its deadline: reap the client so it
                    // cannot pin the single reserved slot (§8).
                    admin.server.counters.increment("admin_reaped");
                    admin.beginTeardown();
                } else {
                    admin.armDeadline();
                }
            } else |err| {
                // The only cancel is teardown's; its drain runs here.
                assert(err == error.Canceled);
                if (admin.state == .tearing_down or admin.state == .closing) {
                    admin.continueTeardown();
                }
            }
        }

        /// The scrape is over once every op has drained. Re-arm the next
        /// accept, or — during drain — let the server check for quiescence.
        fn maybeFinish(admin: *Self) void {
            if (admin.state != .closing) return;
            if (admin.armedCount() != 0) return;
            if (admin.server.draining) {
                admin.listening = false;
                admin.state = .off;
                admin.server.maybeStopAfterDrain();
                return;
            }
            admin.armAccept();
        }

        /// Server drain (§8): close the listener (its armed accept cancels)
        /// and tear down any in-flight scrape. A scrape already past its
        /// send races the drain and finishes through `maybeFinish`.
        pub fn beginDrain(admin: *Self) void {
            if (admin.state == .off) return;
            if (admin.listening) admin.server.io.listenClose(admin.listener);
            switch (admin.state) {
                .accepting => {}, // The listenClose cancels the armed accept.
                .sending, .draining => admin.beginTeardown(),
                .tearing_down, .closing, .off => {},
            }
        }

        /// Quiescent for the drain-stop gate: no armed op and not listening.
        pub fn isQuiescent(admin: *const Self) bool {
            return admin.armedCount() == 0 and !admin.listening;
        }

        fn arm(admin: *Self, comptime bit: []const u8) void {
            assert(!@field(admin.armed, bit));
            @field(admin.armed, bit) = true;
        }

        fn disarm(admin: *Self, comptime bit: []const u8) void {
            assert(@field(admin.armed, bit));
            @field(admin.armed, bit) = false;
        }

        pub fn armedCount(admin: *const Self) u8 {
            return @popCount(@as(u8, @bitCast(admin.armed)));
        }
    };
}
