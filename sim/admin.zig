//! The simulation gate's admin scraper (§8, §9): a client of the
//! admin/metrics listener, so the sweep reaches the plane every other
//! client leaves alone — its accept, the rendered exposition, the
//! lingering close, the plane's one asynchronous close, and its teardown
//! under a drain.
//!
//! A scraper connects, sends a request the plane never reads, and reads to
//! the plane's FIN. Then it closes, which ends the plane's lingering drain
//! — or, a holding scraper, keeps its half open, so the plane is still
//! draining it when the scenario's own drain arrives and must tear it down.
//!
//! The oracle holds on every seed: what arrived is the plane's head and a
//! prefix of a well-formed exposition, every counter in declaration order
//! at no more than the value the run ended with — counters only grow, so a
//! scrape that read one ahead of the end read something that never was —
//! then every gauge, as one snapshot that holds `Gauges.valid`, then lines
//! that are each a comment or a sample. A line cut short is held to being
//! the start of what its place expects, as far as the counters and gauges
//! go. On a clean seed it hardens: a scraper reads the whole response, to
//! its FIN.
//!
//! The oracle's teeth, measured: rendering every counter one ahead fails
//! the sweep's second seed with `CounterAhead`.

const std = @import("std");

const zoxy = @import("zoxy");

const Io = zoxy.Io;
const Counters = zoxy.counters.Counters;
const metric_prefix = Counters.metric_prefix;

const assert = std.debug.assert;

/// The head the plane answers every scrape with, written out here rather
/// than borrowed from `admin.zig`, so a head that drifted fails the oracle.
pub const response_head = "HTTP/1.1 200 OK\r\n" ++
    "Content-Type: text/plain; version=0.0.4\r\n" ++
    "Connection: close\r\n\r\n";

/// What a scraper sends. The plane never parses it, and drains it.
const request = "GET /metrics HTTP/1.1\r\nHost: sim\r\n\r\n";

/// A whole response at most: the head, every counter and gauge, and the
/// labeled breakdown of a config the size the sweep draws.
pub const receive_bytes_max: u32 = 256 * 1024;

pub const ScrapeError = error{
    /// The bytes before the exposition are not the plane's head.
    HeadCorrupted,
    /// A counter or gauge missing from its place, or another in it.
    SeriesOutOfPlace,
    /// A counter read past the value the run ended with.
    CounterAhead,
    /// A line that is neither a comment nor a sample.
    LineCorrupted,
    /// More octets than any response holds.
    ResponseOverrun,
    /// A clean seed's scrape that did not read the whole response.
    GoldenOutcomeMissed,
};

pub fn Scraper(comptime IoType: type) type {
    return struct {
        io: *IoType = undefined,
        address: std.Io.net.IpAddress = undefined,
        on_ended: ?*const fn (?*anyopaque) void = null,
        context: ?*anyopaque = null,
        connect_completion: IoType.Completion = .{},
        connect_cancel_completion: IoType.Completion = .{},
        send_completion: IoType.Completion = .{},
        recv_completion: IoType.Completion = .{},
        socket: IoType.Socket = undefined,
        receive_buffer: [receive_bytes_max]u8 = undefined,
        received_len: u32 = 0,
        overrun_scratch: [1]u8 = undefined,
        overrun: bool = false,
        sent_len: u32 = 0,
        /// Keep this half open after the plane's FIN, so only a drain ends
        /// the plane's side.
        hold: bool = false,
        clean: bool = false,
        connected: bool = false,
        connect_settled: bool = false,
        cancel_requested: bool = false,
        send_pending: bool = false,
        recv_terminal: bool = false,
        /// The plane's FIN arrived: the response, as far as it went, ended
        /// the way the plane ends one.
        finished: bool = false,
        closed: bool = false,
        ended: bool = false,

        const Self = @This();

        pub fn prepare(scraper: *Self, io: *IoType, address: std.Io.net.IpAddress, hold: bool, clean: bool) void {
            assert(!scraper.connected);
            assert(!scraper.ended);
            // A clean seed's scrape is owed whole, so it never holds.
            if (clean) assert(!hold);
            scraper.io = io;
            scraper.address = address;
            scraper.hold = hold;
            scraper.clean = clean;
        }

        pub fn begin(scraper: *Self) void {
            assert(!scraper.connect_settled);
            scraper.io.connect(&.{ .ip = scraper.address }, &scraper.connect_completion, Self, scraper, onConnect);
        }

        fn onConnect(scraper: *Self, result: Io.ConnectError!IoType.Socket) void {
            // A cancel at the wind-down may settle the connect first; the
            // connect's own completion then arrives with nothing to do.
            if (scraper.connect_settled) {
                assert(scraper.cancel_requested);
                if (result) |socket| scraper.io.closeNow(socket) else |_| {}
                return;
            }
            scraper.connect_settled = true;
            // A refused or failed dial reads nothing, which a clean seed's
            // verdict refuses and an adversarial seed's allows.
            scraper.socket = result catch return scraper.end();
            scraper.connected = true;
            scraper.armRecv();
            scraper.armSend();
        }

        fn armSend(scraper: *Self) void {
            assert(!scraper.send_pending);
            assert(scraper.sent_len < request.len);
            scraper.send_pending = true;
            scraper.io.send(scraper.socket, request[scraper.sent_len..], &scraper.send_completion, Self, scraper, onSend);
        }

        fn onSend(scraper: *Self, result: Io.SendError!u32) void {
            assert(scraper.send_pending);
            scraper.send_pending = false;
            const sent = result catch return scraper.settleIfTerminal();
            scraper.sent_len += sent;
            assert(scraper.sent_len <= request.len);
            if (scraper.recv_terminal) return scraper.settleIfTerminal();
            if (scraper.sent_len < request.len) scraper.armSend();
        }

        fn armRecv(scraper: *Self) void {
            assert(scraper.connected);
            const buffer = if (scraper.received_len == receive_bytes_max)
                &scraper.overrun_scratch
            else
                scraper.receive_buffer[scraper.received_len..];
            scraper.io.recv(scraper.socket, buffer, &scraper.recv_completion, Self, scraper, onRecv);
        }

        fn onRecv(scraper: *Self, result: Io.RecvError!u32) void {
            const received = result catch |err| {
                scraper.recv_terminal = true;
                scraper.finished = err == error.EndOfStream;
                return scraper.settleIfTerminal();
            };
            assert(received >= 1);
            if (scraper.received_len == receive_bytes_max) {
                scraper.overrun = true;
            } else {
                scraper.received_len += received;
                assert(scraper.received_len <= receive_bytes_max);
            }
            scraper.armRecv();
        }

        /// Once the read has ended and no send is in flight: close — unless
        /// this scraper holds, and leaves its half to the drain — and end.
        fn settleIfTerminal(scraper: *Self) void {
            assert(scraper.recv_terminal or !scraper.send_pending);
            if (!scraper.recv_terminal or scraper.send_pending) return;
            if (!scraper.hold) scraper.closeIfOpen();
            scraper.end();
        }

        pub fn cancelIfStuck(scraper: *Self) void {
            if (scraper.connect_settled or scraper.cancel_requested) return;
            scraper.cancel_requested = true;
            scraper.io.connectCancel(
                &scraper.connect_completion,
                &scraper.connect_cancel_completion,
                Self,
                scraper,
                onConnectCanceled,
            );
        }

        fn onConnectCanceled(scraper: *Self) void {
            assert(scraper.cancel_requested);
            if (scraper.connect_settled) return;
            scraper.connect_settled = true;
            scraper.end();
        }

        pub fn closeIfOpen(scraper: *Self) void {
            if (!scraper.connected or scraper.closed) return;
            scraper.closed = true;
            scraper.io.closeNow(scraper.socket);
        }

        fn end(scraper: *Self) void {
            if (scraper.ended) return;
            scraper.ended = true;
            if (scraper.on_ended) |ended| ended(scraper.context);
        }

        /// The verdict over everything this scraper read, against the
        /// counters the run ended with.
        pub fn verify(scraper: *const Self, final: *const Counters) ScrapeError!void {
            assert(scraper.received_len <= receive_bytes_max);
            if (scraper.overrun) return error.ResponseOverrun;
            const bytes = scraper.receive_buffer[0..scraper.received_len];
            const head_have = @min(bytes.len, response_head.len);
            if (!std.mem.eql(u8, bytes[0..head_have], response_head[0..head_have])) return error.HeadCorrupted;
            var whole = false;
            if (bytes.len >= response_head.len) {
                whole = try checkExposition(bytes[response_head.len..], final);
            }
            if (!scraper.clean) return;
            assert(!scraper.hold);
            if (!scraper.finished) return error.GoldenOutcomeMissed;
            if (!whole) return error.GoldenOutcomeMissed;
        }
    };
}

/// Complete lines of `bytes`, in order: a line is what precedes a `\n`,
/// so the tail after the last one — a line still arriving — is never one.
const Lines = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(lines: *Lines) ?[]const u8 {
        assert(lines.offset <= lines.bytes.len);
        const end = std.mem.indexOfScalarPos(u8, lines.bytes, lines.offset, '\n') orelse return null;
        const line = lines.bytes[lines.offset..end];
        lines.offset = end + 1;
        return line;
    }

    /// The line still arriving after the last complete one.
    fn tail(lines: *const Lines) []const u8 {
        assert(lines.offset <= lines.bytes.len);
        assert(std.mem.indexOfScalarPos(u8, lines.bytes, lines.offset, '\n') == null);
        return lines.bytes[lines.offset..];
    }
};

/// Whether the exposition arrived whole: every counter, every gauge, and
/// every line after them complete, the last one ended by its `\n`.
fn checkExposition(body: []const u8, final: *const Counters) ScrapeError!bool {
    var lines: Lines = .{ .bytes = body };
    if (!try checkCounters(&lines, final)) return false;
    if (!try checkGauges(&lines)) return false;
    // Each line consumes at least its `\n`, so the walk is bounded by the body.
    var count: u32 = 0;
    while (lines.next()) |line| : (count += 1) {
        assert(count < body.len);
        if (!wellFormed(line)) return error.LineCorrupted;
    }
    assert(lines.offset <= body.len);
    return lines.offset == body.len;
}

/// Every counter, in declaration order, as `# TYPE` then its sample: false
/// when the bytes end before the last of them.
fn checkCounters(lines: *Lines, final: *const Counters) ScrapeError!bool {
    @setEvalBranchQuota(100 * Counters.names.len);
    inline for (Counters.names) |name| {
        const type_text = "# TYPE " ++ metric_prefix ++ name ++ " counter";
        const type_line = lines.next() orelse return cutAt(lines, type_text, false);
        if (!std.mem.eql(u8, type_line, type_text)) return error.SeriesOutOfPlace;
        const sample = lines.next() orelse return cutAt(lines, metric_prefix ++ name ++ " ", true);
        const value = sampleValue(sample, metric_prefix ++ name) orelse return error.SeriesOutOfPlace;
        if (value > final.get(name)) return error.CounterAhead;
    }
    assert(lines.offset <= lines.bytes.len);
    return true;
}

/// Every gauge, in declaration order, the same way — and, read whole, one
/// snapshot that holds the invariant every producer owes (`valid`): a level
/// within its capacity. A gauge moves both ways, so its final value bounds
/// nothing; the snapshot is its own check.
fn checkGauges(lines: *Lines) ScrapeError!bool {
    var gauges: Counters.Gauges = undefined;
    inline for (@typeInfo(Counters.Gauges).@"struct".field_names) |name| {
        const type_text = "# TYPE " ++ metric_prefix ++ name ++ " gauge";
        const type_line = lines.next() orelse return cutAt(lines, type_text, false);
        if (!std.mem.eql(u8, type_line, type_text)) return error.SeriesOutOfPlace;
        const sample = lines.next() orelse return cutAt(lines, metric_prefix ++ name ++ " ", true);
        const value = sampleValue(sample, metric_prefix ++ name) orelse return error.SeriesOutOfPlace;
        @field(gauges, name) = std.math.cast(u32, value) orelse return error.LineCorrupted;
    }
    if (!gauges.valid()) return error.LineCorrupted;
    assert(lines.offset <= lines.bytes.len);
    return true;
}

/// The verdict where the bytes end inside a series: the line still arriving
/// is the start of `expected` — or, a sample, `expected` and then digits.
/// False, the exposition cut short, or the error if it is neither.
fn cutAt(lines: *const Lines, comptime expected: []const u8, sample: bool) ScrapeError!bool {
    assert(expected.len >= 1);
    const tail = lines.tail();
    if (tail.len <= expected.len) {
        if (!std.mem.startsWith(u8, expected, tail)) return error.SeriesOutOfPlace;
        return false;
    }
    if (!sample) return error.SeriesOutOfPlace;
    if (!std.mem.startsWith(u8, tail, expected)) return error.SeriesOutOfPlace;
    for (tail[expected.len..]) |byte| {
        if (!std.ascii.isDigit(byte)) return error.SeriesOutOfPlace;
    }
    return false;
}

/// The value of the unlabeled sample `<series> <digits>`, or null.
fn sampleValue(sample: []const u8, comptime series: []const u8) ?u64 {
    assert(series.len >= 1);
    if (!std.mem.startsWith(u8, sample, series ++ " ")) return null;
    const digits = sample[series.len + 1 ..];
    if (digits.len == 0) return null;
    return std.fmt.parseUnsigned(u64, digits, 10) catch null;
}

/// A comment, or a sample: a metric name, labels in braces if any, one
/// space, and a number.
fn wellFormed(line: []const u8) bool {
    if (std.mem.startsWith(u8, line, "# HELP ") or std.mem.startsWith(u8, line, "# TYPE ")) return true;
    const space = std.mem.lastIndexOfScalar(u8, line, ' ') orelse return false;
    const series = line[0..space];
    const value = line[space + 1 ..];
    assert(series.len <= line.len);
    if (series.len == 0 or value.len == 0) return false;
    const name_end = std.mem.indexOfScalar(u8, series, '{') orelse series.len;
    if (name_end == 0) return false;
    for (series[0..name_end]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != ':') return false;
    }
    if (name_end < series.len and series[series.len - 1] != '}') return false;
    _ = std.fmt.parseFloat(f64, value) catch return false;
    return true;
}
