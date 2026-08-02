//! The admin scrape, read the way an operator's Prometheus reads it
//! (DESIGN.md §8): over a socket, off a live process, as text.
//!
//! This is what makes the counter checks in this tier different in kind
//! from the simulator's. `reconcile` asserts the same identities from
//! *inside* the process, against the struct it is asserting about; here
//! the numbers have been rendered, written to a socket, framed by a
//! close, and parsed back — so the whole admin plane (§8's reserved
//! scrape slot, its lingering close, the asynchronous close op that no
//! other path in the tree uses) is under the same verdict as the
//! arithmetic.
//!
//! The response is `Connection: close`-framed with no `Content-Length`
//! (admin.zig renders the body after the head, so its length is never
//! known in time), which is why this cannot reuse smoke/client.zig: that
//! one requires a framed body, on purpose.

const std = @import("std");

const Io = std.Io;

const assert = std.debug.assert;

/// The exposition prefix every metric carries (`counters.metric_prefix`),
/// spelled here rather than imported: the gate reads what the binary
/// *said*, so a rename must show up as a scrape this harness cannot find
/// its counters in, not as a harness that quietly renames its
/// expectations alongside.
const metric_prefix = "zoxy_";

/// The prefix that makes a counter part of §9's gate identity, on the
/// same terms — `Counters.shedTotal` picks it out of the field set, and
/// this picks it out of the text.
const shed_prefix = metric_prefix ++ "shed_";

/// Response bytes one scrape may carry. The rendering is closed-form in
/// the counter count (`Counters.render_bytes_max`), a few KiB today; this
/// is an order of magnitude over it, so growth is not a silent truncation.
const scrape_bytes_max: u32 = 64 * 1024;

pub const Scrape = struct {
    /// The exposition body, arena-owned: `# TYPE` lines and
    /// `zoxy_<name> <value>` lines.
    body: []const u8,

    /// One counter's value, or null when the scrape does not carry that
    /// name at all — which is a different fact from zero and is why this
    /// is optional rather than defaulting.
    pub fn value(scrape: *const Scrape, name: []const u8) ?u64 {
        assert(name.len >= 1);
        assert(scrape.body.len >= 1);
        var lines = std.mem.splitScalar(u8, scrape.body, '\n');
        while (lines.next()) |line| {
            const parsed = parseSample(line) orelse continue;
            if (std.mem.eql(u8, parsed.name, name)) return parsed.value;
        }
        return null;
    }

    /// Every admission shed, summed off the *text* rather than a list —
    /// so a rung added to counters.zig joins this total by being named,
    /// exactly as it joins `Counters.shedTotal` by being named.
    pub fn shedTotal(scrape: *const Scrape) u64 {
        assert(scrape.body.len >= 1);
        var total: u64 = 0;
        var rungs: u32 = 0;
        var lines = std.mem.splitScalar(u8, scrape.body, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, shed_prefix)) continue;
            const parsed = parseSample(line) orelse continue;
            total += parsed.value;
            rungs += 1;
        }
        // A sum over nothing is zero, and zero would satisfy the identity
        // that reads it — so an empty selection is a broken scrape, not a
        // proxy that shed nothing.
        assert(rungs >= 1);
        return total;
    }
};

const Sample = struct {
    name: []const u8,
    value: u64,
};

/// One `zoxy_<name> <value>` line, or null for the `# TYPE` lines, the
/// blank last line, and anything else this parser was not promised.
fn parseSample(line: []const u8) ?Sample {
    if (!std.mem.startsWith(u8, line, metric_prefix)) return null;
    const space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    assert(space > metric_prefix.len);
    const digits = std.mem.trim(u8, line[space + 1 ..], " \r");
    const value = std.fmt.parseUnsigned(u64, digits, 10) catch return null;
    return .{ .name = line[metric_prefix.len..space], .value = value };
}

/// Scrape the admin listener once. Any request is answered the same way
/// (admin.zig parses none), so the target is documentary.
pub fn fetch(arena: std.mem.Allocator, io: Io, port: u16) ![]const u8 {
    assert(port != 0);
    var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var write_buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.print(
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n",
        .{port},
    );
    try writer.interface.flush();
    const response = try readToClose(arena, io, stream);
    assert(response.len >= 1);
    return response;
}

/// Read until the server closes — the framing admin.zig chose (§8).
fn readToClose(arena: std.mem.Allocator, io: Io, stream: Io.net.Stream) ![]const u8 {
    const response = try arena.alloc(u8, scrape_bytes_max);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var filled: u32 = 0;
    // Bounded by the buffer rather than by trust: every iteration either
    // fills some of it or ends the loop, so `filled` is the clock.
    while (filled < scrape_bytes_max) {
        // A close is how this response ends, and the reader spells both a
        // clean one and a reset as a failed read. They are not
        // distinguished here on purpose: what separates "the body
        // arrived" from "the body was cut short" is whether the body is
        // *whole*, which `parse` decides on the bytes rather than on the
        // manner of the close.
        const read = reader.interface.readSliceShort(response[filled..]) catch break;
        if (read == 0) break;
        filled += @intCast(read);
    }
    assert(filled <= scrape_bytes_max);
    return response[0..filled];
}

/// Split a scrape response into its verdict and its body. A scrape that
/// did not answer 200 is a broken admin plane, and returning its text as
/// though it were metrics would turn that into a pile of missing
/// counters instead.
pub fn parse(response: []const u8) !Scrape {
    const ok_status = "HTTP/1.1 200 OK\r\n";
    const head_end = "\r\n\r\n";
    if (!std.mem.startsWith(u8, response, ok_status)) return error.ScrapeNotOk;
    const end = std.mem.indexOf(u8, response, head_end) orelse return error.ScrapeUnframed;
    const body = response[end + head_end.len ..];
    if (body.len == 0) return error.ScrapeEmpty;
    // Every rendered sample ends in a newline, so a body that does not is
    // one the close cut mid-line. That is the whole truncation check: the
    // read loop cannot tell a clean close from a reset, and a scrape that
    // stopped early would otherwise parse into a shorter list of
    // perfectly plausible numbers.
    if (body[body.len - 1] != '\n') return error.ScrapeTruncated;
    assert(body.len < response.len);
    return .{ .body = body };
}
