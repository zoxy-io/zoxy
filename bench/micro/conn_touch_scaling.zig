//! Tier-0 micro bench (§9): what one completion's bookkeeping costs as the
//! live connection count grows — the memory-hierarchy half of the c10k
//! question, isolated from the network.
//!
//! `Stream.arm`/`Stream.delivered` are three instructions in ReleaseFast
//! (the assertions compile out), so their cost is not the work — it is
//! reaching `stream.armed` at all. A conn slot is ~2 KiB and the stream
//! slot beside it is small, but they are allocated in separate pools, so N
//! live connections spread the pair over 2N distinct locations and the
//! completion order across them is effectively random. At 500 connections
//! the touched set lives in L3; at 10k every touch is a DRAM access plus a
//! page walk.
//!
//! Since #274 a data completion arms on the *stream* — that is the object
//! the ops moved to — and the peak accounting reaches its connection, so
//! both are on the measured path. Comparing bands across that change is
//! the point: the split traded one large object per completion for two
//! smaller ones, and only a measurement says which way that goes.
//!
//! The permutation is the point: a sequential walk measures the prefetcher,
//! not the proxy. A real loop services whichever connection the ring hands
//! back next, which has no relation to slot order.
//!
//! What this is NOT: the arm and the deliver of a real op are separated by a
//! kernel round trip, so production may pay the miss twice where this pays
//! it once. Read the numbers as a floor on the per-connection penalty, and
//! as a scaling curve rather than an absolute.
//!
//!   zig build bench-micro && ./zig-out/bin/zoxy-bench-conn_touch_scaling

const std = @import("std");
const linux = std.os.linux;

const zoxy = @import("zoxy");

const assert = std.debug.assert;

const ServerType = zoxy.Server(zoxy.Io.XevIo);
const ConnType = ServerType.ConnType;
const StreamType = ServerType.StreamType;

/// `std.time` carries only constants in 0.16 — `Instant`/`Timer` moved out —
/// and this bench has no `Io` runtime to borrow a clock from, so it reads
/// CLOCK_MONOTONIC directly. Precise, not COARSE: XevIo's millisecond
/// granule is fine for second-scale deadlines but would quantise a
/// nanosecond-per-op measurement into uselessness.
fn monotonicNs() u64 {
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(linux.CLOCK.MONOTONIC, &ts);
    assert(std.posix.errno(rc) == .SUCCESS);
    assert(ts.sec >= 0);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Completions per measured point. Enough that the timer's resolution and
/// the setup's cache state are both noise against the steady state.
const ops_per_point: u64 = 4_000_000;

/// Live connection counts to sweep — the bench's 500-connection operating
/// point, the c10k one, and the compiled ceiling (read from `constants`, so
/// a ceiling change moves the sweep with it), with steps between so the
/// knee is visible rather than inferred from the endpoints.
const points = [_]u32{ 64, 256, 500, 1000, 2000, 5000, 10000, zoxy.constants.conn_slots_max };

/// The point every ratio is quoted against: the connection count the
/// Tier-1 bench actually runs at, so the column reads as "what c10k costs
/// over the operating point we ship against" rather than over an arbitrary
/// end of the sweep.
const baseline_conns: u32 = 500;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    // Discarded: the first measurement of a run absorbs the core's
    // frequency ramp, and reading that as a data point made the smallest
    // (and therefore cache-friendliest) connection count look like the
    // slowest one.
    _ = try measure(arena, 1024);

    var results: [points.len]Measurement = undefined;
    for (points, 0..) |count, index| results[index] = try measure(arena, count);

    var baseline_ns: f64 = 0;
    for (points, results) |count, result| {
        if (count == baseline_conns) baseline_ns = result.ns_per_op;
    }
    assert(baseline_ns > 0); // `baseline_conns` must be one of `points`.

    std.debug.print(
        "conn slot = {d} B, {d} completions per point\n\n",
        .{ @sizeOf(ConnType), ops_per_point },
    );
    std.debug.print(
        "{s:>8} {s:>12} {s:>11} {s:>12} {s:>12}\n",
        .{ "conns", "touched MiB", "ns/op", "vs 500", "checksum" },
    );
    for (points, results) |count, result| {
        const touched_mib =
            @as(f64, @floatFromInt(@as(u64, count) * @sizeOf(ConnType))) / (1024.0 * 1024.0);
        std.debug.print(
            "{d:>8} {d:>12.1} {d:>11.2} {d:>11.2}x {d:>12}\n",
            .{ count, touched_mib, result.ns_per_op, result.ns_per_op / baseline_ns, result.checksum },
        );
    }
}

const Measurement = struct {
    ns_per_op: f64,
    /// Defeats dead-code elimination: without a consumed result the whole
    /// loop is legally removable, and the bench would measure nothing at
    /// impressive speed.
    checksum: u64,
};

fn measure(arena: std.mem.Allocator, count: u32) !Measurement {
    assert(count >= 1);
    const conns = try arena.alloc(ConnType, count);
    // One stream per connection, as the server pairs them (#274): a data
    // completion's bookkeeping now lands on the stream slot, and the peak
    // tracking inside `arm` reaches back through it to the conn. Both
    // objects are therefore on the path this bench measures, which is the
    // layout change worth watching — the arrays are allocated apart, so a
    // touched pair is two distinct pages exactly as it is in the server.
    const streams = try arena.alloc(StreamType, count);
    // The peak counters `arm` writes under runtime safety (this binary is
    // ReleaseSafe) are the only fields either type reads off the server,
    // and they must be real storage: reaching them through an undefined
    // pointer is what this loop used to do, quietly.
    const server = try arena.create(ServerType);
    server.armed_ops_peak = 0;
    server.stream_armed_ops_peak = 0;
    for (conns, streams, 0..) |*conn, *stream, index| {
        conn.generation = @intCast(index);
        conn.armed = .{};
        conn.server = server;
        conn.stream = stream;
        stream.generation = @intCast(index);
        stream.conn = conn;
        stream.armed = .{};
        stream.op_data_client_to_upstream = .{};
    }

    // A random permutation, walked repeatedly: the completion order a ring
    // hands back bears no relation to slot order, and a sequential walk
    // would measure the hardware prefetcher instead.
    const order = try arena.alloc(u32, count);
    for (order, 0..) |*slot, index| slot.* = @intCast(index);
    var prng = std.Random.DefaultPrng.init(0x5eed_c0ffee);
    prng.random().shuffle(u32, order);

    var checksum: u64 = 0;
    const started = monotonicNs();
    var done: u64 = 0;
    while (done < ops_per_point) {
        for (order) |index| {
            const stream = &streams[index];
            stream.arm(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            stream.delivered(&stream.op_data_client_to_upstream, "data_client_to_upstream");
            checksum +%= stream.conn.generation;
        }
        done += count;
    }
    const elapsed_ns = monotonicNs() - started;

    assert(done >= ops_per_point);
    assert(elapsed_ns >= 1);
    return .{
        .ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(done)),
        .checksum = checksum,
    };
}
