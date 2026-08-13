//! Deterministic simulation backend for the Io seam (DESIGN.md §4, §9):
//! virtual sockets, a virtual clock, and a seeded adversarial scheduler
//! running the real data path single-threaded with no real fds. All
//! nondeterminism flows from one PRNG, so a seed replays its exact
//! schedule byte for byte. The adversary delivers completions in
//! PRNG-permuted bounded batches without refreshing the clock mid-batch
//! (making §4's one-tick staleness adversarial by construction), splits
//! reads and writes down to one byte, delays/refuses/black-holes/
//! pressure-fails connects, and injects resets between batches.
//!
//! Socket handles carry a generation; any use of a stale handle after
//! close trips an assertion — the §5 release rule enforced in the sim.

const std = @import("std");

const constants = @import("../constants.zig");
const Io = @import("io.zig");
const Pool = @import("../mem/Pool.zig").Pool;

const assert = std.debug.assert;

const SimIo = @This();

const sockets_max: u16 = 1024;
const listeners_max: u16 = 32;
const accept_queue_max: u16 = 64;
/// The widest a scenario may open a socket ring. The simulator's own
/// 8 KiB rather than the production head size — which is the config's
/// now (`limits.head_buffer_bytes`) — matching the *default* head
/// buffer, so a scenario can still reproduce a production-shaped
/// delivery: one read filling a default-sized head buffer outright.
const inbox_bytes_max: u32 = 8 * 1024;
/// What a scenario gets unless it asks for more. Half the head buffer, so
/// a head larger than it still arrives in pieces by default and the §7
/// detect-and-retry re-parse keeps being exercised.
const inbox_bytes_default: u32 = 4096;
comptime {
    assert(inbox_bytes_default >= 1);
    assert(inbox_bytes_default <= inbox_bytes_max);
    // The default must stay narrower than a head buffer, or every scenario
    // silently loses the piecewise head arrival it covers today.
    assert(inbox_bytes_default < inbox_bytes_max);
    // The whole-head delivery stays representable at the default size.
    assert(inbox_bytes_max >= constants.head_buffer_bytes_default);
}
/// The simulator's own in-flight-op bound (§9), derived from *its*
/// listener limit rather than production's — which no longer has one, so
/// there is no `constants.in_flight_ops_max` left to borrow. SimIo
/// already keeps a `listeners_max` of its own for the same reason: it is
/// a test double whose bounds describe what the simulator drives, not
/// what a deployment may configure. At the shared pool ceilings this is
/// at least what any scenario can arm.
const pending_ops_max: u32 = constants.inFlightOps(
    constants.conn_slots_max,
    constants.upstream_slots_max,
    listeners_max,
);
const pending_signals_max: u8 = 8;
/// The clock starts at one virtual second, not zero, so code that would
/// misbehave at t=0 gets caught.
const clock_start_ns: u64 = 1_000_000_000;
const jitter_ns_max: u64 = 1_000_000;
const never_ns: u64 = std.math.maxInt(u64);
/// Separates `key_prng` from `prng` while keeping both a function of the
/// run's one seed. Any fixed non-zero constant does; this one is arbitrary.
const key_seed_salt: u64 = 0x7a_74_6c_73_6b_65_79_00;
const peer_none: u16 = std.math.maxInt(u16);
/// Ports the simulator hands out for port-zero binds.
const ephemeral_port_base: u16 = 40_000;
/// The virtual access-log sink (§8): every byte the server writes lands
/// here for the harness to read back and check (§9). Sized so no scenario
/// in the sweep can fill it — `sink_overflow_bytes` is asserted zero by the
/// harness, so a scenario that ever did would fail rather than silently
/// hand the oracle a truncated log.
const sink_bytes_max: u32 = 1024 * 1024;
/// Where the simulated wall clock starts: 2020-01-01T00:00:00Z. Fixed, so
/// a seed's log lines are byte-identical across runs — the determinism the
/// §9 trace-hash check demands, extended to the one output that carries a
/// date. Virtual time advances it exactly as it advances `nowNs`.
const wall_clock_base_ns: u64 = 1_577_836_800 * std.time.ns_per_s;
/// The address block simulated clients dial from (RFC 5737 TEST-NET-2), so
/// a log line read out of the sink is recognizably the simulator's.
const client_ip_bytes: [4]u8 = .{ 198, 51, 100, 1 };
/// The first ephemeral port a simulated client connects from; each new
/// virtual pair takes the next one, so every client in a run is
/// distinguishable in the access log by address alone.
const client_port_base: u16 = 50_000;

sockets: Pool(SocketEntry),
listeners: []ListenerEntry,
listeners_count: u16,
pending: []*Completion,
pending_count: u32,
pending_signals: [pending_signals_max]PendingSignal,
pending_signals_count: u8,
signal_callback: ?*const fn (?*anyopaque, Io.Signal) void,
signal_userdata: ?*anyopaque,
now_ns_value: u64,
prng: std.Random.DefaultPrng,
/// Key material for `fillRandom`, kept on its own stream rather than
/// drawn from `prng`. Both are seeded from the run's seed, so `zig build
/// sim -- <seed>` still replays everything; the split is so that adding or
/// removing a handshake does not shift every later adversary decision in
/// the scenario. Sharing the stream would make any TLS change silently re-roll
/// the delivery schedule of every *non*-TLS connection under every seed —
/// re-rolling the sweep's coverage while the sweep still reports green.
key_prng: std.Random.DefaultPrng,
adversary: Adversary,
/// Pending one-shot `setNodelay`/`setLingerRst` failures (§9). A virtual
/// socket table has no reason to refuse a socket option, so without this
/// the whole set-option path is unreachable in simulation — and a bug
/// there is invisible under every seed. That is not hypothetical: the
/// per-op kernel-pressure split shipped with one `setNodelay` site still
/// bumping the aggregate counter alone, and 64 seeds stayed green because
/// nothing could make the call fail.
pending_set_option_errors: u8,
/// The cause `lastPressure` reports for the next injected failure (§8).
/// Scenario-controlled so a test can drive each classification arm: the
/// real errno comes from the kernel, which a virtual socket table has
/// none of.
pressure_cause: Io.Pressure.Cause,
last_pressure: Io.Pressure,
/// What `advanceWallClock` has added to the wall clock, on top of
/// however far virtual time has moved. Zero on every seed that does not
/// ask, which keeps the two clocks agreeing in the ordinary case.
wall_offset_ns: u64,
stopped: bool,
/// The code a caller gave up with (`abort`), which production would have
/// spent on a process exit. Null until one does.
aborted: ?u8,
dump_on_deadlock: bool,
/// Whether a give-up should print the whole counter set (see
/// `wantsOperatorDump`).
dump_on_abort: bool,
/// FNV-1a over every delivery; two runs of one seed must end equal (§9).
trace_hash: u64,
/// Completions delivered so far, by op kind (§9). `trace_hash` says two
/// runs of a seed did the *same* work; this says how much work that was,
/// which is the question a hash cannot answer — a run doing three times
/// as much hashes identically both times. Cumulative rather than
/// concurrent, so it extends §8's closed-form op budgets from
/// "worst-case in flight" to "total consumed".
delivered: [std.enums.values(OpKind).len]u64,
blackholed_addresses: [blackholed_addresses_max]std.Io.net.IpAddress,
blackholed_count: u8,
/// One-shot dial faults by address (`injectConnectError`): the next
/// connect to a matching address fails with `error.Unexpected`.
connect_error_addresses: [connect_error_addresses_max]std.Io.net.IpAddress,
connect_error_count: u8,
/// The virtual access-log sink (§8): what the server wrote, in order, for
/// the §9 oracle to parse back. Arena-allocated at init like every other
/// simulator buffer.
sink: []u8,
sink_len: u32,
/// Bytes the sink could not hold. Not a model of anything production does
/// — the real sink is a pipe with its own backpressure, which the server's
/// own staging buffer already answers by dropping — but a loud way for the
/// harness to notice its oracle was handed a truncated log.
sink_overflow_bytes: u32,
/// Pending one-shot sink failures (`injectLogWriteError`): the write path
/// a real broken pipe takes, which a virtual sink would otherwise never
/// exercise (§9) — the same argument `pending_set_option_errors` makes.
pending_log_write_errors: u8,
/// One-shot `logReopen` failures (§8 rotation), same shape as the write
/// errors above; and how many reopens succeeded, for scenario oracles.
pending_log_reopen_errors: u8,
log_reopen_count: u32,
/// The ephemeral port the next simulated client connects from.
next_client_port: u16,
/// The provided-buffer group (§5): one slab, a free flag per buffer, and
/// the in-use count the asserts ride on. Selection happens at delivery
/// time — an armed `recv_group` holds nothing — mirroring the kernel's
/// buf_ring, with lowest-free-id in place of the kernel's own choice so
/// the schedule stays a pure function of the seed.
group_slab: []u8,
group_free: []bool,
group_count: u32,
group_bytes: u32,
group_in_use: u32,

const blackholed_addresses_max: u8 = 4;
const connect_error_addresses_max: u8 = 4;

pub const Adversary = struct {
    /// Bias deliveries toward 1-byte and full-length reads/writes.
    partial_io: bool = true,
    /// Usable socket-ring size: the ceiling on what one recv can deliver,
    /// however much the peer wrote. Where `partial_io` fragments a delivery
    /// that could have been whole, this bounds how whole "whole" ever gets —
    /// the two are independent knobs on the same question. Raising it to
    /// `inbox_bytes_max` is what lets a scenario fill a head buffer in one
    /// read, the shape production takes and the default cannot express.
    inbox_bytes: u32 = inbox_bytes_default,
    connect_delay_ns_max: u64 = 0,
    connect_refuse_percent: u8 = 0,
    connect_blackhole_percent: u8 = 0,
    /// Chance per batch to reset one random live connection.
    reset_percent: u8 = 0,
    /// Chance per batch to fail one random live socket's next data op with
    /// `error.Unexpected` (ENOBUFS/ENOMEM-class, §8) — local to that
    /// socket, so the relay witnesses it and tears the connection down.
    kernel_pressure_percent: u8 = 0,
    /// Chance per connect to fail the dial with `error.Unexpected` —
    /// the socket()-time kernel-pressure fate (ENFILE/EADDRNOTAVAIL-
    /// class, §8). Distinct from `connect_refuse_percent`: Refused is
    /// the origin's verdict, this is our own exhaustion, and the two
    /// want opposite responses upstream.
    connect_pressure_percent: u8 = 0,
    /// How long a sink write takes to complete (§8 access log). Zero is an
    /// instant sink, where lines never accumulate and the drop rung is
    /// unreachable; a stall is a reader that has fallen behind, which is
    /// the condition the two staging buffers and the drop counter exist
    /// for. A scenario that stalls the sink long enough overflows the
    /// staging buffer and must still serve every request unaffected —
    /// which is the property being tested.
    log_write_stall_ns: u64 = 0,
    batch_max: u32 = constants.loop_completions_per_tick_max,
};

pub const Options = struct {
    seed: u64,
    adversary: Adversary = .{},
    /// Print pending-op forensics when a deadlock is detected. Tests
    /// that deliberately provoke a deadlock turn this off.
    dump_on_deadlock: bool = true,
    /// Print the whole counter set when a caller gives up (§8 drain
    /// backstop). Gates that provoke that path on purpose turn it off.
    dump_on_abort: bool = true,
    /// The provided-buffer group `recvGroup` selects from — the simulated
    /// twin of the io_uring buf_ring (§5's head-buffer ring). Selection is
    /// deterministic (lowest free id), so a seed replays the same buffer
    /// assignments. Defaults wide enough that no scenario sheds unless it
    /// asks to: one buffer per possible socket, production-sized.
    buffer_group_count: u32 = sockets_max,
    buffer_group_bytes: u32 = constants.head_buffer_bytes_default,
};

pub const Socket = packed struct(u32) {
    index: u16,
    generation: u16,
};

pub const Listener = struct {
    index: u16,
};

pub const Completion = struct {
    op: Op = .none,
    ready_at_ns: u64 = 0,
    pending_index: u32 = 0,
    userdata: ?*anyopaque = null,
    callback: ErasedCallback = undefined,
    state: State = .dead,
    /// An op the backend took and will never deliver (`dropPendingOps`).
    /// It stays pending for the rest of the scenario, holding whatever it
    /// references, which is the one thing this simulator could not
    /// express before #206 — and the shape of #203.
    dropped: bool = false,

    pub const State = enum(u8) { dead, pending };
};

/// The seam's op set, named so the §9 gate can count and report
/// deliveries by kind rather than by tag number.
pub const OpKind = enum(u8) {
    none,
    accept,
    connect,
    recv,
    recv_group,
    send,
    close,
    log_write,
    timer,
    timer_cancel,
    connect_cancel,
};

const Op = union(OpKind) {
    none,
    accept: struct { listener_index: u16 },
    connect: struct { address: std.Io.net.IpAddress, fate: ConnectFate, canceled: bool },
    recv: struct { socket: Socket, buffer: []u8 },
    recv_group: struct { socket: Socket },
    send: struct { socket: Socket, bytes: []const u8 },
    close: struct { socket: Socket },
    log_write: struct { bytes: []const u8 },
    timer: struct { fire_at_ns: u64, canceled: bool },
    timer_cancel: struct { target: *Completion },
    connect_cancel: struct { target: *Completion },
};

const ConnectFate = enum(u8) { succeed, refuse, blackhole, pressure };

const Result = union(enum) {
    accept: Io.AcceptError!Socket,
    connect: Io.ConnectError!Socket,
    recv: Io.RecvError!u32,
    recv_group: Io.RecvGroupError!Io.GroupRecv,
    send: Io.SendError!u32,
    close: void,
    log_write: Io.LogWriteError!u32,
    timer: Io.TimerError!void,
    timer_cancel: void,
    connect_cancel: void,
};

const ErasedCallback = *const fn (?*anyopaque, *const Result) void;
const ResultTag = std.meta.Tag(Result);

/// Builds the type-erased trampoline for an op whose completion carries a
/// value: it asserts the delivered Result matches `tag` and forwards the
/// projected value to the typed `callback`. Collapses the otherwise
/// identical per-op trampolines into one shape.
fn erasedResult(
    comptime Userdata: type,
    comptime tag: ResultTag,
    comptime callback: anytype,
) ErasedCallback {
    return (struct {
        fn erased(context: ?*anyopaque, result: *const Result) void {
            assert(result.* == tag);
            const userdata: *Userdata = @ptrCast(@alignCast(context.?));
            callback(userdata, @field(result.*, @tagName(tag)));
        }
    }).erased;
}

/// The trampoline for an op whose completion carries no value (close and
/// the two cancels): assert the tag, then invoke the value-less callback.
fn erasedVoid(
    comptime Userdata: type,
    comptime tag: ResultTag,
    comptime callback: anytype,
) ErasedCallback {
    return (struct {
        fn erased(context: ?*anyopaque, result: *const Result) void {
            assert(result.* == tag);
            const userdata: *Userdata = @ptrCast(@alignCast(context.?));
            callback(userdata);
        }
    }).erased;
}

const PendingSignal = struct {
    signal: Io.Signal,
    at_ns: u64,
};

const SocketEntry = struct {
    pool_next: u32,
    generation: u32,
    peer: u16,
    /// What `peerAddress` reports for this socket (§8 access log): the
    /// dialed address on a client socket, the synthesized client address
    /// on the accepted one. Held per entry rather than derived from the
    /// peer index because an accepted socket outlives nothing here — but
    /// its peer may close first, and the log still has to name who
    /// connected.
    peer_address: std.Io.net.IpAddress,
    /// What `localAddress` reports (§6 send: the header's destination
    /// field): each end's local address is the other end's
    /// `peer_address`, assigned at the same pair creation and held per
    /// entry for the same reason — the peer may close first, and a
    /// connection mid-dial still has to name the address its client
    /// connected to.
    local_address: std.Io.net.IpAddress,
    fin_received: bool,
    read_shutdown: bool,
    write_shutdown: bool,
    reset: bool,
    /// One-shot: the next recv/send on this socket fails with
    /// `error.Unexpected`, modeling a transient ENOBUFS/ENOMEM op failure
    /// (§8 "any completion" kernel-pressure rung). Local to this socket —
    /// the peer is untouched, unlike `reset`.
    kernel_pressure: bool,
    linger_rst: bool,
    nodelay: bool,
    inbox: Ring,
};

const ListenerEntry = struct {
    address: std.Io.net.IpAddress,
    active: bool,
    accept_queue: [accept_queue_max]Socket,
    accept_queue_len: u16,
    /// Injected kernel-pressure accept failures still to deliver
    /// (`injectAcceptError`) — the ENFILE-class path XevIo can hit but a
    /// virtual socket table never would.
    pending_accept_errors: u8,
    /// A socket whose accept "CQE" was already posted when the listener
    /// closed (§9: the drain race) — delivered to the armed accept as a
    /// success even though the listener is no longer active.
    raced_socket: ?Socket,
};

const Ring = struct {
    bytes: [inbox_bytes_max]u8,
    head: u32,
    count: u32,
    /// What this ring actually wraps at, set per scenario from the
    /// adversary. The backing array is the widest any scenario may ask
    /// for; this is what the scenario asked for.
    capacity: u32,

    fn freeSpace(ring: *const Ring) u32 {
        assert(ring.capacity >= 1);
        assert(ring.capacity <= inbox_bytes_max);
        assert(ring.count <= ring.capacity);
        return ring.capacity - ring.count;
    }

    fn push(ring: *Ring, source: []const u8) u32 {
        const n: u32 = @min(@as(u32, @intCast(source.len)), ring.freeSpace());
        assert(n <= source.len);
        var written: u32 = 0;
        while (written < n) : (written += 1) {
            ring.bytes[(ring.head + ring.count + written) % ring.capacity] = source[written];
        }
        ring.count += n;
        assert(ring.count <= ring.capacity);
        return n;
    }

    fn pop(ring: *Ring, target: []u8) u32 {
        const n: u32 = @min(@as(u32, @intCast(target.len)), ring.count);
        assert(n <= target.len);
        // The modulus below is this function's own precondition, not one
        // borrowed from whoever pushed.
        assert(ring.capacity >= 1);
        assert(ring.capacity <= inbox_bytes_max);
        assert(ring.count <= ring.capacity);
        var read: u32 = 0;
        while (read < n) : (read += 1) {
            target[read] = ring.bytes[(ring.head + read) % ring.capacity];
        }
        ring.head = (ring.head + n) % ring.capacity;
        ring.count -= n;
        return n;
    }
};

/// In-place init; `arena` follows the production shape — this is the
/// simulator's only allocation point, everything after is zero-alloc.
pub fn init(io: *SimIo, arena: std.mem.Allocator, options: Options) error{OutOfMemory}!void {
    // Validate the adversary knobs at the misuse site: a bad value would
    // otherwise surface as an opaque arithmetic/uintLessThan panic deep in
    // a delivery, seeds away from the caller that set it.
    assert(@as(u16, options.adversary.connect_refuse_percent) +
        options.adversary.connect_blackhole_percent +
        options.adversary.connect_pressure_percent <= 100);
    assert(options.adversary.reset_percent <= 100);
    assert(options.adversary.kernel_pressure_percent <= 100);
    assert(options.adversary.batch_max >= 1);
    // A ring that cannot hold a byte can never make progress, and one
    // wider than the backing array would index past it.
    assert(options.adversary.inbox_bytes >= 1);
    assert(options.adversary.inbox_bytes <= inbox_bytes_max);
    // A zero-buffer group is a scenario choice (an L4-only world arms no
    // recv_group); a zero-byte buffer is never anything but a bug. The
    // count ceiling is the kernel twin's own (buf_ring entries are a u16
    // power of two), stated here so ids stay u16 and the slab multiply
    // below cannot overflow before it widens.
    assert(options.buffer_group_bytes >= 1);
    assert(options.buffer_group_count <= constants.buffer_group_entries_max);

    io.listeners = try arena.alloc(ListenerEntry, listeners_max);
    io.pending = try arena.alloc(*Completion, pending_ops_max);
    io.sink = try arena.alloc(u8, sink_bytes_max);
    try io.sockets.init(arena, sockets_max);
    io.listeners_count = 0;
    io.pending_count = 0;
    io.pending_signals = undefined;
    io.pending_signals_count = 0;
    io.signal_callback = null;
    io.signal_userdata = null;
    io.initClocksAndStreams(options.seed);
    io.adversary = options.adversary;
    io.pending_set_option_errors = 0;
    io.pressure_cause = .out_of_buffers;
    io.last_pressure = Io.Pressure.none;
    io.stopped = false;
    io.aborted = null;
    io.dump_on_deadlock = options.dump_on_deadlock;
    io.dump_on_abort = options.dump_on_abort;
    io.trace_hash = std.hash.Fnv1a_64.init().value;
    io.delivered = @splat(0);
    io.blackholed_addresses = undefined;
    io.blackholed_count = 0;
    io.connect_error_addresses = undefined;
    io.connect_error_count = 0;
    io.sink_len = 0;
    io.sink_overflow_bytes = 0;
    io.pending_log_write_errors = 0;
    io.pending_log_reopen_errors = 0;
    io.log_reopen_count = 0;
    io.next_client_port = client_port_base;
    io.group_slab = try arena.alloc(
        u8,
        @as(usize, options.buffer_group_count) * options.buffer_group_bytes,
    );
    // Zeroed for determinism, not residency (the kernel twin faults
    // lazily). No current path reads past what a scenario wrote; the
    // zeroing is cheap insurance that any future such read replays
    // identically instead of flaking on allocator-dependent garbage.
    @memset(io.group_slab, 0);
    io.group_free = try arena.alloc(bool, options.buffer_group_count);
    @memset(io.group_free, true);
    io.group_count = options.buffer_group_count;
    io.group_bytes = options.buffer_group_bytes;
    io.group_in_use = 0;
    assert(io.sockets.isFullyReleased());
}

/// Targeted scenario control: every connect to this address black-holes
/// (never completes), regardless of the percent knobs. Directed tests
/// use this to pin one dial while the adversary stays off the harness's
/// own connects.
pub fn blackholeAddress(io: *SimIo, address: std.Io.net.IpAddress) void {
    assert(io.blackholed_count < blackholed_addresses_max);
    io.blackholed_addresses[io.blackholed_count] = address;
    io.blackholed_count += 1;
}

pub fn listen(io: *SimIo, address: std.Io.net.IpAddress) Io.ListenError!Listener {
    assert(io.listeners_count <= listeners_max);
    if (io.listeners_count == listeners_max) {
        return error.AddressUnavailable;
    }
    var effective = address;
    if (effective.getPort() == 0) {
        effective.setPort(ephemeral_port_base + io.listeners_count);
    }
    for (io.listeners[0..io.listeners_count]) |*existing| {
        if (existing.active and std.meta.eql(existing.address, effective)) {
            return error.AddressInUse;
        }
    }
    const index = io.listeners_count;
    io.listeners[index] = .{
        .address = effective,
        .active = true,
        .accept_queue = undefined,
        .accept_queue_len = 0,
        .pending_accept_errors = 0,
        .raced_socket = null,
    };
    io.listeners_count += 1;
    return .{ .index = index };
}

pub fn listenerAddress(io: *const SimIo, listener: Listener) std.Io.net.IpAddress {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.address.getPort() != 0);
    return entry.address;
}

/// Sync close of a listener (drain, §8): the armed accept — if any —
/// delivers `error.Canceled` on the next tick; queued-but-unaccepted
/// sockets are reset, as a kernel dropping its backlog would.
pub fn listenClose(io: *SimIo, listener: Listener) void {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.active);
    entry.active = false;
    // The drain race (§9): if an accept op is armed and a connection is
    // already queued, the kernel would have posted the accept CQE before
    // any cancel could land — that socket is *delivered*, not canceled.
    // The rest of the backlog resets, as a kernel dropping it would.
    var queue_start: u16 = 0;
    if (entry.accept_queue_len > 0 and io.hasArmedAccept(listener.index)) {
        assert(entry.raced_socket == null);
        entry.raced_socket = entry.accept_queue[0];
        queue_start = 1;
    }
    for (entry.accept_queue[queue_start..entry.accept_queue_len]) |queued| {
        io.closeEntryWithReset(queued);
    }
    entry.accept_queue_len = 0;
}

fn hasArmedAccept(io: *const SimIo, listener_index: u16) bool {
    for (io.pending[0..io.pending_count]) |completion| {
        switch (completion.op) {
            .accept => |op| if (op.listener_index == listener_index) return true,
            else => {},
        }
    }
    return false;
}

pub fn accept(
    io: *SimIo,
    listener: Listener,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.AcceptError!Socket) void,
) void {
    assert(completion.state == .dead);
    assert(listener.index < io.listeners_count);
    completion.* = .{
        .op = .{ .accept = .{ .listener_index = listener.index } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .accept, callback),
    };
    io.enqueue(completion);
}

pub fn connect(
    io: *SimIo,
    address: std.Io.net.IpAddress,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.ConnectError!Socket) void,
) void {
    assert(completion.state == .dead);
    const random = io.prng.random();
    const roll = random.uintLessThan(u8, 100);
    var fate: ConnectFate = .succeed;
    if (io.takeConnectError(address)) {
        fate = .pressure;
    } else if (io.isBlackholed(address)) {
        fate = .blackhole;
    } else if (roll < io.adversary.connect_blackhole_percent) {
        fate = .blackhole;
    } else if (roll < io.adversary.connect_blackhole_percent + io.adversary.connect_refuse_percent) {
        fate = .refuse;
    } else if (roll < io.adversary.connect_blackhole_percent + io.adversary.connect_refuse_percent +
        io.adversary.connect_pressure_percent)
    {
        fate = .pressure;
    }
    const delay_ns = if (io.adversary.connect_delay_ns_max == 0)
        0
    else
        random.uintAtMost(u64, io.adversary.connect_delay_ns_max);
    completion.* = .{
        .op = .{ .connect = .{ .address = address, .fate = fate, .canceled = false } },
        .ready_at_ns = if (fate == .blackhole) never_ns else io.now_ns_value + delay_ns,
        .userdata = userdata,
        .callback = erasedResult(Userdata, .connect, callback),
    };
    io.enqueue(completion);
}

pub fn recv(
    io: *SimIo,
    socket: Socket,
    buffer: []u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvError!u32) void,
) void {
    assert(completion.state == .dead);
    assert(buffer.len >= 1);
    _ = io.socketEntry(socket);
    completion.* = .{
        .op = .{ .recv = .{ .socket = socket, .buffer = buffer } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .recv, callback),
    };
    io.enqueue(completion);
}

/// A recv that carries no buffer (§5's head-buffer ring): the group binds
/// one at delivery time, or answers `error.NoBuffers` if it cannot. The
/// armed op itself holds nothing — that is the entire point.
pub fn recvGroup(
    io: *SimIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.RecvGroupError!Io.GroupRecv) void,
) void {
    assert(completion.state == .dead);
    assert(io.group_count >= 1);
    _ = io.socketEntry(socket);
    completion.* = .{
        .op = .{ .recv_group = .{ .socket = socket } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .recv_group, callback),
    };
    io.enqueue(completion);
}

/// The bytes behind a `GroupRecv.buffer_id`, valid until returned.
pub fn bufferGroupSlice(io: *SimIo, buffer_id: u16) []u8 {
    assert(buffer_id < io.group_count);
    // Only the holder of an id may read it, and the simulator can enforce
    // what the kernel-backed twin cannot observe.
    assert(!io.group_free[buffer_id]);
    return io.group_slab[@as(usize, buffer_id) * io.group_bytes ..][0..io.group_bytes];
}

/// The group's capacity — what a caller's own in-use accounting must
/// agree with, asserted at the composition site rather than trusted.
pub fn bufferGroupCount(io: *const SimIo) u32 {
    return io.group_count;
}

/// One buffer's size, on the same asserted-not-trusted terms.
pub fn bufferGroupBytes(io: *const SimIo) u32 {
    return io.group_bytes;
}

/// Give a selected buffer back to the group. Sync and syscall-free in
/// production (a buf_ring tail bump); here it is the flag flip the sim's
/// leak assertions watch.
pub fn bufferGroupReturn(io: *SimIo, buffer_id: u16) void {
    assert(buffer_id < io.group_count);
    assert(!io.group_free[buffer_id]);
    assert(io.group_in_use >= 1);
    io.group_free[buffer_id] = true;
    io.group_in_use -= 1;
}

pub fn send(
    io: *SimIo,
    socket: Socket,
    bytes: []const u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.SendError!u32) void,
) void {
    assert(completion.state == .dead);
    assert(bytes.len >= 1);
    const entry = io.socketEntry(socket);
    assert(!entry.write_shutdown);
    completion.* = .{
        .op = .{ .send = .{ .socket = socket, .bytes = bytes } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .send, callback),
    };
    io.enqueue(completion);
}

pub fn close(
    io: *SimIo,
    socket: Socket,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(completion.state == .dead);
    _ = io.socketEntry(socket);
    completion.* = .{
        .op = .{ .close = .{ .socket = socket } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .close, callback),
    };
    io.enqueue(completion);
}

/// The access-log sink as a ring op (§8), so the simulator sees exactly
/// what production does: a write that may complete short, at a moment the
/// scheduler picks, while the server keeps serving. `partialLen` fragments
/// it like any other write, which is what exercises the sink's resume.
pub fn logWrite(
    io: *SimIo,
    bytes: []const u8,
    completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.LogWriteError!u32) void,
) void {
    assert(completion.state == .dead);
    assert(bytes.len >= 1);
    completion.* = .{
        .op = .{ .log_write = .{ .bytes = bytes } },
        .ready_at_ns = io.now_ns_value + io.adversary.log_write_stall_ns,
        .userdata = userdata,
        .callback = erasedResult(Userdata, .log_write, callback),
    };
    io.enqueue(completion);
}

/// Who is on the other end (§8 access log). Virtual sockets have no
/// kernel to ask, so the address was assigned when the pair was created —
/// deterministically, so a seed's log lines are reproducible.
pub fn peerAddress(io: *SimIo, socket: Socket) std.Io.net.IpAddress {
    return io.socketEntry(socket).peer_address;
}

/// This end of the pair. Held per entry like `peer_address` and for the
/// same reason: the peer may already have closed — a client can hang up
/// while the proxy is still dialing upstream — and deriving this through
/// the peer index would turn that legal schedule into a panic.
pub fn localAddress(io: *SimIo, socket: Socket) std.Io.net.IpAddress {
    return io.socketEntry(socket).local_address;
}

/// The simulated wall clock (§8): the fixed epoch base, however far
/// virtual time has advanced, and whatever `advanceWallClock` has added
/// on top. The first two keep the ordinary case honest — a scenario's two
/// clocks agree about how much time it took — and the third is what lets
/// a scenario reach a deadline measured in hours.
pub fn nowWallNs(io: *const SimIo) u64 {
    assert(io.now_ns_value >= clock_start_ns);
    return wall_clock_base_ns + (io.now_ns_value - clock_start_ns) +
        io.wall_offset_ns;
}

/// The two clocks and the two random streams a seed starts from. Split
/// out of `init` when the wall-clock offset pushed it past the length
/// limit, and they belong together anyway: these are the whole of what
/// makes one seed replay identically.
///
/// Two streams, not one, and salted apart: key material is drawn from
/// `key_prng` so that how much of it a scenario asks for cannot shift the
/// adversary's schedule, which would make a handshake's mere existence
/// change every delivery after it.
fn initClocksAndStreams(io: *SimIo, seed: u64) void {
    io.now_ns_value = clock_start_ns;
    io.wall_offset_ns = 0;
    io.prng = std.Random.DefaultPrng.init(seed);
    io.key_prng = std.Random.DefaultPrng.init(seed ^ key_seed_salt);
    assert(io.now_ns_value == clock_start_ns);
    assert(io.wall_offset_ns == 0);
}

/// Step the wall clock forward without touching the monotonic one.
///
/// The asymmetry is the whole point, and it is what production actually
/// does: an NTP correction, a VM restore or a leap second moves the wall
/// clock while the loop's clock keeps ticking uniformly. Moving the
/// monotonic clock instead would fire every armed deadline at once —
/// idle, request, drain, health — which is a different scenario and not a
/// useful one.
///
/// It exists because some bounds are measured in hours against scenarios
/// that run for a virtual second: a ticket's lifetime and its sealing
/// key's rotation interval (#202) are both unreachable otherwise, so the
/// sweep would be gating a proxy whose keys never turn over.
pub fn advanceWallClock(io: *SimIo, delta_ns: u64) void {
    assert(delta_ns >= 1);
    // Into the trace: two runs of one seed must jump the same way, and a
    // run that jumped differently must not hash equal to one that did not.
    io.mix(delta_ns);
    io.wall_offset_ns += delta_ns;
    assert(io.wall_offset_ns >= delta_ns);
}

/// Targeted scenario control: the next `logWrite` fails, driving the
/// broken-sink path (§8) a virtual sink would never reach on its own —
/// the same argument `injectSetOptionError` makes for socket options.
pub fn injectLogWriteError(io: *SimIo) void {
    assert(io.pending_log_write_errors < std.math.maxInt(u8));
    io.pending_log_write_errors += 1;
}

/// Reopen the file sink (§8 rotation). The virtual sink has no inode to
/// rotate, so success is a counted no-op — what the scenario observes is
/// the *caller's* sequencing (swap only between writes, heal on success,
/// keep-old on failure), which is the part worth simulating. Sync like
/// the kernel twin.
pub fn logReopen(io: *SimIo) Io.LogReopenError!void {
    if (io.pending_log_reopen_errors >= 1) {
        io.pending_log_reopen_errors -= 1;
        return error.Unexpected;
    }
    assert(io.log_reopen_count < std.math.maxInt(u32));
    io.log_reopen_count += 1;
}

/// Targeted scenario control: the next `logReopen` fails, driving the
/// keep-the-old-sink path (§8 rotation).
pub fn injectLogReopenError(io: *SimIo) void {
    assert(io.pending_log_reopen_errors < std.math.maxInt(u8));
    io.pending_log_reopen_errors += 1;
}

/// Everything the server wrote to the sink, for the §9 oracle.
pub fn sinkBytes(io: *const SimIo) []const u8 {
    assert(io.sink_len <= io.sink.len);
    return io.sink[0..io.sink_len];
}

pub fn timerStart(
    io: *SimIo,
    completion: *Completion,
    delay_ns: u64,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.TimerError!void) void,
) void {
    assert(completion.state == .dead);
    assert(delay_ns < never_ns - io.now_ns_value);
    completion.* = .{
        .op = .{ .timer = .{ .fire_at_ns = io.now_ns_value + delay_ns, .canceled = false } },
        .userdata = userdata,
        .callback = erasedResult(Userdata, .timer, callback),
    };
    io.enqueue(completion);
}

/// The one legal cancel (§4): the pending timer delivers error.Canceled,
/// the cancel op delivers through its own completion. Canceling an
/// already-fired timer is legal — the cancel still completes.
pub fn timerCancel(
    io: *SimIo,
    timer_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(cancel_completion.state == .dead);
    assert(timer_completion != cancel_completion);
    if (timer_completion.state == .pending) {
        assert(timer_completion.op == .timer);
    }
    cancel_completion.* = .{
        .op = .{ .timer_cancel = .{ .target = timer_completion } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .timer_cancel, callback),
    };
    io.enqueue(cancel_completion);
}

/// Teardown of a pending connect (§5): even a black-holed dial must
/// reach a terminal completion (error.Canceled), or the slot owning the
/// connect op could never be released. Canceling an already-completed
/// connect is legal — the cancel still delivers.
pub fn connectCancel(
    io: *SimIo,
    connect_completion: *Completion,
    cancel_completion: *Completion,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata) void,
) void {
    assert(cancel_completion.state == .dead);
    assert(connect_completion != cancel_completion);
    if (connect_completion.state == .pending) {
        assert(connect_completion.op == .connect);
    }
    cancel_completion.* = .{
        .op = .{ .connect_cancel = .{ .target = connect_completion } },
        .userdata = userdata,
        .callback = erasedVoid(Userdata, .connect_cancel, callback),
    };
    io.enqueue(cancel_completion);
}

/// Persistent waiter: every delivered signal invokes the callback; it
/// stays armed. One waiter per loop (the Server).
pub fn signalWait(
    io: *SimIo,
    comptime Userdata: type,
    userdata: *Userdata,
    comptime callback: fn (*Userdata, Io.Signal) void,
) void {
    assert(io.signal_callback == null);
    io.signal_userdata = userdata;
    io.signal_callback = (struct {
        fn erased(context: ?*anyopaque, signal: Io.Signal) void {
            callback(@ptrCast(@alignCast(context.?)), signal);
        }
    }).erased;
}

pub fn setNodelay(io: *SimIo, socket: Socket) Io.SetOptionError!void {
    if (io.takeSetOptionError()) |err| return err;
    io.socketEntry(socket).nodelay = true;
}

pub fn setLingerRst(io: *SimIo, socket: Socket) Io.SetOptionError!void {
    if (io.takeSetOptionError()) |err| return err;
    io.socketEntry(socket).linger_rst = true;
}

/// Consume one injected set-option failure, if any. Returns the error to
/// propagate rather than propagating it here, so both option setters read
/// the same single line.
fn takeSetOptionError(io: *SimIo) ?Io.SetOptionError {
    if (io.pending_set_option_errors == 0) return null;
    io.pending_set_option_errors -= 1;
    io.recordPressure();
    return error.Unexpected;
}

pub fn shutdown(io: *SimIo, socket: Socket, how: Io.ShutdownHow) void {
    const entry = io.socketEntry(socket);
    if (!entry.write_shutdown) {
        entry.write_shutdown = true;
        if (entry.peer != peer_none) {
            io.peerEntry(entry).fin_received = true;
        }
    }
    if (how == .both) {
        entry.read_shutdown = true;
    }
}

/// Sync close for un-admitted sheds (§8): no slot, no completion, no ring
/// op. Honors a prior setLingerRst by resetting the peer.
pub fn closeNow(io: *SimIo, socket: Socket) void {
    io.closeEntry(socket);
}

/// Key material for the TLS engine (§4). Drawn from the scenario's own
/// seeded stream rather than the OS CSPRNG, which is what makes a seeded
/// run replay a byte-exact handshake — and so makes TLS traffic assertable
/// by the §9 identical-trace oracle at all.
pub fn fillRandom(io: *SimIo, buffer: []u8) void {
    assert(buffer.len > 0);
    assert(buffer.len <= Io.random_bytes_max);
    io.key_prng.random().bytes(buffer);
}

pub fn nowNs(io: *SimIo) u64 {
    assert(io.now_ns_value >= clock_start_ns);
    return io.now_ns_value;
}

pub fn stop(io: *SimIo) void {
    io.stopped = true;
}

/// The seam's give-up, which in production is a process exit and here is
/// a recorded fact plus a stopped loop. Recording it rather than taking
/// the process down is the entire reason `abort` is on the seam: the one
/// path a caller reaches when it has decided it cannot continue is
/// otherwise the one path no gate can enter.
pub fn abort(io: *SimIo, code: u8) void {
    assert(code != 0); // A give-up is never a success.
    // A second one would mean the first stopped nothing.
    assert(io.aborted == null);
    io.aborted = code;
    io.stop();
}

/// The code a scenario's server gave up with, or null if it never did —
/// what an oracle asks instead of watching for an exit it cannot survive.
pub fn abortedWith(io: *const SimIo) ?u8 {
    return io.aborted;
}

/// Whether a caller about to give up should also spend its whole counter
/// set on stderr. True everywhere a human reads that output, which is why
/// XevIo's is a constant; a gate that provokes the give-up on purpose
/// turns it off, because 190 lines of forensics bury the two that say
/// what was stuck. Same switch, same reason, as `dump_on_deadlock`.
pub fn wantsOperatorDump(io: *const SimIo) bool {
    return io.dump_on_abort;
}

/// Take every pending op of `kind` and never deliver it (#206). Returns
/// how many were taken, so a caller can tell "I dropped the accept" from
/// "there was no accept to drop" — the difference between a scenario
/// that tested something and one that quietly tested nothing.
///
/// This is the class of defect no seed could reach before. Everything
/// else this simulator does completes: a shutdown delivers EOF to an
/// armed recv, a close delivers to the peer, a cancel lands. That is
/// faithful to io_uring, and it is why a readiness backend's "accepted
/// but never delivered" went unfound by four million nightly seeds and
/// was caught twice in thirteen runs by a shared macOS runner (#203).
///
/// Deliberately *pending* ops rather than the next one enqueued: what
/// #203 needs is an op that was armed and then had its completion taken
/// away, which is what a cancel that does not deliver looks like from
/// above. Marking at enqueue would model a different thing — a backend
/// that refuses work — and that one already has a name (`Unexpected`).
pub fn dropPendingOps(io: *SimIo, kind: OpKind) u32 {
    assert(kind != .none);
    var dropped: u32 = 0;
    for (io.pending[0..io.pending_count]) |completion| {
        if (completion.op != kind) continue;
        if (completion.dropped) continue;
        completion.dropped = true;
        dropped += 1;
    }
    // Into the trace, so a run that dropped a different number of ops
    // cannot hash equal to one that dropped this many.
    io.mix(@intFromEnum(kind));
    io.mix(dropped);
    return dropped;
}

/// #206's other ask: no slot may be released while an op still
/// references it. Every ordinary use of a handle goes through
/// `socketEntry`, which asserts the entry is still acquired and its
/// generation still matches, so a stale handle in the data path panics
/// where it is used. A *dropped* op never reaches that check — it is
/// never delivered — and a stranded seed is exactly where a slot freed
/// under a live reference would go unseen. So ask the pending table
/// directly rather than waiting for a use that will never come.
///
/// Only the four kinds naming an already-open socket can be checked.
/// `accept` names a listener, `connect` a socket that does not exist
/// until it completes, the two cancels name another completion, and
/// `log_write` and `timer` name no socket at all.
///
/// Enumerated rather than defaulted, like every other correctness switch
/// over `op` here (`opReady`, the `Result` construction) and unlike the
/// single-kind filters that may safely say `else`. This one is a §5
/// corruption oracle: a socket-bearing kind added later must fail to
/// compile until someone decides whether it belongs, not slip through an
/// `else => continue` and shrink what the oracle covers in silence.
pub fn pendingOpsReferenceLiveSockets(io: *const SimIo) bool {
    assert(io.pending_count <= pending_ops_max);
    for (io.pending[0..io.pending_count]) |completion| {
        const socket = switch (completion.op) {
            .recv => |op| op.socket,
            .recv_group => |op| op.socket,
            .send => |op| op.socket,
            .close => |op| op.socket,
            .none,
            .accept,
            .connect,
            .log_write,
            .timer,
            .timer_cancel,
            .connect_cancel,
            => continue,
        };
        assert(socket.index < sockets_max);
        const entry = &io.sockets.slots[socket.index];
        if (!io.sockets.isAcquired(entry)) return false;
        if (@as(u16, @truncate(entry.generation)) != socket.generation) return false;
    }
    return true;
}

/// Schedule a signal delivery — drain is just another scheduled event (§4).
pub fn injectSignal(io: *SimIo, signal: Io.Signal) void {
    io.scheduleSignal(signal, io.now_ns_value);
}

// Fault injection (§9). A virtual socket table cannot organically fail
// where a kernel can, so every seam operation that CAN fail has an
// injector: accept (`injectAcceptError`), connect (`injectConnectError`
// and the `connect_pressure_percent` knob), the data ops (the
// `kernel_pressure_percent` knob), and the option setters
// (`injectSetOptionError`). The audit behind that inventory (the ops
// deliberately left without one, because the seam contract makes their
// failure unobservable):
// - close/closeNow: XevIo swallows close errors — the fd is gone either
//   way and the callback carries no error — so there is nothing a
//   scenario could observe.
// - shutdown: returns void; XevIo asserts SUCCESS or the legal NOTCONN
//   race. A failing shutdown is an invariant violation, not an error
//   path.
// - listenerAddress: a pure table lookup on both backends.
// - timerStart: XevIo panics on a kernel timer failure (an unarmed
//   deadline is not a recoverable condition, §4); the only deliverable
//   error is Canceled, which timerCancel produces naturally.
// - listen: fails typed on both backends and is exercised directly
//   (AddressInUse/AddressUnavailable here, the rest in contract_test.zig).

/// Targeted scenario control: the next accept delivery on this listener
/// fails with error.Unexpected — the kernel-pressure (ENFILE-class) path
/// production can hit but a virtual socket table never would (§9).
pub fn injectAcceptError(io: *SimIo, listener: Listener) void {
    assert(listener.index < io.listeners_count);
    const entry = &io.listeners[listener.index];
    assert(entry.active);
    assert(entry.pending_accept_errors < std.math.maxInt(u8));
    entry.pending_accept_errors += 1;
}

/// Targeted scenario control: the next connect to this address fails
/// with error.Unexpected — the dial-time kernel-pressure path
/// (ENFILE/EADDRNOTAVAIL-class, §8) production can hit but a virtual
/// socket table never would (§9). One-shot, unlike `blackholeAddress`,
/// so a scenario can fail one dial and let the retry through.
pub fn injectConnectError(io: *SimIo, address: std.Io.net.IpAddress) void {
    assert(io.connect_error_count < connect_error_addresses_max);
    io.connect_error_addresses[io.connect_error_count] = address;
    io.connect_error_count += 1;
}

/// The classified cause of the op currently being delivered (§8) — the
/// seam contract `Server.witnessKernelPressure` reads. Production learns
/// this from the kernel's errno; a virtual socket table has none, so the
/// scenario states the cause it is simulating and this reports it back.
///
/// Valid only inside the callback for the failure it describes, exactly as
/// on XevIo: every fault site records immediately before returning its
/// error, and anything reading it later sees the previous failure's answer
/// rather than an absent one. A fault site that forgets to record is the
/// specific bug this warning is about — the accept path shipped that way
/// once, reporting whatever the last unrelated op had left behind.
pub fn lastPressure(io: *const SimIo) Io.Pressure {
    return io.last_pressure;
}

/// Stamp the scenario's chosen cause onto the failure being delivered.
/// The errno is 0 because there is no kernel here to have produced one —
/// which is exactly what a `.errno` of 0 is defined to mean, so the sim
/// does not have to invent a plausible number.
fn recordPressure(io: *SimIo) void {
    io.last_pressure = .{ .cause = io.pressure_cause, .errno = 0 };
}

/// Scenario control: which cause the next injected failures report.
pub fn setPressureCause(io: *SimIo, cause: Io.Pressure.Cause) void {
    io.pressure_cause = cause;
}

/// Targeted scenario control: the next `setNodelay`/`setLingerRst` fails
/// with error.Unexpected — the kernel-pressure path on a socket option,
/// which production can hit (ENOBUFS-class, process-wide) and a virtual
/// socket table never would (§9).
pub fn injectSetOptionError(io: *SimIo) void {
    assert(io.pending_set_option_errors < std.math.maxInt(u8));
    io.pending_set_option_errors += 1;
}

pub fn scheduleSignal(io: *SimIo, signal: Io.Signal, at_ns: u64) void {
    assert(io.pending_signals_count < pending_signals_max);
    assert(at_ns >= io.now_ns_value);
    // A signal with no waiter can never be delivered: deliverDueSignals
    // would skip it while it still blocks the clean-exit return and pins
    // earliestWakeNs, tripping the wake assert in run() far from here.
    // Fail at the misuse site instead (the Server arms its waiter in
    // start(), so this holds in-tree).
    assert(io.signal_callback != null);
    io.pending_signals[io.pending_signals_count] = .{ .signal = signal, .at_ns = at_ns };
    io.pending_signals_count += 1;
}

/// Runs until every pending op has delivered, `stop` is called, or
/// nothing can ever become ready (Deadlock — a liveness bug, §9).
pub fn run(io: *SimIo) Io.RunError!void {
    io.stopped = false;
    // Hoisted out of the loop: collectReady overwrites the prefix it
    // returns, so the undefined init is never observed, and a ~32 KiB
    // buffer need not be re-stacked (and Debug-0xAA-filled) each tick.
    var ready_buffer: [pending_ops_max]*Completion = undefined;
    while (!io.stopped) {
        io.deliverDueSignals();
        const ready = io.collectReady(&ready_buffer);
        if (ready.len == 0) {
            if (io.pending_count == 0 and io.pending_signals_count == 0) {
                io.reclaimRacedSockets();
                return;
            }
            const wake_ns = io.earliestWakeNs();
            if (wake_ns == never_ns) {
                if (io.dump_on_deadlock) {
                    io.dumpPendingOps();
                }
                return error.Deadlock;
            }
            assert(wake_ns > io.now_ns_value);
            io.now_ns_value = wake_ns + io.prng.random().uintAtMost(u64, jitter_ns_max);
            continue;
        }
        io.deliverBatch(ready);
        io.maybeInjectReset();
        io.maybeInjectKernelPressure();
    }
    // The loop was stopped (a completed drain). What is already *ready*
    // still delivers, with the virtual clock frozen so nothing new
    // becomes due. In production these effects live kernel-side — the
    // peer of a socket the drain closed observes its FIN/RST whether or
    // not this process takes another tick — but the simulator's peers
    // observe through delivery, so cutting them off at stop() would
    // strand exactly the observations production guarantees. The server
    // is quiescent by stop's precondition (§8: every pool released,
    // every op delivered), so this settles harness actors only; the
    // adversary stays out of a world that is no longer running.
    var flush_passes: u32 = 0;
    while (true) : (flush_passes += 1) {
        // Each pass retires pending ops; a harness that keeps
        // generating fresh ready work under a frozen clock is a
        // liveness bug, not a schedule (§9).
        assert(flush_passes <= pending_ops_max);
        const ready = io.collectReady(&ready_buffer);
        if (ready.len == 0) break;
        io.deliverBatch(ready);
    }
    // A raced accept whose CQE beat the listener close but was never
    // delivered before stop() is an accepted-but-unshed fd — reclaimed
    // at process exit in production, so model that here rather than
    // flagging it as an operational leak.
    io.reclaimRacedSockets();
}

fn reclaimRacedSockets(io: *SimIo) void {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        if (entry.raced_socket) |socket| {
            entry.raced_socket = null;
            io.closeEntry(socket);
        }
    }
}

/// Deadlock forensics: what is stuck, on which socket, in which state.
fn dumpPendingOps(io: *const SimIo) void {
    std.debug.print("SimIo deadlock: {d} pending op(s) can never become ready\n", .{
        io.pending_count,
    });
    for (io.pending[0..io.pending_count]) |completion| {
        // A dropped op is stuck because the scenario asked for it. Saying
        // so is what keeps this dump readable: without it, a deliberate
        // hang and a liveness bug print identically, and the forensics
        // exist precisely to tell them apart.
        if (completion.dropped) std.debug.print("  [dropped]", .{});
        switch (completion.op) {
            .recv => |op| std.debug.print(
                "  recv socket={d} gen={d}\n",
                .{ op.socket.index, op.socket.generation },
            ),
            .recv_group => |op| std.debug.print(
                "  recv_group socket={d} gen={d}\n",
                .{ op.socket.index, op.socket.generation },
            ),
            .send => |op| std.debug.print(
                "  send socket={d} gen={d} len={d}\n",
                .{ op.socket.index, op.socket.generation, op.bytes.len },
            ),
            .accept => |op| std.debug.print("  accept listener={d}\n", .{op.listener_index}),
            .connect => |op| std.debug.print("  connect fate={s}\n", .{@tagName(op.fate)}),
            else => std.debug.print("  {s}\n", .{@tagName(completion.op)}),
        }
    }
}

fn enqueue(io: *SimIo, completion: *Completion) void {
    assert(io.pending_count < pending_ops_max);
    assert(completion.op != .none);
    io.pending[io.pending_count] = completion;
    completion.pending_index = io.pending_count;
    completion.state = .pending;
    io.pending_count += 1;
}

fn unlink(io: *SimIo, completion: *Completion) void {
    assert(io.pending_count >= 1);
    const index = completion.pending_index;
    assert(io.pending[index] == completion);
    const last = io.pending[io.pending_count - 1];
    io.pending[index] = last;
    last.pending_index = index;
    io.pending_count -= 1;
    completion.state = .dead;
}

fn collectReady(io: *SimIo, buffer: []*Completion) []*Completion {
    assert(buffer.len >= io.pending_count);
    var count: u32 = 0;
    for (io.pending[0..io.pending_count]) |completion| {
        if (io.opReady(completion)) {
            buffer[count] = completion;
            count += 1;
        }
    }
    return buffer[0..count];
}

fn opReady(io: *SimIo, completion: *Completion) bool {
    assert(completion.state == .pending);
    // The one choke point every kind of readiness passes through, which
    // is why the drop lives here rather than in each arm: an op the
    // backend never delivers is not "not ready yet", it is never ready,
    // whatever its socket or listener goes on to do.
    if (completion.dropped) return false;
    return switch (completion.op) {
        .none => unreachable,
        .accept => |op| ready: {
            const entry = &io.listeners[op.listener_index];
            break :ready !entry.active or entry.accept_queue_len > 0 or
                entry.pending_accept_errors > 0;
        },
        .connect => |op| op.canceled or io.now_ns_value >= completion.ready_at_ns,
        .recv => |op| ready: {
            const entry = io.socketEntry(op.socket);
            break :ready entry.kernel_pressure or entry.reset or entry.inbox.count > 0 or
                entry.read_shutdown or entry.fin_received;
        },
        // Readiness is the socket's, never the group's: the kernel twin
        // waits for data with an empty group too, and reports NoBuffers
        // only when bytes actually arrive to an empty one.
        .recv_group => |op| ready: {
            const entry = io.socketEntry(op.socket);
            break :ready entry.kernel_pressure or entry.reset or entry.inbox.count > 0 or
                entry.read_shutdown or entry.fin_received;
        },
        .send => |op| ready: {
            const entry = io.socketEntry(op.socket);
            if (entry.kernel_pressure or entry.reset or
                entry.write_shutdown or entry.peer == peer_none)
            {
                break :ready true;
            }
            break :ready io.peerEntry(entry).inbox.freeSpace() > 0;
        },
        .close, .timer_cancel, .connect_cancel => true,
        // A sink that takes its time is the whole point of the staging
        // buffers (§8): while this write is out, lines pile up in the
        // other one, and the drop rung fires when they overflow it. With
        // `log_write_stall_ns` at zero the sink is instant and the rung is
        // unreachable — which is exactly how it stayed invisible before
        // the knob existed.
        .log_write => io.now_ns_value >= completion.ready_at_ns,
        .timer => |op| op.canceled or io.now_ns_value >= op.fire_at_ns,
    };
}

fn deliverBatch(io: *SimIo, ready: []*Completion) void {
    assert(ready.len >= 1);
    const random = io.prng.random();
    const cap: u32 = @intCast(@min(ready.len, io.adversary.batch_max));
    const batch_len = 1 + random.uintLessThan(u32, cap);
    random.shuffle(*Completion, ready);
    // The clock deliberately does not advance inside the batch: every
    // callback sees the same, possibly stale, now (§4).
    for (ready[0..batch_len]) |completion| {
        if (completion.state != .pending) continue;
        if (!io.opReady(completion)) continue;
        io.deliverOne(completion);
    }
}

fn deliverOne(io: *SimIo, completion: *Completion) void {
    io.unlink(completion);
    const result: Result = switch (completion.op) {
        .none => unreachable,
        .accept => |op| .{ .accept = io.finishAccept(op.listener_index) },
        .connect => |op| .{
            .connect = if (op.canceled) error.Canceled else io.finishConnect(op.address, op.fate),
        },
        .recv => |op| .{ .recv = io.finishRecv(op.socket, op.buffer) },
        .recv_group => |op| .{ .recv_group = io.finishRecvGroup(op.socket) },
        .send => |op| .{ .send = io.finishSend(op.socket, op.bytes) },
        .log_write => |op| .{ .log_write = io.finishLogWrite(op.bytes) },
        .close => |op| close: {
            io.closeEntry(op.socket);
            break :close .{ .close = {} };
        },
        .timer => |op| .{ .timer = if (op.canceled) error.Canceled else {} },
        .timer_cancel => |op| cancel: {
            if (op.target.state == .pending) {
                assert(op.target.op == .timer);
                op.target.op.timer.canceled = true;
            }
            break :cancel .{ .timer_cancel = {} };
        },
        .connect_cancel => |op| cancel: {
            if (op.target.state == .pending) {
                assert(op.target.op == .connect);
                op.target.op.connect.canceled = true;
            }
            break :cancel .{ .connect_cancel = {} };
        },
    };
    io.traceMix(completion, &result);
    completion.callback(completion.userdata, &result);
}

fn finishAccept(io: *SimIo, listener_index: u16) Io.AcceptError!Socket {
    const entry = &io.listeners[listener_index];
    if (entry.raced_socket) |socket| {
        // The drain race: this accept's CQE beat the listener close.
        entry.raced_socket = null;
        return socket;
    }
    if (!entry.active) {
        return error.Canceled;
    }
    if (entry.pending_accept_errors > 0) {
        entry.pending_accept_errors -= 1;
        io.recordPressure();
        return error.Unexpected;
    }
    assert(entry.accept_queue_len >= 1);
    const socket = entry.accept_queue[0];
    std.mem.copyForwards(
        Socket,
        entry.accept_queue[0 .. entry.accept_queue_len - 1],
        entry.accept_queue[1..entry.accept_queue_len],
    );
    entry.accept_queue_len -= 1;
    return socket;
}

fn finishConnect(
    io: *SimIo,
    address: std.Io.net.IpAddress,
    fate: ConnectFate,
) Io.ConnectError!Socket {
    assert(fate != .blackhole);
    if (fate == .pressure) {
        // Kernel pressure at dial time (§8): no virtual pair is created,
        // exactly as a failed socket()/connect submission creates no fd.
        io.recordPressure();
        return error.Unexpected;
    }
    if (fate == .refuse) {
        return error.Refused;
    }
    const listener = io.findListener(address) orelse return error.Refused;
    if (listener.accept_queue_len == accept_queue_max) {
        return error.Refused;
    }
    const client_entry = io.sockets.acquire() orelse unreachable;
    const server_entry = io.sockets.acquire() orelse unreachable;
    initSocketEntry(client_entry, io.adversary.inbox_bytes);
    initSocketEntry(server_entry, io.adversary.inbox_bytes);
    client_entry.peer = @intCast(io.sockets.indexOf(server_entry));
    server_entry.peer = @intCast(io.sockets.indexOf(client_entry));
    // Each end names the other, the way a kernel's socket pair does: the
    // dialer's peer is what it dialed, the accepted socket's peer is the
    // client that reached it. Ports climb so every simulated client is
    // distinguishable in the access log; the wrap keeps that bounded
    // rather than overflowing on a long-lived fuzz run.
    client_entry.peer_address = address;
    server_entry.peer_address = .{ .ip4 = .{
        .bytes = client_ip_bytes,
        .port = io.next_client_port,
    } };
    // Local addresses mirror the pair: each end's own address is what
    // the other end names it (§6 send's destination field).
    client_entry.local_address = server_entry.peer_address;
    server_entry.local_address = address;
    io.next_client_port = if (io.next_client_port == std.math.maxInt(u16))
        client_port_base
    else
        io.next_client_port + 1;
    listener.accept_queue[listener.accept_queue_len] = io.socketHandle(server_entry);
    listener.accept_queue_len += 1;
    return io.socketHandle(client_entry);
}

fn finishRecv(io: *SimIo, socket: Socket, buffer: []u8) Io.RecvError!u32 {
    const entry = io.socketEntry(socket);
    if (entry.kernel_pressure) {
        // Transient op failure: consume the flag, leave the socket usable.
        entry.kernel_pressure = false;
        io.recordPressure();
        return error.Unexpected;
    }
    if (entry.reset) {
        return error.Reset;
    }
    if (entry.inbox.count > 0 and !entry.read_shutdown) {
        const available: u32 = @min(@as(u32, @intCast(buffer.len)), entry.inbox.count);
        const n = io.partialLen(available);
        const popped = entry.inbox.pop(buffer[0..n]);
        assert(popped == n);
        assert(n >= 1);
        return n;
    }
    assert(entry.read_shutdown or entry.fin_received);
    return error.EndOfStream;
}

/// `finishRecv` with the buffer bound at delivery instead of at arm — the
/// order of the checks is the contract: reset and EOF outrank selection,
/// so a dying socket never consumes a buffer (the kernel behaves the same;
/// the fork's test pins it).
fn finishRecvGroup(io: *SimIo, socket: Socket) Io.RecvGroupError!Io.GroupRecv {
    const entry = io.socketEntry(socket);
    if (entry.kernel_pressure) {
        // Transient op failure: consume the flag, leave the socket usable.
        entry.kernel_pressure = false;
        io.recordPressure();
        return error.Unexpected;
    }
    if (entry.reset) {
        return error.Reset;
    }
    if (entry.inbox.count > 0 and !entry.read_shutdown) {
        const buffer_id = io.groupPickFree() orelse return error.NoBuffers;
        const buffer = io.bufferGroupSlice(buffer_id);
        const available: u32 = @min(@as(u32, @intCast(buffer.len)), entry.inbox.count);
        const n = io.partialLen(available);
        const popped = entry.inbox.pop(buffer[0..n]);
        assert(popped == n);
        assert(n >= 1);
        return .{ .len = n, .buffer_id = buffer_id };
    }
    assert(entry.read_shutdown or entry.fin_received);
    return error.EndOfStream;
}

/// Lowest free id, or null on exhaustion. Lowest rather than random on
/// purpose: buffer assignment stays a pure function of the seed's
/// schedule, so it cannot fork a trace on its own.
fn groupPickFree(io: *SimIo) ?u16 {
    assert(io.group_in_use <= io.group_count);
    for (io.group_free, 0..) |free, index| {
        if (free) {
            io.group_free[index] = false;
            io.group_in_use += 1;
            assert(io.group_in_use <= io.group_count);
            return @intCast(index);
        }
    }
    assert(io.group_in_use == io.group_count);
    return null;
}

fn finishSend(io: *SimIo, socket: Socket, bytes: []const u8) Io.SendError!u32 {
    const entry = io.socketEntry(socket);
    if (entry.kernel_pressure) {
        // Transient op failure: consume the flag, leave the socket usable.
        entry.kernel_pressure = false;
        io.recordPressure();
        return error.Unexpected;
    }
    if (entry.reset) {
        return error.Reset;
    }
    if (entry.write_shutdown) {
        // A send that was already in flight when the teardown shut the
        // write side down (§5: shutdown flushes pending ops); the kernel
        // answers EPIPE. That is the peer being gone, not the kernel being
        // short of anything — `error.Reset`, matching what XevIo maps
        // `BrokenPipe` to.
        return error.Reset;
    }
    if (entry.peer == peer_none) {
        // The peer fully closed: real TCP answers a send with RST.
        entry.reset = true;
        return error.Reset;
    }
    const peer = io.peerEntry(entry);
    const free = peer.inbox.freeSpace();
    assert(free >= 1);
    const wanted: u32 = @min(@as(u32, @intCast(bytes.len)), free);
    const n = io.partialLen(wanted);
    const pushed = peer.inbox.push(bytes[0..n]);
    assert(pushed == n);
    assert(n >= 1);
    return n;
}

/// Append to the virtual sink, short-writing like any other op (§9). The
/// overflow branch is not a modeled behavior — it is the harness's tripwire
/// for a scenario that outgrew `sink_bytes_max`, counted rather than
/// asserted here so the failure is reported by the oracle that noticed the
/// log was incomplete, not by a panic inside the backend.
fn finishLogWrite(io: *SimIo, bytes: []const u8) Io.LogWriteError!u32 {
    assert(bytes.len >= 1);
    if (io.pending_log_write_errors > 0) {
        io.pending_log_write_errors -= 1;
        return error.Unexpected;
    }
    const free: u32 = @intCast(io.sink.len - io.sink_len);
    const wanted: u32 = @min(@as(u32, @intCast(bytes.len)), free);
    if (wanted == 0) {
        io.sink_overflow_bytes += @intCast(bytes.len);
        // A sink with no room still has to make progress, or the server's
        // staging buffer never drains and the run deadlocks on a pending
        // flush. Report the whole write as accepted and count what was lost.
        return @intCast(bytes.len);
    }
    const n = io.partialLen(wanted);
    @memcpy(io.sink[io.sink_len..][0..n], bytes[0..n]);
    io.sink_len += n;
    assert(io.sink_len <= io.sink.len);
    assert(n >= 1);
    return n;
}

fn deliverDueSignals(io: *SimIo) void {
    if (io.signal_callback == null) return;
    var index: u8 = 0;
    while (index < io.pending_signals_count) {
        const pending_signal = io.pending_signals[index];
        if (pending_signal.at_ns <= io.now_ns_value) {
            io.pending_signals[index] = io.pending_signals[io.pending_signals_count - 1];
            io.pending_signals_count -= 1;
            io.mix(@as(u64, @intFromEnum(pending_signal.signal)) +% 0x5349474e);
            io.signal_callback.?(io.signal_userdata, pending_signal.signal);
        } else {
            index += 1;
        }
    }
}

fn earliestWakeNs(io: *const SimIo) u64 {
    var earliest: u64 = never_ns;
    for (io.pending[0..io.pending_count]) |completion| {
        // A dropped op wakes nothing. Only the three kinds below schedule
        // at all, so a dropped accept or recv was already inert here —
        // but a dropped connect or timer still carries the deadline it
        // was armed with, and honouring it would advance the clock for a
        // completion `opReady` then refuses to deliver.
        const wake = if (completion.dropped) never_ns else switch (completion.op) {
            .connect, .log_write => completion.ready_at_ns,
            .timer => |op| op.fire_at_ns,
            else => never_ns,
        };
        earliest = @min(earliest, wake);
    }
    for (io.pending_signals[0..io.pending_signals_count]) |pending_signal| {
        earliest = @min(earliest, pending_signal.at_ns);
    }
    return earliest;
}

/// Rolls `percent` against the adversary's dice and, on a hit, probes up
/// to 8 random socket-table indices for a live connected one, mixing
/// `mix_seed` with the winning index into the trace hash. Returns the
/// entry found, or null on a miss, an empty table, or an unlucky probe.
/// Shared by `maybeInjectReset` and `maybeInjectKernelPressure` so a
/// change to the probe bound or the liveness check cannot land in one and
/// miss the other.
fn pickRandomLiveConnectedSocket(io: *SimIo, percent: u8, mix_seed: u64) ?*SocketEntry {
    if (percent == 0) return null;
    const random = io.prng.random();
    if (random.uintLessThan(u8, 100) >= percent) return null;
    if (io.sockets.acquired_count == 0) return null;

    var probe: u8 = 0;
    while (probe < 8) : (probe += 1) {
        const index = random.uintLessThan(u16, sockets_max);
        const entry = &io.sockets.slots[index];
        if (io.sockets.isAcquired(entry) and entry.peer != peer_none) {
            io.mix(@as(u64, index) +% mix_seed);
            assert(io.sockets.isAcquired(entry) and entry.peer != peer_none);
            return entry;
        }
    }
    return null;
}

fn maybeInjectReset(io: *SimIo) void {
    const entry = io.pickRandomLiveConnectedSocket(io.adversary.reset_percent, 0x52535421) orelse return;
    entry.reset = true;
    io.peerEntry(entry).reset = true;
}

/// §8 kernel-pressure rung on the data path: flag one random live
/// socket's next recv/send to fail with `error.Unexpected` (ENOBUFS/
/// ENOMEM-class). Unlike a reset it is local and one-shot — only the
/// picked socket's next op fails, the peer is untouched — so the relay
/// witnesses it and tears the connection down.
fn maybeInjectKernelPressure(io: *SimIo) void {
    const mix_seed_enob: u64 = 0x454e4f42; // "ENOB"
    const entry = io.pickRandomLiveConnectedSocket(io.adversary.kernel_pressure_percent, mix_seed_enob) orelse return;
    entry.kernel_pressure = true;
}

fn partialLen(io: *SimIo, available: u32) u32 {
    assert(available >= 1);
    if (!io.adversary.partial_io) return available;
    const random = io.prng.random();
    return switch (random.uintLessThan(u8, 4)) {
        0 => 1,
        1, 2 => available,
        else => 1 + random.uintLessThan(u32, available),
    };
}

fn socketEntry(io: *SimIo, socket: Socket) *SocketEntry {
    assert(socket.index < sockets_max);
    const entry = &io.sockets.slots[socket.index];
    assert(io.sockets.isAcquired(entry));
    assert(@as(u16, @truncate(entry.generation)) == socket.generation);
    return entry;
}

fn peerEntry(io: *SimIo, entry: *const SocketEntry) *SocketEntry {
    assert(entry.peer != peer_none);
    assert(entry.peer < sockets_max);
    const peer = &io.sockets.slots[entry.peer];
    assert(io.sockets.isAcquired(peer));
    return peer;
}

fn socketHandle(io: *SimIo, entry: *SocketEntry) Socket {
    return .{
        .index = @intCast(io.sockets.indexOf(entry)),
        .generation = @truncate(entry.generation),
    };
}

/// Consume a pending one-shot dial fault for this address, if any.
fn takeConnectError(io: *SimIo, address: std.Io.net.IpAddress) bool {
    assert(io.connect_error_count <= connect_error_addresses_max);
    for (io.connect_error_addresses[0..io.connect_error_count], 0..) |pending, index| {
        if (std.meta.eql(pending, address)) {
            assert(io.connect_error_count >= 1);
            io.connect_error_addresses[index] =
                io.connect_error_addresses[io.connect_error_count - 1];
            io.connect_error_count -= 1;
            return true;
        }
    }
    return false;
}

fn isBlackholed(io: *const SimIo, address: std.Io.net.IpAddress) bool {
    for (io.blackholed_addresses[0..io.blackholed_count]) |blackholed| {
        if (std.meta.eql(blackholed, address)) {
            return true;
        }
    }
    return false;
}

fn findListener(io: *SimIo, address: std.Io.net.IpAddress) ?*ListenerEntry {
    for (io.listeners[0..io.listeners_count]) |*entry| {
        if (entry.active and std.meta.eql(entry.address, address)) {
            return entry;
        }
    }
    return null;
}

fn initSocketEntry(entry: *SocketEntry, inbox_capacity: u32) void {
    assert(inbox_capacity >= 1);
    assert(inbox_capacity <= inbox_bytes_max);
    entry.peer = peer_none;
    entry.fin_received = false;
    entry.read_shutdown = false;
    entry.write_shutdown = false;
    entry.reset = false;
    entry.kernel_pressure = false;
    entry.linger_rst = false;
    entry.nodelay = false;
    entry.inbox.head = 0;
    entry.inbox.count = 0;
    entry.inbox.capacity = inbox_capacity;
    // Overwritten by `finishConnect` for both ends of every pair it makes;
    // the placeholder keeps a socket that somehow skipped that from
    // reporting another connection's peer out of a recycled slot.
    entry.peer_address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
    entry.local_address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } };
}

fn closeEntry(io: *SimIo, socket: Socket) void {
    const entry = io.socketEntry(socket);
    if (entry.peer != peer_none) {
        const peer = io.peerEntry(entry);
        // Unread inbox data or SO_LINGER-0 means the peer sees a reset,
        // exactly as real TCP behaves; otherwise an orderly FIN.
        if (entry.linger_rst or entry.inbox.count > 0) {
            peer.reset = true;
        } else {
            peer.fin_received = true;
        }
        peer.peer = peer_none;
    }
    io.sockets.release(entry);
}

fn closeEntryWithReset(io: *SimIo, socket: Socket) void {
    const entry = io.socketEntry(socket);
    entry.linger_rst = true;
    io.closeEntry(socket);
}

/// Deliveries of one op kind so far this run (§9).
pub fn deliveredCount(io: *const SimIo, kind: OpKind) u64 {
    assert(kind != .none);
    return io.delivered[@intFromEnum(kind)];
}

fn traceMix(io: *SimIo, completion: *const Completion, result: *const Result) void {
    // Every delivery funnels through here, which is what makes one
    // increment enough to count them all.
    assert(completion.op != .none);
    io.delivered[@intFromEnum(completion.op)] += 1;
    io.mix(@intFromEnum(completion.op));
    io.mix(@intFromEnum(result.*));
    const detail: u64 = switch (result.*) {
        .recv => |r| if (r) |n| n else |err| 1000 + @intFromError(err),
        // Both halves matter to a trace: the same bytes landing in a
        // different buffer is a different schedule.
        .recv_group => |r| if (r) |g|
            (@as(u64, g.buffer_id) << 32) | g.len
        else |err|
            11000 + @intFromError(err),
        .send => |r| if (r) |n| n else |err| 2000 + @intFromError(err),
        .accept => |r| if (r) |s| @as(u32, @bitCast(s)) else |err| 3000 + @intFromError(err),
        .connect => |r| if (r) |s| @as(u32, @bitCast(s)) else |err| 4000 + @intFromError(err),
        .timer => |r| if (r) |_| 5000 else |err| 5001 + @intFromError(err),
        .close => 6000,
        .timer_cancel => 7000,
        .connect_cancel => 8000,
        .log_write => |r| if (r) |n| 9000 + @as(u64, n) else |err| 10000 + @intFromError(err),
    };
    io.mix(detail);
}

fn mix(io: *SimIo, value: u64) void {
    // Fold each delivery into the run's trace hash. std's FNV-1a owns the
    // constants so a mistyped prime/basis can't silently degrade mixing;
    // the hash only ever compares a seed against itself, so the byte order
    // is immaterial.
    var hasher = std.hash.Fnv1a_64{ .value = io.trace_hash };
    hasher.update(std.mem.asBytes(&value));
    io.trace_hash = hasher.value;
}
