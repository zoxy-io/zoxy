//! zoxy startup (DESIGN.md §5, §8): read config into the arena (the only
//! allocating region), resolve it, verify the fd budget against
//! RLIMIT_NOFILE, print the closed-form budgets, install signal handlers
//! (the only raw syscall surface outside src/io/, held to the rlimit and
//! sigaction allowlist by lint), then hand the process to the event loop
//! until a drain completes.

const std = @import("std");

const zoxy = @import("zoxy");

const XevIo = zoxy.Io.XevIo;
const ServerXev = zoxy.Server(XevIo);

const assert = std.debug.assert;

/// The sigaction handler needs a stable address before main returns;
/// the loop lives for the whole process (§3).
var global_io: XevIo = undefined;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 2) {
        std.debug.print("usage: zoxy <config.json>\n", .{});
        return error.InvalidArguments;
    }

    const config_bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[1],
        arena,
        .limited(zoxy.constants.config_bytes_max),
    ) catch |err| {
        std.debug.print("zoxy: cannot read config '{s}': {t}\n", .{ args[1], err });
        return err;
    };
    const config = zoxy.config.parse(arena, config_bytes) catch |err| {
        std.debug.print("zoxy: invalid config '{s}': {t}\n", .{ args[1], err });
        return err;
    };

    try ensureFdBudget();
    try printBudgets(init.io, &config);

    try global_io.init(arena);
    var server: ServerXev = undefined;
    try server.init(arena, &global_io, &config, config.limits);
    try server.start();
    installSignalHandlers();

    try global_io.run();

    // The loop only stops after a completed drain (§8).
    assert(server.isIdle());
    server.counters.dump();
}

/// fds are pre-budgeted, not shed (§8): raise the soft limit up to the
/// hard limit, and refuse to start if even that cannot cover the budget.
fn ensureFdBudget() !void {
    const fds_max: u64 = zoxy.constants.fds_max;
    var limits = try std.posix.getrlimit(.NOFILE);
    if (limits.cur >= fds_max) return;
    if (limits.max < fds_max) {
        std.debug.print(
            "zoxy: RLIMIT_NOFILE hard limit {d} is below the fd budget {d} (§8)\n",
            .{ limits.max, fds_max },
        );
        return error.FdBudgetUnsatisfiable;
    }
    limits.cur = fds_max;
    try std.posix.setrlimit(.NOFILE, limits);
}

fn printBudgets(io: std.Io, config: *const zoxy.config.Config) !void {
    const constants = zoxy.constants;
    const UpstreamType = zoxy.UpstreamPool(XevIo).Upstream;
    // Pool memory reflects the *effective* limits (config may shrink the
    // pools below the comptime ceilings, §5); fds and ring stay the
    // comptime worst-case budgets — the asserted ceilings.
    const limits = config.limits;
    const memory_total = constants.memoryBytesTotal(
        limits.conn_slots,
        @sizeOf(ServerXev.ConnType),
        limits.relay_buffers,
        @sizeOf(zoxy.RelayBuffer),
        limits.upstream_slots,
        @sizeOf(UpstreamType),
    );
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print(
        \\zoxy budgets (closed-form, DESIGN.md §5/§8):
        \\  memory  pools {d} KiB = conn slots {d} x {d} B + relay buffers {d} x {d} B
        \\          + upstream slots {d} x {d} B
        \\  fds     {d} worst case (asserted against RLIMIT_NOFILE)
        \\  ring    {d} entries, completion queue {d}, in-flight ops <= {d}
        \\  config  {d} listener(s), {d} cluster(s)
        \\
    , .{
        memory_total / 1024,
        limits.conn_slots,
        @sizeOf(ServerXev.ConnType),
        limits.relay_buffers,
        @sizeOf(zoxy.RelayBuffer),
        limits.upstream_slots,
        @sizeOf(UpstreamType),
        constants.fds_max,
        constants.ring_entries,
        constants.completion_queue_entries,
        constants.in_flight_ops_max,
        config.listeners.len,
        config.clusters.len,
    });
    try writer.flush();
}

fn installSignalHandlers() void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onRawSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &action, null);
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.USR1, &action, null);
}

/// Async-signal-safe: delegates to the seam's atomic-mask + eventfd wake
/// (§4); nothing else is legal here.
fn onRawSignal(signal_number: std.posix.SIG) callconv(.c) void {
    const signal: zoxy.Io.Signal = switch (signal_number) {
        .TERM, .INT => .terminate,
        .USR1 => .dump_counters,
        else => return,
    };
    global_io.notifySignalFromHandler(signal);
}
