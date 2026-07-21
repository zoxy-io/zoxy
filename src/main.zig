//! zoxy startup (DESIGN.md §5, §8): read config into the arena (the only
//! allocating region), resolve it, verify the fd budget against
//! RLIMIT_NOFILE, print the closed-form budgets, install signal handlers
//! (the only raw syscall surface outside src/io/, held to the rlimit and
//! sigaction allowlist by lint), then hand the process to the event loop
//! until a drain completes. `--help` and `--version` are answered before any
//! of that and exit immediately.

const std = @import("std");

const zoxy = @import("zoxy");
const build_options = @import("build_options");

const XevIo = zoxy.Io.XevIo;
const ServerXev = zoxy.Server(XevIo);

const assert = std.debug.assert;

// The version is single-sourced from build.zig.zon and reaches the binary
// through the build_options module (see build.zig). Guard its one invariant —
// that it is actually present — once at comptime, rather than re-asserting a
// comptime-known truth on every --version/--help print.
comptime {
    assert(build_options.version.len > 0);
}

/// The sigaction handler needs a stable address before main returns;
/// the loop lives for the whole process (§3).
var global_io: XevIo = undefined;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    const config_path = switch (classifyArgs(args)) {
        .run => |path| path,
        .help => {
            try printHelp(init.io);
            return;
        },
        .version => {
            try printVersion(init.io);
            return;
        },
        .usage => |reason| {
            printUsageError(reason);
            return error.InvalidArguments;
        },
    };

    const config_bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        config_path,
        arena,
        .limited(zoxy.constants.config_bytes_max),
    ) catch |err| {
        std.debug.print("zoxy: cannot read config '{s}': {t}\n", .{ config_path, err });
        return err;
    };
    const config = zoxy.config.parse(arena, config_bytes) catch |err| {
        std.debug.print("zoxy: invalid config '{s}': {t}\n", .{ args[1], err });
        return err;
    };

    // fds and the ring are sized to the *effective* config, not the
    // compiled ceilings (§5, §8): a lean deployment neither demands the
    // c10k RLIMIT_NOFILE nor asks the kernel for a 65536-deep ring.
    const listeners_count: u32 = @intCast(config.listeners.len);
    const fds_required = zoxy.constants.fdsRequired(
        config.limits.conn_slots,
        config.limits.upstream_slots,
        listeners_count,
    );
    const cq_entries = zoxy.constants.completionQueueDepthFor(
        config.limits.conn_slots,
        config.limits.upstream_slots,
        listeners_count,
        config.limits.cq_fill_eighths,
    );
    // The effective config never exceeds the compiled ceilings (§8): the
    // pools, the ring, and the fd demand all fit what the constants proved.
    assert(fds_required <= zoxy.constants.fds_max);
    assert(cq_entries <= zoxy.constants.completion_queue_entries);
    try ensureFdBudget(fds_required);
    try printBudgets(init.io, &config, fds_required, cq_entries);

    try global_io.init(arena, cq_entries);
    var server: ServerXev = undefined;
    try server.init(arena, &global_io, &config, config.limits);
    try server.start();
    installSignalHandlers();

    try global_io.run();

    // The loop only stops after a completed drain (§8).
    assert(server.isIdle());
    server.counters.dump();
}

/// What the command line asked for: run against a config, or one of the
/// two informational modes, or a usage mistake (with the reason so the
/// message can be specific).
const Cli = union(enum) {
    run: []const u8,
    help,
    version,
    usage: UsageError,
};

const UsageError = enum { missing_config, extra_arguments, unknown_option };

/// Classify argv without touching the world, so it is unit-testable. zoxy
/// takes exactly one positional argument — the config path; a `--help` or
/// `--version` anywhere on the line wins so it still works appended to a
/// half-typed command.
fn classifyArgs(args: []const []const u8) Cli {
    assert(args.len >= 1); // argv always carries the program name at [0].
    for (args[1..]) |arg| {
        if (flagMatches(arg, "-h", "--help")) return .help;
    }
    for (args[1..]) |arg| {
        if (flagMatches(arg, "-V", "--version")) return .version;
    }
    if (args.len < 2) return .{ .usage = .missing_config };
    if (args.len > 2) return .{ .usage = .extra_arguments };
    const only = args[1];
    // A lone unrecognized -flag is a typo, not a file named "-x".
    if (only.len > 0 and only[0] == '-') return .{ .usage = .unknown_option };
    assert(only.len == 0 or only[0] != '-');
    return .{ .run = only };
}

fn flagMatches(arg: []const u8, short: []const u8, long: []const u8) bool {
    assert(short.len >= 2); // "-x"
    assert(long.len >= 3); // "--x"
    return std.mem.eql(u8, arg, short) or std.mem.eql(u8, arg, long);
}

const help_text =
    \\zoxy {s} — a zero-allocation L4/L7 edge proxy.
    \\
    \\Usage:
    \\  zoxy <config.json>   Start the proxy with the given JSON config.
    \\  zoxy --help, -h      Show this message and exit.
    \\  zoxy --version, -V   Print the version and exit.
    \\
    \\zoxy reads the whole config once at startup, sizes every pool and the
    \\io_uring ring from it, then serves without allocating again. The config
    \\format is documented by the JSON Schema shipped with each release and by
    \\docs/DESIGN.md.
    \\
    \\Signals:
    \\  SIGTERM, SIGINT   Drain in-flight connections, then exit 0.
    \\  SIGUSR1           Dump counters to stdout.
    \\
;

/// `--help`: the full usage text, to stdout (so `zoxy --help | less` works).
fn printHelp(io: std.Io) !void {
    // The writer drains to stdout whenever this staging buffer fills, so its
    // size is a batching choice, not a cap on the help text length.
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print(help_text, .{build_options.version});
    try writer.flush();
}

/// `--version`: the bare version line, to stdout.
fn printVersion(io: std.Io) !void {
    var buffer: [64]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try writer.print("zoxy {s}\n", .{build_options.version});
    try writer.flush();
}

/// A usage mistake: the specific reason plus a one-line reminder, to stderr.
fn printUsageError(reason: UsageError) void {
    // The switch is exhaustive over UsageError, so every reason has a message
    // and a missing arm is a compile error — no runtime guard adds anything.
    const detail = switch (reason) {
        .missing_config => "missing the required <config.json> argument",
        .extra_arguments => "too many arguments; expected exactly one <config.json>",
        .unknown_option => "unknown option; run `zoxy --help` for usage",
    };
    std.debug.print(
        "zoxy: {s}\nusage: zoxy <config.json>  (or --help, --version)\n",
        .{detail},
    );
}

/// fds are pre-budgeted, not shed (§8): raise the soft limit up to the
/// hard limit, and refuse to start if even that cannot cover the budget.
fn ensureFdBudget(fds_required: u32) !void {
    const required: u64 = fds_required;
    var limits = try std.posix.getrlimit(.NOFILE);
    if (limits.cur >= required) return;
    if (limits.max < required) {
        std.debug.print(
            "zoxy: RLIMIT_NOFILE hard limit {d} is below the fd budget {d} (§8)\n",
            .{ limits.max, required },
        );
        return error.FdBudgetUnsatisfiable;
    }
    limits.cur = required;
    try std.posix.setrlimit(.NOFILE, limits);
}

fn printBudgets(
    io: std.Io,
    config: *const zoxy.config.Config,
    fds_required: u32,
    cq_entries: u32,
) !void {
    const constants = zoxy.constants;
    const UpstreamType = zoxy.UpstreamPool(XevIo).Upstream;
    // Every budget reflects the *effective* config (§5, §8): the config may
    // shrink the pools, the fd demand, and the requested ring below the
    // compiled ceilings, and all three are shown as actually sized.
    const limits = config.limits;
    const in_flight = constants.inFlightOps(
        limits.conn_slots,
        limits.upstream_slots,
        @intCast(config.listeners.len),
    );
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
        \\  fds     {d} required (asserted against RLIMIT_NOFILE)
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
        fds_required,
        constants.ring_entries,
        cq_entries,
        in_flight,
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

const testing = std.testing;

test "classifyArgs: a single positional is the config path" {
    const args = [_][]const u8{ "zoxy", "config.json" };
    const cli = classifyArgs(&args);
    try testing.expect(cli == .run);
    try testing.expectEqualStrings("config.json", cli.run);
}

test "classifyArgs: --help and -h request help" {
    try testing.expect(classifyArgs(&.{ "zoxy", "--help" }) == .help);
    try testing.expect(classifyArgs(&.{ "zoxy", "-h" }) == .help);
}

test "classifyArgs: --version and -V request the version" {
    try testing.expect(classifyArgs(&.{ "zoxy", "--version" }) == .version);
    try testing.expect(classifyArgs(&.{ "zoxy", "-V" }) == .version);
}

test "classifyArgs: help wins over version, and both win appended to a config" {
    // A flag anywhere on the line is honored; help outranks version.
    try testing.expect(classifyArgs(&.{ "zoxy", "--version", "--help" }) == .help);
    try testing.expect(classifyArgs(&.{ "zoxy", "config.json", "--help" }) == .help);
    try testing.expect(classifyArgs(&.{ "zoxy", "config.json", "--version" }) == .version);
}

test "classifyArgs: usage mistakes carry their reason" {
    try testing.expectEqual(Cli{ .usage = .missing_config }, classifyArgs(&.{"zoxy"}));
    try testing.expectEqual(
        Cli{ .usage = .extra_arguments },
        classifyArgs(&.{ "zoxy", "a.json", "b.json" }),
    );
    try testing.expectEqual(
        Cli{ .usage = .unknown_option },
        classifyArgs(&.{ "zoxy", "--nope" }),
    );
}
