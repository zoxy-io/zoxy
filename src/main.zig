//! zoxy startup (DESIGN.md §5, §8): read config into the arena (the only
//! allocating region), resolve it, verify the fd budget against
//! RLIMIT_NOFILE, print the budgets, install signal handlers
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

/// What this build is, when the version alone does not say it.
///
/// A release binary is built at its tag, so `git describe` returns exactly
/// `v<version>` and repeating it would be noise — that case reports the
/// bare version. Every other build is the reason this exists: one made
/// from `main` after a release otherwise claims the release's version
/// string, which is not merely vague but false. There the suffix carries
/// the distance and commit (`v0.0.7-5-gabc1234`), and `-dirty` when the
/// tree had uncommitted changes, which no binary can otherwise be asked.
///
/// Empty when the build could not tell — no `.git`, no `-Dbuild-id` — and
/// an unknown build says nothing rather than guessing.
const build_id_suffix: []const u8 = buildIdSuffix(build_options.version, build_options.build_id);

/// The suffix itself, as a function of the two strings, so the three cases
/// it decides between are testable rather than only observable by building
/// at a tag and not at one.
fn buildIdSuffix(comptime version: []const u8, comptime id: []const u8) []const u8 {
    // The same invariant the module-level block guards, restated where the
    // `"v" ++ version` comparison below depends on it.
    assert(version.len > 0);
    if (id.len == 0) return "";
    // `describe` spells the *tag*, which carries the `v` the version does
    // not; both spellings name the same build as the version already does.
    // Full equality, not a prefix test: `0.0.70` must not be swallowed by
    // a build whose version is `0.0.7`.
    if (comptime std.mem.eql(u8, id, "v" ++ version)) return "";
    if (comptime std.mem.eql(u8, id, version)) return "";
    const suffix = " (" ++ id ++ ")";
    // Whatever it reports, it appends to a version rather than replacing
    // one, so it always starts with the separating space.
    assert(suffix[0] == ' ');
    return suffix;
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

    // Measured across the read, not assumed from the file size: the
    // parse allocates its own structures beside the text it parses, and
    // both live in the arena for the process's life (§5).
    const arena_before = init.arena.queryCapacity();
    const config = try readConfig(init.io, arena, config_path);
    const config_arena_bytes = init.arena.queryCapacity() - arena_before;

    const cq_entries = try resolveBudgets(&config, config_arena_bytes);
    const log_sink_fd = try openLogSinkFd(&config);

    // The ring is the config's to size (§5), count and unit both;
    // Server.init asserts its own accounting against the same numbers.
    try global_io.init(
        arena,
        cq_entries,
        @intCast(config.listeners.len),
        config.limits.head_buffers,
        config.limits.head_buffer_bytes,
        log_sink_fd,
        // The path rides beside its fd so SIGHUP can reopen it (§8).
        if (config.access_log_sink) |sink| switch (sink) {
            .stdout => null,
            .file => |path| path,
        } else null,
    );
    var server: ServerXev = undefined;
    try server.init(arena, &global_io, &config, config.limits);
    try server.start();
    installSignalHandlers();

    try global_io.run();

    // The loop only stops after a completed drain (§8).
    assert(server.isIdle());
    server.dumpMetrics();
}

/// The §5/§8 startup budget gauntlet: fds and the ring are sized to the
/// *effective* config, not the compiled ceilings — a lean deployment
/// neither demands the c10k RLIMIT_NOFILE nor asks the kernel for a
/// 65536-deep ring. Derives both demands, raises RLIMIT_NOFILE to the
/// fd one, prints the banner, and returns the CQ depth the ring must be
/// created with.
fn resolveBudgets(
    config: *const zoxy.config.Config,
    config_arena_bytes: u64,
) !u32 {
    const listeners_count: u32 = @intCast(config.listeners.len);
    assert(listeners_count >= 1);
    const access_log_files: u32 = if (config.access_log_sink) |sink|
        @intFromBool(sink == .file)
    else
        0;
    const fds_required = zoxy.constants.fdsRequired(
        config.limits.conn_slots,
        config.limits.upstream_slots,
        listeners_count,
        access_log_files,
    );
    const cq_entries = zoxy.constants.completionQueueDepthFor(
        config.limits.conn_slots,
        config.limits.upstream_slots,
        listeners_count,
        config.limits.cq_fill_eighths,
    );
    // The effective config never exceeds the compiled ceilings (§8): the
    // pools, the ring, and the fd demand all fit what the constants proved.
    assert(cq_entries <= zoxy.constants.completion_queue_entries);
    try ensureFdBudget(fds_required);
    printBudgets(config, fds_required, cq_entries, config_arena_bytes);
    return cq_entries;
}

/// The §8 access-log sink as the fd `XevIo` will write: the inherited
/// stdout, or the file the config named — opened here, before the loop
/// exists, so a path that cannot open stops the process while the banner
/// above still names what it tried. The seam owns the syscall
/// (`XevIo.openLogSink`); the error report is this caller's, because the
/// path is the operator's own text.
fn openLogSinkFd(config: *const zoxy.config.Config) !@TypeOf(XevIo.log_sink_stdout) {
    const sink = config.access_log_sink orelse return XevIo.log_sink_stdout;
    switch (sink) {
        .stdout => return XevIo.log_sink_stdout,
        .file => |path| {
            // The loader rejected an empty path at parse (§8), so a
            // failure here is the filesystem's answer, not a config shape.
            assert(path.len >= 1);
            return XevIo.openLogSink(path) catch |err| {
                std.debug.print("zoxy: cannot open access log '{s}': {t}\n", .{ path, err });
                return err;
            };
        },
    }
}

/// Read and parse the config file, or say on stderr why it cannot be.
///
/// The read is deliberately unlimited. The config is operator-provided
/// at startup rather than attacker-controlled input, and its size is now
/// the operator's own statement of how much startup arena this
/// deployment should cost (§5) — there is no constant left to check it
/// against, and none that could be justified.
///
/// What that trades away is worth stating plainly: a fixed cap failed a
/// too-large file deterministically, and this does not. The arena runs
/// over `std.heap.page_allocator`, so under Linux's default heuristic
/// overcommit a large request can succeed at `mmap` and only fail as the
/// read faults pages in — where the kernel's OOM killer, not a returned
/// `OutOfMemory`, is what intervenes. The guarantee is therefore "the
/// operator is told what their config cost" (the caller measures the
/// arena across this call and the startup banner prints it), not "an
/// oversized config is refused cleanly".
fn readConfig(
    io: std.Io,
    arena: std.mem.Allocator,
    config_path: []const u8,
) !zoxy.config.Config {
    assert(config_path.len >= 1);
    const config_bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        config_path,
        arena,
        .unlimited,
    ) catch |err| {
        std.debug.print("zoxy: cannot read config '{s}': {t}\n", .{ config_path, err });
        return err;
    };
    // Body files (#159) are read through the loader's seam by the same
    // startup-time reader the config file itself used — the one moment
    // this process touches the filesystem for content (parse-once, §1).
    var file_context: BodyFileContext = .{ .io = io };
    return zoxy.config.parseWithFiles(arena, config_bytes, .{
        .context = &file_context,
        .read = readBodyFile,
    }) catch |err| {
        std.debug.print("zoxy: invalid config '{s}': {t}\n", .{ config_path, err });
        return err;
    };
}

const BodyFileContext = struct {
    io: std.Io,
};

/// The loader's `FileSource.read` against the real filesystem: whole
/// file into the arena, refused past `limit` — the loader turns that
/// into the same verdict an oversized inline body earns.
fn readBodyFile(
    context: ?*anyopaque,
    arena: std.mem.Allocator,
    path: []const u8,
    limit: u32,
) error{ FileUnreadable, FileTooLarge, OutOfMemory }![]const u8 {
    assert(path.len >= 1);
    assert(limit >= 1);
    const body_context: *BodyFileContext = @ptrCast(@alignCast(context.?));
    return std.Io.Dir.cwd().readFileAlloc(
        body_context.io,
        path,
        arena,
        .limited(limit),
    ) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.FileTooLarge,
        else => blk: {
            // Which file and why, here where both are known: the
            // loader's error names the verdict, not the path.
            std.debug.print("zoxy: cannot read body file '{s}': {t}\n", .{ path, err });
            break :blk error.FileUnreadable;
        },
    };
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
    \\  SIGUSR1           Dump counters to stderr.
    \\  SIGHUP            Reopen the access log's file sink (rotation).
    \\                    No other meaning: config changes are a restart.
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
    try writer.print("zoxy {s}{s}\n", .{ build_options.version, build_id_suffix });
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

/// The §5 pool-size vector for the effective config — split from
/// `printBudgets` for the length limit, and so the composition reads as
/// one thing: every term the closed form takes, sourced from the limit
/// or `@sizeOf` that owns it.
fn poolSizesFor(config: *const zoxy.config.Config) zoxy.constants.PoolSizes {
    const limits = config.limits;
    const UpstreamType = zoxy.UpstreamPool(XevIo).Upstream;
    // The head-sized side buffers (§5): Server owns the closed form and
    // asserts its own allocations against it, so printing it here cannot
    // drift from what init actually reserves.
    const head_scratch_bytes = ServerXev.headScratchBytes(limits);
    assert(head_scratch_bytes >= limits.head_buffer_bytes);
    return .{
        .conn_slots = limits.conn_slots,
        .conn_bytes = @sizeOf(ServerXev.ConnType),
        .relay_buffers = limits.relay_buffers,
        .relay_buffer_pair_bytes = @sizeOf(zoxy.RelayBuffer),
        .upstream_slots = limits.upstream_slots,
        .upstream_bytes = @sizeOf(UpstreamType),
        .access_log_bytes = zoxy.constants.accessLogBytes(limits.access_log_buffer_bytes),
        .log_header_bytes = ServerXev.logHeaderBytes(config, limits.conn_slots),
        .endpoint_table_bytes = ServerXev.endpointTableBytes(config),
        .metrics_bytes = ServerXev.metricsBytes(config),
        .head_buffers = limits.head_buffers,
        .head_buffer_bytes = limits.head_buffer_bytes,
        .upstream_head_buffers = limits.upstream_head_buffers,
        // The pool element (the free-list header and the slab slice) plus
        // its share of the slab itself.
        .upstream_head_buffer_bytes = @sizeOf(zoxy.UpstreamHeadBuffer) + limits.head_buffer_bytes,
        .head_scratch_bytes = head_scratch_bytes,
    };
}

/// The §5 banner, to **stderr**: the banner is diagnostics, and stdout
/// belongs to the data an operator may point there — the access log's
/// `stdout` sink must stay one uncontaminated JSON line per event.
/// Stderr is where the counter dump already goes, and via the same
/// `std.debug.print` plain-write path, so the two interleave whole-lines
/// even when both land in one redirected file (a positional writer here
/// would be silently overwritten by the dump's shared-offset writes).
fn printBudgets(
    config: *const zoxy.config.Config,
    fds_required: u32,
    cq_entries: u32,
    /// What the config text and its parsed structures took from the
    /// startup arena, measured (§5). Not closed-form like the pools —
    /// it is whatever the operator's config file needed — which is
    /// exactly why it is reported rather than derived.
    config_arena_bytes: u64,
) void {
    const constants = zoxy.constants;
    // Every budget reflects the *effective* config (§5, §8): the config may
    // shrink the pools, the fd demand, and the requested ring below the
    // compiled ceilings, and all three are shown as actually sized.
    const limits = config.limits;
    const in_flight = constants.inFlightOps(
        limits.conn_slots,
        limits.upstream_slots,
        @intCast(config.listeners.len),
    );
    const access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes);
    const sizes = poolSizesFor(config);
    // §5's promise is that the printed total covers everything this
    // process holds for its life. The config arena qualifies — it is
    // never freed — so it joins the total even though it is the one term
    // measured rather than derived from constants.
    const memory_total = constants.memoryBytesTotal(&sizes) + config_arena_bytes;
    // A banner that could print a zero total or zero fd demand would be
    // reporting a proxy that reserved nothing — the closed form broke.
    assert(memory_total > 0);
    assert(fds_required > 0);
    printMemoryBanner(config, &sizes, memory_total, access_log_bytes, config_arena_bytes);
    std.debug.print(
        \\  fds     {d} required (asserted against RLIMIT_NOFILE)
        \\  ring    {d} entries, completion queue {d}, in-flight ops <= {d}
        \\  config  {d} listener(s), {d} cluster(s), {d} error page(s), access log {s}
        \\
    , .{
        fds_required,
        constants.ring_entries,
        cq_entries,
        in_flight,
        config.listeners.len,
        config.clusters.len,
        // Their rendered bytes live in the config arena term above —
        // read and pre-rendered at load (#159), so the measured number
        // already covers them; this count is what says why it grew.
        config.error_pages.len,
        if (config.access_log_sink) |sink| @tagName(sink) else "off",
    });
}

/// The banner's version and memory lines — the §5 closed form itemized.
/// Split from `printBudgets` for the length limit; the two prints are
/// sequential same-thread writes to stderr, so nothing interleaves.
fn printMemoryBanner(
    config: *const zoxy.config.Config,
    sizes: *const zoxy.constants.PoolSizes,
    memory_total: u64,
    access_log_bytes: u64,
    config_arena_bytes: u64,
) void {
    assert(memory_total > 0);
    assert(config.listeners.len >= 1);
    const limits = config.limits;
    // The version leads, because this banner is what a bug report pastes
    // and `--version` is what it does not think to run.
    std.debug.print(
        \\zoxy {s}{s}
        \\budgets (DESIGN.md §5/§8; closed-form except where marked):
        \\  memory  total {d} KiB = conn slots {d} x {d} B + relay buffers {d} x {d} B
        \\          + upstream slots {d} x {d} B + head buffers {d} x {d} B (+ ring {d} B)
        \\          + upstream head buffers {d} x {d} B + head scratch {d} B
        \\          + access log {d} KiB (+ logged headers {d} B)
        \\          + endpoint tables {d} B ({d} cluster(s) x {d} wide)
        \\          + labeled metrics {d} B (tables, labels and render buffers)
        \\          + config arena {d} KiB (measured, not closed-form)
        \\
    , .{
        build_options.version,
        build_id_suffix,
        memory_total / 1024,
        limits.conn_slots,
        @sizeOf(ServerXev.ConnType),
        limits.relay_buffers,
        @sizeOf(zoxy.RelayBuffer),
        limits.upstream_slots,
        sizes.upstream_bytes,
        limits.head_buffers,
        // The +1 ownership byte stays out of the banner's per-unit figure;
        // the closed-form total above carries it.
        limits.head_buffer_bytes,
        zoxy.constants.bufferGroupDescriptorBytes(limits.head_buffers),
        limits.upstream_head_buffers,
        sizes.upstream_head_buffer_bytes,
        sizes.head_scratch_bytes,
        access_log_bytes / 1024,
        sizes.log_header_bytes,
        ServerXev.endpointTableBytes(config),
        config.clusters.len,
        ServerXev.endpointKeysFor(config).stride,
        ServerXev.metricsBytes(config),
        config_arena_bytes / 1024,
    });
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
    std.posix.sigaction(.HUP, &action, null);
    // A proxy must not die because something downstream of it went away.
    // The access log writes to a pipe the operator owns (§8), and a `write`
    // to a pipe with no reader raises SIGPIPE, whose default action is to
    // terminate — an operator closing `zoxy config.json | jq` would take
    // the data path with it. Ignoring it turns that into the EPIPE the
    // sink already handles by declaring itself broken. Socket sends are
    // covered too: io_uring sets MSG_NOSIGNAL for them, but a proxy
    // relying on that for its liveness is relying on a detail of a
    // dependency's submission path.
    const ignore = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.PIPE, &ignore, null);
}

/// Async-signal-safe: delegates to the seam's atomic-mask + eventfd wake
/// (§4); nothing else is legal here.
fn onRawSignal(signal_number: std.posix.SIG) callconv(.c) void {
    const signal: zoxy.Io.Signal = switch (signal_number) {
        .TERM, .INT => .terminate,
        .USR1 => .dump_counters,
        .HUP => .reopen_log,
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

test "buildIdSuffix: a release says nothing extra, every other build says what it is" {
    // The case the whole thing exists for: built after a release, the
    // version alone would claim to *be* that release.
    try testing.expectEqualStrings(
        " (v0.0.7-5-gabc1234)",
        buildIdSuffix("0.0.7", "v0.0.7-5-gabc1234"),
    );
    // And the question a binary cannot otherwise be asked.
    try testing.expectEqualStrings(
        " (v0.0.7-5-gabc1234-dirty)",
        buildIdSuffix("0.0.7", "v0.0.7-5-gabc1234-dirty"),
    );
    // At the tag `describe` returns the tag, which is the version with a
    // `v`. Repeating it would make every release binary noisier to read
    // for no information, so both spellings collapse to nothing.
    try testing.expectEqualStrings("", buildIdSuffix("0.0.7", "v0.0.7"));
    try testing.expectEqualStrings("", buildIdSuffix("0.0.7", "0.0.7"));
    // No `.git` and no `-Dbuild-id`: an unknown build stays quiet instead
    // of inventing a provenance.
    try testing.expectEqualStrings("", buildIdSuffix("0.0.7", ""));
    // An override that is not a version at all still travels — a tarball
    // or distro build naming itself is the point of the flag.
    try testing.expectEqualStrings(" (nixpkgs-25.05)", buildIdSuffix("0.0.7", "nixpkgs-25.05"));
    // A *different* version's tag is not this build's version, so it is
    // reported rather than swallowed by the prefix match.
    try testing.expectEqualStrings(" (v0.0.6)", buildIdSuffix("0.0.7", "v0.0.6"));
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
