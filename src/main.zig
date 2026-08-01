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

    assert(cq_entries <= zoxy.constants.completion_queue_entries);
    try ensureFdBudget(fds_required);
    try printBudgets(init.io, &config, fds_required, cq_entries, config_arena_bytes);

    // The ring is the config's to size (§5); Server.init asserts its own
    // accounting against the same number.
    try global_io.init(
        arena,
        cq_entries,
        listeners_count,
        config.limits.head_buffers,
        zoxy.constants.head_bytes_max,
    );
    var server: ServerXev = undefined;
    try server.init(arena, &global_io, &config, config.limits);
    try server.start();
    installSignalHandlers();

    try global_io.run();

    // The loop only stops after a completed drain (§8).
    assert(server.isIdle());
    const gauges = server.gauges();
    server.counters.dump(&gauges);
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
    return zoxy.config.parse(arena, config_bytes) catch |err| {
        std.debug.print("zoxy: invalid config '{s}': {t}\n", .{ config_path, err });
        return err;
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

fn printBudgets(
    io: std.Io,
    config: *const zoxy.config.Config,
    fds_required: u32,
    cq_entries: u32,
    /// What the config text and its parsed structures took from the
    /// startup arena, measured (§5). Not closed-form like the pools —
    /// it is whatever the operator's config file needed — which is
    /// exactly why it is reported rather than derived.
    config_arena_bytes: u64,
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
    const access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes);
    const endpoint_stride = ServerXev.endpointKeysFor(config).stride;
    // §5's promise is that the printed total covers everything this
    // process holds for its life. The config arena qualifies — it is
    // never freed — so it joins the total even though it is the one term
    // measured rather than derived from constants.
    const memory_total = constants.memoryBytesTotal(&.{
        .conn_slots = limits.conn_slots,
        .conn_bytes = @sizeOf(ServerXev.ConnType),
        .relay_buffers = limits.relay_buffers,
        .relay_buffer_pair_bytes = @sizeOf(zoxy.RelayBuffer),
        .upstream_slots = limits.upstream_slots,
        .upstream_bytes = @sizeOf(UpstreamType),
        .access_log_bytes = access_log_bytes,
        .endpoint_table_bytes = ServerXev.endpointTableBytes(config),
        .head_buffers = limits.head_buffers,
        .head_buffer_bytes = constants.head_bytes_max,
        .upstream_head_buffers = limits.upstream_head_buffers,
        .upstream_head_buffer_bytes = @sizeOf(zoxy.UpstreamHeadBuffer),
    }) + config_arena_bytes;
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    // The version leads, because this banner is what a bug report pastes
    // and `--version` is what it does not think to run.
    try writer.print(
        \\zoxy {s}{s}
        \\budgets (DESIGN.md §5/§8; closed-form except where marked):
        \\  memory  total {d} KiB = conn slots {d} x {d} B + relay buffers {d} x {d} B
        \\          + upstream slots {d} x {d} B + head buffers {d} x {d} B (+ ring {d} B)
        \\          + upstream head buffers {d} x {d} B + access log {d} KiB
        \\          + endpoint tables {d} B ({d} cluster(s) x {d} wide)
        \\          + config arena {d} KiB (measured, not closed-form)
        \\  fds     {d} required (asserted against RLIMIT_NOFILE)
        \\  ring    {d} entries, completion queue {d}, in-flight ops <= {d}
        \\  config  {d} listener(s), {d} cluster(s), access log {s}
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
        @sizeOf(UpstreamType),
        limits.head_buffers,
        // The +1 ownership byte stays out of the banner's per-unit figure;
        // the closed-form total above carries it.
        constants.head_bytes_max,
        constants.bufferGroupDescriptorBytes(limits.head_buffers),
        limits.upstream_head_buffers,
        @sizeOf(zoxy.UpstreamHeadBuffer),
        access_log_bytes / 1024,
        ServerXev.endpointTableBytes(config),
        config.clusters.len,
        endpoint_stride,
        config_arena_bytes / 1024,
        fds_required,
        constants.ring_entries,
        cq_entries,
        in_flight,
        config.listeners.len,
        config.clusters.len,
        if (config.access_log_sink) |sink| @tagName(sink) else "off",
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
