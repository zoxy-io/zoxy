//! zoxy startup (DESIGN.md §5, §8): read config into the arena (the only
//! allocating region), resolve it, verify the fd budget against
//! RLIMIT_NOFILE, print the budgets, install signal handlers
//! (the only raw syscall surface outside src/io/, held to the rlimit and
//! sigaction allowlist by lint), then hand the process to the event loop
//! until a drain completes. `--help` and `--version` are answered before any
//! of that and exit immediately.
//!
//! `--check` (#301) is that same sequence stopped one step short: it loads
//! the config, opens every file the config names, prices the pools and
//! measures the demand against this box's `RLIMIT_NOFILE` — then reports
//! and exits without binding a port. Deliberately the same code and not a
//! second validator: a pre-flight that agreed with the real binary only by
//! construction would be worse than not having one.
//!
//! This file is the *application* — the CLI, the filesystem, and the two
//! process-level syscalls. Everything an embedder would need identically
//! is the library's (§13): the budget's closed form and banner live in
//! `budget.zig`, the serving path in `Server`. What is left here is what
//! only a program owning a process may do — raise a resource limit,
//! install a signal disposition, decide what argv means.

const std = @import("std");

const zoxy = @import("zoxy");
const build_options = @import("build_options");

const XevIo = zoxy.Io.XevIo;
const ServerXev = zoxy.Server(XevIo);
const BudgetXev = zoxy.Budget(XevIo);

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

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    assert(args.len >= 1); // argv always carries the program name at [0].
    switch (classifyArgs(args)) {
        .run => |path| {
            try serve(init, arena, path);
            return 0;
        },
        // The one mode with more than one non-zero answer, so it returns
        // its own code rather than an error (#301).
        .check => |path| return checkConfig(init, arena, path),
        .help => {
            try printHelp(init.io);
            return 0;
        },
        .version => {
            try printVersion(init.io);
            return 0;
        },
        .usage => |reason| {
            printUsageError(reason);
            return error.InvalidArguments;
        },
    }
}

/// Start the proxy and hand the process to the loop until a drain
/// completes — the module doc's sequence, and the only mode that takes a
/// port.
fn serve(init: std.process.Init, arena: std.mem.Allocator, config_path: []const u8) !void {
    assert(config_path.len >= 1);
    // Measured across the read, not assumed from the file size: the
    // parse allocates its own structures beside the text it parses, and
    // both live in the arena for the process's life (§5).
    const arena_before = init.arena.queryCapacity();
    const config = try readConfig(init.io, arena, config_path);
    const config_arena_bytes = init.arena.queryCapacity() - arena_before;

    const demands = BudgetXev.demandsFor(&config);
    // The closed form and the banner are the library's (`budget.zig`,
    // §13): they have to price exactly what `Server.init` reserves, and
    // a second derivation here would be a copy that could drift.
    //
    // Printed *before* the box is asked for anything, so a start the fd
    // budget refuses still leaves behind the numbers that refused it —
    // `--check` prints whatever its verdict for the same reason (#301),
    // and the two modes agreeing on that is the point.
    BudgetXev.print(&config, demands, config_arena_bytes, .{
        .version = build_options.version,
        .id_suffix = build_id_suffix,
    });
    const resources = try openStartupResources(init.io, arena, &config, demands);

    // The ring is the config's to size (§5), count and unit both;
    // Server.init asserts its own accounting against the same numbers.
    try global_io.init(
        arena,
        demands.cq_entries,
        @intCast(config.listeners.len),
        config.limits.head_buffers,
        config.limits.head_buffer_bytes,
        resources.log_sink_fd,
        // The path rides beside its fd so SIGHUP can reopen it (§8).
        if (config.access_log_sink) |sink| switch (sink) {
            .stdout => null,
            .file => |path| path,
        } else null,
    );
    var server: ServerXev = undefined;
    try server.init(arena, &global_io, &config, config.limits);
    if (resources.tls_credentials.len > 0) {
        server.setTlsCredentials(resources.tls_credentials);
    }
    try server.start();
    installSignalHandlers();

    try global_io.run();

    // The loop only stops after a completed drain (§8).
    assert(server.isIdle());
    server.dumpMetrics();
}

/// Everything a start takes from the box before the loop exists.
const StartupResources = struct {
    /// The fd `XevIo` writes access-log bytes to (§8).
    log_sink_fd: @TypeOf(XevIo.log_sink_stdout),
    /// One slot per listener, null where the listener is plaintext —
    /// empty when nothing terminates TLS.
    tls_credentials: []const ?zoxy.tls.Credentials,
};

/// The §5/§8 startup gauntlet: raise `RLIMIT_NOFILE` to the demand, open
/// the access log's sink, load every listener's certificate. What only an
/// application may do, in the order it must do it.
///
/// One function rather than two hand-synced sequences, because the order
/// is itself a *verdict*: a config that fails two of these earns the
/// answer of whichever a start reaches first, and `--check` (#301)
/// reports that answer as an exit code an operator branches on — `1` says
/// change the file, `2` says run it elsewhere. `serve` and
/// `checkStartFits` both call this, so the two cannot drift and no
/// comment has to guard that they don't.
fn openStartupResources(
    io: std.Io,
    arena: std.mem.Allocator,
    config: *const zoxy.config.Config,
    demands: BudgetXev.Demands,
) !StartupResources {
    assert(config.listeners.len >= 1);
    assert(demands.fds > 0);
    // `demandsFor` bounds this from above but never from below, and a
    // zero is a closed form that broke upstream: `serve` creates the
    // ring at this depth, and a ring that deep completes nothing.
    assert(demands.cq_entries > 0);
    // fds are pre-budgeted rather than shed (§8), so this is both the
    // first thing the box can refuse and the first thing asked of it.
    try ensureFdBudget(demands.fds);
    const log_sink_fd = try openLogSinkFd(config);
    // Certificates before the loop, on `openLogSinkFd`'s reasoning: the
    // config named a file, so open it while a failure can still name it
    // and stop the process, rather than surfacing as a broken connection
    // under traffic (§4).
    const tls_credentials = try loadTlsCredentials(io, arena, config);
    assert(tls_credentials.len == 0 or tls_credentials.len == config.listeners.len);
    return .{ .log_sink_fd = log_sink_fd, .tls_credentials = tls_credentials };
}

/// What `--check` exits with (#301). Three answers rather than two,
/// because the difference is what a CI job acts on: a build agent with a
/// small `RLIMIT_NOFILE` may legitimately accept `does_not_fit` on a
/// config sized for production, and must never accept `invalid_config`.
const CheckExit = enum(u8) {
    /// The config loads and this box can start it.
    ok = 0,
    /// The config is wrong: unreadable, unparseable, semantically
    /// refused, or naming a file that will not load. A path the process
    /// cannot open counts as the config's own, deliberately — the
    /// operator has to change something either way, and a CI job that
    /// does not hold the deployment's certificates should check a config
    /// that does not name them rather than learn to ignore a code that
    /// also covers a real mistake.
    invalid_config = 1,
    /// The config is right and this machine is what refused it: the fd
    /// budget is above `RLIMIT_NOFILE`'s hard limit, the startup arena
    /// could not be had, or libcrypto would not take the fixed heap
    /// (§5). The same file would start elsewhere.
    does_not_fit = 2,
};

/// Which of the two failing verdicts a load error is. The question this
/// answers is not whose fault the failure is but what the operator does
/// next: change the config, or run it somewhere else.
fn checkExitFor(err: anyerror) CheckExit {
    return switch (err) {
        error.OutOfMemory,
        error.FdBudgetUnsatisfiable,
        error.LibcryptoHeapUnavailable,
        => .does_not_fit,
        else => .invalid_config,
    };
}

/// `--check` (#301): everything `serve` does up to the banner, and
/// nothing that takes a port.
///
/// zoxy needs this more than its peers do, because two of its virtues
/// make a bad config expensive. Config shape is the operator's to size
/// (§5) and a shape that does not fit is *refused*, not warned about; and
/// config is parse-once immutable (§1), so the blast radius of a bad one
/// is not a failed reload but an outage. This is the pre-flight that pays
/// for both, and the reason it is a mode rather than a tool is that a
/// second validator could disagree with the binary.
fn checkConfig(init: std.process.Init, arena: std.mem.Allocator, config_path: []const u8) !u8 {
    assert(config_path.len >= 1);
    const arena_before = init.arena.queryCapacity();
    // The one failure with no budget to report: nothing was loaded, so
    // there is no config to price and this arm answers without a banner.
    const config = readConfig(init.io, arena, config_path) catch |err|
        return @intFromEnum(checkExitFor(err));
    const config_arena_bytes = init.arena.queryCapacity() - arena_before;
    const demands = BudgetXev.demandsFor(&config);
    assert(demands.fds > 0);

    // Read before the gauntlet below: `ensureFdBudget` raises the soft
    // limit toward the demand, so asking afterwards would report what
    // this check just did rather than what it found.
    const nofile = try std.posix.getrlimit(.NOFILE);
    const verdict = checkStartFits(init.io, arena, &config, demands);
    try writeCheckReport(init.io, &.{
        .config = &config,
        .demands = demands,
        .config_arena_bytes = config_arena_bytes,
        .config_path = config_path,
        .nofile = nofile,
        .verdict = verdict,
    });
    return @intFromEnum(verdict);
}

/// Ask the box for exactly what a start asks it for, and give it back.
///
/// The gauntlet is `openStartupResources`, unchanged and unbranched — a
/// check that ran its own sequence could reach a different verdict than
/// the start it predicts, which is the way #301 warns a pre-flight can be
/// worse than none. Every arm names its own reason on stderr on the way
/// out (§5's rule that a path which cannot open stops the process), so
/// what comes back here is only the verdict.
fn checkStartFits(
    io: std.Io,
    arena: std.mem.Allocator,
    config: *const zoxy.config.Config,
    demands: BudgetXev.Demands,
) CheckExit {
    assert(config.listeners.len >= 1);
    assert(demands.fds > 0);
    const resources = openStartupResources(io, arena, config, demands) catch |err|
        return checkExitFor(err);
    // Given straight back, because a check holds nothing. The `file`
    // sink was still *created* if it was absent, exactly as a start
    // creates it: the alternative is a check that passes on a log
    // directory the start then cannot write.
    if (resources.log_sink_fd != XevIo.log_sink_stdout) {
        XevIo.closeLogSink(resources.log_sink_fd);
    }
    return .ok;
}

/// What a check run prints: the priced config, the verdict it earned, and
/// the two facts only a check has — the file it was asked about, and the
/// `RLIMIT_NOFILE` it found on the way in.
const CheckReport = struct {
    config: *const zoxy.config.Config,
    demands: BudgetXev.Demands,
    config_arena_bytes: u64,
    config_path: []const u8,
    nofile: std.posix.rlimit,
    verdict: CheckExit,
};

/// A check run's whole output, to **stdout** — unlike the startup banner,
/// which is diagnostics printed beside a process that then goes on to
/// serve. Here there is nothing beside: the budget *is* the result, so an
/// operator redirecting it into a file or a CI artifact must get it
/// rather than an empty one. The reasons for a failure still go to
/// stderr, where every other startup refusal already writes them.
///
/// Printed whatever the verdict, and that is the point of #301: a budget
/// that does not fit is exactly the one whose numbers an operator needs
/// in front of them.
fn writeCheckReport(io: std.Io, report: *const CheckReport) !void {
    assert(report.config_path.len >= 1);
    assert(report.nofile.max >= report.nofile.cur);
    // The writer drains to stdout whenever this staging buffer fills, so
    // its size is a batching choice, not a cap on the banner's length.
    var buffer: [1024]u8 = undefined;
    var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
    const writer = &file_writer.interface;
    try BudgetXev.printTo(writer, report.config, report.demands, report.config_arena_bytes, .{
        .version = build_options.version,
        .id_suffix = build_id_suffix,
    });
    var soft_buffer: [rlimit_text_bytes]u8 = undefined;
    var hard_buffer: [rlimit_text_bytes]u8 = undefined;
    try writer.print(
        \\  rlimit  RLIMIT_NOFILE {s} soft, {s} hard (a start raises the soft limit to the fd budget)
        \\  check   {s}: {s}
        \\
    , .{
        rlimitText(report.nofile.cur, &soft_buffer),
        rlimitText(report.nofile.max, &hard_buffer),
        report.config_path,
        checkVerdictText(report.verdict),
    });
    try writer.flush();
}

/// The verdict as the line an operator reads. The switch is exhaustive
/// over `CheckExit`, so a fourth verdict is a compile error rather than a
/// check that reports nothing — no runtime guard adds anything.
fn checkVerdictText(verdict: CheckExit) []const u8 {
    return switch (verdict) {
        .ok => "valid, and this box can start it",
        .invalid_config => "refused; the reason is on stderr",
        .does_not_fit => "valid, but this box cannot start it; the reason is on stderr",
    };
}

/// The widest a limit renders: `RLIM_INFINITY` is the largest `rlim_t`,
/// and every other value is shorter.
const rlimit_text_bytes = std.fmt.count("{d}", .{std.math.maxInt(std.posix.rlim_t)});

/// One `RLIMIT_NOFILE` bound as an operator reads it. `RLIM_INFINITY`
/// renders as 18446744073709551615, which reads as a bug rather than as
/// "no limit", so it gets the word instead.
fn rlimitText(value: std.posix.rlim_t, buffer: []u8) []const u8 {
    assert(buffer.len == rlimit_text_bytes);
    if (value == std.posix.RLIM.INFINITY) return "unlimited";
    // The assert above covers every `rlim_t`, which is what makes the
    // buffer wide enough for whatever this value is.
    const rendered = std.fmt.bufPrint(buffer, "{d}", .{value}) catch unreachable;
    assert(rendered.len <= rlimit_text_bytes);
    return rendered;
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

/// The fixed libcrypto heap's storage (§4). Static rather than carved
/// from the startup arena, and that is not a style choice: libcrypto
/// registers an atexit handler, and `OPENSSL_cleanup` frees through our
/// hooks *after* `main` has returned and the arena with it. An
/// arena-backed heap therefore segfaults every terminating process on the
/// way out — clean drain, correct exit code, crash after. Found by the
/// Tier-0.5 gate the first time it ran the real binary with TLS
/// configured, which is the only place it could have been found.
///
/// BSS, so the pages a plaintext deployment never touches never become
/// resident; the §5 banner prices this only when a listener terminates,
/// which is when it is actually used.
var libcrypto_heap_storage: [zoxy.constants.libcrypto_heap_bytes]u8 align(16) = undefined;

/// Turn each listener's configured certificate paths into loaded
/// credentials (§4), one slot per listener and null where the listener is
/// plaintext. Startup-only: the arena owns the decoded chains for the
/// process, and every engine on a listener borrows that listener's entry.
///
/// This is where a bad certificate stops the proxy. The alternative —
/// discovering it on the first handshake — turns a typo into an outage
/// that only shows up under traffic, and reports it as a failed
/// connection rather than as the config being wrong.
fn loadTlsCredentials(
    io: std.Io,
    arena: std.mem.Allocator,
    config: *const zoxy.config.Config,
) ![]const ?zoxy.tls.Credentials {
    assert(config.listeners.len >= 1);
    if (config.limits.tls_engines == 0) {
        // No listener terminates TLS: nothing to load, and — the point of
        // checking here — no libcrypto heap to reserve either.
        return &.{};
    }

    // Before any credential, because `Credentials.load` calls libcrypto
    // and the allocator swap is refused once anything has allocated. If
    // it fails the zero-allocation promise (§5) is unbacked, and a proxy
    // that cannot keep its own invariants should not start.
    if (!zoxy.tls.libcrypto_heap.install(&libcrypto_heap_storage)) {
        std.debug.print(
            "zoxy: libcrypto refused the fixed-heap install; " ++
                "the zero-allocation budget (DESIGN.md §5) cannot be kept\n",
            .{},
        );
        return error.LibcryptoHeapUnavailable;
    }

    const credentials = try arena.alloc(?zoxy.tls.Credentials, config.listeners.len);
    for (config.listeners, 0..) |listener, index| {
        const tls = listener.tls orelse {
            credentials[index] = null;
            continue;
        };
        const cert_pem = try readPemFile(io, arena, tls.cert_path);
        const key_pem = try readPemFile(io, arena, tls.key_path);
        credentials[index] = zoxy.tls.Credentials.load(arena, cert_pem, key_pem, .{}) catch |err| {
            // Which listener and which verdict: the paths are right here,
            // and an operator with several listeners needs to know which
            // one to look at.
            std.debug.print(
                "zoxy: listener {d} cannot use '{s}' + '{s}': {t}\n",
                .{ index, tls.cert_path, tls.key_path, err },
            );
            return err;
        };
    }
    // One slot per listener, in listener order: `Server.credentialsFor`
    // indexes this by listener index, so a table of any other length would
    // hand some listener another's key or none at all.
    assert(credentials.len == config.listeners.len);
    return credentials;
}

/// One PEM file into the arena, bounded. The bound's job is to turn "the
/// operator pointed at the wrong file" into a named error rather than an
/// arena the size of whatever was on disk.
fn readPemFile(io: std.Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    assert(path.len >= 1);
    return std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        arena,
        .limited(zoxy.constants.tls_pem_bytes_max),
    ) catch |err| {
        std.debug.print("zoxy: cannot read TLS file '{s}': {t}\n", .{ path, err });
        return err;
    };
}

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

/// What the command line asked for: run against a config, check one
/// without running it (#301), or one of the two informational modes, or a
/// usage mistake (with the reason so the message can be specific).
const Cli = union(enum) {
    run: []const u8,
    check: []const u8,
    help,
    version,
    usage: UsageError,
};

const UsageError = enum { missing_config, extra_arguments, unknown_option };

/// Classify argv without touching the world, so it is unit-testable. zoxy
/// takes exactly one positional argument — the config path — and every
/// flag it has is a *mode* rather than an option carrying a value, so any
/// of them may appear anywhere on the line. `--help` and `--version` win
/// over `--check` for the reason they win over a config path: they still
/// work appended to a half-typed command.
fn classifyArgs(args: []const []const u8) Cli {
    assert(args.len >= 1); // argv always carries the program name at [0].
    for (args[1..]) |arg| {
        if (flagMatches(arg, "-h", "--help")) return .help;
    }
    for (args[1..]) |arg| {
        if (flagMatches(arg, "-V", "--version")) return .version;
    }
    var check = false;
    var config_path: []const u8 = "";
    var positionals: u32 = 0;
    for (args[1..]) |arg| {
        if (flagMatches(arg, "-c", "--check")) {
            check = true;
            continue;
        }
        // A lone unrecognized -flag is a typo, not a file named "-x".
        if (arg.len > 0 and arg[0] == '-') return .{ .usage = .unknown_option };
        positionals += 1;
        assert(positionals < args.len);
        if (positionals == 1) config_path = arg;
    }
    if (positionals == 0) return .{ .usage = .missing_config };
    if (positionals > 1) return .{ .usage = .extra_arguments };
    assert(config_path.len == 0 or config_path[0] != '-');
    return if (check) .{ .check = config_path } else .{ .run = config_path };
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
    \\  zoxy <config.json>          Start the proxy with the given JSON config.
    \\  zoxy --check <config.json>  Validate and price the config, then exit
    \\                              without binding anything (-c).
    \\  zoxy --help, -h             Show this message and exit.
    \\  zoxy --version, -V          Print the version and exit.
    \\
    \\zoxy reads the whole config once at startup, sizes every pool and the
    \\io_uring ring from it, then serves without allocating again. The config
    \\format is documented by the JSON Schema shipped with each release and by
    \\docs/DESIGN.md.
    \\
    \\--check runs that whole load — every body, error page and certificate
    \\the config names is opened, so it needs the same file permissions the
    \\proxy would — and prints the budget banner to stdout. It exits 0 when
    \\the config would start on this machine, 1 when the config is wrong, and
    \\2 when the config is right and this machine cannot fit it (an fd budget
    \\above the RLIMIT_NOFILE hard limit).
    \\
    \\Signals:
    \\  SIGTERM, SIGINT   Drain in-flight connections, then exit 0. The
    \\                    counters are printed once on the way out.
    \\  SIGHUP            Reopen the access log's file sink (rotation).
    \\                    No other meaning: config changes are a restart.
    \\  SIGUSR1           Ignored. It printed the counters until they moved
    \\                    to the admin listener's /metrics, which frames each
    \\                    rendering as its own response.
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
        "zoxy: {s}\nusage: zoxy <config.json>  (or --check, --help, --version)\n",
        .{detail},
    );
}

/// fds are pre-budgeted, not shed (§8): raise the soft limit up to the
/// hard limit, and refuse to start if even that cannot cover the budget.
///
/// One error for every way this can fail, the kernel's included, because
/// they all mean the same thing to whoever reads it — this box will not
/// give this config the descriptors it needs — and because `--check`
/// classifies on the error (#301): a distinct value here is what keeps
/// "run it elsewhere" from ever being reported as "change the file". The
/// specific reason is printed instead of returned, here where the numbers
/// that produced it are still in hand.
fn ensureFdBudget(fds_required: u32) error{FdBudgetUnsatisfiable}!void {
    assert(fds_required > 0);
    const required: u64 = fds_required;
    var limits = std.posix.getrlimit(.NOFILE) catch |err| {
        std.debug.print("zoxy: cannot read RLIMIT_NOFILE: {t}\n", .{err});
        return error.FdBudgetUnsatisfiable;
    };
    assert(limits.max >= limits.cur);
    if (limits.cur >= required) return;
    if (limits.max < required) {
        std.debug.print(
            "zoxy: RLIMIT_NOFILE hard limit {d} is below the fd budget {d} (§8)\n",
            .{ limits.max, required },
        );
        return error.FdBudgetUnsatisfiable;
    }
    limits.cur = required;
    std.posix.setrlimit(.NOFILE, limits) catch |err| {
        std.debug.print(
            "zoxy: cannot raise RLIMIT_NOFILE to the fd budget {d}: {t}\n",
            .{ required, err },
        );
        return error.FdBudgetUnsatisfiable;
    };
}

fn installSignalHandlers() void {
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onRawSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &action, null);
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.HUP, &action, null);
    // §8's drain watchdog (#226). Unlike the three above, this one never
    // reaches the loop: every other bound in the proxy is an op the loop
    // delivers, which makes them all blind to a backend that has stopped
    // delivering — including `onDrainStuck`, the backstop for exactly
    // that. SIGALRM arrives from the kernel regardless, and its handler
    // exits without asking the loop anything.
    const alarm_action = std.posix.Sigaction{
        .handler = .{ .handler = onAlarm },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.ALRM, &alarm_action, null);
    // Only now may anything arm one: the seam refuses to raise a signal
    // whose default action would kill this process silently.
    XevIo.alarmHandlerInstalled();
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
    // SIGUSR1 carried the counter dump until #310 removed it, and its
    // default disposition is *terminate*. Dropping the handler without
    // this line would turn an operator's muscle memory — the signal that
    // used to print counters — into an outage. Ignored rather than
    // handled, because there is nothing left for it to mean: the
    // exposition it used to write is what `/metrics` serves, framed and
    // scrapeable, and the drain still prints the final tally.
    std.posix.sigaction(.USR1, &ignore, null);
}

/// Async-signal-safe by delegation: the seam's handler is one `write` and
/// one `_exit` (§4). Nothing here reads process state, because reaching
/// this means the loop that owns it may be wedged — and nothing here
/// asserts, for the reason `onRawSignal` does not either: `assert` panics,
/// and the panic path locks stdio and captures a stack trace, none of
/// which a signal handler may do. A signal this is not installed for is
/// dropped the same way that one drops it.
fn onAlarm(signal_number: std.posix.SIG) callconv(.c) void {
    if (signal_number != .ALRM) return;
    XevIo.onAlarmFromHandler();
}

/// Async-signal-safe: delegates to the seam's atomic-mask + eventfd wake
/// (§4); nothing else is legal here.
fn onRawSignal(signal_number: std.posix.SIG) callconv(.c) void {
    const signal: zoxy.Io.Signal = switch (signal_number) {
        .TERM, .INT => .terminate,
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

test "classifyArgs: --check names the config it must not run" {
    // Either side of the path: `--check` carries no value of its own, so
    // its position on the line is not information.
    const leading = classifyArgs(&.{ "zoxy", "--check", "config.json" });
    try testing.expect(leading == .check);
    try testing.expectEqualStrings("config.json", leading.check);
    const trailing = classifyArgs(&.{ "zoxy", "config.json", "-c" });
    try testing.expect(trailing == .check);
    try testing.expectEqualStrings("config.json", trailing.check);
    // Still exactly one positional, and still the informational modes
    // first — a `--check` with nothing to check is the same mistake a
    // bare `zoxy` is.
    try testing.expectEqual(
        Cli{ .usage = .missing_config },
        classifyArgs(&.{ "zoxy", "--check" }),
    );
    try testing.expectEqual(
        Cli{ .usage = .extra_arguments },
        classifyArgs(&.{ "zoxy", "--check", "a.json", "b.json" }),
    );
    try testing.expect(classifyArgs(&.{ "zoxy", "--check", "a.json", "--help" }) == .help);
    // And a config path is still a config path when nobody asked to
    // check it.
    try testing.expect(classifyArgs(&.{ "zoxy", "config.json" }) == .run);
}

test "checkExitFor: the box's refusals are told from the config's" {
    // What the operator does next is the whole distinction (#301): these
    // three say "run it elsewhere"…
    try testing.expectEqual(CheckExit.does_not_fit, checkExitFor(error.OutOfMemory));
    try testing.expectEqual(
        CheckExit.does_not_fit,
        checkExitFor(error.LibcryptoHeapUnavailable),
    );
    // The one value `ensureFdBudget` collapses every kernel answer into,
    // and the reason it has a distinct value at all.
    try testing.expectEqual(
        CheckExit.does_not_fit,
        checkExitFor(error.FdBudgetUnsatisfiable),
    );
    // …and everything else says "change the file", including a path in
    // it that would not open, which is the arm most worth pinning: a CI
    // job must not learn to ignore the code a real mistake also earns.
    try testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.FileNotFound));
    try testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.AccessDenied));
    try testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.MissingField));
    // The codes themselves are the CI contract, so they are asserted
    // rather than left to the declaration order.
    try testing.expectEqual(@as(u8, 0), @intFromEnum(CheckExit.ok));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(CheckExit.invalid_config));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(CheckExit.does_not_fit));
}

test "rlimitText: an infinite limit reads as one" {
    var buffer: [rlimit_text_bytes]u8 = undefined;
    try testing.expectEqualStrings("1024", rlimitText(1024, &buffer));
    try testing.expectEqualStrings("0", rlimitText(0, &buffer));
    // The case the helper exists for: 2^64-1 in a banner reads as a bug.
    try testing.expectEqualStrings(
        "unlimited",
        rlimitText(std.posix.RLIM.INFINITY, &buffer),
    );
    // The buffer is wide enough for the widest value that is not
    // INFINITY, which is what the `catch unreachable` inside rests on.
    const widest = std.math.maxInt(std.posix.rlim_t) - 1;
    try testing.expectEqual(rlimit_text_bytes, rlimitText(widest, &buffer).len);
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
