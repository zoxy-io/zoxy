//! zoxy's own binary (#417): the stock product, built on the library the
//! way any custom build is. What is left here is what only this product
//! decides — its command line, and that its config is JSON read from a
//! file named on that line. Everything a running proxy does between a
//! loaded config and a finished drain is `zoxy.App`'s, shared with every
//! other build: pricing and the banner, the descriptor budget, the access
//! log's sink, certificates, signals, the loop.
//!
//! `--check` (#301) is that same sequence stopped one step short: it loads
//! the config, opens every file the config names, prices the pools and
//! measures the demand against this box's `RLIMIT_NOFILE` — then reports
//! and exits without binding a port. Deliberately the same code and not a
//! second validator: a pre-flight that agreed with the real binary only by
//! construction would be worse than not having one. `--help` and
//! `--version` are answered before any of that and exit immediately.

const std = @import("std");

const zoxy = @import("zoxy");
const zoxy_json = @import("zoxy_json");
const build_options = @import("build_options");

/// The stock binary lists no extensions: every extension call compiles
/// out of it (#417).
const App = zoxy.App(.{});

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

/// Load the config the command line named and hand it to the library's
/// start: the only mode that takes a port.
fn serve(init: std.process.Init, arena: std.mem.Allocator, config_path: []const u8) !void {
    assert(config_path.len >= 1);
    // Measured across the read, not assumed from the file size: the
    // parse allocates its own structures beside the text it parses, and
    // both live in the arena for the process's life (§5). The banner adds
    // what resolving the options takes, which `App.serve` measures.
    const arena_before = init.arena.queryCapacity();
    const options = try readConfig(init.io, arena, config_path);
    const options_arena_bytes = init.arena.queryCapacity() - arena_before;
    try App.serve(init, &options, &.{
        .build = .{ .version = build_options.version, .id_suffix = build_id_suffix },
        .source = config_path,
        .options_arena_bytes = options_arena_bytes,
    });
}

/// `--check` (#301): read the config into options, then let the library
/// resolve them and run the start up to the banner. A config whose JSON
/// never translates earns its verdict here, with no budget to report —
/// nothing was loaded to price; options the library refuses earn theirs
/// in `App.check`, the same way.
fn checkConfig(init: std.process.Init, arena: std.mem.Allocator, config_path: []const u8) !u8 {
    assert(config_path.len >= 1);
    const arena_before = init.arena.queryCapacity();
    const options = readConfig(init.io, arena, config_path) catch |err|
        return @backingInt(zoxy.app.checkExitFor(err));
    const options_arena_bytes = init.arena.queryCapacity() - arena_before;
    const verdict = try App.check(init, &options, &.{
        .build = .{ .version = build_options.version, .id_suffix = build_id_suffix },
        .source = config_path,
        .options_arena_bytes = options_arena_bytes,
    });
    return @backingInt(verdict);
}

/// Read the config file and translate it into options, or say on stderr
/// why it cannot be. What the options must satisfy is judged by the
/// library, in `App.serve` and `App.check`, under the same words.
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
/// arena across this call, `App` adds what resolving took, and the
/// startup banner prints the sum), not "an oversized config is refused
/// cleanly".
fn readConfig(
    io: std.Io,
    arena: std.mem.Allocator,
    config_path: []const u8,
) !zoxy.Options {
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
    return zoxy_json.optionsFromJson(arena, config_bytes, .{
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
///
/// Both refusals a read can earn, unreadable and too large, are named
/// here with the path and the reason, where both are known: the loader's
/// error names the verdict, not the file. Bodies, CA bundles and a
/// listener's certificate pair all come through here (#417), so this is
/// the one place a refusal can say which.
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
        error.StreamTooLong => blk: {
            std.debug.print("zoxy: cannot read '{s}': larger than {d} bytes\n", .{ path, limit });
            break :blk error.FileTooLarge;
        },
        else => blk: {
            std.debug.print("zoxy: cannot read '{s}': {t}\n", .{ path, err });
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
