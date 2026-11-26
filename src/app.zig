//! zoxy as a process (#417): what a binary built on the library runs
//! between "here are the options" and "the drain finished". The stock
//! binary and every custom build call the same sequence, so the order its
//! steps run in — which is itself a verdict `--check` reports (#301) — is
//! written once:
//!
//! 0. resolve the options (`config.resolve`) and refuse a selection the
//!    build does not list, so a custom build is held to every rule the
//!    stock loader holds a file to;
//! 1. price the config and print the banner (§5), before the box is
//!    asked for anything, so a start the box refuses still leaves the
//!    numbers that refused it;
//! 2. raise `RLIMIT_NOFILE` to the fd budget, open the access log's sink,
//!    and parse every listener's certificates, in that order;
//! 3. build the loop and the server, bind the build's extensions, hand
//!    over the credentials, install the signal dispositions;
//! 4. start, run until a drain completes, print the final tally.
//!
//! What is left to an application is what only it knows: its command
//! line, and where its options come from — the stock binary's JSON, or a
//! custom build's own code. Everything that touches the process itself —
//! the descriptor limit, signals — sits behind the Io seam, so nothing
//! here makes a syscall.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const extension = @import("extension.zig");
const Budget = @import("budget.zig").Budget;
const Server = @import("Server.zig").Server;
const XevIo = @import("io/XevIo.zig");
const Credentials = @import("tls/Credentials.zig");
const certificate_set = @import("tls/certificate_set.zig");
const libcrypto_heap = @import("tls/libcrypto_heap.zig");
const trust = @import("tls/trust.zig");

const Config = config_module.Config;
const Options = @import("Options.zig");

const assert = std.debug.assert;

/// The application half of a build that lists `extensions`.
pub fn App(comptime extensions: extension.Extensions) type {
    return struct {
        pub const runtime: extension.Runtime = .{ .Io = XevIo, .extensions = extensions };
        pub const ServerType = Server(runtime);
        pub const BudgetType = Budget(runtime);

        /// What a start states about itself beside its options.
        pub const Startup = struct {
            /// What the banner's first line stamps.
            build: BudgetType.Build,
            /// What messages about the options call them: the file a JSON
            /// config came from, or whatever a custom build calls its own.
            source: []const u8,
            /// What building the options took from the startup arena,
            /// measured by whoever built them (§5); zero for options that
            /// are constants. The banner prints it, with what resolving
            /// them took, beside the closed form — the one term not
            /// derived.
            options_arena_bytes: u64,
        };

        /// Options resolved for a start, and what the startup arena holds
        /// for them.
        const Loaded = struct {
            config: Config,
            arena_bytes: u64,
        };

        /// Step zero: resolve `options` into the startup arena, measuring
        /// what that took, or say on stderr why they are refused — in the
        /// words the stock binary has always used, so a file's verdict
        /// reads the same whichever half of the loader reached it.
        fn load(init: std.process.Init, options: *const Options, startup: *const Startup) !Loaded {
            assert(startup.source.len >= 1);
            const arena_before = init.arena.queryCapacity();
            const config = resolveServed(init.arena.allocator(), options) catch |err| {
                std.debug.print("zoxy: invalid config '{s}': {t}\n", .{ startup.source, err });
                return err;
            };
            const arena_after = init.arena.queryCapacity();
            assert(arena_after >= arena_before);
            assert(config.listeners.len == options.listeners.len);
            return .{
                .config = config,
                .arena_bytes = startup.options_arena_bytes + (arena_after - arena_before),
            };
        }

        /// A cluster's check kind (#436): `instance` must point at a probe
        /// type this build lists.
        pub fn probe(instance: anytype) Options.Cluster.Check.Kind {
            const selection = extension.select(extensions.probes, instance);
            assert(selection.index < extensions.probes.len);
            return .{ .extension = selection };
        }

        /// A cluster's pick: `instance`, which must point at a picker type
        /// this build lists — a compile error otherwise.
        pub fn picker(instance: anytype) Options.Cluster.Pick {
            const selection = extension.select(extensions.pickers, instance);
            assert(selection.index < extensions.pickers.len);
            return .{ .extension = selection };
        }

        /// One request-policy selection for a listener's or a route's
        /// list: `instance` must point at a policy type this build lists.
        pub fn policy(instance: anytype) extension.Selection {
            const selection = extension.select(extensions.request_policies, instance);
            assert(selection.index < extensions.request_policies.len);
            return selection;
        }

        /// A route's handler (#434): `instance` must point at a handler
        /// type this build lists. The route names no cluster.
        pub fn handler(instance: anytype) extension.Selection {
            const selection = extension.select(extensions.handlers, instance);
            assert(selection.index < extensions.handlers.len);
            return selection;
        }

        /// One connection-policy selection for a listener's list (#425):
        /// `instance` must point at a connection-policy type this build
        /// lists.
        pub fn connectionPolicy(instance: anytype) extension.Selection {
            const selection = extension.select(extensions.connection_policies, instance);
            assert(selection.index < extensions.connection_policies.len);
            return selection;
        }

        /// One response-policy selection for a listener's or a route's
        /// list (#424): `instance` must point at a response-policy type
        /// this build lists.
        pub fn responsePolicy(instance: anytype) extension.Selection {
            const selection = extension.select(extensions.response_policies, instance);
            assert(selection.index < extensions.response_policies.len);
            return selection;
        }

        /// The options as this build can serve them: resolved, and every
        /// selection one of the build's own lists reaches.
        fn resolveServed(arena: std.mem.Allocator, options: *const Options) !Config {
            const config = try config_module.resolve(arena, options);
            try refuseUnservedSelections(&config);
            try refuseUnfitAnswers(&config);
            try refuseUnfitHandlers(&config);
            try refuseOverEditing(&config);
            try refuseConsultsUnslotted(&config);
            assert(config.clusters.len == options.clusters.len);
            assert(config.listeners.len >= 1);
            return config;
        }

        /// A selection this build's lists do not reach: made by hand rather
        /// than by `picker` or `policy`, which make one only for a listed
        /// type. Refused at startup rather than left to the server's
        /// asserts, because it is the build author's input, not this
        /// proxy's invariant. The instance's type cannot be checked at
        /// runtime — selections are built with `picker` and `policy` so
        /// that it never has to be.
        fn refuseUnservedSelections(config: *const Config) error{ExtensionUnserved}!void {
            assert(config.clusters.len >= 1);
            for (config.clusters) |*cluster| {
                switch (cluster.pick) {
                    .extension => |selection| try refuseUnserved(selection, extensions.pickers.len),
                    .rr, .p2c, .hash => {},
                }
                const checked = cluster.check orelse continue;
                if (checked.probe) |selection| try refuseUnserved(selection, extensions.probes.len);
            }
            for (config.listeners) |*listener| {
                for (listener.connection_policies) |selection| {
                    try refuseUnserved(selection, extensions.connection_policies.len);
                }
                for (listener.sni_routes) |*route| {
                    for (route.connection_policies) |selection| {
                        try refuseUnserved(selection, extensions.connection_policies.len);
                    }
                }
                for (listener.request_policies) |selection| {
                    try refuseUnserved(selection, extensions.request_policies.len);
                }
                for (listener.response_policies) |selection| {
                    try refuseUnserved(selection, extensions.response_policies.len);
                }
                for (listener.routes) |*route| {
                    if (route.handler) |selection| try refuseUnserved(selection, extensions.handlers.len);
                    for (route.request_policies) |selection| {
                        try refuseUnserved(selection, extensions.request_policies.len);
                    }
                    for (route.response_policies) |selection| {
                        try refuseUnserved(selection, extensions.response_policies.len);
                    }
                }
            }
        }

        /// A head buffer smaller than the widest page this build's policies
        /// answer with (#431): an HTTP/2 stream maps a page's head through
        /// scratch of that size, and a page that cannot fit would reset
        /// the stream it answers rather than answer it.
        fn refuseUnfitAnswers(config: *const Config) error{AnswerHeadOverBuffer}!void {
            const Answers = @import("extension_answers.zig").Table(extensions);
            assert(config.limits.head_buffer_bytes >= 1);
            if (!Answers.enabled) return;
            if (Answers.head_bytes_max > config.limits.head_buffer_bytes) return error.AnswerHeadOverBuffer;
        }

        /// A head buffer smaller than the widest answer this build's
        /// handlers declare, with zoxy's own lines around it (#434): the
        /// answer is rendered into the connection's head buffer.
        fn refuseUnfitHandlers(config: *const Config) error{HandlerResponseOverBuffer}!void {
            const widest = comptime extension.handlerResponseBytesMax(extensions);
            assert(config.limits.head_buffer_bytes >= constants.head_buffer_bytes_min);
            if (widest == 0) return;
            const rendered = @as(u64, widest) + constants.handler_head_overhead_bytes;
            if (rendered > config.limits.head_buffer_bytes) return error.HandlerResponseOverBuffer;
        }

        /// Policy lists that could edit one request more times than the
        /// render's buffer holds (#424): every edit-making policy on a
        /// listener and on its route may make `edits_per_verdict_max`.
        fn refuseOverEditing(config: *const Config) error{PolicyEditsOverLimit}!void {
            const Edits = @import("policy_edits.zig").Table(extensions);
            assert(config.listeners.len >= 1);
            const shape = Edits.shapeOf(config);
            if (shape.edits > constants.policy_edits_max) return error.PolicyEditsOverLimit;
            // The same bound on the way out (#424).
            if (Edits.responseShapeOf(config).edits > constants.policy_edits_max) return error.PolicyEditsOverLimit;
        }

        /// A consulting policy selected with no consult slot to consult
        /// from (#437), which would fail every request it sees. Here at
        /// step zero, so `--check` refuses what a start would; the server
        /// refuses it again at bind, for a build that composes one by hand.
        fn refuseConsultsUnslotted(config: *const Config) error{ConsultSlotsRequired}!void {
            assert(config.listeners.len >= 1);
            // `resolve` has held the slots under the upstream slots each
            // consult takes one of.
            assert(config.limits.consult_slots <= config.limits.upstream_slots);
            if (config.limits.consult_slots >= 1) return;
            if (ServerType.selectsConsultingPolicy(config)) return error.ConsultSlotsRequired;
        }

        fn refuseUnserved(selection: extension.Selection, listed_count: usize) error{ExtensionUnserved}!void {
            assert(listed_count <= extension.list_types_max);
            if (selection.index >= listed_count) return error.ExtensionUnserved;
            assert(selection.index < listed_count);
        }

        /// Resolve `options`, start serving them, and hand the process to
        /// the loop until a drain completes. Once per process: the loop
        /// owns the process's signals for its whole life (§3). The options'
        /// own memory is referenced for that whole life too.
        pub fn serve(init: std.process.Init, options: *const Options, startup: *const Startup) !void {
            assert(!serving);
            // Claimed only once the options resolve, so options refused
            // here leave nothing claimed and may be corrected and served.
            const loaded = try load(init, options, startup);
            serving = true;
            const config = &loaded.config;
            const arena = init.arena.allocator();
            const demands = BudgetType.demandsFor(config);
            BudgetType.print(config, demands, loaded.arena_bytes, startup.build);
            const resources = try openStartupResources(arena, config, demands);
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
            var server: ServerType = undefined;
            try server.init(arena, &global_io, config, config.limits);
            try server.bindExtensions(&.{ .arena = arena });
            if (resources.tls_credentials.len > 0) {
                server.setTlsCredentials(resources.tls_credentials);
                server.setTlsCertificateSets(resources.tls_certificate_sets);
            }
            global_io.installProcessSignals();
            try server.start();
            try global_io.run();
            // The loop only stops after a completed drain (§8).
            assert(server.isIdle());
            server.dumpMetrics();
        }

        /// `--check` (#301): the resolution and the gauntlet `serve` runs,
        /// and nothing that takes a port. The report goes to stdout, naming
        /// the options' source, and the verdict comes back; options that
        /// do not resolve earn theirs with no budget to report.
        ///
        /// The gauntlet is `openStartupResources`, unchanged and
        /// unbranched: a check that ran its own sequence could reach a
        /// different verdict than the start it predicts, which is the way
        /// #301 warns a pre-flight can be worse than none.
        pub fn check(
            init: std.process.Init,
            options: *const Options,
            startup: *const Startup,
        ) !CheckExit {
            const loaded = load(init, options, startup) catch |err| return checkExitFor(err);
            const config = &loaded.config;
            const demands = BudgetType.demandsFor(config);
            assert(demands.fds > 0);
            // Read before the gauntlet: `ensureFdBudget` raises the soft
            // limit toward the demand, so asking afterwards would report
            // what this check just did rather than what it found.
            const limit = try XevIo.fdLimit();
            const verdict = startFits(init.arena.allocator(), config, demands);
            try writeCheckReport(init.io, config, demands, loaded.arena_bytes, startup.build, &.{
                .subject = startup.source,
                .limit = limit,
                .verdict = verdict,
            });
            return verdict;
        }

        /// Ask the box for exactly what a start asks it for, and give it
        /// back. Every arm names its own reason on stderr on the way out,
        /// so what comes back is only the verdict.
        fn startFits(arena: std.mem.Allocator, config: *const Config, demands: BudgetType.Demands) CheckExit {
            assert(config.listeners.len >= 1);
            assert(demands.fds > 0);
            const resources = openStartupResources(arena, config, demands) catch |err|
                return checkExitFor(err);
            // Given straight back, because a check holds nothing. A `file`
            // sink was still *created* if absent, exactly as a start creates
            // it: the alternative is a check that passes on a log directory
            // the start then cannot write.
            if (resources.log_sink_fd != XevIo.log_sink_stdout) {
                XevIo.closeLogSink(resources.log_sink_fd);
            }
            return .ok;
        }

        /// A check run's whole output, to **stdout** — unlike the startup
        /// banner, which is diagnostics beside a process that goes on to
        /// serve. Here the budget *is* the result, so an operator
        /// redirecting it into a CI artifact must get it. Printed whatever
        /// the verdict: a budget that does not fit is exactly the one
        /// whose numbers an operator needs in front of them.
        fn writeCheckReport(
            io: std.Io,
            config: *const Config,
            demands: BudgetType.Demands,
            arena_bytes: u64,
            build: BudgetType.Build,
            report: *const CheckReport,
        ) !void {
            assert(report.subject.len >= 1);
            assert(demands.fds > 0);
            // The writer drains to stdout whenever this staging buffer
            // fills, so its size is a batching choice, not a cap.
            var buffer: [1024]u8 = undefined;
            var file_writer: std.Io.File.Writer = .init(.stdout(), io, &buffer);
            const writer = &file_writer.interface;
            try BudgetType.printTo(writer, config, demands, arena_bytes, build);
            var soft_buffer: [limit_text_bytes]u8 = undefined;
            var hard_buffer: [limit_text_bytes]u8 = undefined;
            try writer.print(
                \\  rlimit  RLIMIT_NOFILE {s} soft, {s} hard (a start raises the soft limit to the fd budget)
                \\  check   {s}: {s}
                \\
            , .{
                limitText(report.limit.soft, &soft_buffer),
                limitText(report.limit.hard, &hard_buffer),
                report.subject,
                checkVerdictText(report.verdict),
            });
            try writer.flush();
        }

        /// The §5/§8 startup gauntlet: raise `RLIMIT_NOFILE` to the demand,
        /// open the access log's sink, parse every listener's certificate.
        /// One function rather than two hand-synced sequences, because the
        /// order is itself a verdict: a config that fails two of these
        /// earns the answer of whichever a start reaches first, and
        /// `--check` reports that answer as an exit code an operator
        /// branches on.
        fn openStartupResources(
            arena: std.mem.Allocator,
            config: *const Config,
            demands: BudgetType.Demands,
        ) !StartupResources {
            assert(config.listeners.len >= 1);
            assert(demands.fds > 0);
            // `demandsFor` bounds this from above but never from below,
            // and a ring that deep completes nothing.
            assert(demands.cq_entries > 0);
            // fds are pre-budgeted rather than shed (§8), so this is both
            // the first thing the box can refuse and the first thing
            // asked of it.
            try XevIo.ensureFdBudget(demands.fds);
            const log_sink_fd = try openLogSinkFd(config);
            // Certificates parsed before the loop: a pair that will not
            // parse stops the process here, where the error can still
            // name it, rather than surfacing as a broken connection (§4).
            const tls_credentials = try loadTlsCredentials(arena, config);
            assert(tls_credentials.len == 0 or tls_credentials.len == config.listeners.len);
            const tls_certificate_sets = try loadTlsCertificateSets(arena, config, tls_credentials);
            assert(tls_certificate_sets.len == tls_credentials.len);
            return .{
                .log_sink_fd = log_sink_fd,
                .tls_credentials = tls_credentials,
                .tls_certificate_sets = tls_certificate_sets,
            };
        }
    };
}

/// The process's one loop, and whether a serve has claimed it. The
/// signal dispositions aim at this address, which must hold still for the
/// process's whole life (§3).
var global_io: XevIo = undefined;
var serving: bool = false;

/// The fixed libcrypto heap's storage (§4). Static rather than carved
/// from the startup arena, and that is not a style choice: libcrypto
/// registers an atexit handler, and `OPENSSL_cleanup` frees through our
/// hooks *after* `main` has returned and the arena with it. An
/// arena-backed heap therefore segfaults every terminating process on the
/// way out. BSS pages become resident as libcrypto uses them; the §5
/// banner includes the heap when a listener terminates TLS or an origin
/// uses it.
var libcrypto_heap_storage: [constants.libcrypto_heap_bytes]u8 align(16) = undefined;

/// Everything a start takes from the box before the loop exists.
const StartupResources = struct {
    /// The fd `XevIo` writes access-log bytes to (§8).
    log_sink_fd: @TypeOf(XevIo.log_sink_stdout),
    /// One slot per listener, null where the listener is plaintext —
    /// empty when nothing terminates TLS.
    tls_credentials: []const ?Credentials,
    /// #297: per listener, the certificates a server name chooses among
    /// (the default first), empty where it holds one. One slot per
    /// listener whenever `tls_credentials` has any, empty otherwise.
    tls_certificate_sets: []const []const certificate_set.Choice,
};

/// What a check run prints beside the budget: what it was asked about,
/// the descriptor limit it found on the way in, and its verdict.
const CheckReport = struct {
    subject: []const u8,
    limit: XevIo.FdLimit,
    verdict: CheckExit,
};

/// What `--check` exits with (#301). Three answers rather than two,
/// because the difference is what a CI job acts on: a build agent with a
/// small `RLIMIT_NOFILE` may legitimately accept `does_not_fit` on a
/// config sized for production, and must never accept `invalid_config`.
pub const CheckExit = enum(u8) {
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
    /// could not be had, libcrypto would not take the fixed heap (§5), or
    /// an endpoint's name did not resolve here (#480). The same config
    /// would start elsewhere.
    does_not_fit = 2,
};

/// Which of the two failing verdicts an error is. The question this
/// answers is not whose fault the failure is but what the operator does
/// next: change the config, or run it somewhere else. Public, because a
/// config that never loaded is classified by the application that tried
/// to load it.
pub fn checkExitFor(err: anyerror) CheckExit {
    return switch (err) {
        error.OutOfMemory,
        error.FdBudgetUnsatisfiable,
        error.LibcryptoHeapUnavailable,
        error.EndpointNameUnresolved,
        => .does_not_fit,
        else => .invalid_config,
    };
}

/// The verdict as the line an operator reads. The switch is exhaustive
/// over `CheckExit`, so a fourth verdict is a compile error rather than a
/// check that reports nothing.
fn checkVerdictText(verdict: CheckExit) []const u8 {
    return switch (verdict) {
        .ok => "valid, and this box can start it",
        .invalid_config => "refused; the reason is on stderr",
        .does_not_fit => "valid, but this box cannot start it; the reason is on stderr",
    };
}

/// The widest a finite limit renders.
const limit_text_bytes = std.fmt.count("{d}", .{std.math.maxInt(u64)});

/// One `RLIMIT_NOFILE` bound as an operator reads it: a number, or the
/// word for no limit at all, which as a number would read as a bug.
fn limitText(value: ?u64, buffer: []u8) []const u8 {
    assert(buffer.len == limit_text_bytes);
    const finite = value orelse return "unlimited";
    // The buffer is sized for the widest `u64`, so the format cannot
    // overrun it.
    const rendered = std.fmt.bufPrint(buffer, "{d}", .{finite}) catch unreachable;
    assert(rendered.len <= limit_text_bytes);
    return rendered;
}

/// The §8 access-log sink as the fd `XevIo` will write: the inherited
/// stdout, or the file the config named — opened here, before the loop
/// exists, so a path that cannot open stops the process while the banner
/// above still names what it tried.
fn openLogSinkFd(config: *const Config) !@TypeOf(XevIo.log_sink_stdout) {
    const sink = config.access_log_sink orelse return XevIo.log_sink_stdout;
    switch (sink) {
        .stdout => return XevIo.log_sink_stdout,
        .file => |path| {
            // An empty path is refused when the config is built (§8), so
            // a failure here is the filesystem's answer, not a shape.
            assert(path.len >= 1);
            return XevIo.openLogSink(path) catch |err| {
                std.debug.print("zoxy: cannot open access log '{s}': {t}\n", .{ path, err });
                return err;
            };
        },
    }
}

/// Every listener's default certificate pair, parsed from the bytes the
/// config carries (§4, #417): one slot per listener, null where the
/// listener is plaintext. This is where a bad certificate stops the
/// proxy, rather than on the first handshake, where it would read as a
/// failed connection instead of a wrong config.
fn loadTlsCredentials(arena: std.mem.Allocator, config: *const Config) ![]const ?Credentials {
    assert(config.listeners.len >= 1);
    if (config.limits.tls_engines == 0 and !config_module.originTls(config.clusters)) {
        // No listener terminates TLS and no origin is reached over it:
        // nothing to load, and no libcrypto heap to reserve either.
        return &.{};
    }
    // Before any credential: `Credentials.load` calls libcrypto, and the
    // allocator swap is refused once anything has allocated. If it fails
    // the zero-allocation promise (§5) is unbacked, and a proxy that
    // cannot keep its own invariants should not start.
    if (!libcrypto_heap.install(&libcrypto_heap_storage)) {
        std.debug.print(
            "zoxy: libcrypto refused the fixed-heap install; " ++
                "the zero-allocation budget (DESIGN.md §5) cannot be kept\n",
            .{},
        );
        return error.LibcryptoHeapUnavailable;
    }
    const credentials = try arena.alloc(?Credentials, config.listeners.len);
    for (config.listeners, credentials, 0..) |listener, *slot, index| {
        const tls = listener.tls orelse {
            slot.* = null;
            continue;
        };
        slot.* = Credentials.load(arena, tls.cert_pem, tls.key_pem, .{}) catch |err| {
            std.debug.print("zoxy: listener {d} cannot use {s}: {t}\n", .{ index, tls.label, err });
            return err;
        };
    }
    // One slot per listener, in listener order: `Server` indexes this by
    // listener index.
    assert(credentials.len == config.listeners.len);
    return credentials;
}

/// Every listener's further certificates (#297), parsed beside its
/// default and named by the DNS names each leaf covers. A further
/// certificate that names no DNS host could never be chosen, so it stops
/// startup rather than sit in the table as a typo nobody notices.
fn loadTlsCertificateSets(
    arena: std.mem.Allocator,
    config: *const Config,
    credentials: []const ?Credentials,
) ![]const []const certificate_set.Choice {
    if (credentials.len == 0) return &.{};
    assert(credentials.len == config.listeners.len);
    const sets = try arena.alloc([]const certificate_set.Choice, credentials.len);
    for (config.listeners, credentials, sets, 0..) |listener, *default_credentials, *set, index| {
        set.* = &.{};
        const tls = listener.tls orelse continue;
        if (tls.certificates.len == 0) continue;
        set.* = try loadCertificateSet(arena, &tls, &default_credentials.*.?, index);
    }
    assert(sets.len == credentials.len);
    return sets;
}

/// One listener's set: its default first, then each further pair in
/// config order.
fn loadCertificateSet(
    arena: std.mem.Allocator,
    tls: *const Config.Listener.Tls,
    default_credentials: *const Credentials,
    index: usize,
) ![]const certificate_set.Choice {
    assert(tls.certificates.len >= 1);
    const choices = try arena.alloc(certificate_set.Choice, 1 + tls.certificates.len);
    choices[0] = .{
        .credentials = default_credentials,
        .names = try leafNames(arena, default_credentials, tls.label, index),
        .schemes = default_credentials.schemes(),
    };
    const loaded = try arena.alloc(Credentials, tls.certificates.len);
    for (tls.certificates, loaded, choices[1..]) |certificate, *credentials, *choice| {
        credentials.* = Credentials.load(arena, certificate.cert_pem, certificate.key_pem, .{}) catch |err| {
            std.debug.print("zoxy: listener {d} cannot use {s}: {t}\n", .{ index, certificate.label, err });
            return err;
        };
        choice.* = .{
            .credentials = credentials,
            .names = try leafNames(arena, credentials, certificate.label, index),
            .schemes = credentials.schemes(),
        };
        if (choice.names.len == 0) {
            std.debug.print(
                "zoxy: listener {d}: {s} names no DNS host, so no server name could choose it\n",
                .{ index, certificate.label },
            );
            return error.CertificateNamesNoHost;
        }
    }
    assert(choices[0].credentials == default_credentials);
    return choices;
}

/// The DNS names a loaded certificate's leaf covers, or a startup error
/// naming the pair by its label.
fn leafNames(
    arena: std.mem.Allocator,
    credentials: *const Credentials,
    label: []const u8,
    index: usize,
) ![]const []const u8 {
    assert(credentials.chain.len >= 1);
    assert(label.len >= 1);
    return trust.dnsNames(arena, credentials.chain[0]) catch |err| {
        std.debug.print("zoxy: listener {d}: cannot read the names in {s}: {t}\n", .{ index, label, err });
        return err;
    };
}

test "checkExitFor: the box's refusals are told from the config's" {
    // What the operator does next is the whole distinction (#301): these
    // say "run it elsewhere"…
    try std.testing.expectEqual(CheckExit.does_not_fit, checkExitFor(error.OutOfMemory));
    try std.testing.expectEqual(CheckExit.does_not_fit, checkExitFor(error.LibcryptoHeapUnavailable));
    // The one value `ensureFdBudget` collapses every kernel answer into,
    // and the reason it has a distinct value at all.
    try std.testing.expectEqual(CheckExit.does_not_fit, checkExitFor(error.FdBudgetUnsatisfiable));
    // A name this box's resolver does not know may be known on the next
    // one (#480); a misspelled name says so on stderr beside the verdict.
    try std.testing.expectEqual(CheckExit.does_not_fit, checkExitFor(error.EndpointNameUnresolved));
    // …and everything else says "change the file", including a path in
    // it that would not open, which is the arm most worth pinning: a CI
    // job must not learn to ignore the code a real mistake also earns.
    try std.testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.FileNotFound));
    try std.testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.AccessDenied));
    try std.testing.expectEqual(CheckExit.invalid_config, checkExitFor(error.MissingField));
    // The codes themselves are the CI contract, so they are asserted
    // rather than left to the declaration order.
    try std.testing.expectEqual(@as(u8, 0), @backingInt(CheckExit.ok));
    try std.testing.expectEqual(@as(u8, 1), @backingInt(CheckExit.invalid_config));
    try std.testing.expectEqual(@as(u8, 2), @backingInt(CheckExit.does_not_fit));
}

test "limitText: no limit reads as a word, not as the largest number" {
    var buffer: [limit_text_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("1024", limitText(1024, &buffer));
    try std.testing.expectEqualStrings("0", limitText(0, &buffer));
    try std.testing.expectEqualStrings("unlimited", limitText(null, &buffer));
    // The buffer is wide enough for the widest value, which is what the
    // `catch unreachable` inside rests on.
    try std.testing.expectEqual(limit_text_bytes, limitText(std.math.maxInt(u64), &buffer).len);
}

test "App: a selection the build does not list is refused at startup (#417)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var instance: u8 = 0;
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const bind = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080");
    // Index 0 of a list the stock build leaves empty: a selection made by
    // hand, since `picker` cannot make one for a type nobody listed.
    const options: Options = .{
        .listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .l4 = .{ .target = .{ .cluster = "origin" } } } }},
        .clusters = &.{.{
            .name = "origin",
            .endpoints = &.{.{ .address = .{ .ip = origin } }},
            .pick = .{ .extension = .{ .index = 0, .instance = &instance } },
        }},
        .timeouts = .{ .connect_ms = 1_000, .idle_ms = 5_000, .head_ms = 2_000, .tunnel_ms = 60_000, .health_interval_ms = 2_000 },
        .limits = .{},
    };
    const config = try config_module.resolve(arena, &options);
    try std.testing.expectError(error.ExtensionUnserved, App(.{}).refuseUnservedSelections(&config));
    // The same options, in a build that lists a picker, are served.
    const Picker = struct {
        pub fn pick(_: *@This(), _: *const extension.Candidates, _: *const extension.PickInput) u16 {
            return 0;
        }
    };
    try App(.{ .pickers = &.{Picker} }).refuseUnservedSelections(&config);

    // A route's policy is held to the policies list the same way.
    var routed = options;
    routed.clusters = &.{.{
        .name = "origin",
        .endpoints = &.{.{ .address = .{ .ip = origin } }},
        .pick = .p2c,
    }};
    routed.listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .http = .{
        .target = .{ .routes = &.{.{
            .prefix = "/",
            .cluster = "origin",
            .request_policies = &.{.{ .index = 0, .instance = &instance }},
        }} },
        .max_body_bytes = 0,
        .keepalive_requests = 0,
    } } }};
    const routed_config = try config_module.resolve(arena, &routed);
    try std.testing.expectError(error.ExtensionUnserved, App(.{ .pickers = &.{Picker} }).refuseUnservedSelections(&routed_config));
}

test "App: a selection names the build's own type" {
    const Picker = struct {
        pub fn pick(
            instance: *@This(),
            candidates: *const extension.Candidates,
            input: *const extension.PickInput,
        ) u16 {
            _ = instance;
            _ = candidates;
            _ = input;
            return 0;
        }
    };
    const Policy = struct {
        pub fn evaluate(instance: *@This(), request: *const extension.Request) extension.Verdict {
            _ = instance;
            _ = request;
            return .proceed;
        }
    };
    const Built = App(.{ .pickers = &.{Picker}, .request_policies = &.{Policy} });
    var picker: Picker = .{};
    var policy: Policy = .{};
    const pick = Built.picker(&picker);
    try std.testing.expect(pick == .extension);
    try std.testing.expect(pick.extension.instance == @as(*anyopaque, &picker));
    const selection = Built.policy(&policy);
    try std.testing.expectEqual(@as(u8, 0), selection.index);
    try std.testing.expect(selection.instance == @as(*anyopaque, &policy));
}

test "App: a head buffer smaller than the widest answer's head is refused at startup (#431)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // Two long headers: a head past the smallest buffer a listener may
    // configure, and well inside the default.
    const long_bytes: [700]u8 = @splat('a');
    const long: []const u8 = &long_bytes;
    const Wide = struct {
        pub const answers = .{
            .wide = extension.Answer{
                .status = 503,
                .headers = &.{ .{ .name = "X-First", .value = long }, .{ .name = "X-Second", .value = long } },
            },
        };
        pub fn evaluate(_: *@This(), _: *const extension.Request) extension.Verdict {
            return .proceed;
        }
    };
    const Built = App(.{ .request_policies = &.{Wide} });
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const bind = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080");
    var options: Options = .{
        .listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .l4 = .{ .target = .{ .cluster = "origin" } } } }},
        .clusters = &.{.{ .name = "origin", .endpoints = &.{.{ .address = .{ .ip = origin } }}, .pick = .p2c }},
        .timeouts = .{ .connect_ms = 1_000, .idle_ms = 5_000, .head_ms = 2_000, .tunnel_ms = 60_000, .health_interval_ms = 2_000 },
        .limits = .{ .head_buffer_bytes = 1024 },
    };
    const small = try config_module.resolve(arena, &options);
    try std.testing.expectError(error.AnswerHeadOverBuffer, Built.refuseUnfitAnswers(&small));
    options.limits = .{};
    const default = try config_module.resolve(arena, &options);
    try Built.refuseUnfitAnswers(&default);
    // A build whose policies declare none is never refused for it.
    try App(.{}).refuseUnfitAnswers(&small);
}

test "App: a consulting policy with no consult slot is refused at step zero, as `--check` sees it (#437)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const defaults = @import("defaults.zig");
    const Consulting = @import("testing/consult.zig").ScriptedConsult(.closed);
    const Built = App(.{ .request_policies = &.{Consulting} });
    var policy: Consulting = .{ .cluster_name = "origin" };
    const origin = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:9000");
    const bind = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:8080");
    const routes = [_]Options.Listener.Route{.{ .prefix = "/", .cluster = "origin" }};
    const selections = [_]extension.Selection{Built.policy(&policy)};
    var options: Options = .{
        .listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .http = .{
            .target = .{ .routes = &routes },
            .request_policies = &selections,
            .max_body_bytes = defaults.max_body_bytes,
            .keepalive_requests = defaults.keepalive_requests,
        } } }},
        .clusters = &.{.{ .name = "origin", .endpoints = &.{.{ .address = .{ .ip = origin } }}, .pick = .p2c }},
        .timeouts = defaults.timeouts,
        .limits = .{},
    };
    try std.testing.expectError(error.ConsultSlotsRequired, Built.resolveServed(arena, &options));
    options.limits = .{ .consult_slots = 1 };
    _ = try Built.resolveServed(arena, &options);
    // A selection at a route counts as one at the listener does.
    const guarded = [_]Options.Listener.Route{.{ .prefix = "/", .cluster = "origin", .request_policies = &selections }};
    options.listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .http = .{
        .target = .{ .routes = &guarded },
        .max_body_bytes = defaults.max_body_bytes,
        .keepalive_requests = defaults.keepalive_requests,
    } } }};
    options.limits = .{};
    try std.testing.expectError(error.ConsultSlotsRequired, Built.resolveServed(arena, &options));
    // A build that lists the type but selects none of it reserves nothing.
    options.listeners = &.{.{ .bind = .{ .ip = bind }, .protocol = .{ .l4 = .{ .target = .{ .cluster = "origin" } } } }};
    options.limits = .{};
    _ = try Built.resolveServed(arena, &options);
}
