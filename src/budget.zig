//! The startup budget (DESIGN.md §5, §8): the closed form that prices
//! every pool this process holds for its life, the fd and ring demands
//! the *effective* config makes, and the banner that prints both.
//!
//! It lives beside `Server` rather than inside `main` because it is the
//! one part of startup an embedder (§13) cannot reasonably rewrite: the
//! closed form has to price exactly what `Server.init` reserves, and a
//! second derivation that drifted would break §5's promise — that the
//! printed total covers everything this process holds — while still
//! looking correct. `main.zig` keeps what is genuinely the application's:
//! reading files, raising `RLIMIT_NOFILE`, installing signal handlers.
//!
//! Generic over the Io backend for the same reason `Server` is: a conn
//! slot's size and an upstream slot's size are properties of the backend,
//! so the closed form cannot be stated without one.

const std = @import("std");

const config_module = @import("config.zig");
const constants = @import("constants.zig");
const Io = @import("io/io.zig");
const RelayBuffer = @import("net/relay.zig").RelayBuffer;
const Server = @import("Server.zig").Server;
const TlsEngine = @import("tls/Engine.zig");
const upstream_module = @import("net/upstream.zig");

const assert = std.debug.assert;

pub fn Budget(comptime IoType: type) type {
    Io.assertIoInterface(IoType);

    return struct {
        const ServerType = Server(IoType);
        const UpstreamType = upstream_module.UpstreamPool(IoType).Upstream;

        /// What the effective config demands of the process before a
        /// single connection is admitted (§8): both are pre-budgeted
        /// rather than shed, so both are known here and neither is ever
        /// a ladder rung.
        pub const Demands = struct {
            /// Listeners + conn slots + upstream slots + the ring, async
            /// and signal fds, asserted against `RLIMIT_NOFILE` by
            /// whoever can raise it.
            fds: u32,
            /// The depth the ring must be *created* with, so the
            /// worst-case in-flight ops stay within the configured fill
            /// (§4). Not the SQ, which is `constants.ring_entries`.
            cq_entries: u32,
        };

        /// What the banner's first line stamps. The name on it is zoxy's
        /// either way — what follows is the budget of zoxy's pools, and
        /// `bench/run.zig` parses these lines from outside the process —
        /// so an embedder names itself on a line of its own rather than
        /// through this.
        pub const Build = struct {
            version: []const u8,
            /// `main`'s `git describe` suffix, or empty where the build
            /// cannot say what it is. Printed verbatim, separator
            /// included.
            id_suffix: []const u8 = "",
        };

        /// The §5/§8 demands of the *effective* config, not the compiled
        /// ceilings — a lean deployment neither demands the c10k
        /// `RLIMIT_NOFILE` nor asks the kernel for a 65536-deep ring.
        pub fn demandsFor(config: *const config_module.Config) Demands {
            assert(config.listeners.len >= 1);
            const listeners_count: u32 = @intCast(config.listeners.len);
            const access_log_files: u32 = if (config.access_log_sink) |sink|
                @intFromBool(sink == .file)
            else
                0;
            // The prober's effective probe count (§7, #132): a config
            // with no `check` block anywhere reserves the one probe's
            // worth it always did, so this term moves nothing for a
            // deployment that did not ask for health checks.
            const health_probes = config.healthProbes();
            const demands: Demands = .{
                .fds = constants.fdsRequired(
                    config.limits.conn_slots,
                    config.limits.upstream_slots,
                    listeners_count,
                    access_log_files,
                    health_probes,
                ),
                .cq_entries = constants.completionQueueDepthFor(
                    config.limits.conn_slots,
                    config.limits.upstream_slots,
                    listeners_count,
                    health_probes,
                    config.limits.cq_fill_eighths,
                ),
            };
            // The effective config never exceeds the compiled ceilings
            // (§8): the pools, the ring and the fd demand all fit what
            // the constants proved. A demand of zero would mean a proxy
            // that reserved nothing — the closed form broke.
            assert(demands.cq_entries <= constants.completion_queue_entries);
            assert(demands.fds > 0);
            return demands;
        }

        /// The §5 pool-size vector for the effective config: every term
        /// the closed form takes, sourced from the limit or `@sizeOf`
        /// that owns it.
        pub fn poolSizesFor(config: *const config_module.Config) constants.PoolSizes {
            const limits = config.limits;
            // The head-sized side buffers (§5): Server owns the closed
            // form and asserts its own allocations against it, so
            // pricing it here cannot drift from what init reserves.
            const head_scratch_bytes = ServerType.headScratchBytes(limits, config.healthProbes());
            assert(head_scratch_bytes >= limits.head_buffer_bytes);
            assert(limits.conn_slots >= 1);
            return .{
                .conn_slots = limits.conn_slots,
                .conn_bytes = @sizeOf(ServerType.ConnType),
                // One stream per connection (#274), derived from the
                // same limit `Server.init` sizes the pool from, so the
                // printed number and the reserved one cannot disagree.
                .stream_slots = constants.streamSlotsFor(limits.conn_slots),
                .stream_bytes = @sizeOf(ServerType.StreamType),
                .relay_buffers = limits.relay_buffers,
                // The pool element (free-list header and the two slab
                // slices) plus both halves it points at, the same shape
                // `upstream_head_buffer_bytes` below uses.
                .relay_buffer_pair_bytes = @sizeOf(RelayBuffer) +
                    2 * @as(u64, limits.relay_buffer_bytes),
                .upstream_slots = limits.upstream_slots,
                .upstream_bytes = @sizeOf(UpstreamType),
                .access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes),
                .log_header_bytes = ServerType.logHeaderBytes(config, constants.streamSlotsFor(limits.conn_slots)),
                .endpoint_table_bytes = ServerType.endpointTableBytes(config),
                .metrics_bytes = ServerType.metricsBytes(config),
                .head_buffers = limits.head_buffers,
                .head_buffer_bytes = limits.head_buffer_bytes,
                .upstream_head_buffers = limits.upstream_head_buffers,
                // The pool element (the free-list header and the slab
                // slice) plus its share of the slab itself.
                .upstream_head_buffer_bytes = @sizeOf(upstream_module.HeadBuffer) +
                    limits.head_buffer_bytes,
                .head_scratch_bytes = head_scratch_bytes,
                // Zero unless a listener allows an upgrade, on the same
                // terms as the TLS terms below: a feature nobody asked
                // for costs nothing. Same element as a shared relay
                // buffer, reserved apart from it (§5) — the point of the
                // pool, not an accident of it.
                .tunnels = limits.tunnels,
                .tunnel_buffer_pair_bytes = if (limits.tunnels == 0)
                    0
                else
                    @sizeOf(RelayBuffer) + 2 * @as(u64, limits.relay_buffer_bytes),
                // Zero unless a listener terminates TLS, which is what
                // makes the whole feature free to a deployment that did
                // not ask for it. The three terms move together:
                // `limits.tls_engines` is zero exactly when no listener
                // has a `tls` block.
                .tls_engines = limits.tls_engines,
                .tls_engine_bytes = if (limits.tls_engines == 0) 0 else @sizeOf(TlsEngine),
                .tls_plaintext_bytes = if (limits.tls_engines == 0)
                    0
                else
                    TlsEngine.plaintextBytesFor(limits.head_buffer_bytes),
                // The whole compiled reservation, not this config's
                // share of it: the storage is one static array sized at
                // `tls_engines_max` (it must outlive the arena — see
                // `main.zig`'s `libcrypto_heap_storage`), so that is what
                // the process holds for its life whatever `tls_engines`
                // says, and §5 prices what is held.
                .libcrypto_heap_bytes = if (limits.tls_engines == 0)
                    0
                else
                    constants.libcrypto_heap_bytes,
            };
        }

        /// Everything this process holds for its life, in bytes.
        ///
        /// The config arena is a term because it is never freed, and it
        /// is the one term *measured* rather than derived: there is no
        /// constant bounding a config file's size, so what the operator
        /// writes is what it costs and the only honest thing the budget
        /// can do is report it (§5).
        pub fn totalBytes(
            config: *const config_module.Config,
            config_arena_bytes: u64,
        ) u64 {
            const sizes = poolSizesFor(config);
            return totalBytesFor(&sizes, config_arena_bytes);
        }

        /// The same total for a caller that already holds the vector —
        /// the banner does, and deriving it twice would price one config
        /// through two evaluations of a form that must have exactly one.
        pub fn totalBytesFor(
            sizes: *const constants.PoolSizes,
            config_arena_bytes: u64,
        ) u64 {
            const total = constants.memoryBytesTotal(sizes) + config_arena_bytes;
            // A total of zero would be a proxy that reserved nothing.
            assert(total > 0);
            assert(total >= config_arena_bytes);
            return total;
        }

        /// The §5 banner, to **stderr**: the banner is diagnostics, and
        /// stdout belongs to the data an operator may point there — the
        /// access log's `stdout` sink must stay one uncontaminated JSON
        /// line per event. Stderr is where the counter dump already
        /// goes, and via the same `std.debug.print` plain-write path, so
        /// the two interleave whole-lines even when both land in one
        /// redirected file (a positional writer here would be silently
        /// overwritten by the dump's shared-offset writes).
        pub fn print(
            config: *const config_module.Config,
            demands: Demands,
            /// What the config text and its parsed structures took from
            /// the startup arena, measured (§5).
            config_arena_bytes: u64,
            build: Build,
        ) void {
            assert(config.listeners.len >= 1);
            assert(demands.fds > 0);
            // Every budget reflects the *effective* config (§5, §8): the
            // config may shrink the pools, the fd demand and the
            // requested ring below the compiled ceilings, and all three
            // are shown as actually sized.
            const limits = config.limits;
            const in_flight = constants.inFlightOps(
                limits.conn_slots,
                limits.upstream_slots,
                @intCast(config.listeners.len),
                config.healthProbes(),
            );
            const access_log_bytes = constants.accessLogBytes(limits.access_log_buffer_bytes);
            const sizes = poolSizesFor(config);
            const memory_total = totalBytesFor(&sizes, config_arena_bytes);
            printMemoryBanner(config, &sizes, memory_total, access_log_bytes, config_arena_bytes, build);
            // A stack temporary in a function that runs once at startup,
            // not a reservation (§5).
            var fact_buffer: [failure_detection_fact_bytes]u8 = undefined;
            std.debug.print(
                \\  fds     {d} required (asserted against RLIMIT_NOFILE)
                \\  ring    {d} entries, completion queue {d}, in-flight ops <= {d}
                \\  config  {d} listener(s), {d} cluster(s), {d} error page(s), access log {s}{s}
                \\
            , .{
                demands.fds,
                constants.ring_entries,
                demands.cq_entries,
                in_flight,
                config.listeners.len,
                config.clusters.len,
                // Their rendered bytes live in the config arena term
                // above — read and pre-rendered at load (#159), so the
                // measured number already covers them; this count is
                // what says why it grew.
                config.error_pages.len,
                if (config.access_log_sink) |sink| @tagName(sink) else "off",
                failureDetectionFact(config, &fact_buffer),
            });
        }

        /// The rendering `failure_detection_fact_bytes` is the width of.
        /// One literal, used by the format below *and* by the buffer that
        /// holds it, so a reworded fact cannot silently outgrow its
        /// buffer — the two used to agree only by a copied string.
        const failure_detection_fact_format = ", {d} cluster(s) without failure detection";

        /// The widest that fact can render: the literal with a `u32` at
        /// full width in place of `{d}`.
        const failure_detection_fact_bytes =
            failure_detection_fact_format.len - "{d}".len +
            std.fmt.count("{d}", .{std.math.maxInt(u32)});

        /// The §7 failure-detection fact (#230), appended to the config
        /// line: how many clusters could lose an endpoint and never
        /// notice.
        ///
        /// Empty when there are none, which is deliberately unlike the
        /// tunnel and TLS terms above — those print their zeros to say
        /// "you are not paying for this", where a *pool* at zero is a
        /// standing fact about the deployment. This is not a pool; it is
        /// a count of a gap, and a gap that does not exist has nothing to
        /// report rather than a zero worth reading.
        ///
        /// This is the whole visibility answer #230 asked for, and it is
        /// deliberately not a warning. The banner is what a bug report
        /// pastes, so "why did traffic keep going to a dead backend?"
        /// becomes answerable without a round trip; a warning on a valid
        /// config would decay into noise and take the rest of stderr with
        /// it. §8's own line for the same idea: the budget is printed,
        /// not hoped for.
        fn failureDetectionFact(
            config: *const config_module.Config,
            buffer: []u8,
        ) []const u8 {
            // The claim the `catch unreachable` below rests on, checked
            // rather than argued: this buffer is the one `print` sized.
            assert(buffer.len == failure_detection_fact_bytes);
            const count = config.clustersWithoutFailureDetection();
            if (count == 0) return "";
            const rendered = std.fmt.bufPrint(
                buffer,
                failure_detection_fact_format,
                .{count},
            ) catch unreachable; // The assert above covers every u32.
            assert(rendered.len <= failure_detection_fact_bytes);
            return rendered;
        }

        /// The banner's version and memory lines — the §5 closed form
        /// itemized. Split from `print` for the length limit; the two
        /// prints are sequential same-thread writes to stderr, so
        /// nothing interleaves.
        fn printMemoryBanner(
            config: *const config_module.Config,
            sizes: *const constants.PoolSizes,
            memory_total: u64,
            access_log_bytes: u64,
            config_arena_bytes: u64,
            build: Build,
        ) void {
            assert(memory_total > 0);
            assert(config.listeners.len >= 1);
            const limits = config.limits;
            // The version leads, because this banner is what a bug
            // report pastes and `--version` is what it does not think to
            // run.
            std.debug.print(
                \\zoxy {s}{s}
                \\budgets (DESIGN.md §5/§8; closed-form except where marked):
                \\  memory  total {d} KiB = conn slots {d} x {d} B + stream slots {d} x {d} B
                \\          + relay buffers {d} x {d} B
                \\          + upstream slots {d} x {d} B + head buffers {d} x {d} B (+ ring {d} B)
                \\          + upstream head buffers {d} x {d} B + head scratch {d} B
                \\          + access log {d} KiB (+ logged headers {d} B)
                \\          + endpoint tables {d} B ({d} cluster(s) x {d} wide)
                \\          + labeled metrics {d} B (tables, labels and render buffers)
                \\          + tunnels {d} x {d} B (their own relay buffers, never HTTP's)
                \\          + tls engines {d} x {d} B (+ plaintext {d} B each, libcrypto heap {d} KiB)
                \\          + config arena {d} KiB (measured, not closed-form)
                \\
            , .{
                build.version,
                build.id_suffix,
                memory_total / 1024,
                limits.conn_slots,
                sizes.conn_bytes,
                sizes.stream_slots,
                sizes.stream_bytes,
                limits.relay_buffers,
                sizes.relay_buffer_pair_bytes,
                limits.upstream_slots,
                sizes.upstream_bytes,
                limits.head_buffers,
                // The +1 ownership byte stays out of the banner's
                // per-unit figure; the closed-form total above carries it.
                limits.head_buffer_bytes,
                constants.bufferGroupDescriptorBytes(limits.head_buffers),
                limits.upstream_head_buffers,
                sizes.upstream_head_buffer_bytes,
                sizes.head_scratch_bytes,
                access_log_bytes / 1024,
                sizes.log_header_bytes,
                sizes.endpoint_table_bytes,
                config.clusters.len,
                ServerType.endpointKeysFor(config).stride,
                sizes.metrics_bytes,
                // Both read zero unless a listener allows an upgrade —
                // printed rather than omitted, on the same terms as the
                // TLS line below.
                limits.tunnels,
                sizes.tunnel_buffer_pair_bytes,
                // All four read zero on a plaintext deployment, which is
                // the line saying "you are not paying for this" rather
                // than omitting itself and leaving the reader to wonder.
                limits.tls_engines,
                sizes.tls_engine_bytes,
                sizes.tls_plaintext_bytes,
                sizes.libcrypto_heap_bytes / 1024,
                config_arena_bytes / 1024,
            });
        }
    };
}

const testing = std.testing;

test "demandsFor: the effective config sizes both demands, not the ceilings" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const config = try config_module.parse(arena_instance.allocator(), @embedFile("example_config"));

    const demands = BudgetSim.demandsFor(&config);
    // Both demands are the config's, so both must sit under what the
    // constants compiled — the assert `demandsFor` itself makes, restated
    // here against a config the loader actually accepted.
    try testing.expect(demands.cq_entries <= constants.completion_queue_entries);
    try testing.expect(demands.fds > config.limits.conn_slots);
    // A lean config must not demand the c10k ring: that is the whole
    // reason the depth is derived from the effective config (§4).
    try testing.expect(demands.cq_entries < constants.completion_queue_entries);
}

test "totalBytes: the measured arena joins the closed form" {
    const SimIo = @import("io/SimIo.zig");
    const BudgetSim = Budget(SimIo);

    var arena_instance = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_instance.deinit();
    const config = try config_module.parse(arena_instance.allocator(), @embedFile("example_config"));

    const pools_only = BudgetSim.totalBytes(&config, 0);
    const with_arena = BudgetSim.totalBytes(&config, 4096);
    // §5's promise is that the printed total covers everything held for
    // the process's life, the arena included — so the arena is a term,
    // not a rounding.
    try testing.expectEqual(pools_only + 4096, with_arena);
    try testing.expect(pools_only > 0);
}
