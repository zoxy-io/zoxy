const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The "zoxy" module: everything under src/ rooted at root.zig, which
    // re-exports the public components and aggregates every module's tests.
    const mod = b.addModule("zoxy", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // OpenSSL (vendored, built by the Zig build system — no system library).
    // Linked into the "zoxy" module only: src/tls/ holds the FFI, and the
    // simulator (which imports source files directly, not the module) stays
    // free of it — TLS never enters the simulated data path.
    const openssl_dependency = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });
    const openssl_library = openssl_dependency.artifact("openssl");
    mod.linkLibrary(openssl_library);
    // Also installed (zig-out/lib/libopenssl.a) for builds that bypass the
    // build graph and must link it by path: scripts/coverage.sh.
    b.installArtifact(openssl_library);

    const exe = b.addExecutable(.{
        .name = "zoxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Keep frame pointers even in release builds: `perf record
            // --call-graph fp` then works on the production binary, and the
            // cost is a register we can spare. (DWARF unwinding needs
            // permissions perf often lacks.)
            .omit_frame_pointer = false,
            .imports = &.{
                .{ .name = "zoxy", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    // A Zig test binary tests one module at a time, hence two: the "zoxy"
    // module (all library tests via root.zig) and the executable's root.
    // -Dtest-filter narrows by test-name substring (raw `zig test` on
    // src/root.zig no longer works: it would not link the OpenSSL library).
    const test_filters: []const []const u8 = if (b.option(
        []const u8,
        "test-filter",
        "Run only tests whose name contains this substring",
    )) |filter| b.dupeStrings(&.{filter}) else &.{};
    const mod_tests = b.addTest(.{ .root_module = mod, .filters = test_filters });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const exe_tests = b.addTest(.{ .root_module = exe.root_module, .filters = test_filters });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // The deterministic simulator: the real data path on the simulation IO
    // backend (src/sim.zig declares `zoxy_io = .simulation`). Debug/safe
    // builds only make sense here — the asserts are the test oracle.
    const sim_exe = b.addExecutable(.{
        .name = "sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/sim.zig"),
            .target = target,
            .optimize = optimize,
            .omit_frame_pointer = false,
            .unwind_tables = .sync,
        }),
    });
    // The simulator imports proxy.zig, which now references the TLS
    // terminator's externs — linked even though the sim runs plaintext
    // (its ProxyServer keeps tls_context = null).
    sim_exe.root_module.linkLibrary(openssl_library);
    const run_sim = b.addRunArtifact(sim_exe);
    if (b.args) |args| run_sim.addArgs(args);
    const sim_step = b.step("sim", "Run the deterministic simulator (args: [seed] [iterations])");
    sim_step.dependOn(&run_sim.step);

    // Line-length lint (TigerStyle's 100-column hard limit, docs/TIGER_STYLE.md):
    // kept in Zig rather than shell, per the tooling convention. CI runs this
    // same `zig build lint`, so local and CI share one enforcement path.
    const lint_exe = b.addExecutable(.{
        .name = "check_line_length",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/check_line_length.zig"),
            .target = b.graph.host,
        }),
    });
    const run_lint = b.addRunArtifact(lint_exe);
    add_zig_sources(b, run_lint, "src");
    run_lint.addFileArg(b.path("build.zig"));
    run_lint.addFileArg(b.path("scripts/check_line_length.zig"));
    run_lint.addFileArg(b.path("scripts/config_tool.zig"));
    const lint_step = b.step("lint", "Check the 100-column line-length limit");
    lint_step.dependOn(&run_lint.step);

    // Config JSON Schema (docs/DESIGN.md §7 Phase 6, slice 1). A host tool
    // reflects the schema from the config DTO — config.zig is FFI-free, so this
    // links no OpenSSL. `schema` regenerates the committed file; `check-config`
    // guards it against drift and strict-parses zoxy.json.
    const config_schema_mod = b.createModule(.{
        .root_source_file = b.path("src/config_schema.zig"),
        .target = b.graph.host,
    });
    const config_tool = b.addExecutable(.{
        .name = "config_tool",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/config_tool.zig"),
            .target = b.graph.host,
            .imports = &.{.{ .name = "config_schema", .module = config_schema_mod }},
        }),
    });

    const emit_schema = b.addRunArtifact(config_tool);
    emit_schema.addArg("emit");
    const generated_schema = emit_schema.captureStdOut(.{ .basename = "config.schema.json" });
    const write_schema = b.addUpdateSourceFiles();
    write_schema.addCopyFileToSource(generated_schema, "config.schema.json");
    const schema_step = b.step("schema", "Regenerate config.schema.json from the config DTO");
    schema_step.dependOn(&write_schema.step);

    const check_config = b.addRunArtifact(config_tool);
    check_config.addArg("check");
    check_config.addFileArg(b.path("config.schema.json"));
    check_config.addFileArg(b.path("zoxy.json"));
    const check_config_step = b.step(
        "check-config",
        "Verify config.schema.json is current and zoxy.json is valid",
    );
    check_config_step.dependOn(&check_config.step);

    // Zoxyfile DSL → JSON adapter (docs/DESIGN.md §7 Phase 6, slice 3). Prints
    // the JSON `config.zig` parses: `zig build adapt -- examples/example.zoxy`.
    const adapt = b.addRunArtifact(config_tool);
    adapt.addArg("adapt");
    if (b.args) |args| adapt.addArgs(args);
    const adapt_step = b.step("adapt", "Adapt a Zoxyfile DSL config to JSON (args: <file.zoxy>)");
    adapt_step.dependOn(&adapt.step);
}

/// Add every `.zig` file under `dir_path` (recursively) to `run` as a file
/// argument: the lint tool receives their absolute paths and the step re-runs
/// when any changes. The file set is resolved once, at configure time.
fn add_zig_sources(b: *std.Build, run: *std.Build.Step.Run, dir_path: []const u8) void {
    const io = b.graph.io;
    var dir = b.build_root.handle.openDir(io, dir_path, .{ .iterate = true }) catch |err|
        std.debug.panic("lint: cannot open {s}: {s}", .{ dir_path, @errorName(err) });
    defer dir.close(io);
    var walker = dir.walk(b.allocator) catch @panic("lint: walk failed");
    defer walker.deinit();
    while (walker.next(io) catch @panic("lint: walk failed")) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        run.addFileArg(b.path(b.fmt("{s}/{s}", .{ dir_path, entry.path })));
    }
}
