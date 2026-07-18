//! CPU-affinity helpers shared by the bench harnesses (DESIGN.md §9):
//! dedicate one core to the process under test and pin the load
//! generator and origin off it, so the latency bands and the hardware
//! PMU measure the proxy — not contention with the generator — and match
//! zoxy's one-loop-per-core deployment (§3). Pure Zig, Linux-only; every
//! entry point is a no-op on other targets so the harnesses still build
//! and run (unpinned) on a macOS dev box.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const linux = std.os.linux;

const assert = std.debug.assert;

pub const CpuSet = linux.cpu_set_t;
const cpu_bits = @bitSizeOf(usize);
const cpu_set_words = @typeInfo(CpuSet).array.len;

/// Choose the dedicated core (`override`, else the last P-core, else the
/// last cpu), pin the calling process to every *other* core so its
/// threads and any children it spawns inherit that mask, and return the
/// dedicated core. Null on non-Linux: the caller runs unpinned. Pin
/// children onto the returned core with `pinChildTo`.
pub fn dedicate(io: Io, override: ?u16) ?u16 {
    if (comptime builtin.os.tag != .linux) {
        return null;
    }
    var universe: CpuSet = undefined;
    _ = linux.sched_getaffinity(0, @sizeOf(CpuSet), &universe);
    const cpu = override orelse detectPCore(io) orelse maxCpu(&universe);
    assert(cpu < cpu_set_words * cpu_bits);
    var others = universe;
    cpuClear(&others, cpu);
    // A failed pin only makes the bench less isolated (bands noisier), it
    // never stops it running — benchmarking is best-effort, not a gate.
    linux.sched_setaffinity(0, &others) catch {};
    return cpu;
}

/// Pin a spawned child (the proxy under test) to the dedicated core.
pub fn pinChildTo(pid: std.process.Child.Id, cpu: u16) void {
    if (comptime builtin.os.tag != .linux) {
        return;
    }
    assert(cpu < cpu_set_words * cpu_bits);
    var only = cpuZero();
    cpuSet(&only, cpu);
    // Best-effort like `dedicate`: a failed pin degrades isolation, not
    // correctness.
    linux.sched_setaffinity(pid, &only) catch {};
}

fn cpuZero() CpuSet {
    return @splat(0);
}

fn cpuSet(set: *CpuSet, cpu: u16) void {
    set[cpu / cpu_bits] |= @as(usize, 1) << @intCast(cpu % cpu_bits);
}

fn cpuClear(set: *CpuSet, cpu: u16) void {
    set[cpu / cpu_bits] &= ~(@as(usize, 1) << @intCast(cpu % cpu_bits));
}

fn cpuIsSet(set: *const CpuSet, cpu: u16) bool {
    return set[cpu / cpu_bits] & (@as(usize, 1) << @intCast(cpu % cpu_bits)) != 0;
}

fn maxCpu(set: *const CpuSet) u16 {
    var cpu: u16 = cpu_set_words * cpu_bits;
    while (cpu > 0) {
        cpu -= 1;
        if (cpuIsSet(set, cpu)) return cpu;
    }
    return 0;
}

/// Last cpu id listed in the hybrid P-core sysfs mask (e.g. "0-3" -> 3),
/// so the process under test lands on a performance core. Null when the
/// file is absent (not hybrid, or an older kernel) — the caller falls
/// back to the last available cpu.
fn detectPCore(io: Io) ?u16 {
    const file = Io.Dir.cwd().openFile(io, "/sys/devices/cpu_core/cpus", .{}) catch return null;
    defer file.close(io);
    var read_buffer: [256]u8 = undefined;
    var file_reader = file.reader(io, &read_buffer);
    var content: [256]u8 = undefined;
    const len = file_reader.interface.readSliceShort(&content) catch return null;
    // Take the last run of digits: the highest cpu id in the mask.
    var last: ?u16 = null;
    var current: ?u32 = null;
    for (content[0..len]) |char| {
        if (char >= '0' and char <= '9') {
            current = (current orelse 0) * 10 + (char - '0');
        } else if (current) |value| {
            last = std.math.cast(u16, value) orelse last;
            current = null;
        }
    }
    if (current) |value| last = std.math.cast(u16, value) orelse last;
    return last;
}
