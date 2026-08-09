//! The fixed libcrypto heap (DESIGN.md §4, §5).
//!
//! libcrypto (the ztls crypto backend) mallocs internally during a
//! handshake; left on the libc heap those calls fault pages via
//! mmap/brk, breaking the "zero allocating syscalls after init" promise
//! (§5). This routes every libcrypto allocation into one fixed buffer
//! reserved at startup, via `ztls.mem_hooks` — so after `install`,
//! libcrypto never calls libc malloc and issues no allocating syscall.
//!
//! Design: **segregated fits.** Requests round up to a power-of-two size
//! class; each class owns an intrusive free list plus a bump frontier
//! into the shared buffer. Free returns a block to its class list (size
//! recovered from a 16-byte header); realloc that outgrows its class
//! allocates-copies-frees. No coalescing — blocks stay in their class —
//! which is why this is bounded and allocation-free but trades some
//! internal fragmentation, the standard fixed-FFI-heap shape. libcrypto's
//! handshake allocations are small and transient, exactly this heap's
//! sweet spot.
//!
//! Single-threaded: `CRYPTO_set_mem_functions` is process-global, but the
//! binary has one thread and every handshake runs on the loop (§3), so
//! the hooks take no lock. That is a standing property, not a phase — §1
//! records the worker-pool seam as retired, and CPU scale-out is
//! process-per-core. Crypto on a second thread would need a lock here.

const std = @import("std");

const ztls = @import("ztls");

const assert = std.debug.assert;

/// libcrypto expects malloc-grade alignment; also the header size, so a
/// payload starts 16-aligned right after its header.
const alignment = 16;

/// Smallest and largest served block payloads. A request above the max
/// is refused (null) — libcrypto handshake allocations sit well under
/// this; a refusal is a loud signal to raise the cap, never a silent
/// fallback to libc.
const class_bytes_min = alignment; // 16
const class_bytes_max = 64 * 1024;
const class_count = std.math.log2(@divExact(class_bytes_max, class_bytes_min)) + 1; // 13

comptime {
    // The size-class math assumes both bounds are powers of two and
    // min == alignment, so every class size is a multiple of alignment
    // and payloads stay aligned (§5: limit relationships comptime-asserted).
    assert(class_bytes_min == alignment);
    assert(std.math.isPowerOfTwo(class_bytes_min));
    assert(std.math.isPowerOfTwo(class_bytes_max));
    assert(class_bytes_max % alignment == 0);
}

/// A block header, `alignment` bytes so the payload is aligned. Purely
/// internal — libcrypto sees only the payload — so it carries the
/// size-class index (for free/realloc), a magic (a foreign or freed
/// pointer trips an assert, not silent corruption), and the free-list
/// link. The link is a distinct field, *not* aliased over `magic`, so
/// the free-time poison survives on a populated list.
const Header = struct {
    magic: u32,
    class: u32,
    next_free: ?*Header,

    const value: u32 = 0x7a_74_6c_73; // "ztls"
};

comptime {
    assert(@sizeOf(Header) == alignment);
    assert(@alignOf(Header) <= alignment);
}

/// Deliberately not `pub`: the singleton below is the only instance, and
/// an outside holder of one would be either a second frontier over the
/// same bytes or a pointer the hooks outlive. `install` and `usedPeak`
/// are the whole surface.
const Heap = struct {
    buffer: []align(alignment) u8,
    /// Bump frontier: bytes of `buffer` handed out and never returned to
    /// the frontier (freed blocks go to their class list, not here).
    used: usize,
    free_lists: [class_count]?*Header,
    /// Buffer high-water mark — the frontier only grows, so this is the
    /// peak reservation a workload actually needed: what sizes the
    /// production reservation, and the proof test's witness that
    /// libcrypto used this heap rather than libc's.
    used_peak: usize,

    /// In-place init via out-pointer (the pool-slot pattern). Nothing
    /// outside this file may hold a `Heap`: once the hooks are armed the
    /// singleton below is what libcrypto reaches through, and a second
    /// copy of the struct would have its own frontier over the same bytes.
    pub fn init(heap: *Heap, buffer: []align(alignment) u8) void {
        assert(buffer.len >= alignment + class_bytes_min);
        heap.* = .{
            .buffer = buffer,
            .used = 0,
            .free_lists = @splat(null),
            .used_peak = 0,
        };
    }

    /// Size class for a payload of `n` bytes (n > 0), or null if it
    /// exceeds the largest class.
    fn classOf(n: usize) ?u32 {
        assert(n > 0);
        const need = @max(n, class_bytes_min);
        if (need > class_bytes_max) return null;
        // Smallest power of two >= need, as a class index.
        const bits = std.math.log2_int_ceil(usize, need);
        const min_bits = comptime std.math.log2_int(usize, class_bytes_min);
        const class: u32 = @intCast(bits - min_bits);
        assert(class < class_count);
        return class;
    }

    fn classBytes(class: u32) usize {
        assert(class < class_count);
        return @as(usize, class_bytes_min) << @intCast(class);
    }

    pub fn alloc(heap: *Heap, n: usize) ?[*]u8 {
        if (n == 0) return null;
        const class = classOf(n) orelse return null;
        const block = heap.take(class) orelse return null;
        assert(@intFromPtr(block) % alignment == 0);
        const header: *Header = @ptrCast(block);
        header.* = .{ .magic = Header.value, .class = class, .next_free = null };
        return block + alignment;
    }

    /// A block for `class`: reuse a freed one, else carve from the
    /// frontier. Returns the header start (16-aligned), or null on
    /// exhaustion.
    fn take(heap: *Heap, class: u32) ?[*]align(alignment) u8 {
        assert(class < class_count);
        if (heap.free_lists[class]) |header| {
            heap.free_lists[class] = header.next_free;
            // The block was carved 16-aligned; the header sits at its start.
            return @alignCast(@as([*]u8, @ptrCast(header)));
        }
        const block_bytes = alignment + classBytes(class);
        if (heap.used + block_bytes > heap.buffer.len) return null;
        const block: [*]align(alignment) u8 = @alignCast(heap.buffer.ptr + heap.used);
        heap.used += block_bytes;
        if (heap.used > heap.used_peak) heap.used_peak = heap.used;
        assert(@intFromPtr(block) % alignment == 0);
        return block;
    }

    fn headerOf(payload: [*]u8) *Header {
        const block = payload - alignment;
        const header: *Header = @ptrCast(@alignCast(block));
        assert(header.magic == Header.value); // Foreign or already-freed pointer.
        assert(header.class < class_count);
        return header;
    }

    pub fn free(heap: *Heap, payload: ?[*]u8) void {
        const p = payload orelse return;
        const header = headerOf(p);
        const class = header.class;
        assert(class < class_count);
        header.magic = 0; // Poison: a double free re-enters headerOf and trips.
        header.next_free = heap.free_lists[class];
        heap.free_lists[class] = header;
        // The block is on its class's list and nowhere else — the frontier
        // never takes it back, which is why `used` cannot shrink here.
        assert(heap.free_lists[class] == header);
    }

    pub fn realloc(heap: *Heap, payload: ?[*]u8, n: usize) ?[*]u8 {
        const p = payload orelse return heap.alloc(n);
        if (n == 0) {
            heap.free(p);
            return null;
        }
        const header = headerOf(p);
        const have = classBytes(header.class);
        if (n <= have) return p; // Fits the existing class.
        assert(n > have); // What makes the copy below in-bounds at both ends.
        const fresh = heap.alloc(n) orelse return null;
        @memcpy(fresh[0..have], p[0..have]); // `have` is this block's own span.
        heap.free(p);
        return fresh;
    }
};

// The one heap the C-ABI hooks bind to. `CRYPTO_set_mem_functions` is
// process-global and takes bare function pointers with nowhere to hang a
// context, so the heap has to be reachable from a static — and if it has
// to be static, it lives here rather than in a caller who could hand over
// a stack frame that outlives nothing. That is not hypothetical: the
// earlier shape took a `*Heap`, and the proof test passed it a local,
// leaving the hooks reading a dead frame the moment that test returned.
//
// Written once by `install` before any libcrypto allocation, read-only
// thereafter (§3: one thread, so the hooks take no lock).
var global_heap: Heap = undefined;
var installed: bool = false;

fn hookMalloc(num: usize, file: ?[*:0]const u8, line: c_int) callconv(.c) ?*anyopaque {
    _ = file;
    _ = line;
    assert(installed);
    return global_heap.alloc(num);
}

fn hookRealloc(addr: ?*anyopaque, num: usize, file: ?[*:0]const u8, line: c_int) callconv(.c) ?*anyopaque {
    _ = file;
    _ = line;
    assert(installed);
    return global_heap.realloc(@ptrCast(addr), num);
}

fn hookFree(addr: ?*anyopaque, file: ?[*:0]const u8, line: c_int) callconv(.c) void {
    _ = file;
    _ = line;
    assert(installed);
    global_heap.free(@ptrCast(addr));
}

/// Route libcrypto's allocations into `buffer` for the rest of the
/// process. Must run at startup before any libcrypto call. Returns false
/// if libcrypto refuses the swap (something already allocated) or the
/// backend has no hooks — either way the zero-alloc promise is unbacked
/// and startup should abort.
///
/// `buffer` must outlive the process: the hooks keep serving libcrypto
/// until it exits, and there is no uninstall. In the proxy it is carved
/// from the startup arena (§5), which does.
pub fn install(buffer: []align(alignment) u8) bool {
    assert(!installed); // Install exactly once.
    global_heap.init(buffer);
    if (!ztls.mem_hooks.setMemFunctions(hookMalloc, hookRealloc, hookFree)) {
        return false;
    }
    installed = true;
    return true;
}

/// The frontier's high-water mark, for whoever is sizing the reservation
/// or proving the hooks are the ones libcrypto is calling. Zero before
/// `install`, and zero after it if libcrypto never asked us for anything.
pub fn usedPeak() usize {
    if (!installed) return 0;
    assert(global_heap.used_peak >= global_heap.used);
    assert(global_heap.used_peak <= global_heap.buffer.len);
    return global_heap.used_peak;
}

const testing = std.testing;

test "heap: alloc/free round-trips through size classes" {
    var backing: [64 * 1024]u8 align(alignment) = undefined;
    var heap: Heap = undefined;
    heap.init(&backing);

    // A spread of sizes; write then read to catch aliasing.
    const sizes = [_]usize{ 1, 16, 17, 31, 200, 1000, 4096 };
    var ptrs: [sizes.len][*]u8 = undefined;
    for (sizes, 0..) |n, i| {
        const p = heap.alloc(n) orelse return error.OutOfMemory;
        try testing.expect(@intFromPtr(p) % alignment == 0);
        @memset(p[0..n], @intCast(i + 1));
        ptrs[i] = p;
    }
    for (sizes, 0..) |n, i| {
        for (ptrs[i][0..n]) |b| try testing.expectEqual(@as(u8, @intCast(i + 1)), b);
    }
    // Free in a scrambled order, then re-alloc: the class lists must
    // hand the blocks back without growing the frontier.
    const before = heap.used;
    for ([_]usize{ 3, 0, 6, 1, 5, 2, 4 }) |i| heap.free(ptrs[i]);
    for (sizes) |n| _ = heap.alloc(n) orelse return error.OutOfMemory;
    try testing.expectEqual(before, heap.used);
}

test "heap: realloc grows across a class and preserves bytes" {
    var backing: [8 * 1024]u8 align(alignment) = undefined;
    var heap: Heap = undefined;
    heap.init(&backing);

    const p = heap.alloc(16) orelse return error.OutOfMemory;
    for (0..16) |i| p[i] = @intCast(i);
    // 16 -> 100 crosses classes (16 -> 128), so it must move and copy.
    const grown = heap.realloc(p, 100) orelse return error.OutOfMemory;
    for (0..16) |i| try testing.expectEqual(@as(u8, @intCast(i)), grown[i]);
    // Shrink within the class: same pointer.
    try testing.expectEqual(grown, heap.realloc(grown, 64).?);
    // realloc(null) is alloc; realloc(_, 0) is free.
    try testing.expect(heap.realloc(null, 8) != null);
    try testing.expectEqual(@as(?[*]u8, null), heap.realloc(grown, 0));
}

test "heap: a freed block carries the poison, so a double free trips" {
    // Poison must survive on a *populated* free list: free one block
    // into the class, then a second, then re-read the first's header —
    // its magic must still be zero, not the link pointer's low bytes.
    var backing: [4 * 1024]u8 align(alignment) = undefined;
    var heap: Heap = undefined;
    heap.init(&backing);

    const a = heap.alloc(200) orelse return error.OutOfMemory;
    const b = heap.alloc(200) orelse return error.OutOfMemory;
    heap.free(a);
    heap.free(b); // `a` is now the link target of `b` — must not un-poison it.
    const header_a: *const Header = @ptrCast(@alignCast(a - alignment));
    try testing.expectEqual(@as(u32, 0), header_a.magic);
}

test "heap: oversize and exhaustion both refuse, never overrun" {
    var backing: [4 * 1024]u8 align(alignment) = undefined;
    var heap: Heap = undefined;
    heap.init(&backing);

    try testing.expectEqual(@as(?[*]u8, null), heap.alloc(class_bytes_max + 1));
    // Drain the buffer with same-class blocks until it says no. Bounded:
    // nothing frees here, so every success advances the frontier by a
    // fixed stride and `take` refuses once it would pass `buffer.len` —
    // at most `buffer.len / (alignment + 256)` iterations.
    const blocks_max = @divFloor(backing.len, alignment + 256);
    var count: usize = 0;
    while (heap.alloc(200) != null) : (count += 1) {
        assert(count <= blocks_max);
    }
    try testing.expect(count > 0);
    try testing.expectEqual(blocks_max, count);
    try testing.expect(heap.used <= heap.buffer.len);
}
