//! Fixed-capacity size-class heap backing the OpenSSL memory hook
//! (docs/DESIGN.md §6). One region reserved at startup; OpenSSL suballocates
//! within it. Exhaustion returns null — the OpenSSL operation (ultimately a
//! handshake) fails and that request is rejected. The region never grows:
//! load-shedding, not OOM.
//!
//! Design: segregated free lists over power-of-two size classes plus a bump
//! carver. No coalescing — a freed block returns to its class's list and is
//! reused there. Internal fragmentation is bounded (< 2x per block) in
//! exchange for O(1) alloc/free and no fragmentation collapse over time.
//! Thread-safe behind one mutex: `CRYPTO_set_mem_functions` is process-global,
//! so every worker's handshake allocations funnel here. That lock is
//! handshake-scoped by construction — the relay path never allocates.

const std = @import("std");
const assert = std.debug.assert;
const FutexMutex = @import("../mem/futex_mutex.zig").FutexMutex;

pub const Heap = struct {
    region: []align(block_align) u8,
    mutex: FutexMutex = .{},
    carved_bytes: usize = 0,
    free_lists: [class_count]?*FreeBlock = @splat(null),
    live_count: u64 = 0,
    allocation_count: u64 = 0,
    rejection_count: u64 = 0,

    /// malloc-compatible alignment (x86-64 max_align_t); the 16-byte header
    /// sits directly before the user pointer, preserving it.
    pub const block_align = 16;
    /// Largest single block a class can serve, header included: 32 << 15.
    pub const block_bytes_max: usize = class_bytes_min << (class_count - 1);

    const header_bytes: usize = block_align;
    const class_count = 16;
    const class_bytes_min: usize = 32;
    const magic_live: u32 = 0x7a78_11fe;
    const magic_free: u32 = 0x7a78_dead;

    const Header = extern struct {
        magic: u32,
        class: u32,
        reserved: u64 = 0,
    };

    /// Overlaid on the user area of a freed block (every class has >= 16
    /// bytes of user area), so the header survives for asserts and reuse.
    const FreeBlock = extern struct {
        next: ?*FreeBlock,
    };

    comptime {
        assert(@sizeOf(Header) == header_bytes);
        assert(@sizeOf(FreeBlock) <= class_bytes_min - header_bytes);
        assert(block_bytes_max == 1024 * 1024);
    }

    pub fn init(region: []align(block_align) u8) Heap {
        assert(region.len >= class_bytes_min); // room for at least one block
        assert(region.len % block_align == 0); // carving stays aligned
        return .{ .region = region };
    }

    /// The size class whose block (header included) holds `bytes`, or null
    /// when `bytes` exceeds the largest class (such a request is rejected —
    /// nothing on the TLS path needs megabyte-plus single blocks).
    fn class_for(bytes: usize) ?u32 {
        assert(bytes > 0);
        // Reject before the add so an FFI-supplied `bytes` near maxInt cannot
        // wrap `total` into a small value that slips past the bound below.
        if (bytes > block_bytes_max) return null;
        const total = bytes + header_bytes;
        if (total > block_bytes_max) return null;
        const bits = std.math.log2_int_ceil(usize, total);
        const class: u32 = if (bits <= 5) 0 else @intCast(bits - 5);
        assert(class < class_count);
        assert(class_bytes(class) >= total);
        assert(class == 0 or class_bytes(class - 1) < total);
        return class;
    }

    fn class_bytes(class: u32) usize {
        assert(class < class_count);
        return class_bytes_min << @intCast(class);
    }

    /// Serve `bytes`, 16-aligned, or null when the class is exhausted and the
    /// region is fully carved (the counters record which).
    pub fn alloc(heap: *Heap, bytes: usize) ?[*]u8 {
        assert(bytes > 0); // C-semantics malloc(0) is the hook's concern
        const class = class_for(bytes) orelse {
            heap.mutex.lock();
            defer heap.mutex.unlock();
            heap.rejection_count += 1;
            return null;
        };

        heap.mutex.lock();
        defer heap.mutex.unlock();

        const block: [*]u8 = if (heap.free_lists[class]) |free_block| reuse: {
            heap.free_lists[class] = free_block.next;
            const block: [*]u8 = @ptrFromInt(@intFromPtr(free_block) - header_bytes);
            const header: *Header = @ptrCast(@alignCast(block));
            assert(header.magic == magic_free); // freelist holds only freed blocks
            assert(header.class == class);
            break :reuse block;
        } else carve: {
            const size = class_bytes(class);
            if (heap.carved_bytes + size > heap.region.len) {
                heap.rejection_count += 1;
                return null;
            }
            const block = heap.region.ptr + heap.carved_bytes;
            heap.carved_bytes += size;
            break :carve block;
        };

        const header: *Header = @ptrCast(@alignCast(block));
        header.* = .{ .magic = magic_live, .class = class };
        heap.live_count += 1;
        heap.allocation_count += 1;
        assert(heap.live_count <= heap.allocation_count);
        return block + header_bytes;
    }

    /// Return a block to its class's free list. Asserts the pointer is a
    /// live block this heap handed out (magic tripwire: double free and
    /// foreign pointers fail loudly, not silently).
    pub fn free(heap: *Heap, user_pointer: [*]u8) void {
        const header = header_of(heap, user_pointer);
        assert(header.magic == magic_live); // double free / foreign pointer
        header.magic = magic_free;

        heap.mutex.lock();
        defer heap.mutex.unlock();
        const free_block: *FreeBlock = @ptrCast(@alignCast(user_pointer));
        free_block.next = heap.free_lists[header.class];
        heap.free_lists[header.class] = free_block;
        assert(heap.live_count > 0);
        heap.live_count -= 1;
    }

    /// C realloc semantics minus the null/zero cases (the hook maps those).
    /// Same class: the block already fits, return it unchanged. Otherwise
    /// alloc + copy + free; null on exhaustion with the old block intact.
    pub fn realloc(heap: *Heap, user_pointer: [*]u8, new_bytes: usize) ?[*]u8 {
        assert(new_bytes > 0);
        const header = header_of(heap, user_pointer);
        assert(header.magic == magic_live);

        const old_capacity = class_bytes(header.class) - header_bytes;
        if (new_bytes <= old_capacity) return user_pointer;

        const new_pointer = heap.alloc(new_bytes) orelse return null;
        @memcpy(new_pointer[0..old_capacity], user_pointer[0..old_capacity]);
        heap.free(user_pointer);
        return new_pointer;
    }

    fn header_of(heap: *Heap, user_pointer: [*]u8) *Header {
        const address = @intFromPtr(user_pointer);
        assert(address % block_align == 0);
        const begin = @intFromPtr(heap.region.ptr);
        assert(address >= begin + header_bytes); // inside our region,
        assert(address < begin + heap.region.len); // not a foreign pointer
        return @ptrFromInt(address - header_bytes);
    }
};

test "heap: rounds to class, serves aligned, reuses freed blocks" {
    var region: [4096]u8 align(16) = undefined;
    var heap = Heap.init(&region);

    const a = heap.alloc(1).?;
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(a) % 16);
    try std.testing.expectEqual(@as(usize, 32), heap.carved_bytes); // 1+16 -> 32-byte class
    try std.testing.expectEqual(@as(u64, 1), heap.live_count);

    heap.free(a);
    try std.testing.expectEqual(@as(u64, 0), heap.live_count);
    const b = heap.alloc(10).?; // same class: reuses the freed block
    try std.testing.expectEqual(@intFromPtr(a), @intFromPtr(b));
    try std.testing.expectEqual(@as(usize, 32), heap.carved_bytes);
    heap.free(b);
}

test "heap: exhaustion rejects, frees restore service" {
    var region: [64]u8 align(16) = undefined; // exactly two 32-byte blocks
    var heap = Heap.init(&region);

    const a = heap.alloc(8).?;
    const b = heap.alloc(8).?;
    try std.testing.expectEqual(@as(?[*]u8, null), heap.alloc(8));
    try std.testing.expectEqual(@as(u64, 1), heap.rejection_count);

    heap.free(a);
    const c = heap.alloc(8).?; // load shed, then recovered
    try std.testing.expectEqual(@intFromPtr(a), @intFromPtr(c));
    heap.free(b);
    heap.free(c);
    try std.testing.expectEqual(@as(u64, 0), heap.live_count);
}

test "heap: oversize requests are rejected outright" {
    var region: [4096]u8 align(16) = undefined;
    var heap = Heap.init(&region);

    try std.testing.expectEqual(@as(?[*]u8, null), heap.alloc(2 * 1024 * 1024));
    try std.testing.expectEqual(@as(u64, 1), heap.rejection_count);
    try std.testing.expectEqual(@as(usize, 0), heap.carved_bytes);
}

test "heap: realloc keeps the block within a class, copies across classes" {
    var region: [4096]u8 align(16) = undefined;
    var heap = Heap.init(&region);

    const a = heap.alloc(10).?;
    a[0] = 0xab;
    a[9] = 0xcd;

    const same = heap.realloc(a, 16).?; // still fits the 32-byte class
    try std.testing.expectEqual(@intFromPtr(a), @intFromPtr(same));

    const grown = heap.realloc(a, 100).?; // 128-byte class: moved
    try std.testing.expect(@intFromPtr(grown) != @intFromPtr(a));
    try std.testing.expectEqual(@as(u8, 0xab), grown[0]);
    try std.testing.expectEqual(@as(u8, 0xcd), grown[9]);
    try std.testing.expectEqual(@as(u64, 1), heap.live_count);
    heap.free(grown);
}
