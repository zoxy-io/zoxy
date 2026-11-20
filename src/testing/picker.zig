//! A picker for the gates (#417): it records what zoxy offered it and
//! answers a scripted slot — including one past the end of the set, which
//! is how the gates reach the fallback an out-of-set answer earns.
//! Exported so the simulator, outside this module, can select one.

const std = @import("std");

const extension = @import("../extension.zig");

const assert = std.debug.assert;

pub const ScriptedPicker = struct {
    choice: Choice = .first,
    /// Startup binds received, one per cluster that selected the instance.
    binds: u32 = 0,
    /// Picks asked of it.
    calls: u32 = 0,
    /// The last pick's candidates, by endpoint index, in the order offered.
    offered: [offered_max]u16 = @splat(0),
    offered_count: u16 = 0,
    /// The last pick's flags, as `PickInput` stated them.
    retry: bool = false,
    had_request: bool = false,
    /// The last request's tag (#433), zero when it carried none or the
    /// pick had no request.
    tag: u64 = 0,
    /// The tag every request a pick carries must have, when configured:
    /// a policy's, held to reaching the pick. One that does not stops
    /// the run, so the simulator replays its seed.
    expect_tag: ?u64 = null,
    /// The last request's canonical path, copied out: the view is valid
    /// only for the call, so a gate reading it afterwards reads this.
    path: [path_bytes_max]u8 = @splat(0),
    path_len: u8 = 0,

    pub const offered_max = 8;
    pub const path_bytes_max = 64;

    pub const Choice = enum {
        /// Slot 0: the lowest endpoint index the set still holds.
        first,
        /// The last slot.
        last,
        /// One past the end, which no candidate answers to.
        past_end,
        /// A draw modulo one more than the count: every slot, and now and
        /// then the one past the end, in the generator's own order.
        by_entropy,
    };

    pub fn bind(
        picker: *ScriptedPicker,
        cluster: *const extension.ClusterSite,
        startup: *const extension.Startup,
    ) !void {
        _ = startup;
        assert(cluster.endpoints.len >= 1);
        assert(cluster.name.len >= 1);
        picker.binds += 1;
    }

    pub fn pick(
        picker: *ScriptedPicker,
        candidates: *const extension.Candidates,
        input: *const extension.PickInput,
    ) u16 {
        const count = candidates.count();
        assert(count >= 1);
        assert(input.cluster_index == candidates.cluster_index);
        picker.calls += 1;
        picker.offered_count = @min(count, offered_max);
        for (picker.offered[0..picker.offered_count], 0..) |*offered, slot| {
            offered.* = candidates.endpointIndex(@intCast(slot));
        }
        picker.retry = input.retry;
        picker.had_request = input.request != null;
        picker.path_len = 0;
        picker.tag = 0;
        if (input.request) |request| {
            if (picker.expect_tag) |expected| assert(request.tag == expected);
            picker.tag = request.tag;
            const kept = @min(request.path.len, path_bytes_max);
            @memcpy(picker.path[0..kept], request.path[0..kept]);
            picker.path_len = @intCast(kept);
        }
        return switch (picker.choice) {
            .first => 0,
            .last => count - 1,
            .past_end => count,
            .by_entropy => @intCast(input.random.next() % (@as(u64, count) + 1)),
        };
    }

    /// The last request's path, as recorded.
    pub fn lastPath(picker: *const ScriptedPicker) []const u8 {
        assert(picker.path_len <= path_bytes_max);
        if (!picker.had_request) assert(picker.path_len == 0);
        return picker.path[0..picker.path_len];
    }
};

comptime {
    extension.assertPicker(ScriptedPicker);
}
