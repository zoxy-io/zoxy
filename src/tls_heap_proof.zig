//! Root for `zig build tls-heap-proof` (DESIGN.md §4, §9).
//!
//! The proof itself lives in `tls/heap_proof_test.zig`; this exists only
//! to root that test's module at `src/` rather than `src/tls/`, so it can
//! import `constants.zig` the way the rest of `src/tls/` does — a module
//! rooted inside `src/tls/` cannot reach a file above itself.
//!
//! It stays a separate step from `zig build ci` for the reason it always
//! will: installing the libcrypto allocator is process-global and
//! one-shot, so the proof needs a fresh process to witness it.

test {
    _ = @import("tls/heap_proof_test.zig");
}
