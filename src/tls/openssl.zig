//! OpenSSL FFI seam (docs/DESIGN.md §6, Phase 3 foundation).
//!
//! Hand-written extern declarations — no @cImport, no header dependency; the
//! C ABI surface we use is small and explicit. Everything OpenSSL allocates
//! goes through the process-global memory hook installed here, backed by a
//! fixed heap reserved at startup: no allocation outside pre-reserved pools,
//! and heap exhaustion fails the OpenSSL operation (load-shedding, not OOM).
//!
//! Ordering constraint: `install_memory_hook` must be the first OpenSSL
//! interaction in the process — OpenSSL rejects the hook once it has
//! allocated anything (lazy library init counts).

const std = @import("std");
const assert = std.debug.assert;

pub const Heap = @import("heap.zig").Heap;

pub const BIO = opaque {};
pub const X509 = opaque {};
pub const EVP_PKEY = opaque {};
pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const SSL_METHOD = opaque {};
pub const SSL_CIPHER = opaque {};

// Values verified against the vendored OpenSSL 3.3.2 headers (ssl.h.in,
// tls1.h, prov_ssl.h) — mirrored here because the C names are macros with no
// linkable symbol. Keep the C spelling: these are the FFI contract.
pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub const SSL_CTRL_SET_SESS_CACHE_MODE: c_int = 44;
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const SSL_SESS_CACHE_OFF: c_long = 0x0000;
pub const TLS1_2_VERSION: c_long = 0x0303;
pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

var global_heap: Heap = undefined;
var hook_installed: bool = false;

pub const InstallError = error{
    /// A second install: the hook is process-global and installs exactly once.
    AlreadyInstalled,
    /// OpenSSL already allocated (lazy init ran before us) and refused the hook.
    OpenSslRejectedHook,
};

/// Install the process-global OpenSSL memory hook, backed by `region`
/// (reserved by the caller at startup, before any worker exists).
pub fn install_memory_hook(region: []align(Heap.block_align) u8) InstallError!void {
    assert(region.len >= 4096); // too small to run even library init otherwise
    if (hook_installed) return error.AlreadyInstalled;

    global_heap = Heap.init(region);
    if (CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free) != 1) {
        return error.OpenSslRejectedHook;
    }
    hook_installed = true;
    assert(memory_hook_stats().allocation_count == 0);
}

pub fn memory_hook_installed() bool {
    return hook_installed;
}

/// A locked snapshot of the hook heap's counters, for gates and (later)
/// admin metrics. Live count is the FFI analogue of pool occupancy: it must
/// return to its baseline when TLS work drains.
pub const HeapStats = struct {
    live_count: u64,
    allocation_count: u64,
    rejection_count: u64,
    carved_bytes: usize,
    /// The reserved region's capacity — carved/capacity is heap pressure.
    region_bytes: usize,
};

pub fn memory_hook_stats() HeapStats {
    assert(hook_installed);
    global_heap.mutex.lock();
    defer global_heap.mutex.unlock();
    return .{
        .live_count = global_heap.live_count,
        .allocation_count = global_heap.allocation_count,
        .rejection_count = global_heap.rejection_count,
        .carved_bytes = global_heap.carved_bytes,
        .region_bytes = global_heap.region.len,
    };
}

/// For observers that run whether or not TLS is configured (the admin
/// exposition): null when no hook is installed.
pub fn memory_hook_stats_if_installed() ?HeapStats {
    if (!hook_installed) return null;
    return memory_hook_stats();
}

fn hook_malloc(bytes: usize, file: [*c]const u8, line: c_int) callconv(.c) ?*anyopaque {
    _ = file;
    _ = line;
    assert(hook_installed); // OpenSSL can only know these functions post-install
    if (bytes == 0) return null; // C-semantics malloc(0)
    return @ptrCast(global_heap.alloc(bytes));
}

fn hook_realloc(
    pointer: ?*anyopaque,
    bytes: usize,
    file: [*c]const u8,
    line: c_int,
) callconv(.c) ?*anyopaque {
    assert(hook_installed);
    const live = pointer orelse return hook_malloc(bytes, file, line);
    if (bytes == 0) {
        global_heap.free(@ptrCast(live));
        return null;
    }
    return @ptrCast(global_heap.realloc(@ptrCast(live), bytes));
}

fn hook_free(pointer: ?*anyopaque, file: [*c]const u8, line: c_int) callconv(.c) void {
    _ = file;
    _ = line;
    assert(hook_installed);
    const live = pointer orelse return; // C-semantics free(NULL)
    global_heap.free(@ptrCast(live));
}

pub const IdentityError = error{
    /// The certificate bytes do not parse as a PEM X.509 certificate.
    InvalidCertificate,
    /// The key bytes do not parse as a PEM private key.
    InvalidPrivateKey,
    /// Both parse, but the private key does not match the certificate.
    CertificateKeyMismatch,
};

/// Parse and cross-check a PEM certificate + private key. Startup-time only:
/// every allocation goes through the hook heap and is freed before return —
/// the long-lived SSL_CTX is built from these same bytes in the next slice.
pub fn validate_identity(
    certificate_pem: []const u8,
    private_key_pem: []const u8,
) IdentityError!void {
    assert(hook_installed); // install_memory_hook is the first OpenSSL call
    assert(certificate_pem.len > 0);
    assert(private_key_pem.len > 0);
    defer ERR_clear_error(); // never leak thread error-queue state to callers

    const certificate = read_pem_x509(certificate_pem) orelse
        return error.InvalidCertificate;
    defer X509_free(certificate);

    const private_key = read_pem_private_key(private_key_pem) orelse
        return error.InvalidPrivateKey;
    defer EVP_PKEY_free(private_key);

    if (X509_check_private_key(certificate, private_key) != 1) {
        return error.CertificateKeyMismatch;
    }
}

pub fn read_pem_x509(pem: []const u8) ?*X509 {
    assert(pem.len > 0);
    assert(pem.len <= std.math.maxInt(c_int)); // config parsing bounds file sizes
    const bio = BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return null;
    defer _ = BIO_free(bio);
    return PEM_read_bio_X509(bio, null, null, null);
}

pub fn read_pem_private_key(pem: []const u8) ?*EVP_PKEY {
    assert(pem.len > 0);
    assert(pem.len <= std.math.maxInt(c_int));
    const bio = BIO_new_mem_buf(pem.ptr, @intCast(pem.len)) orelse return null;
    defer _ = BIO_free(bio);
    return PEM_read_bio_PrivateKey(bio, null, null, null);
}

pub extern fn OpenSSL_version_num() c_ulong;

// -- SSL_CTX / SSL / BIO-pair surface (used by terminator.zig) ------------

/// int (*cb)(SSL*, const unsigned char **out, unsigned char *outlen,
///           const unsigned char *in, unsigned int inlen, void *arg)
pub const AlpnSelectCallback = fn (
    ssl: *SSL,
    out: *?[*]const u8,
    out_length: *u8,
    in: [*]const u8,
    in_length: c_uint,
    argument: ?*anyopaque,
) callconv(.c) c_int;

pub extern fn TLS_server_method() *const SSL_METHOD;
pub extern fn TLS_client_method() *const SSL_METHOD;
pub extern fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
pub extern fn SSL_CTX_free(context: *SSL_CTX) void;
pub extern fn SSL_CTX_use_certificate(context: *SSL_CTX, certificate: *X509) c_int;
pub extern fn SSL_CTX_use_PrivateKey(context: *SSL_CTX, key: *EVP_PKEY) c_int;
pub extern fn SSL_CTX_check_private_key(context: *const SSL_CTX) c_int;
pub extern fn SSL_CTX_ctrl(
    context: *SSL_CTX,
    command: c_int,
    argument: c_long,
    pointer: ?*anyopaque,
) c_long;
pub extern fn SSL_CTX_set_num_tickets(context: *SSL_CTX, count: usize) c_int;
pub extern fn SSL_CTX_set_alpn_select_cb(
    context: *SSL_CTX,
    callback: *const AlpnSelectCallback,
    argument: ?*anyopaque,
) void;
/// void (*cb)(const SSL *ssl, const char *line) — NSS key-log format lines.
pub const KeylogCallback = fn (ssl: *const SSL, line: [*:0]const u8) callconv(.c) void;
pub extern fn SSL_CTX_set_keylog_callback(context: *SSL_CTX, callback: *const KeylogCallback) void;

pub extern fn SSL_new(context: *SSL_CTX) ?*SSL;
pub extern fn SSL_free(ssl: *SSL) void;
pub extern fn SSL_set_accept_state(ssl: *SSL) void;
pub extern fn SSL_set_connect_state(ssl: *SSL) void;
/// Takes ownership of the BIO references (one reference when rbio == wbio).
pub extern fn SSL_set_bio(ssl: *SSL, read_bio: *BIO, write_bio: *BIO) void;
pub extern fn SSL_do_handshake(ssl: *SSL) c_int;
pub extern fn SSL_is_init_finished(ssl: *const SSL) c_int;
pub extern fn SSL_get_error(ssl: *const SSL, return_code: c_int) c_int;
pub extern fn SSL_read(ssl: *SSL, buffer: [*]u8, length: c_int) c_int;
pub extern fn SSL_write(ssl: *SSL, buffer: [*]const u8, length: c_int) c_int;
pub extern fn SSL_shutdown(ssl: *SSL) c_int;
/// Returns 0 on success (inverted vs the rest of the API).
pub extern fn SSL_set_alpn_protos(ssl: *SSL, protocols: [*]const u8, length: c_uint) c_int;
pub extern fn SSL_get0_alpn_selected(ssl: *const SSL, data: *?[*]const u8, length: *c_uint) void;
/// ex_data index 0 is the traditional application-data slot (what the
/// SSL_set_app_data macro wraps).
pub extern fn SSL_set_ex_data(ssl: *SSL, index: c_int, data: ?*anyopaque) c_int;
pub extern fn SSL_get_ex_data(ssl: *const SSL, index: c_int) ?*anyopaque;
pub extern fn SSL_get_current_cipher(ssl: *const SSL) ?*const SSL_CIPHER;
/// The SSL's read-side BIO (borrowed, no reference transferred).
pub extern fn SSL_get_rbio(ssl: *const SSL) ?*BIO;
/// 1 when the SSL buffers any received data — decrypted-but-undelivered
/// plaintext or a processed-but-undecrypted record.
pub extern fn SSL_has_pending(ssl: *const SSL) c_int;
/// The IANA cipher-suite id (0x1301 = TLS_AES_128_GCM_SHA256, ...).
pub extern fn SSL_CIPHER_get_protocol_id(cipher: *const SSL_CIPHER) u16;

pub extern fn BIO_new_bio_pair(
    bio1: *?*BIO,
    write_buffer1: usize,
    bio2: *?*BIO,
    write_buffer2: usize,
) c_int;
pub extern fn BIO_read(bio: *BIO, buffer: [*]u8, length: c_int) c_int;
pub extern fn BIO_write(bio: *BIO, buffer: [*]const u8, length: c_int) c_int;
pub extern fn BIO_ctrl_pending(bio: *BIO) usize;

extern fn CRYPTO_set_mem_functions(
    malloc_function: *const fn (usize, [*c]const u8, c_int) callconv(.c) ?*anyopaque,
    realloc_function: *const fn (?*anyopaque, usize, [*c]const u8, c_int) callconv(.c) ?*anyopaque,
    free_function: *const fn (?*anyopaque, [*c]const u8, c_int) callconv(.c) void,
) c_int;

extern fn BIO_new_mem_buf(buffer: *const anyopaque, length: c_int) ?*BIO;
pub extern fn BIO_free(bio: *BIO) c_int;
extern fn PEM_read_bio_X509(
    bio: *BIO,
    out: ?*?*X509,
    password_callback: ?*const anyopaque,
    callback_data: ?*anyopaque,
) ?*X509;
extern fn PEM_read_bio_PrivateKey(
    bio: *BIO,
    out: ?*?*EVP_PKEY,
    password_callback: ?*const anyopaque,
    callback_data: ?*anyopaque,
) ?*EVP_PKEY;
pub extern fn X509_free(certificate: *X509) void;
pub extern fn EVP_PKEY_free(key: *EVP_PKEY) void;
extern fn X509_check_private_key(certificate: *const X509, key: *const EVP_PKEY) c_int;
pub extern fn ERR_clear_error() void;

/// Test-only: the hook installs once per process, so every test file that
/// touches OpenSSL funnels through this one shared region (sized for lazy
/// library init plus a handful of live handshakes).
pub fn install_memory_hook_for_tests() void {
    install_memory_hook(&test_heap_region) catch |err| switch (err) {
        error.AlreadyInstalled => {}, // another test file got here first
        // Only reachable if OpenSSL ran before any installer — a test
        // ordering bug, not a runtime condition.
        error.OpenSslRejectedHook => unreachable,
    };
    assert(memory_hook_installed());
}

var test_heap_region: [16 * 1024 * 1024]u8 align(Heap.block_align) = undefined;

// -- tests --------------------------------------------------------------

const test_certificate_pem = @embedFile("testdata/certificate.pem");
const test_private_key_pem = @embedFile("testdata/private_key.pem");
const test_other_key_pem = @embedFile("testdata/other_key.pem");

fn install_test_hook() !void {
    install_memory_hook_for_tests();
    try std.testing.expect(memory_hook_installed());
}

test "openssl: linked, version is 3.x" {
    const version = OpenSSL_version_num();
    try std.testing.expect(version >= 0x3000_0000);
    try std.testing.expect(version < 0x4000_0000);
}

test "openssl: memory hook installs once, second install is rejected" {
    try install_test_hook();
    try std.testing.expectError(
        error.AlreadyInstalled,
        install_memory_hook(&test_heap_region),
    );
}

test "openssl: identity validation allocates only inside the hook heap and drains" {
    try install_test_hook();

    // Warm-up: OpenSSL's lazy init allocates long-lived globals on first use.
    try validate_identity(test_certificate_pem, test_private_key_pem);

    // Steady state: a validation must drain every allocation it makes.
    const before = memory_hook_stats();
    try validate_identity(test_certificate_pem, test_private_key_pem);
    const after = memory_hook_stats();
    try std.testing.expect(after.allocation_count > before.allocation_count); // FFI used the heap
    try std.testing.expectEqual(before.live_count, after.live_count); // and gave it all back
    try std.testing.expectEqual(@as(u64, 0), after.rejection_count);
}

test "openssl: corrupt certificate, corrupt key, and mismatched key are rejected" {
    try install_test_hook();

    try std.testing.expectError(
        error.InvalidCertificate,
        validate_identity("not a pem", test_private_key_pem),
    );
    try std.testing.expectError(
        error.InvalidPrivateKey,
        validate_identity(test_certificate_pem, "not a pem"),
    );
    try std.testing.expectError(
        error.CertificateKeyMismatch,
        validate_identity(test_certificate_pem, test_other_key_pem),
    );

    // Error paths must drain too — leaks here would bleed the heap on every
    // malformed handshake artifact.
    const before = memory_hook_stats();
    _ = validate_identity("not a pem", test_private_key_pem) catch {};
    const after = memory_hook_stats();
    try std.testing.expectEqual(before.live_count, after.live_count);
}
