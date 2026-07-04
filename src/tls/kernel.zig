//! Kernel TLS ABI (docs/DESIGN.md §6 "kTLS design"): the `linux/tls.h` uapi
//! surface zoxy uses, mirrored by hand and verified against linux-headers
//! 6.18.7 — kernel structs are a stable ABI, so like the OpenSSL externs
//! this is an explicit contract, not a guess.
//!
//! Usage shape: after the userspace handshake, `IO.enable_kernel_tls`
//! attaches the "tls" ULP and installs one `CryptoInfo*` per direction;
//! from then on plain send/recv on the fd carry TLS records. Control
//! records (alerts, post-handshake messages) do NOT flow through plain
//! reads — receiving one fails the read (the caller tears down), and
//! sending one takes a `TLS_SET_RECORD_TYPE` cmsg via `IO.send_message`.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const assert = std.debug.assert;

/// `tls_crypto_info.version` for TLS 1.3.
pub const version_1_3: u16 = 0x0304;

/// `tls_crypto_info.cipher_type` values (TLS_CIPHER_AES_GCM_*).
pub const cipher_aes_gcm_128: u16 = 51;
pub const cipher_aes_gcm_256: u16 = 52;

/// cmsg types at level `SOL.TLS`: set on sendmsg, delivered on recvmsg.
pub const set_record_type: i32 = 1; // TLS_SET_RECORD_TYPE
pub const get_record_type: i32 = 2; // TLS_GET_RECORD_TYPE

/// TLS record content types (RFC 8446 §5.1).
pub const record_type_alert: u8 = 21;
pub const record_type_handshake: u8 = 22;
pub const record_type_application_data: u8 = 23;

/// A close_notify alert body: level warning(1), description close_notify(0).
pub const alert_close_notify = [2]u8{ 1, 0 };

/// IANA TLS 1.3 cipher-suite ids (what SSL_CIPHER_get_protocol_id returns).
pub const cipher_suite_aes_128_gcm_sha256: u16 = 0x1301;
pub const cipher_suite_aes_256_gcm_sha384: u16 = 0x1302;

/// struct tls_crypto_info.
pub const CryptoInfo = extern struct {
    version: u16,
    cipher_type: u16,
};

/// struct tls12_crypto_info_aes_gcm_128 (the "12" is kernel naming; the
/// struct serves TLS 1.3 with `version_1_3`). For TLS 1.3, salt is the
/// first 4 bytes of the HKDF-derived IV and `iv` the remaining 8;
/// `record_sequence` (kernel: rec_seq) is the next record number,
/// big-endian — zoxy only ever installs at sequence zero (§6: the
/// eligibility rule), asserted at the seam.
pub const CryptoInfoAesGcm128 = extern struct {
    info: CryptoInfo,
    iv: [8]u8,
    key: [16]u8,
    salt: [4]u8,
    record_sequence: [8]u8,
};

/// struct tls12_crypto_info_aes_gcm_256.
pub const CryptoInfoAesGcm256 = extern struct {
    info: CryptoInfo,
    iv: [8]u8,
    key: [32]u8,
    salt: [4]u8,
    record_sequence: [8]u8,
};

comptime {
    assert(@sizeOf(CryptoInfo) == 4);
    assert(@sizeOf(CryptoInfoAesGcm128) == 40);
    assert(@sizeOf(CryptoInfoAesGcm256) == 56);
    assert(@offsetOf(CryptoInfoAesGcm128, "salt") == 28);
    assert(@offsetOf(CryptoInfoAesGcm256, "record_sequence") == 48);
}

/// The kernel install parameters for one direction, ready for
/// `IO.enable_kernel_tls`. A tagged union rather than raw bytes so the
/// cipher is visible at the call site and in asserts.
pub const CryptoParameters = union(enum) {
    aes_gcm_128: CryptoInfoAesGcm128,
    aes_gcm_256: CryptoInfoAesGcm256,

    /// The raw struct bytes setsockopt wants.
    pub fn bytes(parameters: *const CryptoParameters) []const u8 {
        return switch (parameters.*) {
            .aes_gcm_128 => |*info| std.mem.asBytes(info),
            .aes_gcm_256 => |*info| std.mem.asBytes(info),
        };
    }
};

pub const DeriveError = error{
    /// Not a cipher suite we hand to the kernel (ChaCha20 is a later add).
    CipherSuiteUnsupported,
    /// The traffic secret's length does not match the suite's hash.
    SecretLengthInvalid,
};

/// RFC 8446 §7.3: key = HKDF-Expand-Label(secret, "key", "", key_length),
/// iv = HKDF-Expand-Label(secret, "iv", "", 12). The kernel wants the
/// 12-byte IV split as salt (first 4 bytes) + iv (last 8). The record
/// sequence is zero by construction: the §6 eligibility rule installs
/// these parameters only when no application record has flowed.
pub fn derive_crypto_parameters(
    cipher_suite: u16,
    traffic_secret: []const u8,
) DeriveError!CryptoParameters {
    assert(traffic_secret.len > 0);
    switch (cipher_suite) {
        cipher_suite_aes_128_gcm_sha256 => {
            const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
            if (traffic_secret.len != Hkdf.prk_length) return error.SecretLengthInvalid;
            const secret: [Hkdf.prk_length]u8 = traffic_secret[0..Hkdf.prk_length].*;
            const key = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "key", "", 16);
            const iv = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "iv", "", 12);
            return .{ .aes_gcm_128 = .{
                .info = .{ .version = version_1_3, .cipher_type = cipher_aes_gcm_128 },
                .iv = iv[4..12].*,
                .key = key,
                .salt = iv[0..4].*,
                .record_sequence = @splat(0),
            } };
        },
        cipher_suite_aes_256_gcm_sha384 => {
            const Hkdf = HkdfSha384;
            if (traffic_secret.len != Hkdf.prk_length) return error.SecretLengthInvalid;
            const secret: [Hkdf.prk_length]u8 = traffic_secret[0..Hkdf.prk_length].*;
            const key = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "key", "", 32);
            const iv = std.crypto.tls.hkdfExpandLabel(Hkdf, secret, "iv", "", 12);
            return .{ .aes_gcm_256 = .{
                .info = .{ .version = version_1_3, .cipher_type = cipher_aes_gcm_256 },
                .iv = iv[4..12].*,
                .key = key,
                .salt = iv[0..4].*,
                .record_sequence = @splat(0),
            } };
        },
        else => return error.CipherSuiteUnsupported,
    }
}

const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384);

/// One TLS_SET_RECORD_TYPE control message, laid out for `msghdr.control`
/// (cmsghdr + one type byte, padded to cmsg alignment). Build once next to
/// the iovec; both must outlive the send_message completion.
pub const RecordTypeControl = extern struct {
    header: linux.cmsghdr,
    record_type: u8,
    padding: [7]u8 = @splat(0),

    pub fn init(record_type: u8) RecordTypeControl {
        assert(record_type == record_type_alert or record_type == record_type_handshake);
        return .{
            .header = .{
                .len = @sizeOf(linux.cmsghdr) + 1, // CMSG_LEN(1)
                .level = linux.SOL.TLS,
                .type = set_record_type,
            },
            .record_type = record_type,
        };
    }
};

comptime {
    assert(@sizeOf(RecordTypeControl) == 24); // CMSG_SPACE(1)
    assert(@offsetOf(RecordTypeControl, "record_type") == @sizeOf(linux.cmsghdr));
}

/// Test-support (like openssl.zig's install_memory_hook_for_tests): whether
/// this environment can attach the "tls" ULP — integration tests assert the
/// kernel switchover when true and the fallback when false.
pub fn test_environment_supports_kernel_tls() bool {
    const pair = LoopbackPair.open() catch return false;
    defer pair.close();
    posix.setsockopt(pair.a, linux.IPPROTO.TCP, linux.TCP.ULP, "tls") catch return false;
    return true;
}

// ---- tests ----------------------------------------------------------------

test "kernel tls: derivation matches the RFC 8448 1-RTT vectors (server direction)" {
    // RFC 8448 §3, TLS_AES_128_GCM_SHA256: server application_traffic_secret_0.
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &secret,
        "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643",
    );
    const parameters = try derive_crypto_parameters(cipher_suite_aes_128_gcm_sha256, &secret);
    const info = parameters.aes_gcm_128;
    try std.testing.expectEqual(version_1_3, info.info.version);

    var expected_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_key, "9f02283b6c9c07efc26bb9f2ac92e356");
    try std.testing.expectEqualSlices(u8, &expected_key, &info.key);

    // RFC iv "cf782b88dd83549aadf1e984": salt is the first 4, iv the last 8.
    var expected_salt: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_salt, "cf782b88");
    var expected_iv: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_iv, "dd83549aadf1e984");
    try std.testing.expectEqualSlices(u8, &expected_salt, &info.salt);
    try std.testing.expectEqualSlices(u8, &expected_iv, &info.iv);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 8, &info.record_sequence);
}

test "kernel tls: derivation matches the RFC 8448 1-RTT vectors (client direction)" {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &secret,
        "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5",
    );
    const parameters = try derive_crypto_parameters(cipher_suite_aes_128_gcm_sha256, &secret);
    const info = parameters.aes_gcm_128;

    var expected_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_key, "17422dda596ed5d9acd890e3c63f5051");
    try std.testing.expectEqualSlices(u8, &expected_key, &info.key);

    var expected_salt: [4]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_salt, "5b78923d");
    var expected_iv: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_iv, "ee08579033e523d9");
    try std.testing.expectEqualSlices(u8, &expected_salt, &info.salt);
    try std.testing.expectEqualSlices(u8, &expected_iv, &info.iv);
}

test "kernel tls: derivation rejects unknown suites and wrong secret lengths" {
    const secret_32 = [_]u8{0xab} ** 32;
    try std.testing.expectError(
        error.CipherSuiteUnsupported,
        derive_crypto_parameters(0x1303, &secret_32), // ChaCha20: not yet
    );
    try std.testing.expectError(
        error.SecretLengthInvalid,
        derive_crypto_parameters(cipher_suite_aes_256_gcm_sha384, &secret_32), // needs 48
    );
    const secret_48 = [_]u8{0xcd} ** 48;
    try std.testing.expectError(
        error.SecretLengthInvalid,
        derive_crypto_parameters(cipher_suite_aes_128_gcm_sha256, &secret_48), // needs 32
    );
    // The 256 path derives with the right length (vector-checked above for 128).
    const parameters = try derive_crypto_parameters(cipher_suite_aes_256_gcm_sha384, &secret_48);
    try std.testing.expectEqual(@as(usize, 56), parameters.bytes().len);
}

const io_mod = @import("../io/io.zig");
const IO = io_mod.IO;
const Completion = io_mod.Completion;

/// A connected blocking loopback TCP pair (kTLS requires an established
/// connection for the ULP attach).
const LoopbackPair = struct {
    listener: posix.socket_t,
    a: posix.socket_t,
    b: posix.socket_t,

    fn open() !LoopbackPair {
        const listener = try socket_or_fail();
        errdefer _ = linux.close(listener);
        var address = linux.sockaddr.in{
            .family = linux.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        if (linux.errno(linux.bind(listener, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) !=
            .SUCCESS) return error.BindFailed;
        if (linux.errno(linux.listen(listener, 1)) != .SUCCESS) return error.ListenFailed;
        var length: posix.socklen_t = @sizeOf(linux.sockaddr.in);
        if (linux.errno(linux.getsockname(listener, @ptrCast(&address), &length)) != .SUCCESS)
            return error.GetSockNameFailed;

        const a = try socket_or_fail();
        errdefer _ = linux.close(a);
        if (linux.errno(linux.connect(a, @ptrCast(&address), @sizeOf(linux.sockaddr.in))) !=
            .SUCCESS) return error.ConnectFailed;
        const accepted = linux.accept4(listener, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(accepted) != .SUCCESS) return error.AcceptFailed;
        return .{ .listener = listener, .a = a, .b = @intCast(accepted) };
    }

    fn socket_or_fail() !posix.socket_t {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
        return @intCast(rc);
    }

    fn close(pair: LoopbackPair) void {
        _ = linux.close(pair.a);
        _ = linux.close(pair.b);
        _ = linux.close(pair.listener);
    }
};

/// Deterministic key material; direction is encoded in the first key byte so
/// a/b cannot accidentally decrypt with the wrong direction's keys.
fn test_crypto_info(direction: u8) CryptoInfoAesGcm128 {
    var info = CryptoInfoAesGcm128{
        .info = .{ .version = version_1_3, .cipher_type = cipher_aes_gcm_128 },
        .iv = @splat(0x42),
        .key = @splat(0x24),
        .salt = @splat(0x11),
        .record_sequence = @splat(0),
    };
    info.key[0] = direction;
    return info;
}

/// Install both directions on both sockets, or skip the test when the
/// environment cannot (tls module absent — e.g. a locked-down CI runner).
fn enable_or_skip(io: *IO, pair: LoopbackPair) !void {
    const a_to_b = test_crypto_info(1);
    const b_to_a = test_crypto_info(2);
    io.enable_kernel_tls(pair.a, std.mem.asBytes(&a_to_b), std.mem.asBytes(&b_to_a)) catch
        return error.SkipZigTest;
    io.enable_kernel_tls(pair.b, std.mem.asBytes(&b_to_a), std.mem.asBytes(&a_to_b)) catch
        return error.SkipZigTest;
}

test "kernel tls: records round-trip between TLS_TX and TLS_RX sockets" {
    var io = try IO.init(16, 0);
    defer io.deinit();
    const pair = try LoopbackPair.open();
    defer pair.close();
    try enable_or_skip(&io, pair);

    // a -> b: the kernel encrypts on write and decrypts on read; both ends
    // see plaintext while the wire carries TLS records.
    const request = "hello through the kernel";
    try std.testing.expectEqual(request.len, write_all(pair.a, request));
    var buffer: [64]u8 = undefined;
    const received = linux.read(pair.b, &buffer, buffer.len);
    try std.testing.expectEqual(request.len, received);
    try std.testing.expectEqualStrings(request, buffer[0..request.len]);

    // b -> a: the reverse direction has its own keys.
    const reply = "pong";
    try std.testing.expectEqual(reply.len, write_all(pair.b, reply));
    const echoed = linux.read(pair.a, &buffer, buffer.len);
    try std.testing.expectEqual(reply.len, echoed);
    try std.testing.expectEqualStrings(reply, buffer[0..reply.len]);
}

fn write_all(fd: posix.socket_t, bytes: []const u8) usize {
    var sent: usize = 0;
    var budget: u32 = 100; // bounded: blocking writes always progress
    while (sent < bytes.len and budget > 0) : (budget -= 1) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        if (linux.errno(rc) != .SUCCESS) break;
        sent += rc;
    }
    return sent;
}

const SendMessageProbe = struct {
    done: bool = false,
    result: io_mod.SendError!usize = error.Unexpected,

    fn on_sent(probe: *SendMessageProbe, _: *Completion, result: io_mod.SendError!usize) void {
        probe.result = result;
        probe.done = true;
    }
};

test "kernel tls: an alert goes out via send_message cmsg and arrives typed" {
    var io = try IO.init(16, 0);
    defer io.deinit();
    const pair = try LoopbackPair.open();
    defer pair.close();
    try enable_or_skip(&io, pair);

    // Send close_notify from a through the ring: payload in the iovec, the
    // record type riding in the TLS_SET_RECORD_TYPE control message.
    const control = RecordTypeControl.init(record_type_alert);
    const payload = alert_close_notify;
    const segments = [_]posix.iovec_const{
        .{ .base = &payload, .len = payload.len },
    };
    const message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &segments,
        .iovlen = segments.len,
        .control = &control,
        .controllen = @sizeOf(RecordTypeControl),
        .flags = 0,
    };
    var probe = SendMessageProbe{};
    var completion: Completion = undefined;
    io.send_message(
        *SendMessageProbe,
        &probe,
        SendMessageProbe.on_sent,
        &completion,
        pair.a,
        &message,
    );
    try io.run_until_done(&probe.done);
    try std.testing.expectEqual(payload.len, try probe.result);

    // b, reading with recvmsg + a cmsg buffer, sees the record type; the
    // payload arrives decrypted.
    var receive_buffer: [16]u8 = undefined;
    var receive_control: RecordTypeControl = undefined;
    var receive_segments = [_]posix.iovec{
        .{ .base = &receive_buffer, .len = receive_buffer.len },
    };
    var receive_message = linux.msghdr{
        .name = null,
        .namelen = 0,
        .iov = &receive_segments,
        .iovlen = receive_segments.len,
        .control = &receive_control,
        .controllen = @sizeOf(RecordTypeControl),
        .flags = 0,
    };
    const received = linux.recvmsg(pair.b, &receive_message, 0);
    try std.testing.expectEqual(payload.len, received);
    try std.testing.expectEqualSlices(u8, &payload, receive_buffer[0..payload.len]);
    try std.testing.expectEqual(get_record_type, receive_control.header.type);
    try std.testing.expectEqual(record_type_alert, receive_control.record_type);

    // A control record hitting a *plain* read is an error by contract —
    // this is exactly how a post-switch client KeyUpdate surfaces (§6).
    const again = RecordTypeControl.init(record_type_alert);
    const again_message = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = &segments,
        .iovlen = segments.len,
        .control = &again,
        .controllen = @sizeOf(RecordTypeControl),
        .flags = 0,
    };
    var again_probe = SendMessageProbe{};
    var again_completion: Completion = undefined;
    io.send_message(
        *SendMessageProbe,
        &again_probe,
        SendMessageProbe.on_sent,
        &again_completion,
        pair.a,
        &again_message,
    );
    try io.run_until_done(&again_probe.done);
    try std.testing.expectEqual(payload.len, try again_probe.result);

    var plain: [16]u8 = undefined;
    const failed_read = linux.read(pair.b, &plain, plain.len);
    try std.testing.expect(linux.errno(failed_read) != .SUCCESS);
}
