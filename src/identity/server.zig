const std = @import("std");

const log = @import("../log.zig");

const identity_sdp = @import("sdp.zig");

const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const jwk_claim_blank = "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}";
const cpk_claim_max_length = jwk_claim_blank.len + 2 * 64;
comptime {
    if (!std.mem.eql(u8, jwk_claim_blank, std.fmt.comptimePrint("{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ "", "" })))
        @compileError("the jwk claim template and the buffer it is sized from disagree");
}
const der_length = 120;
const der_base64_length = std.base64.standard.Encoder.calcSize(der_length);

const protected_header = "eyJhbGciOiJFUzM4NCJ9";

const secret_key_length = 48;

pub const LoadError = Error || std.Io.File.Writer.Error || std.Io.File.OpenError ||
    std.Io.Dir.ReadFileAllocError || std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.HardLinkError || std.Io.Dir.RenamePreserveError;

pub const Error = error{
    MissingFingerprint,
    InvalidFingerprint,
    InvalidSdp,
    IdentityTooLarge,
    InvalidKeyMaterial,
    InvalidIdentityConfig,
} || std.mem.Allocator.Error || std.Io.Writer.Error || std.crypto.errors.IdentityElementError || std.crypto.errors.NonCanonicalError;

pub const Provider = struct {
    io: std.Io,
    key_pair: Scheme.KeyPair,
    domain: []const u8 = "self",
    lifetime_seconds: i64 = 3600,
    cpk_encoding: CpkEncoding = .jwk,

    pub const CpkEncoding = enum { jwk, base64_der };

    pub const Config = struct {
        domain: []const u8 = "self",
        lifetime_seconds: i64 = 3600,
        cpk_encoding: CpkEncoding = .jwk,
    };

    pub fn validateConfig(config: Config) Error!void {
        try validateDomain(config.domain);
        if (config.lifetime_seconds < 60 or config.lifetime_seconds > 604_800) return error.InvalidIdentityConfig;
    }

    pub fn init(io: std.Io, config: Config) Provider {
        return .{
            .io = io,
            .key_pair = Scheme.KeyPair.generate(io),
            .domain = config.domain,
            .lifetime_seconds = config.lifetime_seconds,
            .cpk_encoding = config.cpk_encoding,
        };
    }

    pub fn loadOrCreate(io: std.Io, allocator: std.mem.Allocator, path: []const u8) LoadError!Provider {
        return loadOrCreateWith(io, allocator, path, .{});
    }

    pub fn loadOrCreateWith(io: std.Io, allocator: std.mem.Allocator, path: []const u8, config: Config) LoadError!Provider {
        return readOrCreate(io, allocator, path, config, true);
    }

    fn readOrCreate(io: std.Io, allocator: std.mem.Allocator, path: []const u8, config: Config, may_create: bool) LoadError!Provider {
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(secret_key_length + 1)) catch |err| switch (err) {
            error.FileNotFound => {
                if (!may_create) return error.FileNotFound;
                return writeNewKey(io, path, allocator, config);
            },
            error.StreamTooLong => return error.InvalidKeyMaterial,
            else => return err,
        };
        defer allocator.free(bytes);
        if (bytes.len != secret_key_length) return error.InvalidKeyMaterial;
        var provider = try fromSecretKey(io, bytes[0..secret_key_length].*);
        provider.applyConfig(config);
        return provider;
    }

    fn applyConfig(self: *Provider, config: Config) void {
        self.domain = config.domain;
        self.lifetime_seconds = config.lifetime_seconds;
        self.cpk_encoding = config.cpk_encoding;
    }

    fn writeNewKey(io: std.Io, path: []const u8, allocator: std.mem.Allocator, config: Config) LoadError!Provider {
        const permissions: std.Io.File.Permissions = if (@import("builtin").os.tag == .windows)
            .default_file
        else
            .fromMode(0o600);

        const provider = init(io, config);
        const secret = provider.secretKeyBytes();
        var atomic = try std.Io.Dir.cwd().createFileAtomic(io, path, .{ .permissions = permissions });
        defer atomic.deinit(io);
        try atomic.file.writeStreamingAll(io, &secret);
        atomic.link(io) catch |err| switch (err) {
            error.PathAlreadyExists => return readOrCreate(io, allocator, path, config, false),
            else => return err,
        };
        return provider;
    }

    pub fn fromSecretKey(io: std.Io, secret: [secret_key_length]u8) Error!Provider {
        return .{ .io = io, .key_pair = try Scheme.KeyPair.fromSecretKey(try Scheme.SecretKey.fromBytes(secret)) };
    }

    pub fn secretKeyBytes(self: *const Provider) [secret_key_length]u8 {
        return self.key_pair.secret_key.toBytes();
    }

    pub fn keyFingerprint(self: *const Provider) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        const der = spkiDer(self.key_pair.public_key);
        return sha256(&der);
    }

    pub fn addToSdp(self: *const Provider, allocator: std.mem.Allocator, sdp: []const u8) Error![]u8 {
        try validateConfig(.{ .domain = self.domain, .lifetime_seconds = self.lifetime_seconds, .cpk_encoding = self.cpk_encoding });
        const now = std.Io.Clock.real.now(self.io).toSeconds();

        var cpk_buffer: [cpk_claim_max_length]u8 = undefined;
        const public_key_cpk = self.cpkClaim(&cpk_buffer);
        const cpk_digest = sha256(public_key_cpk);
        const cpk_hex = std.fmt.bytesToHex(cpk_digest, .lower);
        log.debug("server identity: cpk encoding={s} claim={d} bytes sha-256={s}", .{
            @tagName(self.cpk_encoding),
            public_key_cpk.len,
            cpk_hex[0..],
        });

        const claims_json = try std.fmt.allocPrint(allocator, "{{\"exp\":{d},\"iat\":{d},\"cpk\":{s}}}", .{ now + self.lifetime_seconds, now, public_key_cpk });
        defer allocator.free(claims_json);

        const claims_b64 = try encodeUrl(allocator, claims_json);
        defer allocator.free(claims_b64);
        const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_header, claims_b64 });
        defer allocator.free(signing_input);
        const token = try compactSignature(allocator, self.key_pair, signing_input, protected_header, claims_b64);
        defer allocator.free(token);

        const fingerprint_payload = try identity_sdp.fingerprintPayload(allocator, sdp);
        defer allocator.free(fingerprint_payload);
        const payload_b64 = try encodeUrl(allocator, fingerprint_payload);
        defer allocator.free(payload_b64);
        const detached_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_header, payload_b64 });
        defer allocator.free(detached_input);
        const detached_signature = try signatureB64(allocator, self.key_pair, detached_input);
        defer allocator.free(detached_signature);
        const fingerprints = try std.fmt.allocPrint(allocator, "{s}..{s}", .{ protected_header, detached_signature });
        defer allocator.free(fingerprints);

        const inner = try std.fmt.allocPrint(allocator, "{{\"fingerprints\":\"{s}\",\"token\":\"{s}\"}}", .{ fingerprints, token });
        defer allocator.free(inner);
        const escaped_inner = try escapeJson(allocator, inner);
        defer allocator.free(escaped_inner);
        const escaped_domain = try escapeJson(allocator, self.domain);
        defer allocator.free(escaped_domain);
        const envelope = try std.fmt.allocPrint(allocator, "{{\"assertion\":\"{s}\",\"idp\":{{\"domain\":\"{s}\",\"protocol\":\"default\"}}}}", .{ escaped_inner, escaped_domain });
        defer allocator.free(envelope);

        const encoded_len = std.base64.standard.Encoder.calcSize(envelope.len);
        if (encoded_len > 64 * 1024) return error.IdentityTooLarge;
        const encoded = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded);
        _ = std.base64.standard.Encoder.encode(encoded, envelope);

        const insert_at = try identity_sdp.sessionInsertOffset(sdp);
        return std.fmt.allocPrint(allocator, "{s}a=identity:{s}\r\n{s}", .{ sdp[0..insert_at], encoded, sdp[insert_at..] });
    }

    fn cpkClaim(self: *const Provider, buffer: []u8) []const u8 {
        return switch (self.cpk_encoding) {
            .jwk => self.cpkJwk(buffer),
            .base64_der => self.cpkBase64DerQuoted(buffer),
        };
    }

    fn cpkJwk(self: *const Provider, buffer: []u8) []const u8 {
        const point = self.key_pair.public_key.toUncompressedSec1();
        var x_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
        var y_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
        const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buffer, point[1..49]);
        const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buffer, point[49..97]);
        return std.fmt.bufPrint(buffer, "{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x, y }) catch unreachable;
    }

    fn cpkBase64Der(self: *const Provider, buffer: []u8) []const u8 {
        const der = spkiDer(self.key_pair.public_key);
        return std.base64.standard.Encoder.encode(buffer, &der);
    }

    fn cpkBase64DerQuoted(self: *const Provider, buffer: []u8) []const u8 {
        buffer[0] = '"';
        _ = self.cpkBase64Der(buffer[1..]);
        buffer[der_base64_length + 1] = '"';
        return buffer[0 .. der_base64_length + 2];
    }
};

fn validateDomain(domain: []const u8) Error!void {
    if (domain.len == 0 or domain.len > 253) return error.InvalidIdentityConfig;
    var labels = std.mem.splitScalar(u8, domain, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidIdentityConfig;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidIdentityConfig;
        for (label) |byte| switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return error.InvalidIdentityConfig,
        };
    }
}

fn spkiDer(public_key: Scheme.PublicKey) [der_length]u8 {
    var der: [der_length]u8 = undefined;
    const point = public_key.toUncompressedSec1();
    der[0] = 0x30;
    der[1] = 0x76;
    der[2..20].* = .{ 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
    der[20] = 0x03;
    der[21] = 0x62;
    der[22] = 0;
    @memcpy(der[23..der_length], &point);
    return der;
}

fn sha256(value: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    return digest;
}

fn escapeJson(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const hex = "0123456789abcdef";
    var buffer: std.ArrayList(u8) = .empty;
    errdefer buffer.deinit(allocator);

    for (value) |byte| switch (byte) {
        '"' => try buffer.appendSlice(allocator, "\\\""),
        '\\' => try buffer.appendSlice(allocator, "\\\\"),
        '\n' => try buffer.appendSlice(allocator, "\\n"),
        '\r' => try buffer.appendSlice(allocator, "\\r"),
        '\t' => try buffer.appendSlice(allocator, "\\t"),
        else => if (byte < 0x20) {
            try buffer.appendSlice(allocator, "\\u00");
            try buffer.append(allocator, hex[byte >> 4]);
            try buffer.append(allocator, hex[byte & 0x0f]);
        } else {
            try buffer.append(allocator, byte);
        },
    };

    return buffer.toOwnedSlice(allocator);
}

fn encodeUrl(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const length = std.base64.url_safe_no_pad.Encoder.calcSize(value.len);
    const result = try allocator.alloc(u8, length);

    _ = std.base64.url_safe_no_pad.Encoder.encode(result, value);
    return result;
}

fn signatureB64(allocator: std.mem.Allocator, key_pair: Scheme.KeyPair, input: []const u8) ![]u8 {
    const signature = try key_pair.sign(input, null);
    const raw = signature.toBytes();
    const result = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(raw.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(result, &raw);
    return result;
}

fn compactSignature(allocator: std.mem.Allocator, key_pair: Scheme.KeyPair, input: []const u8, header: []const u8, claims: []const u8) ![]u8 {
    const signature = try signatureB64(allocator, key_pair, input);
    defer allocator.free(signature);
    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ header, claims, signature });
}

test "server identity emits Zig-compatible envelope" {
    var provider = Provider.init(std.testing.io, .{});
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const result = try provider.addToSdp(std.testing.allocator, sdp);
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, "a=identity:") != null);
}

test "the identity attribute follows the session fingerprint and precedes the media" {
    const identity = @import("sdp.zig");
    var provider = try deterministicProvider(.jwk, 0x2a);
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:abcd\r\n" ++
        "a=fingerprint:sha-256 AA:BB\r\n" ++
        "a=ice-options:trickle\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=fingerprint:sha-256 CC:DD\r\n";
    const signed = try provider.addToSdp(std.testing.allocator, sdp);
    defer std.testing.allocator.free(signed);

    try std.testing.expect(std.mem.indexOf(u8, signed, "\r\na=fingerprint:sha-256 AA:BB\r\na=identity:") != null);
    const fingerprint_at = std.mem.indexOf(u8, signed, "\r\na=fingerprint:sha-256 AA:BB\r\n") orelse return error.TestUnexpectedResult;
    const identity_at = std.mem.indexOf(u8, signed, "\r\na=identity:") orelse return error.TestUnexpectedResult;
    const media_at = std.mem.indexOf(u8, signed, "\r\nm=") orelse return error.TestUnexpectedResult;
    try std.testing.expect(fingerprint_at < identity_at);
    try std.testing.expect(identity_at < media_at);

    const stripped = try identity.withoutIdentity(std.testing.allocator, signed);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings(sdp, stripped);
}

test "an answer without a session fingerprint is refused" {
    var provider = try deterministicProvider(.jwk, 0x2a);
    const media_only = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 CC:DD\r\n";
    try std.testing.expectError(error.MissingFingerprint, provider.addToSdp(std.testing.allocator, media_only));

    const no_media = "v=0\r\na=fingerprint:sha-256 AA:BB\r\n";
    try std.testing.expectError(error.InvalidSdp, provider.addToSdp(std.testing.allocator, no_media));
}

test "server identity envelope survives extraction as valid JSON" {
    const identity = @import("sdp.zig");
    var provider = Provider.init(std.testing.io, .{});
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const signed = try provider.addToSdp(std.testing.allocator, sdp);
    defer std.testing.allocator.free(signed);

    var envelope = try identity.extract(signed, std.testing.allocator, .{});
    defer identity.deinit(std.testing.allocator, &envelope);
    try std.testing.expectEqualStrings("self", envelope.idp.domain);
    try std.testing.expectEqualStrings("default", envelope.idp.protocol);

    const Assertion = struct { fingerprints: []const u8, token: []const u8 };
    const parsed = try std.json.parseFromSlice(Assertion, std.testing.allocator, envelope.assertion, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, parsed.value.token, "."));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, parsed.value.fingerprints, "."));
}

test "the token header names only the algorithm" {
    const identity = @import("sdp.zig");
    var provider = try deterministicProvider(.jwk, 0x2a);
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const signed = try provider.addToSdp(std.testing.allocator, sdp);
    defer std.testing.allocator.free(signed);

    var envelope = try identity.extract(signed, std.testing.allocator, .{});
    defer identity.deinit(std.testing.allocator, &envelope);
    const Assertion = struct { fingerprints: []const u8, token: []const u8 };
    const parsed = try std.json.parseFromSlice(Assertion, std.testing.allocator, envelope.assertion, .{});
    defer parsed.deinit();

    var parts = std.mem.splitScalar(u8, parsed.value.token, '.');
    const header_segment = parts.next() orelse return error.TestUnexpectedResult;
    var header_buffer: [64]u8 = undefined;
    const header = try decodeUrl(&header_buffer, header_segment);
    try std.testing.expectEqualStrings("{\"alg\":\"ES384\"}", header);
}

fn testKeyPath(buffer: []u8) ![]const u8 {
    var random: [8]u8 = undefined;
    std.testing.io.random(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    return std.fmt.bufPrint(buffer, ".zig-cache/nethernet-key-{s}.bin", .{suffix[0..]});
}

test "the operator key is written once with 0600 and read back" {
    var path_buffer: [128]u8 = undefined;
    const path = try testKeyPath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(std.testing.io, path) catch {};

    const first = try Provider.loadOrCreateWith(std.testing.io, std.testing.allocator, path, .{ .cpk_encoding = .base64_der });
    const secret = first.secretKeyBytes();
    try std.testing.expectEqual(Provider.CpkEncoding.base64_der, first.cpk_encoding);

    if (@import("builtin").os.tag != .windows) {
        const stat = try dir.statFile(std.testing.io, path, .{});
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    }

    const second = try Provider.loadOrCreateWith(std.testing.io, std.testing.allocator, path, .{ .cpk_encoding = .base64_der });
    try std.testing.expectEqualSlices(u8, &secret, &second.secretKeyBytes());
    try std.testing.expectEqual(Provider.CpkEncoding.base64_der, second.cpk_encoding);
    try std.testing.expectEqualSlices(u8, &first.keyFingerprint(), &second.keyFingerprint());
}

test "a key file that is not a scalar is refused and left untouched" {
    var path_buffer: [128]u8 = undefined;
    const path = try testKeyPath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(std.testing.io, path) catch {};

    const corrupt = "not a p-384 scalar";
    try dir.writeFile(std.testing.io, .{ .sub_path = path, .data = corrupt });

    try std.testing.expectError(error.InvalidKeyMaterial, Provider.loadOrCreate(std.testing.io, std.testing.allocator, path));

    const after = try dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(corrupt, after);
}

fn deterministicProvider(encoding: Provider.CpkEncoding, seed: u8) !Provider {
    return .{
        .io = std.testing.io,
        .key_pair = try Scheme.KeyPair.generateDeterministic([_]u8{seed} ** Scheme.KeyPair.seed_length),
        .cpk_encoding = encoding,
    };
}

fn pointFromClaim(claim: []const u8, encoding: Provider.CpkEncoding) ![97]u8 {
    var point: [97]u8 = undefined;
    point[0] = 0x04;
    switch (encoding) {
        .jwk => {
            const Jwk = struct { crv: []const u8, kty: []const u8, x: []const u8, y: []const u8 };
            const parsed = try std.json.parseFromSlice(Jwk, std.testing.allocator, claim, .{});
            defer parsed.deinit();
            try std.testing.expectEqualStrings("P-384", parsed.value.crv);
            try std.testing.expectEqualStrings("EC", parsed.value.kty);
            if (try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(parsed.value.x) != 48) return error.InvalidCoordinate;
            if (try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(parsed.value.y) != 48) return error.InvalidCoordinate;
            try std.base64.url_safe_no_pad.Decoder.decode(point[1..49], parsed.value.x);
            try std.base64.url_safe_no_pad.Decoder.decode(point[49..97], parsed.value.y);
        },
        .base64_der => {
            const parsed = try std.json.parseFromSlice([]const u8, std.testing.allocator, claim, .{});
            defer parsed.deinit();
            var der: [der_length]u8 = undefined;
            try std.base64.standard.Decoder.decode(&der, parsed.value);
            const prefix = [_]u8{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };
            try std.testing.expectEqualSlices(u8, &prefix, der[0..prefix.len]);
            @memcpy(&point, der[prefix.len..der_length]);
        },
    }
    return point;
}

fn claimFromJwtClaims(claims: []const u8) Error![]const u8 {
    const key = "\"cpk\":";
    const start = std.mem.indexOf(u8, claims, key) orelse return error.MissingFingerprint;
    const end = std.mem.lastIndexOfScalar(u8, claims, '}') orelse return error.InvalidSdp;
    if (end <= start + key.len) return error.InvalidSdp;
    return claims[start + key.len .. end];
}

fn decodeUrl(buffer: []u8, text: []const u8) ![]const u8 {
    const length = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text);
    if (length > buffer.len) return error.NoSpaceLeft;
    try std.base64.url_safe_no_pad.Decoder.decode(buffer[0..length], text);
    return buffer[0..length];
}

test "the jwk claim is the RFC 7518 object of the signing key, byte for byte" {
    const provider = try deterministicProvider(.jwk, 0x2a);
    var buffer: [cpk_claim_max_length]u8 = undefined;
    const claim = provider.cpkClaim(&buffer);

    const point = provider.key_pair.public_key.toUncompressedSec1();
    var x_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    var y_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buffer, point[1..49]);
    const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buffer, point[49..97]);
    const expected = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}",
        .{ x, y },
    );
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, claim);
    try std.testing.expectEqual(@as(usize, 64), x.len);
    try std.testing.expectEqual(@as(usize, 64), y.len);
    try std.testing.expect(std.mem.indexOfAny(u8, claim, "+/=") == null);

    const declared = try pointFromClaim(claim, .jwk);
    try std.testing.expectEqualSlices(u8, &point, &declared);
}

test "the base64_der claim is the quoted DER of the same key" {
    const provider = try deterministicProvider(.base64_der, 0x2a);
    var buffer: [cpk_claim_max_length]u8 = undefined;
    const claim = provider.cpkClaim(&buffer);
    try std.testing.expectEqual(@as(usize, der_base64_length + 2), claim.len);
    try std.testing.expect(claim[0] == '"');
    try std.testing.expect(claim[claim.len - 1] == '"');

    const point = provider.key_pair.public_key.toUncompressedSec1();
    const declared = try pointFromClaim(claim, .base64_der);
    try std.testing.expectEqualSlices(u8, &point, &declared);

    const jwk_provider = try deterministicProvider(.jwk, 0x2a);
    var jwk_buffer: [cpk_claim_max_length]u8 = undefined;
    const from_jwk = try pointFromClaim(jwk_provider.cpkClaim(&jwk_buffer), .jwk);
    try std.testing.expectEqualSlices(u8, &declared, &from_jwk);
}

test "both cpk encodings name the key that signed the JWT" {
    const identity = @import("sdp.zig");
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const Assertion = struct { fingerprints: []const u8, token: []const u8 };

    for ([_]Provider.CpkEncoding{ .jwk, .base64_der }) |encoding| {
        const provider = try deterministicProvider(encoding, 0x2a);
        const signed = try provider.addToSdp(std.testing.allocator, sdp);
        defer std.testing.allocator.free(signed);

        var envelope = try identity.extract(signed, std.testing.allocator, .{});
        defer identity.deinit(std.testing.allocator, &envelope);
        const assertion = try std.json.parseFromSlice(Assertion, std.testing.allocator, envelope.assertion, .{});
        defer assertion.deinit();

        var parts = std.mem.splitScalar(u8, assertion.value.token, '.');
        const header_b64 = parts.next().?;
        const claims_b64 = parts.next().?;
        const signature_b64 = parts.next().?;
        try std.testing.expect(parts.next() == null);

        var header_buffer: [320]u8 = undefined;
        const header = try decodeUrl(&header_buffer, header_b64);
        try std.testing.expect(std.mem.indexOf(u8, header, "\"alg\":\"ES384\"") != null);
        var claims_buffer: [cpk_claim_max_length + 64]u8 = undefined;
        const claims = try decodeUrl(&claims_buffer, claims_b64);
        const claim = try claimFromJwtClaims(claims);

        const value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, claim, .{});
        defer value.deinit();
        switch (std.meta.activeTag(value.value)) {
            .object => try std.testing.expectEqual(Provider.CpkEncoding.jwk, encoding),
            .string => try std.testing.expectEqual(Provider.CpkEncoding.base64_der, encoding),
            else => return error.UnexpectedClaimType,
        }

        const point = try pointFromClaim(claim, encoding);
        const public_key = try Scheme.PublicKey.fromSec1(&point);
        const signing_input = try std.fmt.allocPrint(std.testing.allocator, "{s}.{s}", .{ header_b64, claims_b64 });
        defer std.testing.allocator.free(signing_input);
        var signature_bytes: [Scheme.Signature.encoded_length]u8 = undefined;
        try std.base64.url_safe_no_pad.Decoder.decode(&signature_bytes, signature_b64);
        const signature = Scheme.Signature.fromBytes(signature_bytes);

        try signature.verify(signing_input, public_key);
        var altered = try std.testing.allocator.dupe(u8, signing_input);
        defer std.testing.allocator.free(altered);
        altered[altered.len - 1] ^= 0x01;
        try std.testing.expectError(error.SignatureVerificationFailed, signature.verify(altered, public_key));
    }
}

test "a coordinate with a zero top byte keeps its 48 bytes in both claims" {
    var attempt: u16 = 0;
    while (attempt < 4096) : (attempt += 1) {
        var seed = [_]u8{0x5a} ** Scheme.KeyPair.seed_length;
        std.mem.writeInt(u16, seed[0..2], attempt, .little);
        const key_pair = try Scheme.KeyPair.generateDeterministic(seed);
        const point = key_pair.public_key.toUncompressedSec1();
        if (point[1] != 0 and point[49] != 0) continue;

        const jwk = Provider{ .io = std.testing.io, .key_pair = key_pair, .cpk_encoding = .jwk };
        var jwk_buffer: [cpk_claim_max_length]u8 = undefined;
        const claim = jwk.cpkClaim(&jwk_buffer);
        const Jwk = struct { crv: []const u8, kty: []const u8, x: []const u8, y: []const u8 };
        const parsed = try std.json.parseFromSlice(Jwk, std.testing.allocator, claim, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(@as(usize, 64), parsed.value.x.len);
        try std.testing.expectEqual(@as(usize, 64), parsed.value.y.len);
        if (point[1] == 0) try std.testing.expect(parsed.value.x[0] == 'A');
        if (point[49] == 0) try std.testing.expect(parsed.value.y[0] == 'A');
        const declared = try pointFromClaim(claim, .jwk);
        try std.testing.expectEqualSlices(u8, &point, &declared);

        const der = Provider{ .io = std.testing.io, .key_pair = key_pair, .cpk_encoding = .base64_der };
        var der_buffer: [cpk_claim_max_length]u8 = undefined;
        const from_der = try pointFromClaim(der.cpkClaim(&der_buffer), .base64_der);
        try std.testing.expectEqualSlices(u8, &point, &from_der);
        return;
    }
    return error.NoKeyWithZeroTopByte;
}

test "a provider defaults to the jwk claim the guide asks for" {
    const default = Provider.init(std.testing.io, .{});
    try std.testing.expectEqual(Provider.CpkEncoding.jwk, default.cpk_encoding);
    try std.testing.expectEqualStrings("self", default.domain);
    try std.testing.expectEqual(@as(i64, 3600), default.lifetime_seconds);

    const from_config = Provider.init(std.testing.io, .{ .cpk_encoding = .base64_der });
    try std.testing.expectEqual(Provider.CpkEncoding.base64_der, from_config.cpk_encoding);
    const from_field = Provider{ .io = std.testing.io, .key_pair = default.key_pair, .cpk_encoding = .base64_der };
    try std.testing.expectEqual(Provider.CpkEncoding.base64_der, from_field.cpk_encoding);
}

test "the identity config rejects domains and lifetimes that cannot travel" {
    const invalid_domains = [_][]const u8{
        "",
        "partner\"example",
        "partner\\example",
        "part ner",
        "part\nner",
        ".partner.example",
        "partner..example",
        "partner.example.",
        "-partner.example",
        "partner-.example",
        ("a" ** 64) ++ ".example",
        ("a" ** 50) ++ "." ++ ("a" ** 50) ++ "." ++ ("a" ** 50) ++ "." ++ ("a" ** 50) ++ "." ++ ("a" ** 50),
        "partnér.example",
        "_partner.example",
    };
    for (invalid_domains) |domain| {
        try std.testing.expectError(error.InvalidIdentityConfig, Provider.validateConfig(.{ .domain = domain }));
    }
    try std.testing.expectError(error.InvalidIdentityConfig, Provider.validateConfig(.{ .lifetime_seconds = 59 }));
    try std.testing.expectError(error.InvalidIdentityConfig, Provider.validateConfig(.{ .lifetime_seconds = 604_801 }));
    try Provider.validateConfig(.{ .domain = "A.partner-1.example", .lifetime_seconds = 60 });
    try Provider.validateConfig(.{ .lifetime_seconds = 604_800 });
}

test "the answer carries the configured domain and lifetime" {
    const provider = Provider.init(std.testing.io, .{ .domain = "partner.example", .lifetime_seconds = 3600 });
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const signed = try provider.addToSdp(std.testing.allocator, sdp);
    defer std.testing.allocator.free(signed);

    var envelope = try identity_sdp.extract(signed, std.testing.allocator, .{});
    defer identity_sdp.deinit(std.testing.allocator, &envelope);
    try std.testing.expectEqualStrings("partner.example", envelope.idp.domain);

    const Assertion = struct { token: []const u8 };
    const assertion = try std.json.parseFromSlice(Assertion, std.testing.allocator, envelope.assertion, .{ .ignore_unknown_fields = true });
    defer assertion.deinit();
    var parts = std.mem.splitScalar(u8, assertion.value.token, '.');
    _ = parts.next();
    const claims_b64 = parts.next() orelse return error.TestUnexpectedResult;
    var buffer: [512]u8 = undefined;
    const claims = try decodeUrl(&buffer, claims_b64);
    const Claims = struct { exp: i64, iat: i64 };
    const parsed = try std.json.parseFromSlice(Claims, std.testing.allocator, claims, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 3600), parsed.value.exp - parsed.value.iat);

    const broken = Provider{ .io = std.testing.io, .key_pair = provider.key_pair, .domain = "partner\"example" };
    try std.testing.expectError(error.InvalidIdentityConfig, broken.addToSdp(std.testing.allocator, sdp));
    const short = Provider{ .io = std.testing.io, .key_pair = provider.key_pair, .lifetime_seconds = 0 };
    try std.testing.expectError(error.InvalidIdentityConfig, short.addToSdp(std.testing.allocator, sdp));
}
