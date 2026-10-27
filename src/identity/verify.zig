const std = @import("std");

const identity_sdp = @import("sdp.zig");
const pin_store = @import("pin_store.zig");
const server_identity = @import("server.zig");

const Scheme = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const rsa = std.crypto.Certificate.rsa;

pub const Form = server_identity.Provider.CpkEncoding;

pub const Error = error{
    MissingIdentity,
    InvalidIdentity,
    UnsupportedAlgorithm,
    UnknownKey,
    MissingExpiration,
    ExpiredToken,
    TokenNotYetValid,
    BadTokenSignature,
    BadFingerprintSignature,
    MissingFingerprint,
    IdentityTooLarge,
    JwksUnavailable,
    MissingCpk,
    UnsupportedCpkForm,
    UnsupportedCurve,
    InvalidCpk,
    InvalidFingerprint,
    InvalidArgument,
} || std.mem.Allocator.Error || std.Io.Writer.Error;

pub const Assertion = struct {
    fingerprints: []const u8,
    token: []const u8,
};

pub const Claims = struct {
    cpk: std.json.Value,
    form: Form,
    issued_at: i64,
    expires_at: i64,
    xuid: ?[]const u8 = null,
    uuid: ?[]const u8 = null,
    playfab_id: ?[]const u8 = null,
    permissions: ?[]const u8 = null,
};

/// What the token said about the player, copied out of the parse tree that read it so
/// it outlives that tree. `SessionIdentity.deinit` frees it.
pub const SessionClaims = struct {
    xuid: ?[]u8 = null,
    uuid: ?[]u8 = null,
    playfab_id: ?[]u8 = null,
    permissions: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator, claims: *const Claims) std.mem.Allocator.Error!SessionClaims {
        var copied: SessionClaims = .{};
        errdefer copied.deinit(allocator);
        copied.xuid = try copyClaim(allocator, claims.xuid);
        copied.uuid = try copyClaim(allocator, claims.uuid);
        copied.playfab_id = try copyClaim(allocator, claims.playfab_id);
        copied.permissions = try copyClaim(allocator, claims.permissions);
        return copied;
    }

    pub fn deinit(self: *SessionClaims, allocator: std.mem.Allocator) void {
        for ([_]?[]u8{ self.xuid, self.uuid, self.playfab_id, self.permissions }) |claim| {
            if (claim) |bytes| allocator.free(bytes);
        }
        self.* = .{};
    }
};

fn copyClaim(allocator: std.mem.Allocator, claim: ?[]const u8) std.mem.Allocator.Error!?[]u8 {
    const value = claim orelse return null;
    return try allocator.dupe(u8, value);
}

/// The unanchored path keeps the token as JSON, so the claims are read back out of it.
fn sessionClaimsFromJson(allocator: std.mem.Allocator, claims_json: []const u8) Error!SessionClaims {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, claims_json, .{}) catch return error.InvalidIdentity;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidIdentity,
    };

    var claims: SessionClaims = .{};
    errdefer claims.deinit(allocator);
    claims.xuid = try copyMember(allocator, object, "xuid");
    claims.uuid = try copyMember(allocator, object, "uuid");
    claims.playfab_id = try copyMember(allocator, object, "playfabId");
    claims.permissions = try copyMember(allocator, object, "permissions");
    return claims;
}

fn copyMember(allocator: std.mem.Allocator, object: std.json.ObjectMap, name: []const u8) std.mem.Allocator.Error!?[]u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| try allocator.dupe(u8, text),
        else => null,
    };
}

pub const SessionIdentity = struct {
    form: Form,
    key_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    anchored: bool = false,
    claims: ?SessionClaims = null,

    /// The claims are borrowed slices: a consumer that copies this value must not call
    /// this twice, and must not call it on a copy either.
    pub fn deinit(self: *SessionIdentity, allocator: std.mem.Allocator) void {
        if (self.claims) |*claims| claims.deinit(allocator);
        self.* = undefined;
    }
};

pub const Verified = struct {
    public_key: Scheme.PublicKey,
    cpk_der: [spki_length]u8,
    cpk_digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    claims: Claims,
    parsed: std.json.Parsed(JsonClaims),

    pub fn deinit(self: *Verified, allocator: std.mem.Allocator) void {
        _ = allocator;
        self.parsed.deinit();
        self.* = undefined;
    }

    pub fn sessionIdentity(self: Verified, allocator: std.mem.Allocator) std.mem.Allocator.Error!SessionIdentity {
        return .{
            .form = self.claims.form,
            .key_sha256 = self.cpk_digest,
            .anchored = true,
            .claims = try SessionClaims.init(allocator, &self.claims),
        };
    }
};

pub const Cpk = struct {
    public_key: Scheme.PublicKey,
    form: Form,
};

pub const IdentityPolicy = struct {
    ctx: *anyopaque,
    allow: *const fn (ctx: *anyopaque, network_id: []const u8, claims: ?*const Claims) bool,
};

const spki_prefix = [23]u8{ 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };
const spki_length = spki_prefix.len + 97;
const point_length = 97;

comptime {
    if (spki_length != 120) @compileError("the spki prefix and the point disagree");
}

pub fn spkiDer(public_key: Scheme.PublicKey) [spki_length]u8 {
    var der: [spki_length]u8 = undefined;
    der[0..spki_prefix.len].* = spki_prefix;
    const point = public_key.toUncompressedSec1();
    @memcpy(der[spki_prefix.len..], &point);
    return der;
}

pub fn cpkPublicKey(cpk: std.json.Value) Error!Cpk {
    return switch (cpk) {
        .object => |object| .{ .public_key = try keyFromJwk(object), .form = .jwk },
        .string => |text| .{ .public_key = try keyFromDer(text), .form = .base64_der },
        else => error.UnsupportedCpkForm,
    };
}

fn stringMember(object: std.json.ObjectMap, name: []const u8) Error![]const u8 {
    const value = object.get(name) orelse return error.InvalidCpk;
    return switch (value) {
        .string => |text| text,
        else => error.InvalidCpk,
    };
}

fn keyFromJwk(object: std.json.ObjectMap) Error!Scheme.PublicKey {
    if (!std.mem.eql(u8, try stringMember(object, "kty"), "EC")) return error.InvalidCpk;
    if (!std.mem.eql(u8, try stringMember(object, "crv"), "P-384")) return error.UnsupportedCurve;

    var point: [point_length]u8 = undefined;
    point[0] = 0x04;
    try decodeEither(point[1..49], try stringMember(object, "x"), error.InvalidCpk);
    try decodeEither(point[49..97], try stringMember(object, "y"), error.InvalidCpk);
    return Scheme.PublicKey.fromSec1(&point) catch return error.InvalidCpk;
}

pub const TokenKey = union(enum) {
    ec: Scheme.PublicKey,
    rsa: RsaKey,

    pub const RsaKey = struct {
        public_key: rsa.PublicKey,
        modulus_len: usize,
    };
};

const Algorithm = enum { es384, rs256 };

fn algorithmForName(name: []const u8) ?Algorithm {
    for (allowed_algorithms) |allowed| {
        if (std.mem.eql(u8, name, allowed)) {
            if (std.mem.eql(u8, allowed, "ES384")) return .es384;
            return .rs256;
        }
    }
    return null;
}

fn rsaKeyFromJwk(object: std.json.ObjectMap) Error!TokenKey.RsaKey {
    const modulus_text = try stringMember(object, "n");
    const exponent_text = try stringMember(object, "e");

    const modulus_len = decodedSize(modulus_text) orelse return error.InvalidCpk;
    if (modulus_len != 256 and modulus_len != 384 and modulus_len != 512) return error.InvalidCpk;
    var modulus: [512]u8 = undefined;
    try decodeEither(modulus[0..modulus_len], modulus_text, error.InvalidCpk);

    const exponent_len = decodedSize(exponent_text) orelse return error.InvalidCpk;
    if (exponent_len == 0 or exponent_len > 4) return error.InvalidCpk;
    var exponent: [4]u8 = undefined;
    try decodeEither(exponent[0..exponent_len], exponent_text, error.InvalidCpk);

    return .{
        .public_key = rsa.PublicKey.fromBytes(exponent[0..exponent_len], modulus[0..modulus_len]) catch return error.InvalidCpk,
        .modulus_len = modulus_len,
    };
}

fn jwksKeyFromJwk(object: std.json.ObjectMap) Error!TokenKey {
    const kty = try stringMember(object, "kty");
    if (std.mem.eql(u8, kty, "EC")) return .{ .ec = try keyFromJwk(object) };
    if (std.mem.eql(u8, kty, "RSA")) return .{ .rsa = try rsaKeyFromJwk(object) };
    return error.UnsupportedCpkForm;
}

fn keyFromDer(text: []const u8) Error!Scheme.PublicKey {
    var der: [spki_length]u8 = undefined;
    var point: [point_length]u8 = undefined;
    switch (decodedSize(text) orelse return error.InvalidCpk) {
        spki_length => {
            try decodeEither(&der, text, error.InvalidCpk);
            if (!std.mem.eql(u8, der[0..spki_prefix.len], &spki_prefix)) return error.InvalidCpk;
            @memcpy(&point, der[spki_prefix.len..]);
        },
        point_length => try decodeEither(&point, text, error.InvalidCpk),
        else => return error.InvalidCpk,
    }
    return Scheme.PublicKey.fromSec1(&point) catch return error.InvalidCpk;
}

const Segments = struct {
    header: []const u8,
    claims: []const u8,
    signature: []const u8,
};

fn splitToken(token: []const u8) Error!Segments {
    var parts = std.mem.splitScalar(u8, token, '.');
    const header = parts.next() orelse return error.InvalidIdentity;
    const claims = parts.next() orelse return error.InvalidIdentity;
    const signature = parts.next() orelse return error.InvalidIdentity;
    if (parts.next() != null) return error.InvalidIdentity;
    if (header.len == 0 or claims.len == 0 or signature.len == 0) return error.InvalidIdentity;
    return .{ .header = header, .claims = claims, .signature = signature };
}

const JwsHeader = struct {
    alg: []const u8,
    kid: ?[]const u8 = null,
    b64: ?bool = null,
    crit: ?[]const []const u8 = null,
};

const JsonClaims = struct {
    cpk: ?std.json.Value = null,
    exp: std.json.Value,
    iat: std.json.Value,
    xuid: ?[]const u8 = null,
    uuid: ?[]const u8 = null,
    playfab_id: ?[]const u8 = null,
    permissions: ?[]const u8 = null,
};

const allowed_algorithms = [_][]const u8{ "ES384", "RS256" };

const allowed_algorithm = "ES384";

fn decodeAlloc(allocator: std.mem.Allocator, text: []const u8, comptime failure: Error) Error![]u8 {
    const trimmed = std.mem.trimEnd(u8, text, "=");
    const size = decodedSize(trimmed) orelse return failure;
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try decodeEither(out, trimmed, failure);
    return out;
}

fn decodeAllocJson(allocator: std.mem.Allocator, segment: []const u8, comptime failure: Error) Error![]u8 {
    return decodeAlloc(allocator, segment, failure);
}

const max_jws_header_b64: usize = 2048;

fn parseJwsHeader(allocator: std.mem.Allocator, header_b64: []const u8) Error!std.json.Parsed(JwsHeader) {
    if (header_b64.len == 0 or header_b64.len > max_jws_header_b64) return error.InvalidIdentity;
    const json = try decodeAllocJson(allocator, header_b64, error.InvalidIdentity);
    defer allocator.free(json);
    return std.json.parseFromSlice(JwsHeader, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidIdentity;
}

fn checkJwsHeader(allocator: std.mem.Allocator, header_b64: []const u8) Error!void {
    const parsed = try parseJwsHeader(allocator, header_b64);
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.alg, allowed_algorithm)) return error.UnsupportedAlgorithm;
    if (parsed.value.b64 == false) return error.UnsupportedAlgorithm;
    // RFC 7515 §4.1.11: a critical extension this verifier does not implement.
    if (parsed.value.crit) |crit| if (crit.len != 0) return error.UnsupportedAlgorithm;
}

pub const ClockOptions = struct {
    now_seconds: ?i64 = null,
    clock_skew_seconds: i64 = 300,
    require_exp: bool = true,
};

pub fn verifyToken(io: std.Io, allocator: std.mem.Allocator, token: []const u8, options: ClockOptions) Error!Identity {
    const segments = try splitToken(token);
    try checkJwsHeader(allocator, segments.header);

    const claims_json = try decodeAllocJson(allocator, segments.claims, error.InvalidIdentity);
    errdefer allocator.free(claims_json);
    var claims = try parseClaims(allocator, claims_json);
    defer claims.deinit();
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ segments.header, segments.claims });
    defer allocator.free(signing_input);
    try verifyEcdsa(claims.cpk.public_key, signing_input, segments.signature, error.BadTokenSignature);
    const now = options.now_seconds orelse std.Io.Clock.real.now(io).toSeconds();
    try checkClockValues(now, claims.issued_at, claims.expires_at, options.clock_skew_seconds, options.require_exp);
    return .{ .public_key = claims.cpk.public_key, .form = claims.cpk.form, .claims = claims_json };
}

pub fn verifyAssertion(allocator: std.mem.Allocator, assertion_json: []const u8, sdp: []const u8) Error!Identity {
    const parsed = std.json.parseFromSlice(Assertion, allocator, assertion_json, .{ .ignore_unknown_fields = true }) catch return error.InvalidIdentity;
    defer parsed.deinit();
    const segments = try splitToken(parsed.value.token);
    try checkJwsHeader(allocator, segments.header);
    const claims_json = try decodeAllocJson(allocator, segments.claims, error.InvalidIdentity);
    errdefer allocator.free(claims_json);
    var claims = try parseClaims(allocator, claims_json);
    defer claims.deinit();
    try verifyFingerprints(allocator, claims.cpk.public_key, parsed.value.fingerprints, sdp);
    return .{ .public_key = claims.cpk.public_key, .form = claims.cpk.form, .claims = claims_json };
}

pub const Identity = struct {
    public_key: Scheme.PublicKey,
    form: Form,
    claims: []u8,

    pub fn deinit(self: *Identity, allocator: std.mem.Allocator) void {
        allocator.free(self.claims);
        self.* = undefined;
    }

    pub fn sessionIdentity(self: Identity, allocator: std.mem.Allocator) Error!SessionIdentity {
        const der = spkiDer(self.public_key);
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});
        return .{
            .form = self.form,
            .key_sha256 = digest,
            .anchored = false,
            .claims = try sessionClaimsFromJson(allocator, self.claims),
        };
    }
};

const ParsedClaims = struct {
    parsed: std.json.Parsed(std.json.Value),
    cpk: Cpk,
    expires_at: ?i64,
    issued_at: ?i64,

    fn deinit(self: *ParsedClaims) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

fn parseClaims(allocator: std.mem.Allocator, claims_json: []const u8) Error!ParsedClaims {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, claims_json, .{}) catch return error.InvalidIdentity;
    errdefer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidIdentity,
    };
    return .{
        .parsed = parsed,
        .cpk = try cpkPublicKey(object.get("cpk") orelse return error.MissingCpk),
        .expires_at = try epochOptional(object.get("exp")),
        .issued_at = try epochOptional(object.get("iat")),
    };
}

pub fn verifyFingerprints(allocator: std.mem.Allocator, public_key: Scheme.PublicKey, jws: []const u8, sdp: []const u8) Error!void {
    var parts = std.mem.splitScalar(u8, jws, '.');
    const header = parts.next() orelse return error.InvalidIdentity;
    const payload = parts.next() orelse return error.InvalidIdentity;
    const signature = parts.next() orelse return error.InvalidIdentity;
    if (parts.next() != null) return error.InvalidIdentity;
    if (header.len == 0 or payload.len != 0 or signature.len == 0) return error.InvalidIdentity;
    try checkJwsHeader(allocator, header);

    const payload_json = try identity_sdp.fingerprintPayload(allocator, sdp);
    defer allocator.free(payload_json);
    const payload_b64 = try encodeUrl(allocator, payload_json);
    defer allocator.free(payload_b64);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header, payload_b64 });
    defer allocator.free(signing_input);
    try verifyEcdsa(public_key, signing_input, signature, error.BadFingerprintSignature);
}

pub fn verifyEcdsa(public_key: Scheme.PublicKey, signing_input: []const u8, signature_text: []const u8, comptime failure: Error) Error!void {
    var raw: [Scheme.Signature.encoded_length]u8 = undefined;
    try decodeEither(&raw, signature_text, failure);
    const signature = Scheme.Signature.fromBytes(raw);
    signature.verify(signing_input, public_key) catch return failure;
}

fn verifyTokenSignature(key: TokenKey, algorithm: Algorithm, signing_input: []const u8, signature_text: []const u8, comptime failure: Error) Error!void {
    switch (algorithm) {
        .es384 => try verifyEcdsa(switch (key) {
            .ec => |public_key| public_key,
            .rsa => return error.UnsupportedAlgorithm,
        }, signing_input, signature_text, failure),
        .rs256 => try verifyPkcs1(switch (key) {
            .rsa => |rsa_key| rsa_key,
            .ec => return error.UnsupportedAlgorithm,
        }, signing_input, signature_text, failure),
    }
}

fn verifyPkcs1(key: TokenKey.RsaKey, signing_input: []const u8, signature_text: []const u8, comptime failure: Error) Error!void {
    const length = decodedSize(signature_text) orelse return failure;
    if (length != key.modulus_len) return failure;
    var raw: [512]u8 = undefined;
    try decodeEither(raw[0..length], signature_text, failure);
    const Hash = std.crypto.hash.sha2.Sha256;
    const result = switch (length) {
        256 => rsa.PKCS1v1_5Signature.verify(256, raw[0..256].*, signing_input, key.public_key, Hash),
        384 => rsa.PKCS1v1_5Signature.verify(384, raw[0..384].*, signing_input, key.public_key, Hash),
        512 => rsa.PKCS1v1_5Signature.verify(512, raw[0..512].*, signing_input, key.public_key, Hash),
        else => return failure,
    };
    result catch return failure;
}

pub const JwksClient = struct {
    allocator: std.mem.Allocator,
    uri: ?[]const u8 = null,
    document: ?[]const u8 = null,
    cache_ttl_seconds: i64 = 3600,
    min_refresh_interval_seconds: i64 = 10,
    next_refresh_at_seconds: i64 = 0,

    fetched_at_seconds: i64 = std.math.minInt(i64),
    keys: std.StringArrayHashMapUnmanaged(JwkKey) = .empty,

    pub const JwkKey = struct {
        kid: []u8,
        key: TokenKey,
    };

    pub fn init(allocator: std.mem.Allocator, uri: ?[]const u8, document: ?[]const u8, cache_ttl_seconds: i64) JwksClient {
        return .{
            .allocator = allocator,
            .uri = uri,
            .document = document,
            .cache_ttl_seconds = cache_ttl_seconds,
        };
    }

    pub fn deinit(self: *JwksClient) void {
        for (self.keys.values()) |key| self.allocator.free(key.kid);
        self.keys.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: *const JwksClient) usize {
        return self.keys.count();
    }

    pub fn keyFor(self: *JwksClient, io: std.Io, mutex: *std.Io.Mutex, kid: ?[]const u8) Error!TokenKey {
        mutex.lockUncancelable(io);
        defer mutex.unlock(io);

        const now = std.Io.Clock.real.now(io).toSeconds();
        const stale = self.fetched_at_seconds == std.math.minInt(i64) or
            now - self.fetched_at_seconds >= self.cache_ttl_seconds;
        if (self.lookup(kid)) |key| {
            if (!stale) return key;
            try self.refreshIfDue(io, now);
            return self.lookup(kid) orelse error.UnknownKey;
        }
        // A `kid` the document does not list refreshes at most once per window: the
        // key may be one the provider just rotated in, and a flood of invented kids
        // must not turn into a flood of fetches.
        try self.refreshIfDue(io, now);
        return self.lookup(kid) orelse error.UnknownKey;
    }

    fn refreshIfDue(self: *JwksClient, io: std.Io, now: i64) Error!void {
        if (now < self.next_refresh_at_seconds) return;
        self.next_refresh_at_seconds = now + @max(self.min_refresh_interval_seconds, 1);
        return self.refresh(io);
    }

    fn lookup(self: *const JwksClient, kid: ?[]const u8) ?TokenKey {
        if (kid) |value| {
            const entry = self.keys.get(value) orelse return null;
            return entry.key;
        }
        if (self.keys.count() != 1) return null;
        return self.keys.values()[0].key;
    }

    fn refresh(self: *JwksClient, io: std.Io) Error!void {
        if (self.document) |pinned| {
            try self.load(pinned);
            self.fetched_at_seconds = std.Io.Clock.real.now(io).toSeconds();
            return;
        }
        const uri = self.uri orelse return error.JwksUnavailable;

        var client: std.http.Client = .{ .allocator = self.allocator, .io = io };
        defer client.deinit();
        var body: std.Io.Writer.Allocating = .init(self.allocator);
        defer body.deinit();
        const result = client.fetch(.{
            .location = .{ .url = uri },
            .redirect_behavior = .not_allowed,
            .response_writer = &body.writer,
        }) catch return error.JwksUnavailable;
        if (@intFromEnum(result.status) != 200) return error.JwksUnavailable;
        const document = body.written();
        if (document.len == 0 or document.len > 1024 * 1024) return error.JwksUnavailable;
        try self.load(document);
        self.fetched_at_seconds = std.Io.Clock.real.now(io).toSeconds();
    }

    fn load(self: *JwksClient, document: []const u8) Error!void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, document, .{}) catch return error.JwksUnavailable;
        defer parsed.deinit();
        const object = switch (parsed.value) {
            .object => |object| object,
            else => return error.JwksUnavailable,
        };
        const listed = switch (object.get("keys") orelse return error.JwksUnavailable) {
            .array => |array| array,
            else => return error.JwksUnavailable,
        };
        if (listed.items.len == 0) return error.JwksUnavailable;

        for (self.keys.values()) |key| self.allocator.free(key.kid);
        self.keys.clearRetainingCapacity();
        for (listed.items) |item| {
            const entry = switch (item) {
                .object => |entry| entry,
                else => continue,
            };
            const kid = stringMember(entry, "kid") catch continue;
            const key = jwksKeyFromJwk(entry) catch continue;
            const owned = try self.allocator.dupe(u8, kid);
            errdefer self.allocator.free(owned);
            const slot = try self.keys.getOrPut(self.allocator, owned);
            if (slot.found_existing) {
                self.allocator.free(owned);
                slot.value_ptr.* = .{ .kid = @constCast(slot.key_ptr.*), .key = key };
            } else {
                slot.key_ptr.* = owned;
                slot.value_ptr.* = .{ .kid = owned, .key = key };
            }
        }
        if (self.keys.count() == 0) return error.JwksUnavailable;
    }
};

pub const Config = struct {
    jwks_uri: ?[]const u8 = null,
    jwks_document: ?[]const u8 = null,
    jwks_cache_ttl_seconds: i64 = 3600,
    jwks_min_refresh_seconds: i64 = 10,
    clock_skew_seconds: i64 = 300,
    max_identity_bytes: usize = 64 * 1024,
};

pub const Verifier = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    jwks: JwksClient,
    jwks_lock: std.Io.Mutex = .init,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) Error!Verifier {
        if (config.jwks_uri == null and config.jwks_document == null) return error.InvalidArgument;
        var jwks = JwksClient.init(allocator, config.jwks_uri, config.jwks_document, config.jwks_cache_ttl_seconds);
        jwks.min_refresh_interval_seconds = @max(config.jwks_min_refresh_seconds, 1);
        return .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .jwks = jwks,
        };
    }

    pub fn deinit(self: *Verifier) void {
        self.jwks.deinit();
        self.* = undefined;
    }

    pub fn verifyOffer(self: *Verifier, offer: []const u8) Error!Verified {
        var envelope = identity_sdp.extract(offer, self.allocator, .{ .max_attribute_size = self.config.max_identity_bytes }) catch |err| return switch (err) {
            error.PayloadTooLarge => error.IdentityTooLarge,
            error.MissingIdentity => error.MissingIdentity,
            else => error.InvalidIdentity,
        };
        defer identity_sdp.deinit(self.allocator, &envelope);

        const assertion = std.json.parseFromSlice(Assertion, self.allocator, envelope.assertion, .{ .ignore_unknown_fields = true }) catch return error.InvalidIdentity;
        defer assertion.deinit();

        const segments = try splitToken(assertion.value.token);
        const header = try parseJwsHeader(self.allocator, segments.header);
        defer header.deinit();
        const algorithm = algorithmForName(header.value.alg) orelse return error.UnsupportedAlgorithm;

        const signing_key = try self.jwks.keyFor(self.io, &self.jwks_lock, header.value.kid);
        const signing_input = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ segments.header, segments.claims });
        defer self.allocator.free(signing_input);
        try verifyTokenSignature(signing_key, algorithm, signing_input, segments.signature, error.BadTokenSignature);

        const claims_json = try decodeAllocJson(self.allocator, segments.claims, error.InvalidIdentity);
        defer self.allocator.free(claims_json);
        var parsed = std.json.parseFromSlice(JsonClaims, self.allocator, claims_json, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return error.InvalidIdentity;
        errdefer parsed.deinit();

        const cpk_value = parsed.value.cpk orelse return error.MissingCpk;
        const declared = try cpkPublicKey(cpk_value);
        const issued_at = try epoch(parsed.value.iat);
        const expires_at = try epoch(parsed.value.exp);
        try self.checkClock(issued_at, expires_at);

        try verifyFingerprints(self.allocator, declared.public_key, assertion.value.fingerprints, offer);

        const der = spkiDer(declared.public_key);
        var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});

        return .{
            .public_key = declared.public_key,
            .cpk_der = der,
            .cpk_digest = digest,
            .claims = .{
                .cpk = cpk_value,
                .form = declared.form,
                .issued_at = issued_at,
                .expires_at = expires_at,
                .xuid = parsed.value.xuid,
                .uuid = parsed.value.uuid,
                .playfab_id = parsed.value.playfab_id,
                .permissions = parsed.value.permissions,
            },
            .parsed = parsed,
        };
    }

    fn checkClock(self: *Verifier, issued_at: i64, expires_at: i64) Error!void {
        const now = std.Io.Clock.real.now(self.io).toSeconds();
        try checkClockValues(now, issued_at, expires_at, self.config.clock_skew_seconds, true);
    }
};

pub const PinStore = pin_store.PinStore;
pub const Pin = pin_store.Pin;
pub const PinStoreError = pin_store.Error;

pub const AnswerError = Error || pin_store.Error || error{UnexpectedIdentityProvider};

pub const UnknownKey = enum { pin_and_accept, accept_once, reject };

pub const ToFu = struct {
    store: *PinStore,
    /// `null` refuses a key the store has not seen: the default does not trust.
    on_unknown: ?*const fn (ctx: *anyopaque, idp_domain: []const u8, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8) UnknownKey = null,
    ctx: *anyopaque = undefined,

    fn decide(self: ToFu, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8, domain: []const u8, allow_change: bool) AnswerError!bool {
        if (self.store.lookup(digest)) |pin| {
            if (!std.mem.eql(u8, pin.domainName(), domain)) return error.OperatorKeyChanged;
            return true;
        }
        if (!allow_change and self.store.hasDomain(domain)) return error.OperatorKeyChanged;
        const decision = if (self.on_unknown) |callback| callback(self.ctx, domain, digest) else .reject;
        return switch (decision) {
            .reject => error.UnknownOperatorKey,
            .accept_once => false,
            .pin_and_accept => blk: {
                try self.store.remember(digest, domain, std.Io.Clock.real.now(self.store.io).toSeconds());
                try self.store.save();
                break :blk true;
            },
        };
    }
};

pub const Trust = union(enum) {
    transport_authenticated,
    tofu: ToFu,
    pinned: *PinStore,
};

pub const AnswerOptions = struct {
    trust: Trust,
    clock_skew_seconds: i64 = 300,
    now_seconds: ?i64 = null,
    max_identity_bytes: usize = 64 * 1024,
    expected_domain: ?[]const u8 = null,
    allow_key_change: bool = false,
};

pub const VerifiedAnswer = struct {
    identity: SessionIdentity,
    idp_domain: []u8,
    public_key_sha256: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    clean_sdp: []u8,
    anchored: bool,

    pub fn deinit(self: *VerifiedAnswer, allocator: std.mem.Allocator) void {
        self.identity.deinit(allocator);
        allocator.free(self.idp_domain);
        allocator.free(self.clean_sdp);
        self.* = undefined;
    }
};

pub fn verifyAnswer(io: std.Io, allocator: std.mem.Allocator, answer_sdp: []const u8, options: AnswerOptions) AnswerError!VerifiedAnswer {
    var envelope = identity_sdp.extract(answer_sdp, allocator, .{ .max_attribute_size = options.max_identity_bytes }) catch |err| return switch (err) {
        error.PayloadTooLarge => error.IdentityTooLarge,
        error.MissingIdentity => error.MissingIdentity,
        else => error.InvalidIdentity,
    };
    defer identity_sdp.deinit(allocator, &envelope);

    if (options.expected_domain) |domain| {
        if (!std.mem.eql(u8, envelope.idp.domain, domain)) return error.UnexpectedIdentityProvider;
    }

    const parsed = std.json.parseFromSlice(Assertion, allocator, envelope.assertion, .{ .ignore_unknown_fields = true }) catch return error.InvalidIdentity;
    defer parsed.deinit();

    var token = try verifyToken(io, allocator, parsed.value.token, .{
        .now_seconds = options.now_seconds,
        .clock_skew_seconds = options.clock_skew_seconds,
    });
    defer token.deinit(allocator);
    try verifyFingerprints(allocator, token.public_key, parsed.value.fingerprints, answer_sdp);

    var identity = try token.sessionIdentity(allocator);
    const anchored = switch (options.trust) {
        .transport_authenticated => true,
        .pinned => |store| try store.require(identity.key_sha256, envelope.idp.domain, options.allow_key_change),
        .tofu => |tofu| try tofu.decide(identity.key_sha256, envelope.idp.domain, options.allow_key_change),
    };
    identity.anchored = anchored;

    const idp_domain = try allocator.dupe(u8, envelope.idp.domain);
    errdefer allocator.free(idp_domain);
    const clean_sdp = identity_sdp.withoutIdentity(allocator, answer_sdp) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidIdentity,
    };
    errdefer allocator.free(clean_sdp);

    return .{
        .identity = identity,
        .idp_domain = idp_domain,
        .public_key_sha256 = identity.key_sha256,
        .clean_sdp = clean_sdp,
        .anchored = anchored,
    };
}

fn checkClockValues(now: i64, issued_at: ?i64, expires_at: ?i64, skew: i64, require_exp: bool) Error!void {
    if (skew < 0) return error.InvalidArgument;
    const exp = expires_at orelse {
        if (require_exp) return error.MissingExpiration;
        return;
    };
    if (exp <= (issued_at orelse std.math.minInt(i64))) return error.InvalidIdentity;
    // Claims are attacker-supplied in the self-signed path; saturate instead of panicking.
    if (std.math.add(i64, exp, skew) catch std.math.maxInt(i64) < now) return error.ExpiredToken;
    if (issued_at) |iat| {
        if (std.math.sub(i64, iat, skew) catch std.math.minInt(i64) > now) return error.TokenNotYetValid;
    }
}

fn epochOptional(value: ?std.json.Value) Error!?i64 {
    return if (value) |present| try epoch(present) else null;
}

fn epoch(value: std.json.Value) Error!i64 {
    return switch (value) {
        .integer => |number| number,
        .float => |number| if (std.math.isFinite(number) and number >= @as(f64, @floatFromInt(std.math.minInt(i64))) and number <= @as(f64, @floatFromInt(std.math.maxInt(i64))))
            @intFromFloat(number)
        else
            return error.InvalidIdentity,
        else => error.InvalidIdentity,
    };
}

fn decodedSize(text: []const u8) ?usize {
    const trimmed = std.mem.trimEnd(u8, text, "=");
    if (trimmed.len == 0) return null;
    if (std.base64.standard_no_pad.Decoder.calcSizeForSlice(trimmed)) |size| return size else |_| {}
    if (std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed)) |size| return size else |_| {}
    return null;
}

fn decodeEither(out: []u8, text: []const u8, comptime failure: Error) Error!void {
    const trimmed = std.mem.trimEnd(u8, text, "=");
    if (trimmed.len == 0) return failure;
    if (decodeInto(std.base64.standard_no_pad, out, trimmed)) return;
    if (decodeInto(std.base64.url_safe_no_pad, out, trimmed)) return;
    return failure;
}

fn decodeInto(comptime codec: std.base64.Codecs, out: []u8, text: []const u8) bool {
    const decoder = codec.Decoder;
    const size = decoder.calcSizeForSlice(text) catch return false;
    if (size != out.len) return false;
    decoder.decode(out, text) catch return false;
    return true;
}

fn encodeUrl(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const length = std.base64.url_safe_no_pad.Encoder.calcSize(value.len);
    const result = try allocator.alloc(u8, length);
    _ = std.base64.url_safe_no_pad.Encoder.encode(result, value);
    return result;
}

const testing = std.testing;
const protected_header = "eyJhbGciOiJFUzM4NCJ9";

const test_sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
const two_line_sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\na=fingerprint:sha-256 11:22:33:44\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

const issuer_kid = "auth-1";

fn testKey(seed: u8) !Scheme.KeyPair {
    return Scheme.KeyPair.generateDeterministic([_]u8{seed} ** Scheme.KeyPair.seed_length);
}

fn encode(comptime capacity: usize, buffer: *[capacity]u8, value: []const u8) []const u8 {
    return std.base64.url_safe_no_pad.Encoder.encode(buffer, value);
}

fn signatureText(allocator: std.mem.Allocator, key_pair: Scheme.KeyPair, input: []const u8) ![]u8 {
    const signature = try key_pair.sign(input, null);
    const raw = signature.toBytes();
    const encoded = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(raw.len));
    defer allocator.free(encoded);
    return allocator.dupe(u8, std.base64.url_safe_no_pad.Encoder.encode(encoded, &raw));
}

fn jwkClaim(allocator: std.mem.Allocator, public_key: Scheme.PublicKey) ![]u8 {
    const point = public_key.toUncompressedSec1();
    var x_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    var y_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buffer, point[1..49]);
    const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buffer, point[49..97]);
    return std.fmt.allocPrint(allocator, "{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x, y });
}

fn claimText(allocator: std.mem.Allocator, public_key: Scheme.PublicKey, form: Form) ![]u8 {
    switch (form) {
        .jwk => return jwkClaim(allocator, public_key),
        .base64_der => {
            const der = spkiDer(public_key);
            var encoded_buffer: [std.base64.standard.Encoder.calcSize(spki_length)]u8 = undefined;
            const encoded = std.base64.standard.Encoder.encode(&encoded_buffer, &der);
            return std.fmt.allocPrint(allocator, "\"{s}\"", .{encoded});
        },
    }
}

fn jwksDocument(allocator: std.mem.Allocator, public_key: Scheme.PublicKey, kid: []const u8) ![]u8 {
    const point = public_key.toUncompressedSec1();
    var x_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    var y_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buffer, point[1..49]);
    const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buffer, point[49..97]);
    return std.fmt.allocPrint(
        allocator,
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-384\",\"kid\":\"{s}\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
        .{ kid, x, y },
    );
}

fn jsonEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (value) |byte| switch (byte) {
        '"' => try out.appendSlice(allocator, "\\\""),
        '\\' => try out.appendSlice(allocator, "\\\\"),
        else => try out.append(allocator, byte),
    };
    return out.toOwnedSlice(allocator);
}

fn embedAssertion(allocator: std.mem.Allocator, sdp: []const u8, assertion_json: []const u8) ![]u8 {
    const escaped = try jsonEscape(allocator, assertion_json);
    defer allocator.free(escaped);
    const envelope = try std.fmt.allocPrint(
        allocator,
        "{{\"assertion\":\"{s}\",\"idp\":{{\"domain\":\"self\",\"protocol\":\"default\"}}}}",
        .{escaped},
    );
    defer allocator.free(envelope);
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(envelope.len));
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, envelope);

    const media = std.mem.indexOf(u8, sdp, "m=") orelse return error.TestUnexpectedResult;
    return std.fmt.allocPrint(allocator, "{s}a=identity:{s}\r\n{s}", .{ sdp[0..media], encoded, sdp[media..] });
}

const OfferOptions = struct {
    form: Form = .jwk,
    sdp: []const u8 = test_sdp,
    kid: ?[]const u8 = issuer_kid,
    alg: []const u8 = allowed_algorithm,
    fingerprint_header: []const u8 = "{\"alg\":\"ES384\"}",
    now_seconds: ?i64 = null,
    exp_offset: ?i64 = 60,
    iat_offset: i64 = -1,
    token_signer: ?Scheme.KeyPair = null,
};

fn clientOffer(allocator: std.mem.Allocator, issuer: Scheme.KeyPair, peer: Scheme.KeyPair, options: OfferOptions) ![]u8 {
    const now = options.now_seconds orelse std.Io.Clock.real.now(testing.io).toSeconds();
    const claim = try claimText(allocator, peer.public_key, options.form);
    defer allocator.free(claim);

    const header_json = if (options.kid) |kid|
        try std.fmt.allocPrint(allocator, "{{\"alg\":\"{s}\",\"kid\":\"{s}\"}}", .{ options.alg, kid })
    else
        try std.fmt.allocPrint(allocator, "{{\"alg\":\"{s}\"}}", .{options.alg});
    defer allocator.free(header_json);
    const claims_json = if (options.exp_offset) |offset|
        try std.fmt.allocPrint(
            allocator,
            "{{\"cpk\":{s},\"exp\":{d},\"iat\":{d},\"xuid\":\"2535400000000001\",\"uuid\":\"069a79f4-44e9-4726-a5be-fca90e38aaf5\",\"permissions\":\"player\"}}",
            .{ claim, now + offset, now + options.iat_offset },
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "{{\"cpk\":{s},\"iat\":{d},\"xuid\":\"2535400000000001\",\"uuid\":\"069a79f4-44e9-4726-a5be-fca90e38aaf5\",\"permissions\":\"player\"}}",
            .{ claim, now + options.iat_offset },
        );
    defer allocator.free(claims_json);

    var header_buffer: [256]u8 = undefined;
    const header_segment = encode(header_buffer.len, &header_buffer, header_json);
    var claims_buffer: [1024]u8 = undefined;
    const claims_segment = encode(claims_buffer.len, &claims_buffer, claims_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_segment, claims_segment });
    defer allocator.free(signing_input);
    const token_signature = try signatureText(allocator, options.token_signer orelse issuer, signing_input);
    defer allocator.free(token_signature);
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ header_segment, claims_segment, token_signature });
    defer allocator.free(token);

    const payload = try identity_sdp.fingerprintPayload(allocator, options.sdp);
    defer allocator.free(payload);
    var payload_buffer: [2048]u8 = undefined;
    const payload_segment = encode(payload_buffer.len, &payload_buffer, payload);
    var fingerprint_header_buffer: [256]u8 = undefined;
    const fingerprint_header_segment = encode(fingerprint_header_buffer.len, &fingerprint_header_buffer, options.fingerprint_header);
    const detached_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ fingerprint_header_segment, payload_segment });
    defer allocator.free(detached_input);
    const fingerprint_signature = try signatureText(allocator, peer, detached_input);
    defer allocator.free(fingerprint_signature);
    const fingerprints = try std.fmt.allocPrint(allocator, "{s}..{s}", .{ fingerprint_header_segment, fingerprint_signature });
    defer allocator.free(fingerprints);

    const assertion = try std.fmt.allocPrint(
        allocator,
        "{{\"fingerprints\":\"{s}\",\"token\":\"{s}\"}}",
        .{ fingerprints, token },
    );
    defer allocator.free(assertion);
    return embedAssertion(allocator, options.sdp, assertion);
}

fn tamperFingerprint(allocator: std.mem.Allocator, sdp: []const u8, occurrence: usize) ![]u8 {
    const copy = try allocator.dupe(u8, sdp);
    errdefer allocator.free(copy);
    var index: usize = 0;
    var seen: usize = 0;
    while (std.mem.indexOfPos(u8, copy, index, "a=fingerprint:")) |start| {
        if (seen == occurrence) {
            const end = std.mem.indexOfScalarPos(u8, copy, start, '\r') orelse copy.len;
            copy[end - 1] = if (copy[end - 1] == 'D') 'E' else 'D';
            return copy;
        }
        seen += 1;
        index = start + 1;
    }
    return error.TestUnexpectedResult;
}

fn tamperDetachedSignature(allocator: std.mem.Allocator, offer: []const u8) ![]u8 {
    var envelope = try identity_sdp.extract(offer, allocator, .{});
    defer identity_sdp.deinit(allocator, &envelope);
    const assertion = try allocator.dupe(u8, envelope.assertion);
    defer allocator.free(assertion);
    const key = "\"fingerprints\":\"";
    const start = std.mem.indexOf(u8, assertion, key).? + key.len;
    const end = std.mem.indexOfScalarPos(u8, assertion, start, '"').?;
    const dot = std.mem.lastIndexOfScalar(u8, assertion[start..end], '.') orelse return error.TestUnexpectedResult;
    const at = start + dot + 1;
    assertion[at] = if (assertion[at] == 'A') 'B' else 'A';
    const clean = try identity_sdp.withoutIdentity(allocator, offer);
    defer allocator.free(clean);
    return embedAssertion(allocator, clean, assertion);
}

fn verifierFor(document: []const u8) !Verifier {
    return Verifier.init(testing.io, testing.allocator, .{ .jwks_document = document });
}

fn replaceTokenHeader(allocator: std.mem.Allocator, signed: []const u8, header_json: []const u8) ![]u8 {
    var envelope = try identity_sdp.extract(signed, allocator, .{});
    defer identity_sdp.deinit(allocator, &envelope);
    const assertion = try std.json.parseFromSlice(Assertion, allocator, envelope.assertion, .{ .ignore_unknown_fields = true });
    defer assertion.deinit();
    const dot = std.mem.indexOfScalar(u8, assertion.value.token, '.') orelse return error.TestUnexpectedResult;
    var header_buffer: [256]u8 = undefined;
    const header_segment = encode(header_buffer.len, &header_buffer, header_json);
    const token = try std.fmt.allocPrint(allocator, "{s}{s}", .{ header_segment, assertion.value.token[dot..] });
    defer allocator.free(token);
    const rebuilt = try std.fmt.allocPrint(
        allocator,
        "{{\"fingerprints\":\"{s}\",\"token\":\"{s}\"}}",
        .{ assertion.value.fingerprints, token },
    );
    defer allocator.free(rebuilt);
    const clean = try identity_sdp.withoutIdentity(allocator, signed);
    defer allocator.free(clean);
    return embedAssertion(allocator, clean, rebuilt);
}

test "the auth service's token and the peer's signature verify in either cpk form" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    var digests: [2]SessionIdentity = undefined;
    defer for (&digests) |*digest| digest.deinit(testing.allocator);
    for ([_]Form{ .jwk, .base64_der }, 0..) |form, index| {
        const offer = try clientOffer(testing.allocator, issuer, peer, .{ .form = form });
        defer testing.allocator.free(offer);

        var verified = try verifier.verifyOffer(offer);
        defer verified.deinit(testing.allocator);
        try testing.expectEqual(form, verified.claims.form);
        try testing.expectEqualStrings("2535400000000001", verified.claims.xuid.?);
        try testing.expectEqualStrings("player", verified.claims.permissions.?);
        try testing.expect(verified.claims.expires_at > verified.claims.issued_at);

        const expected = spkiDer(peer.public_key);
        try testing.expectEqualSlices(u8, &expected, &verified.cpk_der);
        try testing.expectEqualSlices(u8, &expected, &spkiDer(verified.public_key));

        digests[index] = try verified.sessionIdentity(testing.allocator);
        try testing.expectEqualStrings("2535400000000001", digests[index].claims.?.xuid.?);
        try testing.expectEqual(form, digests[index].form);
        try testing.expect(digests[index].anchored);
        try testing.expectEqualSlices(u8, &verified.cpk_digest, &digests[index].key_sha256);
    }
    try testing.expectEqualSlices(u8, &digests[0].key_sha256, &digests[1].key_sha256);
}

test "session claims outlive the verified token they came from" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const offer = try clientOffer(testing.allocator, issuer, peer, .{});
    defer testing.allocator.free(offer);

    var verified = try verifier.verifyOffer(offer);
    var identity = try verified.sessionIdentity(testing.allocator);
    verified.deinit(testing.allocator);
    defer identity.deinit(testing.allocator);

    try testing.expect(identity.anchored);
    try testing.expectEqualStrings("2535400000000001", identity.claims.?.xuid.?);
    try testing.expectEqualStrings("player", identity.claims.?.permissions.?);
    try testing.expectEqualStrings("069a79f4-44e9-4726-a5be-fca90e38aaf5", identity.claims.?.uuid.?);
    try testing.expect(identity.claims.?.playfab_id == null);
}

test "a claim that does not verify is refused, never returned as verified" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const stranger = try testKey(0x43);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const offer = try clientOffer(testing.allocator, issuer, peer, .{});
    defer testing.allocator.free(offer);

    const changed = try tamperFingerprint(testing.allocator, offer, 0);
    defer testing.allocator.free(changed);
    try testing.expectError(error.BadFingerprintSignature, verifier.verifyOffer(changed));

    const flipped = try tamperDetachedSignature(testing.allocator, offer);
    defer testing.allocator.free(flipped);
    try testing.expectError(error.BadFingerprintSignature, verifier.verifyOffer(flipped));

    const forged = try clientOffer(testing.allocator, issuer, peer, .{ .token_signer = stranger });
    defer testing.allocator.free(forged);
    try testing.expectError(error.BadTokenSignature, verifier.verifyOffer(forged));
}

test "the token's algorithm and key id are checked before its signature" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const none = try clientOffer(testing.allocator, issuer, peer, .{ .alg = "none" });
    defer testing.allocator.free(none);
    try testing.expectError(error.UnsupportedAlgorithm, verifier.verifyOffer(none));

    const unknown = try clientOffer(testing.allocator, issuer, peer, .{ .kid = "auth-2" });
    defer testing.allocator.free(unknown);
    try testing.expectError(error.UnknownKey, verifier.verifyOffer(unknown));
}

test "expiry and issue time allow for clock skew between hosts" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const expired = try clientOffer(testing.allocator, issuer, peer, .{ .exp_offset = -301, .iat_offset = -400 });
    defer testing.allocator.free(expired);
    try testing.expectError(error.ExpiredToken, verifier.verifyOffer(expired));

    const just_expired = try clientOffer(testing.allocator, issuer, peer, .{ .exp_offset = -60, .iat_offset = -120 });
    defer testing.allocator.free(just_expired);
    var accepted = try verifier.verifyOffer(just_expired);
    accepted.deinit(testing.allocator);

    const future = try clientOffer(testing.allocator, issuer, peer, .{ .exp_offset = 660, .iat_offset = 600 });
    defer testing.allocator.free(future);
    try testing.expectError(error.TokenNotYetValid, verifier.verifyOffer(future));
}

test "every fingerprint line is covered, not just the first" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const offer = try clientOffer(testing.allocator, issuer, peer, .{ .sdp = two_line_sdp });
    defer testing.allocator.free(offer);
    var verified = try verifier.verifyOffer(offer);
    verified.deinit(testing.allocator);

    const changed = try tamperFingerprint(testing.allocator, offer, 1);
    defer testing.allocator.free(changed);
    try testing.expectError(error.BadFingerprintSignature, verifier.verifyOffer(changed));
}

test "an oversized identity is refused on its length" {
    const issuer = try testKey(0x41);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const oversized = try std.fmt.allocPrint(
        std.testing.allocator,
        "v=0\r\na=ice-ufrag:abcd\r\na=fingerprint:sha-256 AA:BB\r\na=identity:{s}\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n",
        .{"A" ** (64 * 1024 + 1)},
    );
    defer std.testing.allocator.free(oversized);
    try testing.expectError(error.IdentityTooLarge, verifier.verifyOffer(oversized));
}

const rsa_fixture_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test-rsa-1\",\"n\":\"wCBCth7Se2e3-1mdX2OmxAOSi5KglwW7jwYnnVNkAOM2mQM8toJUbVOoYiwNOGcOux-qEgEfR-oxG3SVN8xBqPoG5h-EErFf3UIm3UiGrQf4iGkC455V3lV82mMcU06r07Ed-Ur-hfxsCvX4Emf6_KAAS44UUV-tBCoPHj9t5uuGHS_RLlaIq2AH9KpFMM6IiPMxS2bmXBCTTnbQUGjxGDNKaL_ggb8vXzgUW6r4ZOxt49jygCkj3kEmsZWrdsIW8pUdCcwQG251XR-JhTG0XoIRbEGImzW9iA0PMSKJDBJu_ZgeOocaeay43bE5SnppDOP4cJ08K29CAWSc5qgJ2Q\",\"e\":\"AQAB\"}]}";
const rsa_fixture_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QtcnNhLTEifQ.eyJjcGsiOnsiY3J2IjoiUC0zODQiLCJrdHkiOiJFQyIsIngiOiJwZmRzQnR2d3JfQ3RXci1zb09ZcFJmNEZBTTNzcFl4dmhTVU1NWGtzcmszQnNidGZnWXdRV25uZXpESE1wbGNMIiwieSI6Ilo4ZmRnQjBUZEN3dTBXeEVvNml1THZ0YlVIcnd5QmxpalNSNGR5dXdibXdVZGd0Snl4bkU5MmtwSHd4amh2eHAifSwiZXhwIjo0MTAyNDQ0ODAwLCJpYXQiOjE3MDAwMDAwMDAsInBlcm1pc3Npb25zIjoicGxheWVyIiwidXVpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsInh1aWQiOiIyNTM1MDAwMDAwMDAwMDAxIn0.SgOASrPXBl8zLY90KBU-Z9_l0wocSfOvZDvd2jzOwJ6CSz2AX8LspVRgK7VdA4L5mFR7N5-hoFONY0gv6u5nlat5xvUp1hVah3zYrjfpdnnhVUskAwsoPwVaZ5wrCmraO-ZsYKXWkVLi5MrDcMFA67-nNTXqzmP5USjIpw6fEp82373nKoCPdmmd57GCt987k6oWYoxM1UlIqFI4nnpuy73KypKGQpAazqlVGPYX4li7Oz1Z2NRRY0gbU8raWjGiac3sv5bHwoPhEt8LcddERKjjBAtgQiVVX675NHFhL7stH7QvJqL3tFWxbUSZ6zZGfoLSc2FQ-TVCX2vxDvGngg";
const rsa_fixture_peer_secret = [_]u8{
    0x1e, 0x40, 0x24, 0x40, 0x9f, 0x0d, 0xeb, 0xc8, 0x5a, 0x84, 0x5a, 0xc9,
    0x4a, 0xaa, 0x68, 0xa4, 0xdb, 0x7a, 0x6f, 0x0d, 0x38, 0xc7, 0x29, 0xe8,
    0x91, 0xe5, 0x0a, 0xc7, 0xdd, 0x71, 0xb8, 0xa4, 0xe0, 0x2e, 0xa6, 0xf5,
    0x26, 0x58, 0xc9, 0x79, 0x90, 0x95, 0x4b, 0xe0, 0x18, 0xe4, 0x98, 0x8c,
};

fn rsaFixtureOffer(allocator: std.mem.Allocator, token: []const u8) ![]u8 {
    const peer = try Scheme.KeyPair.fromSecretKey(try Scheme.SecretKey.fromBytes(rsa_fixture_peer_secret));
    const payload = try identity_sdp.fingerprintPayload(allocator, test_sdp);
    defer allocator.free(payload);
    var payload_buffer: [2048]u8 = undefined;
    const payload_segment = encode(payload_buffer.len, &payload_buffer, payload);
    const detached_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ protected_header, payload_segment });
    defer allocator.free(detached_input);
    const signature = try signatureText(allocator, peer, detached_input);
    defer allocator.free(signature);
    const assertion = try std.fmt.allocPrint(
        allocator,
        "{{\"fingerprints\":\"{s}..{s}\",\"token\":\"{s}\"}}",
        .{ protected_header, signature, token },
    );
    defer allocator.free(assertion);
    return embedAssertion(allocator, test_sdp, assertion);
}

test "a client token signed with the auth service's rsa key is verified" {
    var verifier = try verifierFor(rsa_fixture_jwks);
    defer verifier.deinit();
    const offer = try rsaFixtureOffer(testing.allocator, rsa_fixture_token);
    defer testing.allocator.free(offer);

    var verified = try verifier.verifyOffer(offer);
    defer verified.deinit(testing.allocator);
    try testing.expectEqualStrings("2535000000000001", verified.claims.xuid.?);
    try testing.expectEqualStrings("player", verified.claims.permissions.?);
    try testing.expectEqual(@as(i64, 4_102_444_800), verified.claims.expires_at);
    var identity = try verified.sessionIdentity(testing.allocator);
    defer identity.deinit(testing.allocator);
    try testing.expect(identity.anchored);
    try testing.expectEqualStrings("2535000000000001", identity.claims.?.xuid.?);
}

test "a tampered rsa token signature is refused" {
    var verifier = try verifierFor(rsa_fixture_jwks);
    defer verifier.deinit();

    const tampered = try testing.allocator.dupe(u8, rsa_fixture_token);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] = if (tampered[tampered.len - 1] == 'A') 'B' else 'A';

    const offer = try rsaFixtureOffer(testing.allocator, tampered);
    defer testing.allocator.free(offer);
    try testing.expectError(error.BadTokenSignature, verifier.verifyOffer(offer));
}

test "an rsa token is not checked against an ec key with the same kid" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const offer = try clientOffer(testing.allocator, issuer, peer, .{ .alg = "RS256", .kid = issuer_kid });
    defer testing.allocator.free(offer);
    try testing.expectError(error.UnsupportedAlgorithm, verifier.verifyOffer(offer));
}

test "a jwks with keys this verifier cannot use still loads the ones it can" {
    const mixed = try std.mem.replaceOwned(
        u8,
        testing.allocator,
        rsa_fixture_jwks,
        "\"keys\":[",
        "\"keys\":[{\"kty\":\"oct\",\"kid\":\"hmac\",\"k\":\"AAAA\"},{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"other\",\"x\":\"AA\",\"y\":\"AA\"},",
    );
    defer testing.allocator.free(mixed);

    var verifier = try verifierFor(mixed);
    defer verifier.deinit();

    const offer = try rsaFixtureOffer(testing.allocator, rsa_fixture_token);
    defer testing.allocator.free(offer);
    var verified = try verifier.verifyOffer(offer);
    verified.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), verifier.jwks.count());
}

test "a verifier without a jwks cannot exist, and an unreachable one fails closed" {
    try testing.expectError(error.InvalidArgument, Verifier.init(testing.io, testing.allocator, .{}));

    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const offer = try clientOffer(testing.allocator, issuer, peer, .{});
    defer testing.allocator.free(offer);

    var unreachable_verifier = try Verifier.init(testing.io, testing.allocator, .{ .jwks_uri = "http://127.0.0.1:1/jwks" });
    defer unreachable_verifier.deinit();
    try testing.expectError(error.JwksUnavailable, unreachable_verifier.verifyOffer(offer));
}

test "an offer without an identity is reported, not silently admitted" {
    const jwks = try jwksDocument(testing.allocator, (try testKey(0x41)).public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();
    try testing.expectError(error.MissingIdentity, verifier.verifyOffer(test_sdp));
}

test "the detached jws header decides which algorithm is checked" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const cases = [_]struct { header: []const u8, expected: Error }{
        .{ .header = "{\"alg\":\"none\"}", .expected = error.UnsupportedAlgorithm },
        .{ .header = "{\"alg\":\"HS256\"}", .expected = error.UnsupportedAlgorithm },
        .{ .header = "{\"alg\":\"RS256\"}", .expected = error.UnsupportedAlgorithm },
        .{ .header = "{}", .expected = error.InvalidIdentity },
        .{ .header = "not json", .expected = error.InvalidIdentity },
        .{ .header = "", .expected = error.InvalidIdentity },
    };
    for (cases) |case| {
        const offer = try clientOffer(testing.allocator, issuer, peer, .{ .fingerprint_header = case.header });
        defer testing.allocator.free(offer);
        try testing.expectError(case.expected, verifier.verifyOffer(offer));
    }
}

test "a detached jws that declares unimplemented semantics is refused" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const jwks = try jwksDocument(testing.allocator, issuer.public_key, issuer_kid);
    defer testing.allocator.free(jwks);
    var verifier = try verifierFor(jwks);
    defer verifier.deinit();

    const refused = [_][]const u8{
        "{\"alg\":\"ES384\",\"b64\":false}",
        "{\"alg\":\"ES384\",\"crit\":[\"exp\"]}",
    };
    for (refused) |header| {
        const offer = try clientOffer(testing.allocator, issuer, peer, .{ .fingerprint_header = header });
        defer testing.allocator.free(offer);
        try testing.expectError(error.UnsupportedAlgorithm, verifier.verifyOffer(offer));
    }

    const empty_crit = try clientOffer(testing.allocator, issuer, peer, .{
        .fingerprint_header = "{\"alg\":\"ES384\",\"crit\":[]}",
    });
    defer testing.allocator.free(empty_crit);
    var verified = try verifier.verifyOffer(empty_crit);
    defer verified.deinit(testing.allocator);
}

test "an oversized detached header is refused before it is decoded" {
    const peer = try testKey(0x42);
    var buffer: [64]u8 align(@alignOf(usize)) = undefined;
    var allocator: std.heap.FixedBufferAllocator = .init(&buffer);
    const header = "A" ** (max_jws_header_b64 + 1);
    const jws = try std.fmt.allocPrint(testing.allocator, "{s}..AAAA", .{header});
    defer testing.allocator.free(jws);
    try testing.expectError(error.InvalidIdentity, verifyFingerprints(allocator.allocator(), peer.public_key, jws, test_sdp));
}

fn tokenFromOffer(allocator: std.mem.Allocator, offer: []const u8) ![]u8 {
    var envelope = try identity_sdp.extract(offer, allocator, .{});
    defer identity_sdp.deinit(allocator, &envelope);
    const assertion = try std.json.parseFromSlice(Assertion, allocator, envelope.assertion, .{ .ignore_unknown_fields = true });
    defer assertion.deinit();
    return allocator.dupe(u8, assertion.value.token);
}

test "a token is only as fresh as its exp claim" {
    const issuer = try testKey(0x41);
    const peer = try testKey(0x42);
    const now: i64 = 1_700_000_000;

    const cases = [_]struct {
        exp_offset: ?i64,
        iat_offset: i64,
        require_exp: bool,
        expected: ?Error,
    }{
        .{ .exp_offset = -301, .iat_offset = -400, .require_exp = true, .expected = error.ExpiredToken },
        .{ .exp_offset = -60, .iat_offset = -120, .require_exp = true, .expected = null },
        .{ .exp_offset = 60, .iat_offset = -1, .require_exp = true, .expected = null },
        .{ .exp_offset = 660, .iat_offset = 600, .require_exp = true, .expected = error.TokenNotYetValid },
        .{ .exp_offset = null, .iat_offset = -1, .require_exp = true, .expected = error.MissingExpiration },
        .{ .exp_offset = null, .iat_offset = -1, .require_exp = false, .expected = null },
        .{ .exp_offset = -10, .iat_offset = 0, .require_exp = true, .expected = error.InvalidIdentity },
        .{ .exp_offset = std.math.maxInt(i64) - now, .iat_offset = -1, .require_exp = true, .expected = null },
        .{ .exp_offset = 60, .iat_offset = std.math.minInt(i64) + now, .require_exp = true, .expected = null },
    };
    for (cases) |case| {
        const offer = try clientOffer(testing.allocator, issuer, peer, .{
            .now_seconds = now,
            .exp_offset = case.exp_offset,
            .iat_offset = case.iat_offset,
            .token_signer = peer,
        });
        defer testing.allocator.free(offer);
        const token = try tokenFromOffer(testing.allocator, offer);
        defer testing.allocator.free(token);

        const result = verifyToken(testing.io, testing.allocator, token, .{
            .now_seconds = now,
            .require_exp = case.require_exp,
        });
        if (case.expected) |expected| {
            try testing.expectError(expected, result);
        } else {
            var identity = try result;
            identity.deinit(testing.allocator);
        }
    }
}

test "a token whose header names another algorithm is refused before its signature" {
    var header_buffer: [64]u8 = undefined;
    const header = encode(header_buffer.len, &header_buffer, "{\"alg\":\"none\"}");
    const token = try std.fmt.allocPrint(testing.allocator, "{s}.e30.AAAA", .{header});
    defer testing.allocator.free(token);
    try testing.expectError(error.UnsupportedAlgorithm, verifyToken(testing.io, testing.allocator, token, .{}));
}

test "a token inside an assertion is checked for its algorithm too" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const signed = try provider.addToSdp(testing.allocator, two_line_sdp);
    defer testing.allocator.free(signed);

    const forged = try replaceTokenHeader(testing.allocator, signed, "{\"alg\":\"none\"}");
    defer testing.allocator.free(forged);
    var envelope = try identity_sdp.extract(forged, testing.allocator, .{});
    defer identity_sdp.deinit(testing.allocator, &envelope);
    try testing.expectError(error.UnsupportedAlgorithm, verifyAssertion(testing.allocator, envelope.assertion, forged));
}

test "the claim's own jws and token are checked without an issuer" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const signed = try provider.addToSdp(testing.allocator, two_line_sdp);
    defer testing.allocator.free(signed);

    var envelope = try identity_sdp.extract(signed, testing.allocator, .{});
    defer identity_sdp.deinit(testing.allocator, &envelope);
    const assertion = try std.json.parseFromSlice(Assertion, testing.allocator, envelope.assertion, .{});
    defer assertion.deinit();

    var identity = try verifyAssertion(testing.allocator, envelope.assertion, signed);
    defer identity.deinit(testing.allocator);
    const expected = provider.key_pair.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &expected, &identity.public_key.toUncompressedSec1());
    var token_identity = try verifyToken(testing.io, testing.allocator, assertion.value.token, .{});
    defer token_identity.deinit(testing.allocator);
    try testing.expectEqual(identity.form, token_identity.form);

    const attached = try std.fmt.allocPrint(testing.allocator, "eyJhbGciOiJFUzM4NCJ9.e30.{s}", .{
        assertion.value.fingerprints[std.mem.lastIndexOfScalar(u8, assertion.value.fingerprints, '.').? + 1 ..],
    });
    defer testing.allocator.free(attached);
    try testing.expectError(error.InvalidIdentity, verifyFingerprints(testing.allocator, provider.key_pair.public_key, attached, signed));
}

const test_answer_sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

fn signedAnswer(allocator: std.mem.Allocator, provider: *server_identity.Provider) ![]u8 {
    return provider.addToSdp(allocator, test_answer_sdp);
}

const AcceptingPin = struct {
    calls: usize = 0,

    fn decide(ctx: *anyopaque, _: []const u8, _: [32]u8) UnknownKey {
        const self: *AcceptingPin = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return .pin_and_accept;
    }
};

fn testPinPath(buffer: []u8) ![]const u8 {
    var random: [8]u8 = undefined;
    testing.io.random(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    return std.fmt.bufPrint(buffer, ".zig-cache/nethernet-answer-pins-{s}.json", .{suffix[0..]});
}

test "a pinned key survives in the file and the next store does not ask" {
    var path_buffer: [128]u8 = undefined;
    const path = try testPinPath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(testing.io, path) catch {};

    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    {
        var store = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
        defer store.deinit();
        var counter: AcceptingPin = .{};
        var first = try verifyAnswer(testing.io, testing.allocator, answer, .{
            .trust = .{ .tofu = .{ .store = &store, .on_unknown = AcceptingPin.decide, .ctx = &counter } },
        });
        defer first.deinit(testing.allocator);
        try testing.expectEqual(@as(usize, 1), counter.calls);
    }

    var reloaded = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer reloaded.deinit();
    try reloaded.load();
    try testing.expectEqual(@as(usize, 1), reloaded.count());

    var known = try verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .pinned = &reloaded } });
    defer known.deinit(testing.allocator);
    try testing.expect(known.anchored);
}

const AcceptOnce = struct {
    fn decide(_: *anyopaque, _: []const u8, _: [32]u8) UnknownKey {
        return .accept_once;
    }
};

test "a server answer verifies and the backend gets a description without identity" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    var verified = try verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .transport_authenticated });
    defer verified.deinit(testing.allocator);

    try testing.expect(verified.anchored);
    try testing.expect(verified.identity.anchored);
    try testing.expectEqualStrings("self", verified.idp_domain);
    try testing.expectEqualStrings(test_answer_sdp, verified.clean_sdp);
    try testing.expectEqualSlices(u8, &provider.keyFingerprint(), &verified.public_key_sha256);
    try testing.expectEqualSlices(u8, &verified.public_key_sha256, &verified.identity.key_sha256);
    try testing.expectEqual(Form.jwk, verified.identity.form);
}

test "a first contact pins the key and a second answer does not ask again" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    var store = try PinStore.init(testing.io, testing.allocator, .{});
    defer store.deinit();
    var counter: AcceptingPin = .{};
    const tofu: ToFu = .{ .store = &store, .on_unknown = AcceptingPin.decide, .ctx = &counter };

    var first = try verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .tofu = tofu } });
    defer first.deinit(testing.allocator);
    try testing.expect(first.anchored);
    try testing.expectEqual(@as(usize, 1), counter.calls);
    try testing.expectEqual(@as(usize, 1), store.count());

    var second = try verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .tofu = tofu } });
    defer second.deinit(testing.allocator);
    try testing.expect(second.anchored);
    try testing.expectEqual(@as(usize, 1), counter.calls);
}

test "accepting a key once leaves the identity unanchored and stored nowhere" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    var store = try PinStore.init(testing.io, testing.allocator, .{});
    defer store.deinit();
    var ctx: u8 = 0;

    var verified = try verifyAnswer(testing.io, testing.allocator, answer, .{
        .trust = .{ .tofu = .{ .store = &store, .on_unknown = AcceptOnce.decide, .ctx = &ctx } },
    });
    defer verified.deinit(testing.allocator);
    try testing.expect(!verified.anchored);
    try testing.expect(!verified.identity.anchored);
    try testing.expectEqual(@as(usize, 0), store.count());
}

test "a key the store has not seen, or a second key for a pinned domain, is refused" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    var store = try PinStore.init(testing.io, testing.allocator, .{});
    defer store.deinit();
    try testing.expectError(error.UnknownOperatorKey, verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .pinned = &store } }));
    try testing.expectError(error.UnknownOperatorKey, verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .tofu = .{ .store = &store } } }));

    try store.remember(provider.keyFingerprint(), "self", 1);
    var known = try verifyAnswer(testing.io, testing.allocator, answer, .{ .trust = .{ .pinned = &store } });
    defer known.deinit(testing.allocator);
    try testing.expect(known.anchored);

    var other = server_identity.Provider.init(testing.io, .{});
    const other_answer = try signedAnswer(testing.allocator, &other);
    defer testing.allocator.free(other_answer);
    try testing.expectError(error.OperatorKeyChanged, verifyAnswer(testing.io, testing.allocator, other_answer, .{ .trust = .{ .pinned = &store } }));
    try testing.expectError(error.OperatorKeyChanged, verifyAnswer(testing.io, testing.allocator, other_answer, .{
        .trust = .{ .tofu = .{ .store = &store, .on_unknown = AcceptingPin.decide, .ctx = &other } },
    }));
}

test "a tampered answer, an altered header or an expired token is refused" {
    var provider = server_identity.Provider.init(testing.io, .{ .lifetime_seconds = 60 });
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    const tampered = try testing.allocator.dupe(u8, answer);
    defer testing.allocator.free(tampered);
    const fingerprint = "a=fingerprint:sha-256 AA:BB:CC:DD";
    const at = std.mem.indexOf(u8, tampered, fingerprint).?;
    tampered[at + fingerprint.len - 1] = 'E';
    try testing.expectError(error.BadFingerprintSignature, verifyAnswer(testing.io, testing.allocator, tampered, .{ .trust = .transport_authenticated }));

    const forged = try replaceTokenHeader(testing.allocator, answer, "{\"alg\":\"none\"}");
    defer testing.allocator.free(forged);
    try testing.expectError(error.UnsupportedAlgorithm, verifyAnswer(testing.io, testing.allocator, forged, .{ .trust = .transport_authenticated }));

    const now = std.Io.Clock.real.now(testing.io).toSeconds();
    try testing.expectError(error.ExpiredToken, verifyAnswer(testing.io, testing.allocator, answer, .{
        .trust = .transport_authenticated,
        .now_seconds = now + 1000,
    }));
}

test "an answer for another provider, or with no identity at all, is refused" {
    var provider = server_identity.Provider.init(testing.io, .{});
    const answer = try signedAnswer(testing.allocator, &provider);
    defer testing.allocator.free(answer);

    try testing.expectError(error.UnexpectedIdentityProvider, verifyAnswer(testing.io, testing.allocator, answer, .{
        .trust = .transport_authenticated,
        .expected_domain = "other",
    }));
    try testing.expectError(error.MissingIdentity, verifyAnswer(testing.io, testing.allocator, test_answer_sdp, .{ .trust = .transport_authenticated }));
}

test "the cpk claim is read by its json type in both forms" {
    const peer = try testKey(0x42);
    const jwk = try jwkClaim(testing.allocator, peer.public_key);
    defer testing.allocator.free(jwk);

    const parsed_jwk = try std.json.parseFromSlice(std.json.Value, testing.allocator, jwk, .{});
    defer parsed_jwk.deinit();
    const from_jwk = try cpkPublicKey(parsed_jwk.value);
    try testing.expectEqual(Form.jwk, from_jwk.form);

    const quoted = try claimText(testing.allocator, peer.public_key, .base64_der);
    defer testing.allocator.free(quoted);
    const parsed_der = try std.json.parseFromSlice(std.json.Value, testing.allocator, quoted, .{});
    defer parsed_der.deinit();
    const from_der = try cpkPublicKey(parsed_der.value);
    try testing.expectEqual(Form.base64_der, from_der.form);

    const point = peer.public_key.toUncompressedSec1();
    try testing.expectEqualSlices(u8, &point, &from_jwk.public_key.toUncompressedSec1());
    try testing.expectEqualSlices(u8, &point, &from_der.public_key.toUncompressedSec1());
    try testing.expectEqualSlices(u8, &spkiDer(peer.public_key), &spkiDer(from_der.public_key));

    const cases = [_]struct { claim: []const u8, expected: Error }{
        .{ .claim = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"AA\",\"y\":\"AA\"}", .expected = error.UnsupportedCurve },
        .{ .claim = "{\"kty\":\"RSA\",\"n\":\"AA\",\"e\":\"AQAB\"}", .expected = error.InvalidCpk },
        .{ .claim = "42", .expected = error.UnsupportedCpkForm },
        .{ .claim = "null", .expected = error.UnsupportedCpkForm },
        .{ .claim = "{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"AA\"}", .expected = error.InvalidCpk },
        .{ .claim = "\"not base64!\"", .expected = error.InvalidCpk },
        .{ .claim = "\"AAAA\"", .expected = error.InvalidCpk },
    };
    for (cases) |case| {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, case.claim, .{});
        defer parsed.deinit();
        try testing.expectError(case.expected, cpkPublicKey(parsed.value));
    }
}

test "an unknown kid cannot turn every join into an identity provider fetch" {
    const allocator = std.testing.allocator;
    const key_pair = try testKey(7);
    const document = try jwksDocument(allocator, key_pair.public_key, "issuer-key");
    defer allocator.free(document);

    var verifier = try Verifier.init(std.testing.io, allocator, .{
        .jwks_document = document,
        .jwks_min_refresh_seconds = 60,
    });
    defer verifier.deinit();

    const first = try verifier.jwks.keyFor(std.testing.io, &verifier.jwks_lock, "issuer-key");
    try std.testing.expectEqual(key_pair.public_key.toUncompressedSec1(), first.ec.toUncompressedSec1());
    const primed_at = verifier.jwks.next_refresh_at_seconds;
    try std.testing.expect(primed_at > 0);

    try std.testing.expectError(error.UnknownKey, verifier.jwks.keyFor(std.testing.io, &verifier.jwks_lock, "made-up"));
    try std.testing.expectEqual(primed_at, verifier.jwks.next_refresh_at_seconds);

    const cached = try verifier.jwks.keyFor(std.testing.io, &verifier.jwks_lock, "issuer-key");
    try std.testing.expectEqual(key_pair.public_key.toUncompressedSec1(), cached.ec.toUncompressedSec1());
    try std.testing.expectEqual(primed_at, verifier.jwks.next_refresh_at_seconds);

    verifier.jwks.next_refresh_at_seconds = 0;
    try std.testing.expectError(error.UnknownKey, verifier.jwks.keyFor(std.testing.io, &verifier.jwks_lock, "made-up"));
    try std.testing.expect(verifier.jwks.next_refresh_at_seconds > 0);
}
