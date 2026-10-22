const std = @import("std");
const json = @import("../json.zig");

pub const Error = error{
    MissingIdentity,
    InvalidIdentity,
    PayloadTooLarge,
} || std.mem.Allocator.Error;

pub const IdentityProvider = struct {
    domain: []const u8,
    protocol: []const u8,
};

pub const IdentityEnvelope = struct {
    idp: IdentityProvider,
    assertion: []const u8,
};

pub const Limits = struct {
    max_attribute_size: usize = 64 * 1024,
};

pub fn validate(identity: IdentityEnvelope) Error!void {
    if (identity.idp.domain.len == 0 or identity.assertion.len == 0) return error.InvalidIdentity;
    if (!std.mem.eql(u8, identity.idp.protocol, "default")) return error.InvalidIdentity;
}

const Line = struct {
    start: usize,
    next: usize,
    text: []const u8,
};

fn nextLine(sdp: []const u8, index: usize) ?Line {
    if (index >= sdp.len) return null;
    const newline = std.mem.indexOfScalarPos(u8, sdp, index, '\n');
    const end = newline orelse sdp.len;
    const text_end = if (newline != null and end > index and sdp[end - 1] == '\r') end - 1 else end;
    return .{ .start = index, .next = end + 1, .text = sdp[index..text_end] };
}

fn identityValue(trimmed: []const u8) ?[]const u8 {
    const prefix = "a=identity:";
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
    return trimmed[prefix.len..];
}

fn isIdentityLine(trimmed: []const u8) bool {
    const attribute = "a=identity";
    if (!std.mem.startsWith(u8, trimmed, attribute)) return false;
    return trimmed.len == attribute.len or trimmed[attribute.len] == ':';
}

fn sessionIdentityValue(sdp: []const u8) Error![]const u8 {
    var found: ?[]const u8 = null;
    var in_media = false;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        const trimmed = std.mem.trim(u8, line.text, " \t");
        if (std.mem.startsWith(u8, trimmed, "m=")) {
            in_media = true;
            continue;
        }
        if (!isIdentityLine(trimmed)) continue;
        const value = identityValue(trimmed) orelse return error.InvalidIdentity;
        if (in_media or found != null) return error.InvalidIdentity;
        found = value;
    }
    return std.mem.trim(u8, found orelse return error.MissingIdentity, " \t");
}

pub fn sessionInsertOffset(sdp: []const u8) error{ InvalidSdp, MissingFingerprint }!usize {
    var first_media: ?usize = null;
    var insert_at: ?usize = null;
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        const trimmed = std.mem.trim(u8, line.text, " \t");
        if (std.mem.startsWith(u8, trimmed, "m=")) {
            first_media = line.start;
            break;
        }
        if (std.mem.startsWith(u8, trimmed, "a=fingerprint:")) insert_at = line.next;
    }
    if (first_media == null) return error.InvalidSdp;
    return insert_at orelse error.MissingFingerprint;
}

pub fn extract(sdp: []const u8, allocator: std.mem.Allocator, limits: Limits) Error!IdentityEnvelope {
    const encoded = try sessionIdentityValue(sdp);
    if (encoded.len == 0 or encoded.len > limits.max_attribute_size) return error.PayloadTooLarge;

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.InvalidIdentity;
    if (decoded_len > limits.max_attribute_size) return error.PayloadTooLarge;
    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, encoded) catch return error.InvalidIdentity;

    const parsed = std.json.parseFromSlice(IdentityEnvelope, allocator, decoded, .{}) catch return error.InvalidIdentity;
    defer parsed.deinit();
    var identity: IdentityEnvelope = undefined;
    identity.idp.domain = try allocator.dupe(u8, parsed.value.idp.domain);
    errdefer allocator.free(identity.idp.domain);
    identity.idp.protocol = try allocator.dupe(u8, parsed.value.idp.protocol);
    errdefer allocator.free(identity.idp.protocol);
    identity.assertion = try allocator.dupe(u8, parsed.value.assertion);
    errdefer allocator.free(identity.assertion);
    try validate(identity);
    return identity;
}

pub fn withoutCandidates(allocator: std.mem.Allocator, sdp: []const u8) Error![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        const trimmed = std.mem.trim(u8, line.text, " \t");
        const dropped = std.mem.startsWith(u8, trimmed, "a=candidate:") or
            std.mem.eql(u8, trimmed, "a=end-of-candidates");
        if (dropped) continue;
        try result.appendSlice(allocator, line.text);
        if (line.next <= sdp.len) try result.appendSlice(allocator, "\r\n");
    }
    return result.toOwnedSlice(allocator);
}

pub fn withoutIdentity(allocator: std.mem.Allocator, sdp: []const u8) Error![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (isIdentityLine(std.mem.trim(u8, line.text, " \t"))) continue;
        try result.appendSlice(allocator, line.text);
        if (line.next <= sdp.len) try result.appendSlice(allocator, "\r\n");
    }
    return result.toOwnedSlice(allocator);
}

pub fn hasIdentity(sdp: []const u8) bool {
    var index: usize = 0;
    while (nextLine(sdp, index)) |line| : (index = line.next) {
        if (isIdentityLine(std.mem.trim(u8, line.text, " \t"))) return true;
    }
    return false;
}

pub fn iceUfrag(sdp: []const u8) ?[]const u8 {
    const prefix = "a=ice-ufrag:";
    const start = std.mem.indexOf(u8, sdp, prefix) orelse return null;
    const end = std.mem.indexOfScalarPos(u8, sdp, start, '\n') orelse sdp.len;
    const value = std.mem.trim(u8, sdp[start + prefix.len .. end], " \r");
    return if (value.len == 0) null else value;
}

pub fn maxMessageSize(sdp: []const u8) ?u32 {
    const prefix = "a=max-message-size:";
    const start = std.mem.indexOf(u8, sdp, prefix) orelse return null;
    const end = std.mem.indexOfScalarPos(u8, sdp, start, '\n') orelse sdp.len;
    const value = std.mem.trim(u8, sdp[start + prefix.len .. end], " \r");
    return std.fmt.parseInt(u32, value, 10) catch null;
}

pub const Fingerprint = struct {
    algorithm: []const u8,
    digest: []const u8,
};

pub const FingerprintError = error{
    MissingFingerprint,
    InvalidFingerprint,
};

pub fn fingerprints(sdp: []const u8, allocator: std.mem.Allocator) (FingerprintError || std.mem.Allocator.Error)![]Fingerprint {
    var found: std.ArrayList(Fingerprint) = .empty;
    errdefer found.deinit(allocator);

    var index: usize = 0;
    while (index < sdp.len) {
        const newline = std.mem.indexOfScalarPos(u8, sdp, index, '\n');
        const end = newline orelse sdp.len;
        const line = std.mem.trim(u8, sdp[index..end], " \r\t");
        index = end + 1;
        if (!std.mem.startsWith(u8, line, "a=fingerprint:")) continue;

        const value = std.mem.trim(u8, line["a=fingerprint:".len..], " \t");
        const split = std.mem.indexOfScalar(u8, value, ' ') orelse return error.InvalidFingerprint;
        if (split == 0 or split + 1 >= value.len) return error.InvalidFingerprint;
        const digest = std.mem.trim(u8, value[split + 1 ..], " \t");
        if (digest.len == 0) return error.InvalidFingerprint;
        try found.append(allocator, .{ .algorithm = value[0..split], .digest = digest });
    }

    if (found.items.len == 0) return error.MissingFingerprint;
    return found.toOwnedSlice(allocator);
}

pub fn writeFingerprintPayload(writer: *std.Io.Writer, values: []const Fingerprint) std.Io.Writer.Error!void {
    try writer.writeAll("{\"fingerprint\":[");
    for (values, 0..) |value, position| {
        if (position != 0) try writer.writeByte(',');
        try writer.writeAll("{\"algorithm\":\"");
        try json.writeString(writer, value.algorithm);
        try writer.writeAll("\",\"digest\":\"");
        try json.writeString(writer, value.digest);
        try writer.writeAll("\"}");
    }
    try writer.writeAll("]}");
}

pub fn fingerprintPayload(allocator: std.mem.Allocator, sdp: []const u8) (FingerprintError || std.Io.Writer.Error || std.mem.Allocator.Error)![]u8 {
    const values = try fingerprints(sdp, allocator);
    defer allocator.free(values);
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try writeFingerprintPayload(&out.writer, values);
    return out.toOwnedSlice();
}

pub fn deinit(allocator: std.mem.Allocator, identity: *IdentityEnvelope) void {
    allocator.free(identity.idp.domain);
    allocator.free(identity.idp.protocol);
    allocator.free(identity.assertion);
    identity.* = undefined;
}

test "identity extracts base64 JSON from SDP" {
    var identity = try extract("v=0\na=identity:eyJpZHAiOnsiZG9tYWluIjoieCIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ0b2tlbiJ9\r\n", std.testing.allocator, .{});
    defer deinit(std.testing.allocator, &identity);
    try std.testing.expectEqualStrings("x", identity.idp.domain);
    try std.testing.expectEqualStrings("default", identity.idp.protocol);
    try std.testing.expectEqualStrings("token", identity.assertion);
}

test "identity rejects absent and malformed attributes" {
    try std.testing.expectError(error.MissingIdentity, extract("v=0\r\n", std.testing.allocator, .{}));
    try std.testing.expectError(error.InvalidIdentity, extract("a=identity:not-base64\r\n", std.testing.allocator, .{}));
}

const identity_attribute_payload = "eyJpZHAiOnsiZG9tYWluIjoieCIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ0b2tlbiJ9";

test "identity extraction requires the whole session line" {
    const prefixed = "v=0\r\nx-a=identity:" ++ identity_attribute_payload ++ "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    try std.testing.expectError(error.MissingIdentity, extract(prefixed, std.testing.allocator, .{}));

    const suffixed = "v=0\r\na=identity-x:" ++ identity_attribute_payload ++ "\r\n";
    try std.testing.expectError(error.MissingIdentity, extract(suffixed, std.testing.allocator, .{}));

    const inside_value = "v=0\r\na=ice-ufrag:a=identity:" ++ identity_attribute_payload ++ "\r\n";
    try std.testing.expectError(error.MissingIdentity, extract(inside_value, std.testing.allocator, .{}));
}

test "identity extraction refuses a value-less, duplicated or media-level attribute" {
    try std.testing.expectError(error.InvalidIdentity, extract("v=0\r\na=identity\r\n", std.testing.allocator, .{}));

    const duplicated = "v=0\r\na=identity:" ++ identity_attribute_payload ++ "\r\n" ++
        "a=identity:" ++ identity_attribute_payload ++ "\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    try std.testing.expectError(error.InvalidIdentity, extract(duplicated, std.testing.allocator, .{}));

    const media_level = "v=0\r\na=fingerprint:sha-256 AA:BB\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=identity:" ++ identity_attribute_payload ++ "\r\n";
    try std.testing.expectError(error.InvalidIdentity, extract(media_level, std.testing.allocator, .{}));
}

test "identity extraction handles crlf, lf and a final line without a newline" {
    const crlf = "v=0\r\na=identity:" ++ identity_attribute_payload ++ "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    var from_crlf = try extract(crlf, std.testing.allocator, .{});
    defer deinit(std.testing.allocator, &from_crlf);
    try std.testing.expectEqualStrings("x", from_crlf.idp.domain);
    try std.testing.expectEqualStrings("token", from_crlf.assertion);

    const lf = "v=0\na=identity:" ++ identity_attribute_payload ++ "\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\n";
    var from_lf = try extract(lf, std.testing.allocator, .{});
    defer deinit(std.testing.allocator, &from_lf);
    try std.testing.expectEqualStrings("x", from_lf.idp.domain);

    var last_line = try extract("v=0\na=identity:" ++ identity_attribute_payload, std.testing.allocator, .{});
    defer deinit(std.testing.allocator, &last_line);
    try std.testing.expectEqualStrings("token", last_line.assertion);
}

test "the session insertion point follows the last session fingerprint" {
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:u\r\n" ++
        "a=fingerprint:sha-256 AA:BB\r\n" ++
        "a=fingerprint:sha-256 CC:DD\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=fingerprint:sha-256 EE:FF\r\n";
    const at = try sessionInsertOffset(sdp);
    try std.testing.expectEqualStrings(
        "v=0\r\na=ice-ufrag:u\r\na=fingerprint:sha-256 AA:BB\r\na=fingerprint:sha-256 CC:DD\r\n",
        sdp[0..at],
    );
    try std.testing.expect(std.mem.startsWith(u8, sdp[at..], "m="));

    try std.testing.expectError(
        error.MissingFingerprint,
        sessionInsertOffset("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"),
    );
    try std.testing.expectError(error.InvalidSdp, sessionInsertOffset("v=0\r\na=fingerprint:sha-256 AA:BB\r\n"));
}

test "trickle answers drop candidates but keep the rest of the description" {
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:trickleUfrag\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host\r\n" ++
        "a=end-of-candidates\r\n" ++
        "a=setup:passive\r\n";
    const stripped = try withoutCandidates(std.testing.allocator, sdp);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "a=ice-ufrag:trickleUfrag\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=setup:passive\r\n",
        stripped,
    );
    try std.testing.expectEqualStrings("trickleUfrag", iceUfrag(sdp).?);
    try std.testing.expect(iceUfrag("v=0\n") == null);
}

test "identity is stripped from a description and the rest survives byte for byte" {
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:trickleUfrag\r\n" ++
        "a=identity:BASE64\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host\r\n" ++
        "a=identity\r\n" ++
        "a=setup:passive\r\n";
    const stripped = try withoutIdentity(std.testing.allocator, sdp);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings(
        "v=0\r\n" ++
            "a=ice-ufrag:trickleUfrag\r\n" ++
            "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
            "a=candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host\r\n" ++
            "a=setup:passive\r\n",
        stripped,
    );
}

test "only the exact identity attribute is dropped" {
    const sdp = "v=0\r\n" ++
        "a=fingerprint:sha-256 AA:BB\r\n" ++
        "a=identity-x:kept\r\n" ++
        "x-a=identity:kept\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const stripped = try withoutIdentity(std.testing.allocator, sdp);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings(sdp, stripped);
    try std.testing.expect(!hasIdentity(sdp));
    try std.testing.expect(hasIdentity("v=0\r\na=identity:value\r\n"));
    try std.testing.expect(hasIdentity("v=0\na=identity \n"));
    try std.testing.expect(hasIdentity("v=0\r\nm=x\r\na=identity"));
}

test "a trailing identity line leaves no orphan line ending" {
    const sdp = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=identity:last";
    const stripped = try withoutIdentity(std.testing.allocator, sdp);
    defer std.testing.allocator.free(stripped);
    try std.testing.expectEqualStrings("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", stripped);
    try std.testing.expect(!hasIdentity(stripped));
}

test "max-message-size reads the peer's announced SCTP limit" {
    const sdp = "v=0\r\n" ++
        "m=application 50000 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=sctp-port:5000\r\n" ++
        "a=max-message-size:262144\r\n";
    try std.testing.expectEqual(@as(u32, 262144), maxMessageSize(sdp).?);
    try std.testing.expect(maxMessageSize("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n") == null);
    try std.testing.expect(maxMessageSize("a=max-message-size:\r\n") == null);
    try std.testing.expect(maxMessageSize("a=max-message-size:notanumber\r\n") == null);
}

test "the canonical payload covers every fingerprint line, in order" {
    const two = "v=0\r\na=fingerprint:sha-256 AA:BB\r\na=fingerprint:sha-256 11:22\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const values = try fingerprints(two, std.testing.allocator);
    defer std.testing.allocator.free(values);
    try std.testing.expectEqual(@as(usize, 2), values.len);
    try std.testing.expectEqualStrings("sha-256", values[0].algorithm);
    try std.testing.expectEqualStrings("AA:BB", values[0].digest);
    try std.testing.expectEqualStrings("11:22", values[1].digest);

    const payload = try fingerprintPayload(std.testing.allocator, two);
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqualStrings(
        "{\"fingerprint\":[{\"algorithm\":\"sha-256\",\"digest\":\"AA:BB\"},{\"algorithm\":\"sha-256\",\"digest\":\"11:22\"}]}",
        payload,
    );
}

test "a quote in a fingerprint cannot end the canonical json early" {
    const odd = "v=0\r\na=fingerprint:sha-256 AA\"BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const payload = try fingerprintPayload(std.testing.allocator, odd);
    defer std.testing.allocator.free(payload);
    try std.testing.expect(std.mem.indexOf(u8, payload, "AA\\\"BB") != null);
}

test "a description without a fingerprint line has no payload" {
    try std.testing.expectError(
        error.MissingFingerprint,
        fingerprints("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n", std.testing.allocator),
    );
}
