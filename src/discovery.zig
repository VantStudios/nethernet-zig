const std = @import("std");

pub const Error = error{
    InvalidFrame,
    InvalidChecksum,
    InvalidPacket,
    UnsupportedPacket,
    PayloadTooLarge,
    InvalidServerData,
    UnsupportedServerDataVersion,
    InvalidSignal,
} || std.mem.Allocator.Error || std.Io.Writer.Error || std.crypto.errors.AuthenticationError;

pub const SignalType = enum { connect_request, connect_response, candidate_add, connect_error };

pub const ErrorCode = enum(u32) {
    none = 0,
    negotiation_timeout = 2,
    failed_to_create_peer_connection = 4,
    ice = 5,
    candidate_add = 8,
    failed_to_create_offer = 10,
    failed_to_create_answer = 11,
    failed_to_set_local_description = 12,
    failed_to_set_remote_description = 13,
    negotiation_timeout_waiting_for_accept = 15,
    incoming_connection_ignored = 16,
    signaling_parsing_failure = 17,
    no_signaling_channel = 24,
    data_channel_closed = 32,
    internal_error_json_serialization = 33,
    invalid_argument = 34,
    generic_failure = 35,
    failed_to_create_identity_assertion = 36,
    identity_not_allowed = 37,
};

pub const SignalRef = struct {
    kind: SignalType,
    connection_id: []const u8,
    data: []const u8,

    pub fn parse(text: []const u8) Error!SignalRef {
        const first = std.mem.indexOfScalar(u8, text, ' ') orelse return error.InvalidSignal;
        const second = std.mem.indexOfScalarPos(u8, text, first + 1, ' ') orelse return error.InvalidSignal;
        const kind_text = text[0..first];
        const kind: SignalType = if (std.mem.eql(u8, kind_text, "CONNECTREQUEST")) .connect_request else if (std.mem.eql(u8, kind_text, "CONNECTRESPONSE")) .connect_response else if (std.mem.eql(u8, kind_text, "CANDIDATEADD")) .candidate_add else if (std.mem.eql(u8, kind_text, "CONNECTERROR")) .connect_error else return error.InvalidSignal;
        return .{
            .kind = kind,
            .connection_id = text[first + 1 .. second],
            .data = text[second + 1 ..],
        };
    }
};

pub const Signal = struct {
    kind: SignalType,
    connection_id: []const u8,
    data: []const u8,

    pub fn parse(allocator: std.mem.Allocator, text: []const u8) Error!Signal {
        const parsed = try SignalRef.parse(text);
        const connection_id = try allocator.dupe(u8, parsed.connection_id);
        errdefer allocator.free(connection_id);
        return .{
            .kind = parsed.kind,
            .connection_id = connection_id,
            .data = try allocator.dupe(u8, parsed.data),
        };
    }

    pub fn deinit(self: *Signal, allocator: std.mem.Allocator) void {
        allocator.free(self.connection_id);
        allocator.free(self.data);
        self.* = undefined;
    }

    pub fn write(self: Signal, writer: *std.Io.Writer) !void {
        const kind = switch (self.kind) {
            .connect_request => "CONNECTREQUEST",
            .connect_response => "CONNECTRESPONSE",
            .candidate_add => "CANDIDATEADD",
            .connect_error => "CONNECTERROR",
        };
        try writer.print("{s} {s} {s}", .{ kind, self.connection_id, self.data });
    }
};

pub const GameType = enum(i32) { survival = 0, creative = 1, adventure = 2 };

pub const advertised_build = .{ .protocol = 4422, .game_version = "1.26.60" };

/// `transportLayer` in the status JSON: the NetherNet transport.
pub const transport_layer_nethernet: i32 = 2;

pub const ServerData = struct {
    server_name: []const u8,
    protocol: i32 = advertised_build.protocol,
    game_version: []const u8 = advertised_build.game_version,
    level_name: []const u8,
    player_count: i32 = 0,
    max_player_count: i32 = 0,
    game_type: GameType = .survival,
    editor_world: bool = false,
    hardcore: bool = false,
    accepts_online_auth: bool = true,
    accepts_self_signed_auth: bool = true,
    nonce: []const u8 = "",
    connection_type: i32 = 8,

    pub const version: u8 = 7;

    pub fn write(self: ServerData, writer: *std.Io.Writer) !void {
        try writer.writeByte(version);
        try writeString(writer, self.server_name);
        try writeVarInt(writer, self.protocol);
        try writeString(writer, self.game_version);
        try writeString(writer, self.level_name);
        try writeVarInt(writer, self.player_count);
        try writeVarInt(writer, self.max_player_count);
        try writeVarInt(writer, @intFromEnum(self.game_type));
        try writer.writeByte(@intFromBool(self.editor_world));
        try writer.writeByte(@intFromBool(self.hardcore));
        try writer.writeByte(@intFromBool(self.accepts_online_auth));
        try writer.writeByte(@intFromBool(self.accepts_self_signed_auth));
        try writeString(writer, self.nonce);
        try writeVarInt(writer, self.connection_type);
    }

    pub fn decode(data: []const u8) Error!ServerData {
        var reader = Reader{ .bytes = data };
        const layout = reader.byte() orelse return error.InvalidServerData;
        if (layout != version) return error.UnsupportedServerDataVersion;
        const server_name = reader.string() orelse return error.InvalidServerData;
        const protocol = reader.varInt() orelse return error.InvalidServerData;
        const game_version = reader.string() orelse return error.InvalidServerData;
        const level_name = reader.string() orelse return error.InvalidServerData;
        const player_count = reader.varInt() orelse return error.InvalidServerData;
        const max_player_count = reader.varInt() orelse return error.InvalidServerData;
        const game_type: GameType = switch (reader.varInt() orelse return error.InvalidServerData) {
            0 => .survival,
            1 => .creative,
            2 => .adventure,
            else => return error.InvalidServerData,
        };
        const editor_world = reader.boolean() orelse return error.InvalidServerData;
        const hardcore = reader.boolean() orelse return error.InvalidServerData;
        const accepts_online_auth = reader.boolean() orelse return error.InvalidServerData;
        const accepts_self_signed_auth = reader.boolean() orelse return error.InvalidServerData;
        const nonce = reader.string() orelse return error.InvalidServerData;
        const connection_type = reader.varInt() orelse return error.InvalidServerData;
        if (reader.pos != data.len) return error.InvalidServerData;
        return .{
            .server_name = server_name,
            .protocol = protocol,
            .game_version = game_version,
            .level_name = level_name,
            .player_count = player_count,
            .max_player_count = max_player_count,
            .game_type = game_type,
            .editor_world = editor_world,
            .hardcore = hardcore,
            .accepts_online_auth = accepts_online_auth,
            .accepts_self_signed_auth = accepts_self_signed_auth,
            .nonce = nonce,
            .connection_type = connection_type,
        };
    }

    pub fn encodedLength(self: ServerData) usize {
        var buffer: [2048]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        self.write(&writer) catch return 0;
        return writer.buffered().len;
    }
};

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Reader, count: usize) ?[]const u8 {
        if (count > self.bytes.len - self.pos) return null;
        const slice = self.bytes[self.pos .. self.pos + count];
        self.pos += count;
        return slice;
    }

    fn byte(self: *Reader) ?u8 {
        return (self.take(1) orelse return null)[0];
    }

    fn boolean(self: *Reader) ?bool {
        return (self.byte() orelse return null) != 0;
    }

    fn varInt(self: *Reader) ?i32 {
        var result: u32 = 0;
        var shift: u5 = 0;
        var count: usize = 0;
        while (count < 5) : (count += 1) {
            const value = self.byte() orelse return null;
            result |= @as(u32, value & 0x7f) << shift;
            if (value & 0x80 == 0) return @bitCast(result);
            shift += 7;
        }
        return null;
    }

    fn string(self: *Reader) ?[]const u8 {
        const length = self.varInt() orelse return null;
        if (length < 0 or length > 4096) return null;
        return self.take(@intCast(length));
    }
};

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
    try writeVarInt(writer, @intCast(value.len));
    try writer.writeAll(value);
}

fn writeVarInt(writer: *std.Io.Writer, value: i32) !void {
    var n: u32 = @bitCast(value);
    while (n >= 0x80) {
        try writer.writeByte(@as(u8, @truncate(n)) | 0x80);
        n >>= 7;
    }
    try writer.writeByte(@intCast(n));
}

const app_id: u64 = 0xdeadbeef;

const key_bytes: [32]u8 = blk: {
    @setEvalBranchQuota(20_000);
    var input: [8]u8 = undefined;
    std.mem.writeInt(u64, &input, app_id, .little);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&input, &digest, .{});
    break :blk digest;
};

fn key() [32]u8 {
    return key_bytes;
}

fn sealedLength(plaintext_len: usize) usize {
    return plaintext_len / 16 * 16 + 16;
}

fn aesEcbEncrypt(allocator: std.mem.Allocator, plaintext: []const u8) Error![]u8 {
    const padded_len = sealedLength(plaintext.len);
    const result = try allocator.alloc(u8, padded_len);
    errdefer allocator.free(result);
    @memcpy(result[0..plaintext.len], plaintext);
    @memset(result[plaintext.len..], @intCast(padded_len - plaintext.len));
    const cipher = std.crypto.core.aes.Aes256.initEnc(key());
    var block: [16]u8 = undefined;
    for (0..padded_len / 16) |index| {
        @memcpy(&block, result[index * 16 ..][0..16]);
        cipher.encrypt(result[index * 16 ..][0..16], &block);
    }
    return result;
}

fn aesEcbDecryptInto(buffer: []u8, ciphertext: []const u8) Error![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return error.InvalidFrame;
    if (buffer.len < ciphertext.len) return error.PayloadTooLarge;
    const plain = buffer[0..ciphertext.len];
    const cipher = std.crypto.core.aes.Aes256.initDec(key());
    var block: [16]u8 = undefined;
    for (0..ciphertext.len / 16) |index| {
        @memcpy(&block, ciphertext[index * 16 ..][0..16]);
        cipher.decrypt(plain[index * 16 ..][0..16], &block);
    }
    const padding = plain[plain.len - 1];
    if (padding == 0 or padding > 16 or padding > plain.len) return error.InvalidFrame;
    for (plain[plain.len - padding ..]) |byte| if (byte != padding) return error.InvalidFrame;
    return plain[0 .. plain.len - padding];
}

fn aesEcbDecrypt(allocator: std.mem.Allocator, ciphertext: []const u8) Error![]u8 {
    if (ciphertext.len == 0 or ciphertext.len % 16 != 0) return error.InvalidFrame;
    const plain = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plain);
    const message = try aesEcbDecryptInto(plain, ciphertext);
    return allocator.realloc(plain, message.len);
}

pub const PacketKind = enum(u16) { request = 0, response = 1, message = 2 };

pub const DecodedPacket = struct {
    kind: PacketKind,
    sender_id: u64,
    recipient_id: u64 = 0,
    data: []const u8 = "",
    recovered_bytes: usize = 0,

    pub fn deinit(self: *const DecodedPacket, allocator: std.mem.Allocator) void {
        if (self.data.len != 0) allocator.free(self.data);
    }
};

const min_inner_length: usize = 18;

fn recoverableSignalTail(declared: []const u8, tail: []const u8) bool {
    if (tail.len == 0) return false;
    if (std.mem.indexOfScalar(u8, tail, 0) != null) return false;
    return std.mem.startsWith(u8, declared, "CONNECTREQUEST ") or
        std.mem.startsWith(u8, declared, "CONNECTRESPONSE ");
}

pub const DecodedPacketRef = struct {
    kind: PacketKind,
    sender_id: u64,
    recipient_id: u64 = 0,
    data: []const u8 = "",
    recovered_bytes: usize = 0,
};

pub fn decodePacket(allocator: std.mem.Allocator, frame: []const u8) Error!DecodedPacket {
    const payload = try open(allocator, frame);
    defer allocator.free(payload);
    const packet = try decodePayload(payload);
    return .{
        .kind = packet.kind,
        .sender_id = packet.sender_id,
        .recipient_id = packet.recipient_id,
        .data = if (packet.data.len == 0) "" else try allocator.dupe(u8, packet.data),
        .recovered_bytes = packet.recovered_bytes,
    };
}

pub fn decodePacketInto(buffer: []u8, frame: []const u8) Error!DecodedPacketRef {
    const payload = try openInto(buffer, frame);
    return decodePayload(payload);
}

fn decodePayload(payload: []u8) Error!DecodedPacketRef {
    if (payload.len < 20) return error.InvalidPacket;
    const declared = std.mem.readInt(u16, payload[0..2], .little);
    if (declared < min_inner_length or declared > payload.len) return error.InvalidPacket;
    const raw_kind = std.mem.readInt(u16, payload[2..4], .little);
    const kind: PacketKind = switch (raw_kind) {
        0 => .request,
        1 => .response,
        2 => .message,
        else => return error.UnsupportedPacket,
    };
    const sender_id = std.mem.readInt(u64, payload[4..12], .little);
    if (!std.mem.allEqual(u8, payload[12..20], 0)) return error.InvalidPacket;
    const body = payload[20..];
    return switch (kind) {
        .request => if (body.len == 0) .{ .kind = .request, .sender_id = sender_id } else error.InvalidPacket,
        .response => blk: {
            if (body.len < 4) return error.InvalidPacket;
            const hex_len = std.mem.readInt(u32, body[0..4], .little);
            if (hex_len != body.len - 4 or hex_len % 2 != 0) return error.InvalidPacket;
            const decoded_len = hex_len / 2;
            const decoded = payload[0..decoded_len];
            for (decoded, 0..) |*byte, i| byte.* = try parseHex(body[4 + i * 2 ..][0..2]);
            break :blk .{ .kind = .response, .sender_id = sender_id, .data = decoded };
        },
        .message => blk: {
            if (body.len < 12) return error.InvalidPacket;
            const recipient_id = std.mem.readInt(u64, body[0..8], .little);
            const length = std.mem.readInt(u32, body[8..12], .little);
            if (length > body.len - 12) return error.InvalidPacket;
            var data = body[12 .. 12 + length];
            var recovered_bytes: usize = 0;
            if (data.len < body.len - 12 and recoverableSignalTail(data, body[12 + length ..])) {
                recovered_bytes = body.len - 12 - data.len;
                data = body[12..];
            }
            break :blk .{
                .kind = .message,
                .sender_id = sender_id,
                .recipient_id = recipient_id,
                .data = data,
                .recovered_bytes = recovered_bytes,
            };
        },
    };
}

pub fn encodeHexLower(output: []u8, input: []const u8) []const u8 {
    const digits = "0123456789abcdef";
    for (input, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 0x0f];
    }
    return output[0 .. input.len * 2];
}

fn parseHex(bytes: []const u8) Error!u8 {
    if (bytes.len != 2) return error.InvalidPacket;
    return (std.fmt.charToDigit(bytes[0], 16) catch return error.InvalidPacket) * 16 +
        (std.fmt.charToDigit(bytes[1], 16) catch return error.InvalidPacket);
}

pub fn seal(allocator: std.mem.Allocator, packet: []const u8) Error![]u8 {
    const encrypted = try aesEcbEncrypt(allocator, packet);
    defer allocator.free(encrypted);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, packet, &key());
    const result = try allocator.alloc(u8, mac.len + encrypted.len);
    @memcpy(result[0..mac.len], &mac);
    @memcpy(result[mac.len..], encrypted);
    return result;
}

pub fn open(allocator: std.mem.Allocator, frame: []const u8) Error![]u8 {
    if (frame.len < 48 or (frame.len - 32) % 16 != 0) return error.InvalidFrame;
    const plain = try allocator.alloc(u8, frame.len - 32);
    errdefer allocator.free(plain);
    const message = try openInto(plain, frame);
    return allocator.realloc(plain, message.len);
}

pub fn openInto(buffer: []u8, frame: []const u8) Error![]u8 {
    if (frame.len < 48 or (frame.len - 32) % 16 != 0) return error.InvalidFrame;
    const plain = try aesEcbDecryptInto(buffer, frame[32..]);
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, plain, &key());
    if (!std.crypto.timing_safe.eql([32]u8, mac, frame[0..32].*)) return error.InvalidChecksum;
    return plain;
}

pub fn sealInPlace(buffer: []u8, payload: []const u8) Error![]u8 {
    const padded_len = sealedLength(payload.len);
    if (buffer.len < 32 + padded_len) return error.PayloadTooLarge;
    const staged = buffer[32..][0..padded_len];
    if (@intFromPtr(payload.ptr) != @intFromPtr(staged.ptr)) {
        if (payload.len > padded_len) return error.PayloadTooLarge;
        std.mem.copyForwards(u8, staged[0..payload.len], payload);
    }
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, staged[0..payload.len], &key());
    @memset(staged[payload.len..], @intCast(padded_len - payload.len));
    const cipher = std.crypto.core.aes.Aes256.initEnc(key());
    var block: [16]u8 = undefined;
    for (0..padded_len / 16) |index| {
        @memcpy(&block, staged[index * 16 ..][0..16]);
        cipher.encrypt(staged[index * 16 ..][0..16], &block);
    }
    @memcpy(buffer[0..32], &mac);
    return buffer[0 .. 32 + padded_len];
}

pub const max_body_bytes: usize = 65535 - 20;

fn buildPayload(buffer: []u8, kind: PacketKind, sender_id: u64, body: []const u8) Error![]u8 {
    if (body.len > max_body_bytes) return error.PayloadTooLarge;
    if (buffer.len < 20 + body.len) return error.PayloadTooLarge;
    const payload = buffer[0 .. 20 + body.len];
    std.mem.writeInt(u16, payload[0..2], @intCast(payload.len), .little);
    std.mem.writeInt(u16, payload[2..4], @intFromEnum(kind), .little);
    std.mem.writeInt(u64, payload[4..12], sender_id, .little);
    @memset(payload[12..20], 0);
    @memcpy(payload[20..], body);
    return payload;
}

pub fn encodePacket(allocator: std.mem.Allocator, kind: PacketKind, sender_id: u64, body: []const u8) Error![]u8 {
    if (body.len > max_body_bytes) return error.PayloadTooLarge;
    const frame = try allocator.alloc(u8, 32 + sealedLength(20 + body.len));
    errdefer allocator.free(frame);
    const written = try encodePacketInPlace(frame, kind, sender_id, body);
    return allocator.realloc(frame, written.len);
}

pub fn encodePacketInPlace(buffer: []u8, kind: PacketKind, sender_id: u64, body: []const u8) Error![]u8 {
    if (body.len > max_body_bytes) return error.PayloadTooLarge;
    const payload_len = 20 + body.len;
    if (buffer.len < 32 + sealedLength(payload_len)) return error.PayloadTooLarge;
    const payload = buffer[32..][0..payload_len];
    std.mem.writeInt(u16, payload[0..2], @intCast(payload_len), .little);
    std.mem.writeInt(u16, payload[2..4], @intFromEnum(kind), .little);
    std.mem.writeInt(u64, payload[4..12], sender_id, .little);
    @memset(payload[12..20], 0);
    @memcpy(payload[20..], body);
    return sealInPlace(buffer, payload);
}

pub fn encodeRequest(allocator: std.mem.Allocator, sender_id: u64) Error![]u8 {
    return encodePacket(allocator, .request, sender_id, "");
}

pub fn encodeResponse(allocator: std.mem.Allocator, sender_id: u64, application_data: []const u8) Error![]u8 {
    const frame = try allocator.alloc(u8, 32 + sealedLength(20 + 4 + application_data.len * 2));
    errdefer allocator.free(frame);
    const written = try encodeResponseInPlace(frame, sender_id, application_data);
    return allocator.realloc(frame, written.len);
}

pub fn encodeResponseInPlace(buffer: []u8, sender_id: u64, application_data: []const u8) Error![]u8 {
    const hex_len = application_data.len * 2;
    if (hex_len > max_body_bytes - 4) return error.PayloadTooLarge;
    const payload_len = 20 + 4 + hex_len;
    if (buffer.len < 32 + sealedLength(payload_len)) return error.PayloadTooLarge;
    const payload = buffer[32..][0..payload_len];
    std.mem.writeInt(u16, payload[0..2], @intCast(payload_len), .little);
    std.mem.writeInt(u16, payload[2..4], @intFromEnum(PacketKind.response), .little);
    std.mem.writeInt(u64, payload[4..12], sender_id, .little);
    @memset(payload[12..20], 0);
    std.mem.writeInt(u32, payload[20..24], @intCast(hex_len), .little);
    _ = encodeHexLower(payload[24..][0..hex_len], application_data);
    return sealInPlace(buffer, payload);
}

pub fn encodeMessage(allocator: std.mem.Allocator, sender_id: u64, recipient_id: u64, data: []const u8) Error![]u8 {
    const frame = try allocator.alloc(u8, 32 + sealedLength(20 + 12 + data.len));
    errdefer allocator.free(frame);
    const written = try encodeMessageInPlace(frame, sender_id, recipient_id, data);
    return allocator.realloc(frame, written.len);
}

pub fn encodeMessageInPlace(buffer: []u8, sender_id: u64, recipient_id: u64, data: []const u8) Error![]u8 {
    if (data.len > max_body_bytes - 12) return error.PayloadTooLarge;
    const payload_len = 20 + 12 + data.len;
    if (buffer.len < 32 + sealedLength(payload_len)) return error.PayloadTooLarge;
    const payload = buffer[32..][0..payload_len];
    std.mem.writeInt(u16, payload[0..2], @intCast(payload_len), .little);
    std.mem.writeInt(u16, payload[2..4], @intFromEnum(PacketKind.message), .little);
    std.mem.writeInt(u64, payload[4..12], sender_id, .little);
    @memset(payload[12..20], 0);
    std.mem.writeInt(u64, payload[20..28], recipient_id, .little);
    std.mem.writeInt(u32, payload[28..32], @intCast(data.len), .little);
    @memcpy(payload[32..][0..data.len], data);
    return sealInPlace(buffer, payload);
}

test "signals round trip" {
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try (Signal{ .kind = .connect_request, .connection_id = "id", .data = "sdp" }).write(&writer);
    var signal = try Signal.parse(std.testing.allocator, writer.buffered());
    defer signal.deinit(std.testing.allocator);
    try std.testing.expectEqual(SignalType.connect_request, signal.kind);
    try std.testing.expectEqualStrings("sdp", signal.data);
}

test "discovery packet request round trip" {
    const frame = try encodeRequest(std.testing.allocator, 123);
    defer std.testing.allocator.free(frame);
    var packet = try decodePacket(std.testing.allocator, frame);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(PacketKind.request, packet.kind);
    try std.testing.expectEqual(@as(u64, 123), packet.sender_id);
}

test "discovery encryption matches OpenSSL-compatible envelope properties" {
    const frame = try seal(std.testing.allocator, "payload");
    defer std.testing.allocator.free(frame);
    const opened = try open(std.testing.allocator, frame);
    defer std.testing.allocator.free(opened);
    try std.testing.expectEqualStrings("payload", opened);
}

const server_data_1_26_60 = "07084e65787869693033c62207312e32362e3630084d7920576f726c64020a0200000101103139333264643838633963333463333208";

fn fixtureBytes(hex: []const u8, buffer: []u8) Error![]u8 {
    if (buffer.len < hex.len / 2 or hex.len % 2 != 0) return error.InvalidServerData;
    for (0..hex.len / 2) |index| buffer[index] = try parseHex(hex[index * 2 ..][0..2]);
    return buffer[0 .. hex.len / 2];
}

test "server data v7 decodes the 1.26.60 capture field by field" {
    var buffer: [128]u8 = undefined;
    const data = try fixtureBytes(server_data_1_26_60, &buffer);
    try std.testing.expectEqual(@as(usize, 54), data.len);

    const server_data = try ServerData.decode(data);
    try std.testing.expectEqualStrings("Nexxii03", server_data.server_name);
    try std.testing.expectEqual(@as(i32, 4422), server_data.protocol);
    try std.testing.expectEqualStrings("1.26.60", server_data.game_version);
    try std.testing.expectEqualStrings("My World", server_data.level_name);
    try std.testing.expectEqual(@as(i32, 2), server_data.player_count);
    try std.testing.expectEqual(@as(i32, 10), server_data.max_player_count);
    try std.testing.expectEqual(GameType.adventure, server_data.game_type);
    try std.testing.expect(!server_data.editor_world);
    try std.testing.expect(!server_data.hardcore);
    try std.testing.expect(server_data.accepts_online_auth);
    try std.testing.expect(server_data.accepts_self_signed_auth);
    try std.testing.expectEqualStrings("1932dd88c9c34c32", server_data.nonce);
    try std.testing.expectEqual(@as(i32, 8), server_data.connection_type);
}

test "server data v7 encoder reproduces the 1.26.60 capture byte for byte" {
    var buffer: [128]u8 = undefined;
    const expected = try fixtureBytes(server_data_1_26_60, &buffer);
    const server_data: ServerData = .{
        .server_name = "Nexxii03",
        .protocol = 4422,
        .game_version = "1.26.60",
        .level_name = "My World",
        .player_count = 2,
        .max_player_count = 10,
        .game_type = .adventure,
        .nonce = "1932dd88c9c34c32",
        .connection_type = 8,
    };
    var encoded: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&encoded);
    try server_data.write(&writer);
    try std.testing.expectEqualSlices(u8, expected, writer.buffered());
    try std.testing.expectEqual(expected.len, server_data.encodedLength());
}

test "server data v7 decode rejects stale layout versions and trailing bytes" {
    var buffer: [128]u8 = undefined;
    const data = try fixtureBytes(server_data_1_26_60, &buffer);
    try std.testing.expectError(error.InvalidServerData, ServerData.decode(data[0 .. data.len - 1]));
    data[0] = 6;
    try std.testing.expectError(error.UnsupportedServerDataVersion, ServerData.decode(data));
    data[0] = 7;
    data[data.len - 1] = 9;
    try std.testing.expectEqual(@as(i32, 9), (try ServerData.decode(data)).connection_type);
}

test "nonce hex encoding is lower case and twice as long" {
    var output: [16]u8 = undefined;
    const nonce = encodeHexLower(&output, &[_]u8{ 0x19, 0x32, 0xdd, 0x88, 0xc9, 0xc3, 0x4c, 0x32 });
    try std.testing.expectEqualStrings("1932dd88c9c34c32", nonce);
}

const message_data_length_offset: usize = 28;
const message_data_offset: usize = 32;

fn offerSignal(buffer: []u8) []const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    writer.writeAll("CONNECTREQUEST 12066214442905225968 v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\na=msid-semantic: WMS\r\nm=application 50000 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 10.0.0.1\r\n") catch unreachable;
    for (0..10) |index| {
        writer.print(
            "a=candidate:{d} 1 udp {d} 10.0.0.{d} {d} typ host generation 0 network-id {d}\r\n",
            .{ 1000000000 + index, 2122000000 + index, index, 50000 + index, index },
        ) catch unreachable;
    }
    writer.writeAll("a=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef0123456789abcdef\r\na=ice-options:trickle\r\na=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\na=setup:active\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144") catch unreachable;
    return writer.buffered();
}

fn messagePlaintext(
    buffer: []u8,
    sender_id: u64,
    recipient_id: u64,
    signal: []const u8,
    data_length: ?u32,
    outer_length: ?u16,
) Error![]u8 {
    var body_buffer: [8192]u8 = undefined;
    var body_writer: std.Io.Writer = .fixed(&body_buffer);
    try body_writer.writeInt(u64, recipient_id, .little);
    try body_writer.writeInt(u32, data_length orelse @intCast(signal.len), .little);
    try body_writer.writeAll(signal);
    const payload = try buildPayload(buffer, .message, sender_id, body_writer.buffered());
    if (outer_length) |value| std.mem.writeInt(u16, payload[0..2], value, .little);
    return payload;
}

fn sealedMessage(
    allocator: std.mem.Allocator,
    sender_id: u64,
    recipient_id: u64,
    signal: []const u8,
    data_length: ?u32,
    outer_length: ?u16,
) Error![]u8 {
    var buffer: [65537]u8 = undefined;
    const payload = try messagePlaintext(&buffer, sender_id, recipient_id, signal, data_length, outer_length);
    return seal(allocator, payload);
}

test "message length prefixes sit at the documented offsets" {
    const signal = "CONNECTREQUEST 42 v=0\r\ns=-";
    var buffer: [1024]u8 = undefined;
    const payload = try messagePlaintext(&buffer, 1, 2, signal, null, null);
    try std.testing.expectEqual(@as(u16, @intCast(payload.len)), std.mem.readInt(u16, payload[0..2], .little));
    try std.testing.expectEqual(@as(u32, @intCast(signal.len)), std.mem.readInt(u32, payload[message_data_length_offset..][0..4], .little));
    try std.testing.expectEqualStrings(signal, payload[message_data_offset..]);
}

test "an underdeclared signal length still yields the whole SDP" {
    var signal_buffer: [4096]u8 = undefined;
    const signal = offerSignal(&signal_buffer);
    const undercount: u32 = 244;
    const frame = try sealedMessage(std.testing.allocator, 0x1234, 0x5678, signal, @intCast(signal.len - undercount), null);
    defer std.testing.allocator.free(frame);

    var packet = try decodePacket(std.testing.allocator, frame);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(PacketKind.message, packet.kind);
    try std.testing.expectEqual(@as(u64, 0x1234), packet.sender_id);
    try std.testing.expectEqual(@as(u64, 0x5678), packet.recipient_id);
    try std.testing.expectEqualStrings(signal, packet.data);
    try std.testing.expectEqual(@as(usize, undercount), packet.recovered_bytes);
    try std.testing.expect(std.mem.endsWith(u8, packet.data, "a=max-message-size:262144"));
}

test "a length hint that undercounts the packet never truncates it" {
    const signal = "CONNECTREQUEST 42 v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:0123456789abcdef";
    var plain_buffer: [1024]u8 = undefined;
    const full = try messagePlaintext(&plain_buffer, 11, 22, signal, null, null);
    for ([_]u16{ @intCast(full.len), @intCast(full.len - 2), 18 }) |hint| {
        const frame = try sealedMessage(std.testing.allocator, 11, 22, signal, null, hint);
        defer std.testing.allocator.free(frame);
        var packet = try decodePacket(std.testing.allocator, frame);
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(signal, packet.data);
        try std.testing.expectEqual(@as(usize, 0), packet.recovered_bytes);
    }
}

test "an impossible length hint is rejected" {
    const signal = "CONNECTREQUEST 42 v=0";
    for ([_]u16{ 4, 65535 }) |hint| {
        const frame = try sealedMessage(std.testing.allocator, 11, 22, signal, null, hint);
        defer std.testing.allocator.free(frame);
        try std.testing.expectError(error.InvalidPacket, decodePacket(std.testing.allocator, frame));
    }
    const over = try sealedMessage(std.testing.allocator, 11, 22, signal, @intCast(signal.len + 8), null);
    defer std.testing.allocator.free(over);
    try std.testing.expectError(error.InvalidPacket, decodePacket(std.testing.allocator, over));
}

test "an appended discovery frame is never absorbed into a short signal" {
    var signal_buffer: [4096]u8 = undefined;
    const signal = offerSignal(&signal_buffer);
    const undercount: u32 = 244;
    var first_buffer: [65537]u8 = undefined;
    const first = try messagePlaintext(&first_buffer, 11, 22, signal, @intCast(signal.len - undercount), null);
    var second_buffer: [1024]u8 = undefined;
    const second = try messagePlaintext(&second_buffer, 33, 44, "Ping", null, null);
    var batch_buffer: [65537]u8 = undefined;
    @memcpy(batch_buffer[0..first.len], first);
    @memcpy(batch_buffer[first.len..][0..second.len], second);
    const frame = try seal(std.testing.allocator, batch_buffer[0 .. first.len + second.len]);
    defer std.testing.allocator.free(frame);

    var packet = try decodePacket(std.testing.allocator, frame);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(signal[0 .. signal.len - undercount], packet.data);
    try std.testing.expectEqual(@as(usize, 0), packet.recovered_bytes);
}

test "signals that carry no SDP are never extended" {
    const signal = "CANDIDATEADD 42 candidate:1 1 udp 2122000000 10.0.0.1 50000 typ host";
    const frame = try sealedMessage(std.testing.allocator, 11, 22, signal, @intCast(signal.len - 20), null);
    defer std.testing.allocator.free(frame);

    var packet = try decodePacket(std.testing.allocator, frame);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(signal[0 .. signal.len - 20], packet.data);
    try std.testing.expectEqual(@as(usize, 0), packet.recovered_bytes);
}

test "recovery cannot resurrect a datagram with a bad checksum" {
    var signal_buffer: [4096]u8 = undefined;
    const signal = offerSignal(&signal_buffer);
    const frame = try sealedMessage(std.testing.allocator, 11, 22, signal, @intCast(signal.len - 244), null);
    defer std.testing.allocator.free(frame);
    frame[0] ^= 0xff;
    try std.testing.expectError(error.InvalidChecksum, decodePacket(std.testing.allocator, frame));
}

test "discovery response round trip keeps the advertisement intact" {
    var bytes: [128]u8 = undefined;
    const advertisement = try fixtureBytes(server_data_1_26_60, &bytes);
    const frame = try encodeResponse(std.testing.allocator, 99, advertisement);
    defer std.testing.allocator.free(frame);

    var packet = try decodePacket(std.testing.allocator, frame);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(PacketKind.response, packet.kind);
    try std.testing.expectEqual(@as(u64, 99), packet.sender_id);
    try std.testing.expectEqualStrings(advertisement, packet.data);
    try std.testing.expectEqual(@as(usize, 0), packet.recovered_bytes);
}

test "an advertisement whose hex length stops short is rejected, not halved" {
    var body_buffer: [64]u8 = undefined;
    var body_writer: std.Io.Writer = .fixed(&body_buffer);
    try body_writer.writeInt(u32, 6, .little);
    try body_writer.writeAll("0708090a");
    const frame = try encodePacket(std.testing.allocator, .response, 7, body_writer.buffered());
    defer std.testing.allocator.free(frame);
    try std.testing.expectError(error.InvalidPacket, decodePacket(std.testing.allocator, frame));
}

test "the largest body the length field can express round trips instead of overflowing" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, max_body_bytes - 12);
    defer allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index *% 7);

    const frame = try encodeMessage(allocator, 0x1122, 0x3344, data);
    defer allocator.free(frame);

    const plain = try allocator.alloc(u8, frame.len - 32);
    defer allocator.free(plain);
    const packet = try decodePacketInto(plain, frame);
    try std.testing.expectEqual(PacketKind.message, packet.kind);
    try std.testing.expectEqual(@as(u64, 0x1122), packet.sender_id);
    try std.testing.expectEqual(@as(u64, 0x3344), packet.recipient_id);
    try std.testing.expectEqualSlices(u8, data, packet.data);
}

test "a body past what the length field holds is refused before anything is written" {
    const allocator = std.testing.allocator;
    const data = try allocator.alloc(u8, max_body_bytes - 11);
    defer allocator.free(data);
    @memset(data, 0x5a);
    try std.testing.expectError(error.PayloadTooLarge, encodeMessage(allocator, 1, 2, data));

    var small: [64]u8 = undefined;
    try std.testing.expectError(error.PayloadTooLarge, encodeMessageInPlace(&small, 1, 2, data));
}

test "a sealed frame round trips through caller-owned buffers with no allocation" {
    var frame_buffer: [512]u8 = undefined;
    var plain_buffer: [512]u8 = undefined;

    const frame = try encodeMessageInPlace(&frame_buffer, 7, 9, "CONNECTREQUEST 9 v=0\r\n");
    const packet = try decodePacketInto(&plain_buffer, frame);
    try std.testing.expectEqual(PacketKind.message, packet.kind);
    try std.testing.expectEqual(@as(u64, 7), packet.sender_id);
    try std.testing.expectEqual(@as(u64, 9), packet.recipient_id);
    try std.testing.expectEqualStrings("CONNECTREQUEST 9 v=0\r\n", packet.data);

    const expected = try seal(std.testing.allocator, plain_buffer[0..0] ++ "");
    defer std.testing.allocator.free(expected);
    const empty_frame = try encodeMessageInPlace(&frame_buffer, 7, 9, "");
    var reopened: [64]u8 = undefined;
    const empty = try decodePacketInto(&reopened, empty_frame);
    try std.testing.expectEqual(@as(usize, 0), empty.data.len);
}

test "a signal is parsed in place without copying its fields" {
    const text = "CANDIDATEADD 12066214442905225968 candidate:1 1 udp 2122000000 10.0.0.1 50000 typ host";
    const signal = try SignalRef.parse(text);
    try std.testing.expectEqual(SignalType.candidate_add, signal.kind);
    try std.testing.expectEqual(@intFromPtr(text.ptr) + "CANDIDATEADD ".len, @intFromPtr(signal.connection_id.ptr));
    try std.testing.expectEqualStrings("12066214442905225968", signal.connection_id);
    try std.testing.expectEqualStrings("candidate:1 1 udp 2122000000 10.0.0.1 50000 typ host", signal.data);
    try std.testing.expectError(error.InvalidSignal, SignalRef.parse("CONNECTREQUEST nope"));
}
