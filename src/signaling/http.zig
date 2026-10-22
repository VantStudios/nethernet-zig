const std = @import("std");
const builtin = @import("builtin");
const server_http = if (builtin.is_test) @import("../server/http.zig") else struct {};
const server_lan = if (builtin.is_test) @import("../server/lan.zig") else struct {};
const identity_mod = if (builtin.is_test) @import("../identity/server.zig") else struct {};
const identity_verify = @import("../identity/verify.zig");
const peer_mod = if (builtin.is_test) @import("../webrtc/peer.zig") else struct {};

pub const Error = error{
    InvalidNetworkId,
    InvalidSdp,
    InvalidJson,
    ResponseStatusFailure,
    PayloadTooLarge,
    InvalidState,
    Timeout,
    TransportFailure,
} || std.mem.Allocator.Error;

pub const JoinError = Error || identity_verify.AnswerError;

pub const Submission = struct {
    sdp: []u8,
    identity: identity_verify.SessionIdentity,
    idp_domain: []u8,
    anchored: bool,

    pub fn deinit(self: *Submission, allocator: std.mem.Allocator) void {
        allocator.free(self.sdp);
        allocator.free(self.idp_domain);
        self.* = undefined;
    }
};

pub const Method = enum { get, post };
pub const Response = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

pub const ServerInfo = struct {
    name: []const u8,
    protocol: u32,
    version: []const u8,
    level: []const u8,
    players: u32,
    maxPlayers: u32,
    gameType: u32,
};

pub const ClientTransport = struct {
    allocator: std.mem.Allocator,
    client: std.http.Client,
    base_url: []const u8,
    response_body: std.Io.Writer.Allocating,
    max_response_bytes: usize = 1024 * 1024,
    content_type_storage: [256]u8 = undefined,
    content_type_len: usize = 0,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, base_url: []const u8) !ClientTransport {
        return .{
            .allocator = allocator,
            .client = .{ .allocator = allocator, .io = io },
            .base_url = try allocator.dupe(u8, base_url),
            .response_body = .init(allocator),
        };
    }

    pub fn deinit(self: *ClientTransport) void {
        self.client.deinit();
        self.response_body.deinit();
        self.allocator.free(self.base_url);
        self.* = undefined;
    }

    pub fn transport(self: *ClientTransport) Transport {
        return .{ .context = self, .requestFn = requestFn };
    }

    fn requestFn(
        context: *anyopaque,
        method: Method,
        path: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) Error!Response {
        const self: *ClientTransport = @ptrCast(@alignCast(context));
        self.response_body.clearRetainingCapacity();
        self.content_type_len = 0;

        const url = try joinUrl(self.allocator, self.base_url, path);
        defer self.allocator.free(url);

        return self.executeRequest(method, url, content_type, body) catch |err| switch (err) {
            error.PayloadTooLarge => error.PayloadTooLarge,
            error.Timeout => error.Timeout,
            else => error.TransportFailure,
        };
    }

    fn executeRequest(
        self: *ClientTransport,
        method: Method,
        url: []const u8,
        content_type: []const u8,
        body: []const u8,
    ) !Response {
        const uri = try std.Uri.parse(url);
        var req = try self.client.request(switch (method) {
            .get => .GET,
            .post => .POST,
        }, uri, .{
            .redirect_behavior = .not_allowed,
            .headers = .{
                .content_type = if (method == .post) .{ .override = content_type } else .omit,
            },
        });
        defer req.deinit();

        if (method == .post) {
            req.transfer_encoding = .{ .content_length = body.len };
            var body_writer = try req.sendBodyUnflushed(&.{});
            try body_writer.writer.writeAll(body);
            try body_writer.end();
            try req.connection.?.flush();
        } else {
            try req.sendBodiless();
        }

        var response = try req.receiveHead(&.{});
        const status = @intFromEnum(response.head.status);
        if (response.head.content_type) |value| {
            const length = @min(value.len, self.content_type_storage.len);
            @memcpy(self.content_type_storage[0..length], value[0..length]);
            self.content_type_len = length;
        }

        const decompress_buffer: []u8 = switch (response.head.content_encoding) {
            .identity => &.{},
            .zstd => try self.allocator.alloc(u8, std.compress.zstd.default_window_len),
            .deflate, .gzip => try self.allocator.alloc(u8, std.compress.flate.max_window_len),
            .compress => return error.UnsupportedCompressionMethod,
        };
        defer if (decompress_buffer.len != 0) self.allocator.free(decompress_buffer);

        if (response.head.content_length) |declared| {
            if (declared > self.max_response_bytes) return error.PayloadTooLarge;
        }

        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
        var chunk: [8 * 1024]u8 = undefined;
        var received: usize = 0;
        while (true) {
            const count = reader.readSliceShort(&chunk) catch |err| switch (err) {
                error.ReadFailed => return response.bodyErr().?,
                else => |e| return e,
            };
            if (count == 0) break;
            if (count > self.max_response_bytes - received) return error.PayloadTooLarge;
            self.response_body.writer.writeAll(chunk[0..count]) catch |err| switch (err) {
                error.WriteFailed => return error.TransportFailure,
                else => |e| return e,
            };
            received += count;
        }

        return .{
            .status = status,
            .content_type = self.content_type_storage[0..self.content_type_len],
            .body = self.response_body.written(),
        };
    }
};

fn joinUrl(allocator: std.mem.Allocator, origin: []const u8, path: []const u8) ![]u8 {
    const trimmed = std.mem.trimEnd(u8, origin, "/");
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ trimmed, path });
}

pub const Transport = struct {
    context: *anyopaque,
    requestFn: *const fn (*anyopaque, Method, []const u8, []const u8, []const u8) Error!Response,

    pub fn request(self: Transport, method: Method, path: []const u8, content_type: []const u8, body: []const u8) Error!Response {
        return self.requestFn(self.context, method, path, content_type, body);
    }
};

fn contentTypeIs(actual: []const u8, expected: []const u8) bool {
    const semicolon = std.mem.indexOfScalar(u8, actual, ';') orelse actual.len;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, actual[0..semicolon], " \t"), expected);
}

pub const Joiner = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    transport: Transport,
    base_path: []const u8,
    answer_options: identity_verify.AnswerOptions,
    max_body_size: usize = 1024 * 1024,
    max_network_id_bytes: usize = 1024,
    state: State = .idle,

    pub const State = enum { idle, capability_known, offer_sent, answer_received, failed };

    pub fn init(io: std.Io, allocator: std.mem.Allocator, transport: Transport, base_path: []const u8, answer_options: identity_verify.AnswerOptions) Joiner {
        return .{
            .io = io,
            .allocator = allocator,
            .transport = transport,
            .base_path = base_path,
            .answer_options = answer_options,
        };
    }

    fn endpoint(self: *const Joiner, comptime suffix: []const u8, args: anytype) ![]u8 {
        const prefix = std.mem.trimEnd(u8, self.base_path, "/");
        return std.fmt.allocPrint(self.allocator, "{s}" ++ suffix, .{prefix} ++ args);
    }

    fn networkPath(self: *const Joiner, network_id: []const u8) std.mem.Allocator.Error![]u8 {
        const prefix = std.mem.trimEnd(u8, self.base_path, "/");
        var path: std.ArrayList(u8) = .empty;
        errdefer path.deinit(self.allocator);
        try path.ensureTotalCapacity(self.allocator, prefix.len + "/v1/join/".len + network_id.len * 3);
        try path.appendSlice(self.allocator, prefix);
        try path.appendSlice(self.allocator, "/v1/join/");
        for (network_id) |byte| switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => try path.append(self.allocator, byte),
            else => {
                const digits = "0123456789ABCDEF";
                try path.append(self.allocator, '%');
                try path.append(self.allocator, digits[byte >> 4]);
                try path.append(self.allocator, digits[byte & 0x0f]);
            },
        };
        return path.toOwnedSlice(self.allocator);
    }

    pub fn capability(self: *Joiner) Error!ServerInfo {
        if (self.state != .idle) return error.InvalidState;
        const path = try self.endpoint("/v1/join", .{});
        defer self.allocator.free(path);
        const response = try self.transport.request(.get, path, "", "");
        if (response.status < 200 or response.status >= 300) {
            self.state = .failed;
            return error.ResponseStatusFailure;
        }
        if (!contentTypeIs(response.content_type, "application/json")) {
            self.state = .failed;
            return error.InvalidJson;
        }
        if (response.body.len > self.max_body_size) return error.PayloadTooLarge;
        const parsed = std.json.parseFromSlice(ServerInfo, self.allocator, response.body, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.state = .failed;
            return error.InvalidJson;
        };
        const name = try self.allocator.dupe(u8, parsed.value.name);
        errdefer self.allocator.free(name);
        const version = try self.allocator.dupe(u8, parsed.value.version);
        errdefer self.allocator.free(version);
        const level = try self.allocator.dupe(u8, parsed.value.level);
        errdefer self.allocator.free(level);
        const info = ServerInfo{
            .name = name,
            .protocol = parsed.value.protocol,
            .version = version,
            .level = level,
            .players = parsed.value.players,
            .maxPlayers = parsed.value.maxPlayers,
            .gameType = parsed.value.gameType,
        };
        parsed.deinit();
        self.state = .capability_known;
        return info;
    }

    pub fn submitOffer(self: *Joiner, network_id: []const u8, offer_sdp: []const u8) JoinError!Submission {
        const body = try self.exchange(network_id, offer_sdp);
        defer self.allocator.free(body);
        const verified = identity_verify.verifyAnswer(self.io, self.allocator, body, self.answer_options) catch |err| {
            self.state = .failed;
            return err;
        };
        return .{
            .sdp = verified.clean_sdp,
            .identity = verified.identity,
            .idp_domain = verified.idp_domain,
            .anchored = verified.anchored,
        };
    }

    pub fn submitOfferRaw(self: *Joiner, network_id: []const u8, offer_sdp: []const u8) Error![]u8 {
        return self.exchange(network_id, offer_sdp);
    }

    fn exchange(self: *Joiner, network_id: []const u8, offer_sdp: []const u8) Error![]u8 {
        if (self.state != .capability_known) return error.InvalidState;
        if (network_id.len == 0 or network_id.len > self.max_network_id_bytes or
            !std.unicode.utf8ValidateSlice(network_id) or
            std.mem.indexOfScalar(u8, network_id, '/') != null)
            return error.InvalidNetworkId;
        if (offer_sdp.len == 0 or offer_sdp.len > self.max_body_size) return error.InvalidSdp;

        const path = try self.networkPath(network_id);
        defer self.allocator.free(path);
        const response = try self.transport.request(.post, path, "application/sdp", offer_sdp);
        if (response.status < 200 or response.status >= 300) {
            self.state = .failed;
            return error.ResponseStatusFailure;
        }
        if (!contentTypeIs(response.content_type, "application/sdp")) return error.InvalidSdp;
        if (response.body.len == 0 or response.body.len > self.max_body_size) return error.InvalidSdp;
        self.state = .answer_received;
        return try self.allocator.dupe(u8, response.body);
    }

    pub fn deinitInfo(_: *Joiner, allocator: std.mem.Allocator, info: *ServerInfo) void {
        allocator.free(info.name);
        allocator.free(info.version);
        allocator.free(info.level);
        info.* = undefined;
    }
};

test "HTTP joiner validates capability and returns SDP answer" {
    const Context = struct {
        fn request(_: *anyopaque, method: Method, path: []const u8, content_type: []const u8, body: []const u8) Error!Response {
            if (method == .get) return .{ .status = 200, .content_type = "application/json", .body = "{\"name\":\"test\",\"protocol\":1,\"version\":\"1\",\"level\":\"world\",\"players\":1,\"maxPlayers\":10,\"gameType\":0}" };
            if (!std.mem.eql(u8, path, "/v1/join/abc") or
                !std.mem.eql(u8, content_type, "application/sdp") or
                !std.mem.eql(u8, body, "offer")) return error.InvalidState;
            return .{ .status = 200, .content_type = "application/sdp", .body = "answer" };
        }
    };
    var ctx: u8 = 0;
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &ctx, .requestFn = Context.request }, "", .{ .trust = .transport_authenticated });
    var info = try joiner.capability();
    defer joiner.deinitInfo(std.testing.allocator, &info);
    try std.testing.expectEqualStrings("test", info.name);
    const answer = try joiner.submitOfferRaw("abc", "offer");
    defer std.testing.allocator.free(answer);
    try std.testing.expectEqualStrings("answer", answer);
}

test "HTTP joiner rejects unsafe network IDs and non-success responses" {
    const Context = struct {
        fn request(_: *anyopaque, _: Method, _: []const u8, _: []const u8, _: []const u8) Error!Response {
            return .{ .status = 500, .content_type = "", .body = "" };
        }
    };
    var ctx: u8 = 0;
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &ctx, .requestFn = Context.request }, "", .{ .trust = .transport_authenticated });
    try std.testing.expectError(error.ResponseStatusFailure, joiner.capability());
}

test "HTTP joiner percent-encodes the network id byte by byte" {
    const Context = struct {
        last_path: [96]u8 = undefined,
        last_path_len: usize = 0,

        fn request(ptr: *anyopaque, method: Method, path: []const u8, _: []const u8, _: []const u8) Error!Response {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (method == .get) return .{
                .status = 200,
                .content_type = "application/json",
                .body = "{\"name\":\"t\",\"protocol\":1,\"version\":\"1\",\"level\":\"l\",\"players\":0,\"maxPlayers\":4,\"gameType\":0}",
            };
            @memcpy(self.last_path[0..path.len], path);
            self.last_path_len = path.len;
            return .{ .status = 200, .content_type = "application/sdp", .body = "v=0\r\n" };
        }
    };

    var record = Context{};
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &record, .requestFn = Context.request }, "/", .{ .trust = .transport_authenticated });
    var info = try joiner.capability();
    defer joiner.deinitInfo(std.testing.allocator, &info);

    const answer = try joiner.submitOfferRaw("a b\xc3\xb1#%", "v=0\r\n");
    defer std.testing.allocator.free(answer);
    try std.testing.expectEqualStrings("/v1/join/a%20b%C3%B1%23%25", record.last_path[0..record.last_path_len]);
}

test "HTTP joiner refuses a network id the server could not route" {
    const Context = struct {
        fn request(_: *anyopaque, _: Method, _: []const u8, _: []const u8, _: []const u8) Error!Response {
            return .{ .status = 200, .content_type = "application/sdp", .body = "v=0\r\n" };
        }
    };
    var ctx: u8 = 0;
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &ctx, .requestFn = Context.request }, "", .{ .trust = .transport_authenticated });
    joiner.state = .capability_known;
    try std.testing.expectError(error.InvalidNetworkId, joiner.submitOfferRaw("a/b", "v=0\r\n"));
    try std.testing.expectError(error.InvalidNetworkId, joiner.submitOfferRaw("", "v=0\r\n"));
    try std.testing.expectError(error.InvalidNetworkId, joiner.submitOfferRaw("a" ** (1024 + 1), "v=0\r\n"));
    try std.testing.expectError(error.InvalidNetworkId, joiner.submitOfferRaw("\xff", "v=0\r\n"));
}

test "HTTP joiner applies base_path and normalizes slashes" {
    const CallRecord = struct {
        last_method: Method = .get,
        last_path: [128]u8 = undefined,
        last_path_len: usize = 0,
        last_content_type: [64]u8 = undefined,
        last_content_type_len: usize = 0,
        last_body: [64]u8 = undefined,
        last_body_len: usize = 0,

        fn request(ptr: *anyopaque, method: Method, path: []const u8, content_type: []const u8, body: []const u8) Error!Response {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.last_method = method;
            @memcpy(self.last_path[0..path.len], path);
            self.last_path_len = path.len;
            @memcpy(self.last_content_type[0..content_type.len], content_type);
            self.last_content_type_len = content_type.len;
            @memcpy(self.last_body[0..body.len], body);
            self.last_body_len = body.len;
            if (method == .get) {
                return .{
                    .status = 200,
                    .content_type = "application/json",
                    .body = "{\"name\":\"test\",\"protocol\":1,\"version\":\"1\",\"level\":\"world\",\"players\":0,\"maxPlayers\":4,\"gameType\":0}",
                };
            }
            return .{ .status = 200, .content_type = "application/sdp", .body = "v=0\r\n" };
        }
    };

    const allocator = std.testing.allocator;
    var record = CallRecord{};
    const transport: Transport = .{ .context = &record, .requestFn = CallRecord.request };

    var partner = Joiner.init(std.testing.io, allocator, transport, "/partner", .{ .trust = .transport_authenticated });
    var info = try partner.capability();
    partner.deinitInfo(allocator, &info);
    try std.testing.expectEqual(Method.get, record.last_method);
    try std.testing.expectEqualStrings("/partner/v1/join", record.last_path[0..record.last_path_len]);

    const answer = try partner.submitOfferRaw("abc", "v=0\r\nm=x\r\n");
    defer allocator.free(answer);
    try std.testing.expectEqual(Method.post, record.last_method);
    try std.testing.expectEqualStrings("/partner/v1/join/abc", record.last_path[0..record.last_path_len]);
    try std.testing.expectEqualStrings("application/sdp", record.last_content_type[0..record.last_content_type_len]);
    try std.testing.expectEqualStrings("v=0\r\nm=x\r\n", record.last_body[0..record.last_body_len]);

    var empty_base = Joiner.init(std.testing.io, allocator, transport, "", .{ .trust = .transport_authenticated });
    var empty_info = try empty_base.capability();
    empty_base.deinitInfo(allocator, &empty_info);
    const empty_path = try allocator.dupe(u8, record.last_path[0..record.last_path_len]);
    defer allocator.free(empty_path);

    var slash_base = Joiner.init(std.testing.io, allocator, transport, "/", .{ .trust = .transport_authenticated });
    var slash_info = try slash_base.capability();
    slash_base.deinitInfo(allocator, &slash_info);
    try std.testing.expectEqualStrings("/v1/join", empty_path);
    try std.testing.expectEqualStrings(empty_path, record.last_path[0..record.last_path_len]);

    const url_a = try joinUrl(allocator, "http://127.0.0.1:19132/", "/v1/join");
    defer allocator.free(url_a);
    const url_b = try joinUrl(allocator, "http://127.0.0.1:19132", "/v1/join");
    defer allocator.free(url_b);
    try std.testing.expectEqualStrings("http://127.0.0.1:19132/v1/join", url_a);
    try std.testing.expectEqualStrings(url_a, url_b);
}

test "HTTP joiner tolerates content-type parameters and ignores unknown JSON fields" {
    const Context = struct {
        fn request(_: *anyopaque, _: Method, _: []const u8, _: []const u8, _: []const u8) Error!Response {
            return .{
                .status = 200,
                .content_type = "application/json; charset=utf-8",
                .body = "{\"name\":\"srv\",\"protocol\":944,\"version\":\"1.26\",\"level\":\"lvl\",\"players\":2,\"maxPlayers\":8,\"gameType\":1,\"icon\":\"x\"}",
            };
        }
    };
    var ctx: u8 = 0;
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &ctx, .requestFn = Context.request }, "", .{ .trust = .transport_authenticated });
    var info = try joiner.capability();
    defer joiner.deinitInfo(std.testing.allocator, &info);
    try std.testing.expectEqualStrings("srv", info.name);
    try std.testing.expectEqual(@as(u32, 944), info.protocol);
    try std.testing.expectEqual(@as(u32, 2), info.players);
    try std.testing.expectEqual(@as(u32, 8), info.maxPlayers);
}

test "HTTP joiner refuses an answer it cannot verify" {
    const Context = struct {
        fn request(_: *anyopaque, method: Method, _: []const u8, _: []const u8, _: []const u8) Error!Response {
            if (method == .get) return .{
                .status = 200,
                .content_type = "application/json",
                .body = "{\"name\":\"t\",\"protocol\":1,\"version\":\"1\",\"level\":\"l\",\"players\":0,\"maxPlayers\":4,\"gameType\":0}",
            };
            return .{ .status = 200, .content_type = "application/sdp", .body = "v=0\r\n" };
        }
    };
    var ctx: u8 = 0;
    var joiner = Joiner.init(std.testing.io, std.testing.allocator, .{ .context = &ctx, .requestFn = Context.request }, "", .{ .trust = .transport_authenticated });
    var info = try joiner.capability();
    defer joiner.deinitInfo(std.testing.allocator, &info);
    try std.testing.expectError(error.MissingIdentity, joiner.submitOffer("abc", "offer"));
    try std.testing.expectEqual(Joiner.State.failed, joiner.state);
}

const PinFirstContact = struct {
    fn decide(_: *anyopaque, _: []const u8, _: [32]u8) identity_verify.UnknownKey {
        return .pin_and_accept;
    }
};

var test_io_instance: std.Io.Threaded = undefined;

test "ClientTransport and Joiner complete capability and offer exchange against Server" {
    test_io_instance = .init(std.heap.smp_allocator, .{});
    const io = test_io_instance.io();
    const allocator = std.heap.smp_allocator;

    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19982) };
    var server = try server_http.Server.init(io, allocator, .{
        .bind_address = address,
        .server_data = .{
            .server_name = "partner-test",
            .level_name = "partner-world",
            .game_type = .survival,
            .max_player_count = 12,
        },
        .accept_unverified_identity = true,
    });
    defer server.deinit();
    try server.start();

    var client_transport = try ClientTransport.init(io, std.testing.allocator, "http://127.0.0.1:19982/");
    defer client_transport.deinit();
    var pins = try identity_verify.PinStore.init(io, std.testing.allocator, .{});
    defer pins.deinit();
    var pin_ctx: u8 = 0;
    var joiner = Joiner.init(io, std.testing.allocator, client_transport.transport(), "/", .{
        .trust = .{ .tofu = .{ .store = &pins, .on_unknown = PinFirstContact.decide, .ctx = &pin_ctx } },
    });

    var info = try joiner.capability();
    defer joiner.deinitInfo(std.testing.allocator, &info);

    try std.testing.expectEqualStrings("partner-test", info.name);
    try std.testing.expectEqualStrings("partner-world", info.level);
    try std.testing.expectEqual(@as(u32, 12), info.maxPlayers);
    try std.testing.expectEqual(Joiner.State.capability_known, joiner.state);

    var provider = identity_mod.Provider.init(io, .{});
    const signed_offer = try provider.addToSdp(std.testing.allocator, server_lan.real_offer);
    defer std.testing.allocator.free(signed_offer);

    var submission = try joiner.submitOffer("partner-net-1", signed_offer);
    defer submission.deinit(std.testing.allocator);

    try std.testing.expectEqual(Joiner.State.answer_received, joiner.state);
    try std.testing.expect(std.mem.indexOf(u8, submission.sdp, "a=identity:") == null);
    try std.testing.expect(submission.anchored);
    try std.testing.expectEqual(@as(usize, 1), pins.count());
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());
}

test "ClientTransport preserves response content-type parameters across requests" {
    const Worker = struct {
        fn serve(listener: *std.Io.net.Server, io: std.Io) void {
            var stream = listener.accept(io) catch return;
            defer stream.close(io);
            var in_buf: [2048]u8 = undefined;
            var out_buf: [2048]u8 = undefined;
            var reader = std.Io.net.Stream.reader(stream, io, &in_buf);
            var writer = std.Io.net.Stream.writer(stream, io, &out_buf);
            var http_server = std.http.Server.init(&reader.interface, &writer.interface);
            var req = http_server.receiveHead() catch return;
            req.respond(
                "{\"name\":\"charset-srv\",\"protocol\":944,\"version\":\"1.26\",\"level\":\"world\",\"players\":1,\"maxPlayers\":4,\"gameType\":0,\"icon\":\"png\"}",
                .{
                    .status = .ok,
                    .keep_alive = false,
                    .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json; charset=utf-8" }},
                },
            ) catch {};
        }
    };

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19983) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const thread = try std.Thread.spawn(.{}, Worker.serve, .{ &listener, io });
    defer thread.join();

    var client_transport = try ClientTransport.init(io, allocator, "http://127.0.0.1:19983");
    defer client_transport.deinit();
    var joiner = Joiner.init(io, allocator, client_transport.transport(), "", .{ .trust = .transport_authenticated });

    var info = try joiner.capability();
    defer joiner.deinitInfo(allocator, &info);
    try std.testing.expectEqualStrings("charset-srv", info.name);
    try std.testing.expectEqualStrings(
        "application/json; charset=utf-8",
        client_transport.content_type_storage[0..client_transport.content_type_len],
    );
}

test "ClientTransport refuses an answer that declares more than its ceiling" {
    const Worker = struct {
        fn serve(listener: *std.Io.net.Server, io: std.Io) void {
            var stream = listener.accept(io) catch return;
            defer stream.close(io);
            var in_buf: [2048]u8 = undefined;
            var out_buf: [1024]u8 = undefined;
            var reader = std.Io.net.Stream.reader(stream, io, &in_buf);
            var writer = std.Io.net.Stream.writer(stream, io, &out_buf);
            var http_server = std.http.Server.init(&reader.interface, &writer.interface);
            _ = http_server.receiveHead() catch return;
            writer.interface.writeAll(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 5000000\r\nconnection: close\r\n\r\n",
            ) catch return;
            writer.interface.flush() catch return;
        }
    };

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19984) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const thread = try std.Thread.spawn(.{}, Worker.serve, .{ &listener, io });
    defer thread.join();

    var client_transport = try ClientTransport.init(io, allocator, "http://127.0.0.1:19984");
    defer client_transport.deinit();
    client_transport.max_response_bytes = 64 * 1024;
    var joiner = Joiner.init(io, allocator, client_transport.transport(), "", .{ .trust = .transport_authenticated });

    try std.testing.expectError(error.PayloadTooLarge, joiner.capability());
}

test "ClientTransport stops a chunked answer at the ceiling" {
    const Worker = struct {
        fn serve(listener: *std.Io.net.Server, io: std.Io) void {
            var stream = listener.accept(io) catch return;
            defer stream.close(io);
            var in_buf: [2048]u8 = undefined;
            var out_buf: [1024]u8 = undefined;
            var reader = std.Io.net.Stream.reader(stream, io, &in_buf);
            var writer = std.Io.net.Stream.writer(stream, io, &out_buf);
            var http_server = std.http.Server.init(&reader.interface, &writer.interface);
            _ = http_server.receiveHead() catch return;
            writer.interface.writeAll(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
            ) catch return;
            writer.interface.flush() catch return;
            var chunk: [8192]u8 = @splat('x');
            for (0..64) |_| {
                writer.interface.writeAll("2000\r\n") catch return;
                writer.interface.writeAll(&chunk) catch return;
                writer.interface.writeAll("\r\n") catch return;
                writer.interface.flush() catch return;
            }
            writer.interface.writeAll("0\r\n\r\n") catch return;
            writer.interface.flush() catch return;
        }
    };

    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19985) };
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const thread = try std.Thread.spawn(.{}, Worker.serve, .{ &listener, io });
    defer thread.join();

    var client_transport = try ClientTransport.init(io, allocator, "http://127.0.0.1:19985");
    defer client_transport.deinit();
    client_transport.max_response_bytes = 64 * 1024;
    var joiner = Joiner.init(io, allocator, client_transport.transport(), "", .{ .trust = .transport_authenticated });

    try std.testing.expectError(error.PayloadTooLarge, joiner.capability());
}
