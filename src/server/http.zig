const std = @import("std");
const discovery = @import("../discovery.zig");
const policy = @import("policy.zig");
const dispatch = @import("dispatch.zig");
const framing = @import("../transport/framing.zig");
const sdp_edit = @import("../transport/sdp_edit.zig");
const wire_log = @import("wire_log.zig");
const log = @import("../log.zig");
const peer_mod = @import("../webrtc/peer.zig");
const identity_mod = @import("../identity/server.zig");
const sdp_identity = @import("../identity/sdp.zig");
const json = @import("../json.zig");
const identity_verify = @import("../identity/verify.zig");
const lan_srv = @import("lan.zig");
const rate_limit = @import("rate_limit.zig");
const platform_net = @import("../platform/net.zig");

pub const Config = struct {
    bind_address: std.Io.net.IpAddress = .{ .ip4 = .unspecified(19132) },
    server_data: discovery.ServerData = .{
        .server_name = "NetherNet Zig test server",
        .level_name = "nethernet-zig-test",
        .game_type = .creative,
    },
    occupancy: ?policy.PlayerSource = null,
    max_header_size: usize = 16 * 1024,
    max_body_size: usize = 256 * 1024,
    max_concurrent_requests: usize = 32,
    request_timeout_ms: i64 = 10_000,
    gather_timeout_ms: i64 = 8_000,
    rate_limit: ?rate_limit.Config = null,
    max_network_id_bytes: usize = 1024,
    max_sessions: usize = 256,
    tick_shards: usize = 1,
    tick_interval_ms: i64 = 10,
    establish_timeout_ms: i64 = 15_000,
    /// How long an *established* session survives after its peer leaves `connected`.
    /// The establishment timeout is the wrong measure once a player is in the world:
    /// a client that quits must not hold its slot for another 15 s. The ICE agent has
    /// already spent its own silence window before it reports `disconnected`, so this
    /// is the additional grace that keeps a brief network blip from ending the session.
    disconnect_timeout_ms: i64 = 3_000,
    handler: ?peer_mod.MessageHandler = null,
    max_message_size: u32 = framing.default_message_size,
    max_packet_bytes: usize = framing.default_max_packet_bytes,
    echo_packets: bool = true,
    identity_verifier: ?*identity_verify.Verifier = null,
    identity_policy: ?identity_verify.IdentityPolicy = null,
    accept_unverified_identity: bool = false,
    max_identity_bytes: usize = 64 * 1024,
    require_identity: bool = true,
    cpk_encoding: identity_mod.Provider.CpkEncoding = .jwk,
    identity: ?identity_mod.Provider = null,
    ice_servers: []const peer_mod.IceServer = &.{},
    public_candidate: ?sdp_edit.PublicCandidate = null,
};

pub const RateLimitConfig = rate_limit.Config;

pub const max_server_name_bytes: usize = 128;
pub const max_level_name_bytes: usize = 128;
pub const max_game_version_bytes: usize = 32;

const status_body_bytes: usize = 2048;
const status_unavailable_body = "{\"error\":\"status unavailable\"}";
const join_path_prefix = "/v1/join/";

const NetworkIdError = error{ InvalidNetworkId, NetworkIdTooLong } || std.mem.Allocator.Error;

fn decodeNetworkId(allocator: std.mem.Allocator, raw: []const u8, max: usize) NetworkIdError![]u8 {
    if (raw.len == 0) return error.InvalidNetworkId;
    const decoded = try allocator.alloc(u8, @min(raw.len, max));
    errdefer allocator.free(decoded);

    var used: usize = 0;
    var index: usize = 0;
    while (index < raw.len) {
        const byte: u8 = if (raw[index] == '%') blk: {
            if (index + 2 >= raw.len) return error.InvalidNetworkId;
            const high = std.fmt.charToDigit(raw[index + 1], 16) catch return error.InvalidNetworkId;
            const low = std.fmt.charToDigit(raw[index + 2], 16) catch return error.InvalidNetworkId;
            index += 3;
            break :blk (high << 4) | low;
        } else blk: {
            const value = raw[index];
            index += 1;
            break :blk value;
        };
        if (byte == 0 or byte == '/') return error.InvalidNetworkId;
        if (used == decoded.len) return error.NetworkIdTooLong;
        decoded[used] = byte;
        used += 1;
    }
    if (used == 0 or !std.unicode.utf8ValidateSlice(decoded[0..used])) return error.InvalidNetworkId;
    return allocator.realloc(decoded, used);
}

const log_id_bytes: usize = 192;

fn logNetworkId(buffer: *[log_id_bytes]u8, network_id: []const u8) []const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    for (network_id) |byte| {
        if (byte >= 0x20 and byte < 0x7f) {
            writer.writeByte(byte) catch break;
        } else {
            writer.print("%{X:0>2}", .{byte}) catch break;
        }
    }
    return writer.buffered();
}

fn validateServerData(data: discovery.ServerData) error{InvalidServerData}!void {
    try validateConfigText(data.server_name, max_server_name_bytes);
    try validateConfigText(data.level_name, max_level_name_bytes);
    try validateConfigText(data.game_version, max_game_version_bytes);
}

fn validateConfigText(value: []const u8, max_bytes: usize) error{InvalidServerData}!void {
    if (value.len > max_bytes or !json.isValidUtf8(value)) return error.InvalidServerData;
    for (value) |byte| if (byte < 0x20) return error.InvalidServerData;
}

const PeerConfig = peer_mod.PeerConfig;

const Dispatcher = struct {
    server: *Server,
    session: *ActiveSession,
    kind: peer_mod.ChannelKind,

    fn onMessage(ctx: *anyopaque, message: []const u8) framing.FramingError!void {
        const self: *Dispatcher = @ptrCast(@alignCast(ctx));
        const reply = dispatch.replyFor(
            self.server.config.handler,
            &self.session.handle,
            self.kind,
            message,
            self.server.config.echo_packets,
        ) orelse return;
        var escaped: [log_id_bytes]u8 = undefined;
        var label_buffer: [96 + log_id_bytes]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buffer, "session id={d} networkId={s}", .{
            self.session.handle.id,
            logNetworkId(&escaped, self.session.network_id),
        }) catch "session";
        return dispatch.sendPacket(
            self.session.scratchProvider(),
            self.session.max_message_size,
            &self.session.handle,
            self.kind,
            label,
            reply,
        );
    }
};

/// A session that has been connected gets the short disconnect grace; one that never
/// got there gets the full establishment timeout.
fn peerGoneTimeout(config: Config, connected_once: bool) i64 {
    return if (connected_once) config.disconnect_timeout_ms else config.establish_timeout_ms;
}

const ActiveSession = struct {
    allocator: std.mem.Allocator,
    native: *peer_mod.NativePeerConnection,
    peer: peer_mod.Peer,
    handle: peer_mod.PeerHandle,
    network_id: []u8,
    max_message_size: u32,
    assembly: framing.Channels,
    scratch: []u8 = &.{},
    identity: ?identity_verify.SessionIdentity = null,
    slot_index: usize = 0,
    last_progress_ms: i64 = 0,
    opened: bool = false,
    established: bool = false,
    /// Once true the session is judged by `disconnect_timeout_ms`, not by the
    /// establishment timeout, even after `established` drops back to false.
    connected_once: bool = false,

    fn scratchEnsure(ctx: *anyopaque, needed: usize) framing.FramingError![]u8 {
        const self: *ActiveSession = @ptrCast(@alignCast(ctx));
        if (self.scratch.len >= needed) return self.scratch;
        if (needed > self.max_message_size) return error.PayloadTooLarge;
        return self.growScratch(needed);
    }

    fn scratchProvider(self: *ActiveSession) framing.Scratch {
        return .{ .ctx = self, .ensure = scratchEnsure };
    }

    fn growScratch(self: *ActiveSession, needed: usize) framing.FramingError![]u8 {
        const target = @min(self.max_message_size, @max(needed, @max(self.scratch.len *| 2, 1024)));
        const grown = try self.allocator.alloc(u8, target);
        self.allocator.free(self.scratch);
        self.scratch = grown;
        return self.scratch;
    }

    fn deinit(self: *ActiveSession, handler: ?peer_mod.MessageHandler) void {
        if (self.opened) dispatch.closeFor(handler, &self.handle);
        self.peer.deinit(self.allocator);
        self.native.deinit();
        self.assembly.deinit();
        self.allocator.free(self.network_id);
        self.allocator.free(self.scratch);
        self.allocator.destroy(self);
    }
};

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    listener: std.Io.net.Server,
    identity: identity_mod.Provider,
    sessions: []?*ActiveSession,
    shard_locks: []std.Io.Mutex,
    session_total: std.atomic.Value(usize) = .init(0),
    player_total: std.atomic.Value(usize) = .init(0),
    verified_total: std.atomic.Value(usize) = .init(0),
    unverified_total: std.atomic.Value(usize) = .init(0),
    unverified_warned: std.atomic.Value(bool) = .init(false),
    next_shard: std.atomic.Value(usize) = .init(0),
    next_session_id: std.atomic.Value(u64) = .init(0),
    workers: []std.Thread = &.{},
    stopping: std.atomic.Value(bool) = .init(false),
    limiter: ?rate_limit.Limiter = null,
    limiter_unavailable: std.atomic.Value(bool) = .init(false),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) !Server {
        if (config.max_sessions == 0) return error.InvalidArgument;
        if (config.tick_shards == 0 or config.tick_shards > config.max_sessions) return error.InvalidArgument;
        if (config.max_network_id_bytes == 0 or
            config.max_network_id_bytes + join_path_prefix.len > config.max_header_size)
            return error.InvalidNetworkIdLimit;
        if (config.max_concurrent_requests == 0) return error.InvalidArgument;
        if (config.request_timeout_ms < 0 or config.gather_timeout_ms < 0) return error.InvalidArgument;
        if (config.establish_timeout_ms < 0) return error.InvalidArgument;
        if (config.disconnect_timeout_ms < 0) return error.InvalidArgument;
        try peer_mod.validateIceServers(config.ice_servers);
        if (config.public_candidate) |candidate| try sdp_edit.validateCandidate(candidate);
        try validateServerData(config.server_data);
        if (config.identity_verifier == null and !config.accept_unverified_identity) return error.IdentityVerifierRequired;
        if (!config.require_identity) std.log.warn("HTTP signaling admits offers without identity: require_identity=false", .{});
        var listener = try std.Io.net.IpAddress.listen(&config.bind_address, io, .{
            .reuse_address = true,
            .kernel_backlog = 128,
        });

        errdefer listener.deinit(io);
        const sessions = try allocator.alloc(?*ActiveSession, config.max_sessions);
        errdefer allocator.free(sessions);
        @memset(sessions, null);
        const shard_locks = try allocator.alloc(std.Io.Mutex, config.tick_shards);
        errdefer allocator.free(shard_locks);
        for (shard_locks) |*lock| lock.* = .init;

        var limiter: ?rate_limit.Limiter = null;
        if (config.rate_limit) |limit_config| {
            limiter = try rate_limit.Limiter.init(io, allocator, limit_config);
            errdefer if (limiter) |*value| value.deinit();
        }

        return .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .listener = listener,
            .identity = config.identity orelse identity_mod.Provider.init(io, .{ .cpk_encoding = config.cpk_encoding }),
            .sessions = sessions,
            .shard_locks = shard_locks,
            .limiter = limiter,
        };
    }

    pub fn deinit(self: *Server) void {
        self.stop();
        self.listener.deinit(self.io);
        for (self.sessions) |*slot| if (slot.*) |active| {
            active.deinit(self.config.handler);
            slot.* = null;
        };
        self.allocator.free(self.sessions);
        self.allocator.free(self.shard_locks);
        if (self.limiter) |*limiter| limiter.deinit();
        self.* = undefined;
    }

    pub fn shardCount(self: *const Server) usize {
        return self.shard_locks.len;
    }

    pub fn sessionCount(self: *const Server) usize {
        return self.session_total.load(.monotonic);
    }

    pub fn playerCount(self: *const Server) usize {
        return self.player_total.load(.monotonic);
    }

    pub fn verifiedCount(self: *const Server) usize {
        return self.verified_total.load(.monotonic);
    }

    pub fn unverifiedCount(self: *const Server) usize {
        return self.unverified_total.load(.monotonic);
    }

    pub fn tick(self: *Server) void {
        for (0..self.shard_locks.len) |shard| self.tickShard(shard);
    }

    pub fn tickShard(self: *Server, shard: usize) void {
        if (shard >= self.shard_locks.len) return;
        const now = peer_mod.nowMs(self.io);

        self.shard_locks[shard].lockUncancelable(self.io);
        defer self.shard_locks[shard].unlock(self.io);

        for (self.shardSessions(shard)) |*slot| if (slot.*) |active| {
            var escaped: [log_id_bytes]u8 = undefined;
            const log_id = logNetworkId(&escaped, active.network_id);
            active.peer.tick() catch |err| {
                std.log.err("session id={d} networkId={s} tick failed: {s}", .{ active.handle.id, log_id, @errorName(err) });
                self.noteReleased(active);
                active.deinit(self.config.handler);
                slot.* = null;
                continue;
            };

            var released = false;
            while (active.peer.pollEvent()) |event| switch (event) {
                .binary => |message| {
                    var hex_buffer: wire_log.HexBuffer = undefined;
                    log.debug("session id={d} networkId={s} wire bytes={d} hex={s}", .{
                        active.handle.id,
                        log_id,
                        message.data.len,
                        wire_log.hex(&hex_buffer, message.data),
                    });
                    const channel: framing.Channel = switch (message.kind) {
                        .reliable => .reliable,
                        .unreliable => .unreliable,
                    };
                    var dispatcher = Dispatcher{ .server = self, .session = active, .kind = message.kind };
                    active.assembly.feed(channel, message.data, .{
                        .ctx = &dispatcher,
                        .on_message = Dispatcher.onMessage,
                    }) catch |err| std.log.warn(
                        "session id={d} networkId={s} framing error: {s}",
                        .{ active.handle.id, log_id, @errorName(err) },
                    );
                },
                .state_changed => |state| log.debug("session id={d} networkId={s} state={s}", .{ active.handle.id, log_id, @tagName(state) }),
                .channel_opened => |kind| log.debug("session id={d} networkId={s} channel opened={s}", .{ active.handle.id, log_id, @tagName(kind) }),
                .channel_closed => |kind| log.debug("session id={d} networkId={s} channel closed={s}", .{ active.handle.id, log_id, @tagName(kind) }),
                .failed => |err| {
                    std.log.err("session id={d} networkId={s} peer failure={s}", .{ active.handle.id, log_id, @errorName(err) });
                    self.noteReleased(active);
                    active.deinit(self.config.handler);
                    slot.* = null;
                    released = true;
                    break;
                },
                .channel_attached => {},
            };
            if (released) continue;

            if (active.peer.stateOf() == .connected) {
                active.last_progress_ms = now;
                active.connected_once = true;
            } else if (now - active.last_progress_ms >= peerGoneTimeout(self.config, active.connected_once)) {
                std.log.warn("closing session id={d} networkId={s}: {s} for {d} ms", .{
                    active.handle.id,
                    log_id,
                    @tagName(active.peer.stateOf()),
                    now - active.last_progress_ms,
                });
                self.noteReleased(active);
                active.deinit(self.config.handler);
                slot.* = null;
                continue;
            }

            self.noteEstablished(active, active.peer.stateOf() == .connected);
        };
    }

    fn shardSessions(self: *const Server, shard: usize) []?*ActiveSession {
        const per_shard = self.perShard();
        const begin = shard * per_shard;
        const end = @min(begin + per_shard, self.sessions.len);
        return self.sessions[begin..end];
    }

    fn perShard(self: *const Server) usize {
        return (self.sessions.len + self.shard_locks.len - 1) / self.shard_locks.len;
    }

    fn publishSession(self: *Server, active: *ActiveSession) bool {
        const shards = self.shard_locks.len;
        const first = self.next_shard.fetchAdd(1, .monotonic) % shards;
        for (0..shards) |offset| {
            const shard = (first + offset) % shards;
            const sessions = self.shardSessions(shard);
            self.shard_locks[shard].lockUncancelable(self.io);
            for (sessions, 0..) |*slot, index| if (slot.* == null) {
                dispatch.openFor(self.config.handler, &active.handle);
                active.opened = true;
                active.slot_index = index + shard * self.perShard();
                slot.* = active;
                self.notePublished(active);
                self.shard_locks[shard].unlock(self.io);
                return true;
            };
            self.shard_locks[shard].unlock(self.io);
        }
        return false;
    }

    fn unpublishSession(self: *Server, active: *ActiveSession) void {
        const index = active.slot_index;
        if (index >= self.sessions.len) return;
        const shard = @min(index / self.perShard(), self.shard_locks.len - 1);
        self.shard_locks[shard].lockUncancelable(self.io);
        defer self.shard_locks[shard].unlock(self.io);
        if (self.sessions[index] == active) {
            self.sessions[index] = null;
            self.noteReleased(active);
        }
    }

    fn evictNetwork(self: *Server, network_id: []const u8) void {
        for (0..self.shard_locks.len) |shard| {
            self.shard_locks[shard].lockUncancelable(self.io);
            var evicted: ?*ActiveSession = null;
            for (self.shardSessions(shard)) |*slot| {
                const active = slot.* orelse continue;
                if (!std.mem.eql(u8, active.network_id, network_id)) continue;
                slot.* = null;
                self.noteReleased(active);
                evicted = active;
                break;
            }
            self.shard_locks[shard].unlock(self.io);
            // Released outside the shard lock: `deinit` calls the handler, which can
            // run arbitrary consumer code (closing the player, touching its world).
            if (evicted) |active| {
                var escaped: [log_id_bytes]u8 = undefined;
                std.log.info("closing session id={d} networkId={s}: the client joined again", .{
                    active.handle.id,
                    logNetworkId(&escaped, network_id),
                });
                active.deinit(self.config.handler);
            }
        }
    }

    fn notePublished(self: *Server, active: *ActiveSession) void {
        _ = self.session_total.fetchAdd(1, .monotonic);
        if (active.established) _ = self.player_total.fetchAdd(1, .monotonic);
        if (active.identity) |identity| {
            if (identity.anchored) _ = self.verified_total.fetchAdd(1, .monotonic);
        }
    }

    fn noteUnverifiedJoin(self: *Server) void {
        _ = self.unverified_total.fetchAdd(1, .monotonic);
        if (self.unverified_warned.swap(true, .monotonic)) return;
        std.log.warn("admitting an identity this server cannot anchor: accept_unverified_identity=true", .{});
    }

    fn noteReleased(self: *Server, active: *const ActiveSession) void {
        _ = self.session_total.fetchSub(1, .monotonic);
        if (active.established) _ = self.player_total.fetchSub(1, .monotonic);
        if (active.identity) |identity| {
            if (identity.anchored) _ = self.verified_total.fetchSub(1, .monotonic);
        }
    }

    fn noteEstablished(self: *Server, active: *ActiveSession, established: bool) void {
        if (established == active.established) return;
        active.established = established;
        if (established) {
            _ = self.player_total.fetchAdd(1, .monotonic);
        } else {
            _ = self.player_total.fetchSub(1, .monotonic);
        }
    }

    fn releaseSession(self: *Server, active: *ActiveSession) void {
        self.unpublishSession(active);
        active.deinit(self.config.handler);
    }

    pub fn serveOne(self: *Server) !void {
        const input = try self.allocator.alloc(u8, self.config.max_header_size);
        defer self.allocator.free(input);
        return self.serveOneWithBuffer(input);
    }

    pub fn serveOneWithBuffer(self: *Server, input: []u8) !void {
        var stream = try self.listener.accept(self.io);
        defer stream.close(self.io);
        if (self.stopping.load(.acquire)) return;
        log.debug("accepted HTTP signaling connection", .{});

        var timed_out: std.atomic.Value(bool) = .init(false);
        if (self.config.request_timeout_ms <= 0) return self.serveStream(stream, input, &timed_out);

        var done: std.Io.Event = .unset;
        const watchdog = std.Thread.spawn(.{ .stack_size = watchdog_stack_bytes }, watchConnection, .{
            self.io,
            stream,
            &done,
            &timed_out,
            self.config.request_timeout_ms,
        }) catch return self.serveStream(stream, input, &timed_out);
        defer {
            done.set(self.io);
            watchdog.join();
        }
        return self.serveStream(stream, input, &timed_out);
    }

    fn serveStream(self: *Server, stream: std.Io.net.Stream, input: []u8, timed_out: *std.atomic.Value(bool)) !void {
        var output_buffer: [16 * 1024]u8 = undefined;
        var body_buffer: [16 * 1024]u8 = undefined;
        var stream_reader = std.Io.net.Stream.reader(stream, self.io, input);
        var stream_writer = std.Io.net.Stream.writer(stream, self.io, &output_buffer);

        if (!try sniffFirstChunk(self.io, &stream_reader.interface, &stream_writer.interface)) {
            if (timed_out.load(.acquire)) writeRawError(&stream_writer.interface, "408 Request Timeout");
            return;
        }

        var http_server = std.http.Server.init(&stream_reader.interface, &stream_writer.interface);
        while (true) {
            var request = http_server.receiveHead() catch |err| {
                if (timed_out.load(.acquire)) {
                    writeRawError(&stream_writer.interface, "408 Request Timeout");
                    std.log.warn("signaling peer exceeded its {d} ms request budget", .{self.config.request_timeout_ms});
                    return;
                }
                if (err == error.HttpHeadersOversize) {
                    writeRawError(&stream_writer.interface, "400 Bad Request");
                    std.log.warn("signaling peer sent more than {d} bytes of headers", .{self.config.max_header_size});
                    return;
                }
                if (err == error.HttpConnectionClosing) {
                    return;
                }
                std.log.err("failed to parse HTTP request head: {s}", .{@errorName(err)});
                return err;
            };
            std.log.info("HTTP request at ms={d}: {s} {s}", .{ wallClockMs(self.io), @tagName(request.head.method), request.head.target });
            var headers = request.iterateHeaders();
            while (headers.next()) |header| log.debug("HTTP header: {s}: {s}", .{ header.name, header.value });

            const path = pathOnly(request.head.target);
            if ((request.head.method == .GET or request.head.method == .HEAD) and
                (std.mem.eql(u8, path, "/v1/join") or std.mem.eql(u8, path, "/v1/join/")))
            {
                const reusable = request.head.keep_alive;
                try self.respondStatus(&request, reusable);
                if (!reusable) return;
                continue;
            }

            if (request.head.method == .POST and std.mem.startsWith(u8, path, join_path_prefix)) {
                if (self.rateDecision(stream)) |decision| {
                    if (!decision.allowed) {
                        var retry_buffer: [8]u8 = undefined;
                        const retry = std.fmt.bufPrint(&retry_buffer, "{d}", .{decision.retry_after_seconds}) catch "1";
                        std.log.warn("rejecting join: too many requests from this address", .{});
                        try request.respond("Too many requests\n", .{
                            .status = .too_many_requests,
                            .keep_alive = false,
                            .extra_headers = &.{.{ .name = "retry-after", .value = retry }},
                        });
                        return;
                    }
                }
                const network_id = decodeNetworkId(
                    self.allocator,
                    path[join_path_prefix.len..],
                    self.config.max_network_id_bytes,
                ) catch |err| {
                    var escaped_buffer: [log_id_bytes]u8 = undefined;
                    std.log.warn("rejecting join: network id {s} ({s})", .{
                        logNetworkId(&escaped_buffer, path[join_path_prefix.len..]),
                        @errorName(err),
                    });
                    const status: std.http.Status = switch (err) {
                        error.NetworkIdTooLong => .uri_too_long,
                        else => .bad_request,
                    };
                    try request.respond("Invalid network id\n", .{ .status = status, .keep_alive = false });
                    return;
                };
                defer self.allocator.free(network_id);
                const offer = self.readOffer(&request, body_buffer[0..]) catch |err| switch (err) {
                    error.InvalidContentLength, error.UnsupportedMediaType => return,
                    else => {
                        std.log.warn("could not read SDP offer: {s}", .{@errorName(err)});
                        return err;
                    },
                };
                defer self.allocator.free(offer);
                return self.handleOffer(&request, offer, network_id);
            }

            std.log.warn("unknown HTTP route: {s}", .{path});
            try request.respond("Not found\n", .{ .status = .not_found, .keep_alive = false });
            return;
        }
    }

    fn readOffer(self: *Server, request: *std.http.Server.Request, body_buffer: []u8) ![]u8 {
        if (request.head.content_length == null or request.head.content_length.? > self.config.max_body_size) {
            std.log.warn("rejecting SDP offer: invalid content length {?d}", .{request.head.content_length});
            try request.respond("Offer too large or missing content-length\n", .{ .status = .bad_request, .keep_alive = false });
            return error.InvalidContentLength;
        }
        if (request.head.content_type == null or !contentTypeIs(request.head.content_type.?, "application/sdp")) {
            try request.respond("Expected application/sdp\n", .{ .status = .unsupported_media_type, .keep_alive = false });
            return error.UnsupportedMediaType;
        }

        const body_reader = request.readerExpectContinue(body_buffer) catch |err| {
            std.log.err("could not initialize SDP body reader: {s}", .{@errorName(err)});
            return err;
        };
        return body_reader.allocRemaining(self.allocator, .limited(self.config.max_body_size)) catch |err| {
            std.log.err("could not read SDP offer: {s}", .{@errorName(err)});
            try request.respond("Invalid SDP body\n", .{ .status = .bad_request, .keep_alive = false });
            return err;
        };
    }

    fn respondStatus(self: *Server, request: *std.http.Server.Request, keep_alive: bool) !void {
        const data = self.config.server_data;
        const capacity = if (data.max_player_count > 0)
            @as(u32, @intCast(data.max_player_count))
        else
            @as(u32, @intCast(@min(self.sessions.len, std.math.maxInt(u32))));
        var body: [status_body_bytes]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&body);
        writeStatusBody(&writer, data, self.playerCount(), capacity) catch |err| switch (err) {
            error.WriteFailed => {
                std.log.err("status body does not fit its buffer", .{});
                return respondStaticStatus(request, .internal_server_error);
            },
        };
        const response_body = writer.buffered();
        log.debug("responding status bytes={d} body={s}", .{ response_body.len, response_body });
        try request.respond(response_body, .{
            .status = .ok,
            .keep_alive = keep_alive,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
    }

    fn handleOffer(self: *Server, request: *std.http.Server.Request, offer: []const u8, network_id: []const u8) !void {
        var log_id_buffer: [log_id_bytes]u8 = undefined;
        const log_id = logNetworkId(&log_id_buffer, network_id);
        std.log.info("received SDP offer networkId={s} bytes={d}", .{ log_id, offer.len });

        // The cap is checked before the claim: a full server must not spend a
        // signature check, or a JWKS fetch, to answer `503`.
        const player_limit = self.config.server_data.max_player_count;
        const occupied = if (self.config.occupancy) |source| source.count(source.ctx) else self.sessionCount();
        if (player_limit > 0 and occupied >= @as(usize, @intCast(player_limit))) {
            std.log.warn("rejecting offer networkId={s}: player limit {d} reached", .{ log_id, player_limit });
            try request.respond("Server is full\n", .{ .status = .service_unavailable, .keep_alive = false });
            return;
        }

        const verified_identity = self.validateClientIdentity(network_id, offer) catch |err| {
            std.log.warn("rejecting SDP offer networkId={s}: identity={s}", .{ log_id, @errorName(err) });
            if (err == error.JwksUnavailable) {
                try request.respond("Identity provider unavailable\n", .{ .status = .service_unavailable, .keep_alive = false });
                return;
            }
            const body = switch (err) {
                error.MissingIdentity => "Identity assertion required\n",
                else => "Identity rejected\n",
            };
            try request.respond(body, .{ .status = .bad_request, .keep_alive = false });
            return;
        };

        const clean_offer = sdp_identity.withoutIdentity(self.allocator, offer) catch |err| {
            std.log.err("SDP cleanup failed networkId={s}: {s}", .{ log_id, @errorName(err) });
            try request.respond("Session setup failed\n", .{ .status = .internal_server_error, .keep_alive = false });
            return;
        };
        defer self.allocator.free(clean_offer);

        const max_message_size = framing.negotiatedMaxMessageSize(
            sdp_identity.maxMessageSize(clean_offer),
            self.config.max_message_size,
        );
        log.debug("SDP offer networkId={s} negotiated maxMessageSize={d}", .{ log_id, max_message_size });

        self.evictNetwork(network_id);

        var answer_sdp: []const u8 = &.{};
        const active = self.buildSession(network_id, clean_offer, max_message_size, verified_identity, &answer_sdp) catch |err| {
            const status = setupFailureStatus(err);
            std.log.err("session setup failed networkId={s}: {s}", .{ log_id, @errorName(err) });
            try request.respond("Session setup failed\n", .{ .status = status, .keep_alive = false });
            return;
        };
        var published = false;
        defer if (!published) active.deinit(self.config.handler);

        const edited_answer = sdp_edit.editAnswer(self.allocator, answer_sdp, .{
            .max_message_size = max_message_size,
            .public_candidate = self.config.public_candidate,
        }) catch |err| {
            std.log.err("answer edit failed networkId={s}: {s}", .{ log_id, @errorName(err) });
            try request.respond("Session setup failed\n", .{ .status = .internal_server_error, .keep_alive = false });
            return;
        };
        defer self.allocator.free(edited_answer);

        const signed_answer = self.identity.addToSdp(self.allocator, edited_answer) catch |err| {
            std.log.err("identity generation failed networkId={s}: {s}", .{ log_id, @errorName(err) });
            try request.respond("Identity generation failed\n", .{ .status = .internal_server_error, .keep_alive = false });
            return;
        };
        defer self.allocator.free(signed_answer);

        if (!self.publishSession(active)) {
            std.log.warn("rejecting offer networkId={s}: no free session slot", .{log_id});
            try request.respond("Server is full\n", .{ .status = .service_unavailable, .keep_alive = false });
            return;
        }
        published = true;
        request.respond(signed_answer, .{
            .status = .ok,
            .keep_alive = false,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/sdp" }},
        }) catch |err| {
            self.releaseSession(active);
            return err;
        };
        std.log.info(
            "SDP answer sent session id={d} networkId={s} bytes={d}; session retained",
            .{ active.handle.id, log_id, signed_answer.len },
        );
    }

    fn buildSession(
        self: *Server,
        network_id: []const u8,
        offer: []const u8,
        max_message_size: u32,
        verified: ?identity_verify.SessionIdentity,
        answer_out: *[]const u8,
    ) !*ActiveSession {
        // Everything acquired below moves into `active` exactly once; only one
        // error path may release it.
        const active = try self.allocator.create(ActiveSession);
        var session_ready = false;
        errdefer {
            if (session_ready) active.deinit(self.config.handler) else self.allocator.destroy(active);
        }
        const native = try peer_mod.NativePeerConnection.init(self.io, self.allocator, .{
            .profile = .http_full_ice,
            .event_capacity = 128,
            .max_event_payload = 262144,
            .max_message_size = max_message_size,
            .gather_timeout_ms = self.config.gather_timeout_ms,
            .ice_servers = self.config.ice_servers,
        });
        var peer = try peer_mod.Peer.init(self.allocator, native.connectionSpi(), .{
            .profile = .http_full_ice,
            .event_capacity = 128,
            .max_event_payload = 262144,
            .max_message_size = max_message_size,
            .ice_servers = self.config.ice_servers,
        });
        const stored_id = try self.allocator.dupe(u8, network_id);

        var moved = false;
        errdefer if (!moved) {
            peer.deinit(self.allocator);
            native.deinit();
            self.allocator.free(stored_id);
        };

        active.* = .{
            .allocator = self.allocator,
            .native = native,
            .peer = peer,
            .handle = .{ .id = self.next_session_id.fetchAdd(1, .monotonic) + 1, .peer = undefined },
            .network_id = stored_id,
            .max_message_size = max_message_size,
            .assembly = framing.Channels.init(self.allocator, max_message_size, self.config.max_packet_bytes),
            .identity = verified,
            .last_progress_ms = peer_mod.nowMs(self.io),
        };
        active.handle.peer = &active.peer;
        moved = true;
        session_ready = true;

        const answer = try active.peer.acceptOffer(.{ .kind = .offer, .sdp = offer });
        answer_out.* = answer.sdp;
        return active;
    }

    fn validateClientIdentity(self: *Server, network_id: []const u8, offer: []const u8) !?identity_verify.SessionIdentity {
        if (self.config.identity_verifier) |verifier| return self.validateVerified(verifier, network_id, offer);
        if (!self.config.accept_unverified_identity) return error.IdentityVerifierRequired;
        return self.validateUnanchored(network_id, offer);
    }

    fn validateVerified(self: *Server, verifier: *identity_verify.Verifier, network_id: []const u8, offer: []const u8) !?identity_verify.SessionIdentity {
        var verified = verifier.verifyOffer(offer) catch |err| switch (err) {
            error.MissingIdentity => return self.admitAnonymous(network_id),
            else => return err,
        };
        defer verified.deinit(self.allocator);

        if (self.config.identity_policy) |admission| {
            if (!admission.allow(admission.ctx, network_id, &verified.claims)) return error.IdentityRejected;
        }
        const identity = verified.sessionIdentity();
        const key_hex = std.fmt.bytesToHex(identity.key_sha256, .lower);
        log.debug("peer identity verified cpk form={s} key sha-256={s}", .{ @tagName(identity.form), key_hex[0..] });
        return identity;
    }

    fn validateUnanchored(self: *Server, network_id: []const u8, offer: []const u8) !?identity_verify.SessionIdentity {
        const identity = self.parseClientIdentity(offer) catch |err| switch (err) {
            error.MissingIdentity => return self.admitAnonymous(network_id),
            else => return err,
        };
        if (self.config.identity_policy) |admission| {
            if (!admission.allow(admission.ctx, network_id, null)) return error.IdentityRejected;
        }
        self.noteUnverifiedJoin();
        return identity;
    }

    fn admitAnonymous(self: *Server, network_id: []const u8) !?identity_verify.SessionIdentity {
        if (self.config.identity_policy) |admission| {
            if (!admission.allow(admission.ctx, network_id, null)) return error.IdentityRejected;
        }
        if (self.config.require_identity) return error.MissingIdentity;
        log.debug("admitting anonymous join networkId={s}: require_identity=false", .{network_id});
        return null;
    }

    fn parseClientIdentity(self: *Server, offer: []const u8) !identity_verify.SessionIdentity {
        var envelope = try sdp_identity.extract(offer, self.allocator, .{ .max_attribute_size = self.config.max_identity_bytes });
        defer sdp_identity.deinit(self.allocator, &envelope);
        const Assertion = struct { fingerprints: []const u8, token: []const u8 };
        const parsed = std.json.parseFromSlice(Assertion, self.allocator, envelope.assertion, .{ .ignore_unknown_fields = true }) catch return error.InvalidIdentity;
        defer parsed.deinit();
        if (std.mem.count(u8, parsed.value.token, ".") != 2 or
            std.mem.count(u8, parsed.value.fingerprints, ".") != 2)
            return error.InvalidIdentity;

        var identity = identity_verify.verifyAssertion(self.allocator, envelope.assertion, offer) catch |err| {
            std.log.warn("peer identity did not verify: {s}", .{@errorName(err)});
            return error.InvalidIdentity;
        };
        defer identity.deinit(self.allocator);
        return identity.sessionIdentity();
    }

    fn rateDecision(self: *Server, stream: std.Io.net.Stream) ?rate_limit.Decision {
        const limiter = if (self.limiter) |*value| value else return null;
        const key = platform_net.peerKey(stream) catch |err| {
            if (!self.limiter_unavailable.swap(true, .monotonic)) {
                std.log.warn(
                    "rate limiting is off for this listener: peer address unavailable ({s}). A proxy in front hides the player's address, so expect the limit to be keyed on the proxy or unavailable entirely",
                    .{@errorName(err)},
                );
            }
            return null;
        };
        return limiter.check(key, peer_mod.nowMs(self.io));
    }

    pub fn start(self: *Server) !void {
        if (self.workers.len != 0) return;
        const workers = try self.allocator.alloc(std.Thread, self.config.max_concurrent_requests);
        errdefer self.allocator.free(workers);
        self.stopping.store(false, .release);

        var spawned: usize = 0;
        errdefer {
            self.stopping.store(true, .release);
            for (workers[0..spawned]) |thread| thread.join();
        }
        while (spawned < workers.len) : (spawned += 1) {
            workers[spawned] = try std.Thread.spawn(.{ .stack_size = worker_stack_bytes }, workerMain, .{self});
        }
        self.workers = workers;
    }

    fn workerMain(self: *Server) void {
        const input = self.allocator.alloc(u8, self.config.max_header_size) catch return;
        defer self.allocator.free(input);
        while (!self.stopping.load(.acquire)) {
            self.serveOneWithBuffer(input) catch |err| {
                if (err == error.Canceled or err == error.SocketNotListening) return;
                std.log.err("server request failed: {s}", .{@errorName(err)});
            };
        }
    }

    pub fn stop(self: *Server) void {
        if (self.workers.len == 0) return;
        self.stopping.store(true, .release);
        const listener: std.Io.net.Stream = .{ .socket = self.listener.socket };
        listener.shutdown(self.io, .both) catch {};
        wakeWorkers(self);
        for (self.workers) |thread| thread.join();
        self.allocator.free(self.workers);
        self.workers = &.{};
    }

    fn wakeWorkers(self: *Server) void {
        const address = self.listener.socket.address;
        for (self.workers) |_| {
            const stream = address.connect(self.io, .{ .mode = .stream }) catch return;
            stream.close(self.io);
        }
    }

    pub fn tickLoop(self: *Server) void {
        while (!self.stopping.load(.acquire)) {
            self.tick();
            std.Io.sleep(self.io, .fromMilliseconds(self.config.tick_interval_ms), .awake) catch return;
        }
    }

    pub fn acceptLoop(self: *Server) void {
        self.start() catch |err| {
            std.log.err("could not start the signaling workers: {s}", .{@errorName(err)});
            return;
        };
        self.tickLoop();
    }
};

const worker_stack_bytes: usize = 1024 * 1024;
const watchdog_stack_bytes: usize = 1024 * 1024;

fn watchConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    done: *std.Io.Event,
    timed_out: *std.atomic.Value(bool),
    timeout_ms: i64,
) void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromMilliseconds(timeout_ms),
    });
    while (true) {
        done.waitTimeout(io, .{ .deadline = deadline }) catch |err| switch (err) {
            error.Canceled => return,
            error.Timeout => {
                if (std.Io.Clock.Timestamp.now(io, .awake).compare(.lt, deadline)) continue;
                timed_out.store(true, .release);
                stream.shutdown(io, .recv) catch {};
                return;
            },
        };
        return;
    }
}

fn writeRawError(writer: *std.Io.Writer, status_line: []const u8) void {
    writer.print("HTTP/1.1 {s}\r\ncontent-type: text/plain\r\ncontent-length: 0\r\nconnection: close\r\n\r\n", .{status_line}) catch {};
    writer.flush() catch {};
}

const PeerProtocol = enum { http, tls };

fn wallClockMs(io: std.Io) i96 {
    return @divTrunc(std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds, std.time.ns_per_ms);
}

fn classifyFirstChunk(preview: []const u8) PeerProtocol {
    if (preview.len >= 3 and preview[0] == 0x16 and preview[1] == 0x03) return .tls;
    return .http;
}

fn previewText(buffer: []u8, data: []const u8) []const u8 {
    const length = @min(data.len, buffer.len);
    for (data[0..length], buffer[0..length]) |byte, *out| {
        out.* = if (byte >= 0x20 and byte < 0x7f) byte else '.';
    }
    return buffer[0..length];
}

// Dropped before the HTTP parser sees it: a TLS ClientHello never sends a header
// terminator, so receiveHead would block the accept worker.
fn setupFailureStatus(err: anyerror) std.http.Status {
    return switch (err) {
        error.InvalidDescription, error.InvalidState => .bad_request,
        error.GatheringTimeout => .gateway_timeout,
        else => .internal_server_error,
    };
}

/// A fatal TLS `handshake_failure` alert (record 15 03 03, alert level 2, description 40).
/// This is what BDS sends to the probe. A silent close is indistinguishable from a
/// network failure for some clients, which then never try the plaintext fallback.
const tls_handshake_failure_alert = [7]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28 };

fn sniffFirstChunk(io: std.Io, reader: *std.Io.Reader, writer: *std.Io.Writer) !bool {
    reader.fillMore() catch |err| {
        std.log.warn("signaling peer sent nothing before closing: {s}", .{@errorName(err)});
        return false;
    };
    const received = reader.buffered();
    switch (classifyFirstChunk(received)) {
        .tls => {
            std.log.warn(
                "signaling peer opened a TLS handshake ({d} bytes) at ms={d} on this port instead of HTTP; answering with a fatal TLS alert and closing so it falls back to plaintext.",
                .{ received.len, wallClockMs(io) },
            );
            writer.writeAll(&tls_handshake_failure_alert) catch {};
            writer.flush() catch {};
            return false;
        },
        .http => {
            var preview_buffer: [128]u8 = undefined;
            log.debug(
                "signaling peer first chunk bytes={d} preview=\"{s}\"",
                .{ received.len, previewText(&preview_buffer, received) },
            );
            return true;
        },
    }
}

fn pathOnly(target: []const u8) []const u8 {
    return target[0..(std.mem.indexOfScalar(u8, target, '?') orelse target.len)];
}

fn contentTypeIs(actual: []const u8, expected: []const u8) bool {
    const semi = std.mem.indexOfScalar(u8, actual, ';') orelse actual.len;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, actual[0..semi], " \t"), expected);
}

fn writeStatusBody(
    writer: *std.Io.Writer,
    data: discovery.ServerData,
    players: usize,
    capacity: u32,
) std.Io.Writer.Error!void {
    try writer.writeAll("{\"name\":\"");
    try json.writeString(writer, data.server_name);
    try writer.print("\",\"protocol\":{d},\"version\":\"", .{data.protocol});
    try json.writeString(writer, data.game_version);
    try writer.writeAll("\",\"level\":\"");
    try json.writeString(writer, data.level_name);
    try writer.print("\",\"players\":{d},\"maxPlayers\":{d},\"gameType\":{d}}}", .{
        players,
        capacity,
        @intFromEnum(data.game_type),
    });
}

fn respondStaticStatus(request: *std.http.Server.Request, status: std.http.Status) !void {
    try request.respond(status_unavailable_body, .{
        .status = status,
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
    });
}

test "server config uses the Partner port" {
    const config = Config{};
    try std.testing.expectEqual(@as(u16, 19132), config.bind_address.getPort());
    try std.testing.expectEqual(@as(usize, 256), config.max_sessions);
    try std.testing.expectEqual(@as(usize, 1), config.tick_shards);
    try std.testing.expectEqual(@as(i64, 10), config.tick_interval_ms);
    try std.testing.expectEqual(@as(i32, 0), config.server_data.max_player_count);
    try std.testing.expectEqual(discovery.advertised_build.protocol, config.server_data.protocol);
    try std.testing.expectEqualStrings(discovery.advertised_build.game_version, config.server_data.game_version);
}

test "network ids decode exactly once and keep every byte" {
    const allocator = std.testing.allocator;
    const plain = try decodeNetworkId(allocator, "12345678", 1024);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("12345678", plain);

    const escaped = try decodeNetworkId(allocator, "a%20b%C3%B1%23", 1024);
    defer allocator.free(escaped);
    try std.testing.expectEqualStrings("a b\xc3\xb1#", escaped);

    // One pass, not two: `%2541` is the literal `%41`, never `A`.
    const once = try decodeNetworkId(allocator, "%2541", 1024);
    defer allocator.free(once);
    try std.testing.expectEqualStrings("%41", once);

    const plus = try decodeNetworkId(allocator, "a+b", 1024);
    defer allocator.free(plus);
    try std.testing.expectEqualStrings("a+b", plus);
}

test "an unusable network id is refused instead of repaired" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{ "", "A%2FB", "%00", "%ZZ", "%A", "%", "%FF", "a%2fb" };
    for (cases) |raw| {
        try std.testing.expectError(error.InvalidNetworkId, decodeNetworkId(allocator, raw, 1024));
    }
}

test "the network id limit bounds the decoded segment, not the path" {
    const allocator = std.testing.allocator;
    const long = "a" ** 300;
    const decoded = try decodeNetworkId(allocator, long, 1024);
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 300), decoded.len);

    const wider = "a" ** 1025;
    try std.testing.expectError(error.NetworkIdTooLong, decodeNetworkId(allocator, wider, 1024));

    const escaped_run = "%41" ** 400;
    const short = try decodeNetworkId(allocator, escaped_run, 512);
    defer allocator.free(short);
    try std.testing.expectEqual(@as(usize, 400), short.len);
}

test "a network id limit that cannot fit the header is refused" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20001) };
    try std.testing.expectError(error.InvalidNetworkIdLimit, Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .max_network_id_bytes = 0,
    }));
    try std.testing.expectError(error.InvalidNetworkIdLimit, Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .max_network_id_bytes = 16 * 1024,
    }));
}

test "a percent-encoded network id reaches the session decoded" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20002) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "a%20b%C3%B1%23", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));

    const active = latestSession(&server) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("a b\xc3\xb1#", active.network_id);
    server.releaseSession(active);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
}

test "a join whose network id cannot be decoded is refused before any session" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20003) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer server.deinit();

    var rejected_buffer: [512]u8 = undefined;
    const escaped_slash = try sendAndServe(
        io,
        &server,
        address,
        "POST /v1/join/A%2FB HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\ncontent-length: 3\r\nconnection: close\r\n\r\nv=0",
        &rejected_buffer,
    );
    try std.testing.expect(std.mem.startsWith(u8, escaped_slash, "HTTP/1.1 400"));

    var request: std.Io.Writer.Allocating = .init(allocator);
    defer request.deinit();
    try request.writer.print(
        "POST /v1/join/{s} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: 3\r\nconnection: close\r\n\r\nv=0",
        .{"a" ** 1025},
    );
    var too_long_buffer: [512]u8 = undefined;
    const too_long = try sendAndServe(io, &server, address, request.written(), &too_long_buffer);
    try std.testing.expect(std.mem.startsWith(u8, too_long, "HTTP/1.1 414"));
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
}

test "session capacity and shard layout follow the config" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19934) };
    var server = try Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .max_sessions = 10,
        .tick_shards = 3,
        .accept_unverified_identity = true,
    });
    defer server.deinit();

    try std.testing.expectEqual(@as(usize, 10), server.sessions.len);
    try std.testing.expectEqual(@as(usize, 3), server.shardCount());
    try std.testing.expectEqual(@as(usize, 4), server.perShard());
    try std.testing.expectEqual(@as(usize, 4), server.shardSessions(0).len);
    try std.testing.expectEqual(@as(usize, 2), server.shardSessions(2).len);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.playerCount());

    server.tick();
    server.tickShard(3);
}

fn scanSessions(server: *const Server) usize {
    var count: usize = 0;
    for (server.sessions) |slot| {
        if (slot != null) count += 1;
    }
    return count;
}

fn scanEstablished(server: *const Server) usize {
    var count: usize = 0;
    for (server.sessions) |slot| if (slot) |active| {
        if (active.established) count += 1;
    };
    return count;
}

test "the session counters follow the table without taking its locks" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19946) };
    var server = try Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .max_sessions = 4,
        .tick_shards = 2,
        .accept_unverified_identity = true,
    });
    defer server.deinit();

    var active: ActiveSession = undefined;
    active.handle = .{ .id = 7, .peer = &active.peer };
    active.opened = false;
    active.established = false;
    active.slot_index = 0;

    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expect(server.publishSession(&active));
    try std.testing.expectEqual(scanSessions(&server), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());

    server.noteEstablished(&active, true);
    try std.testing.expectEqual(scanEstablished(&server), server.playerCount());
    try std.testing.expectEqual(@as(usize, 1), server.playerCount());
    server.noteEstablished(&active, false);
    try std.testing.expectEqual(@as(usize, 0), server.playerCount());
    server.noteEstablished(&active, true);

    server.unpublishSession(&active);
    try std.testing.expectEqual(scanSessions(&server), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.playerCount());
}

test "an offer the backend refuses leaves nothing allocated" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19950) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer server.deinit();

    const invalid_offer = "v=0\r\na=ice-ufrag:abcd\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    var answer: []const u8 = &.{};
    if (server.buildSession("unparseable", invalid_offer, 262144, null, &answer)) |active| {
        active.deinit(null);
        return error.TestUnexpectedResult;
    } else |_| {}

    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
}

test "the HTTP backend receives the offer without its identity attribute" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19980) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);
    try std.testing.expect(sdp_identity.hasIdentity(offer));

    var request_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&request_buffer);
    try writer.print(
        "POST /v1/join/ident-0001 HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: {d}\r\nconnection: close\r\n\r\n",
        .{offer.len},
    );
    try writer.writeAll(offer);

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try sendAndServe(io, &server, address, writer.buffered(), &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());

    var active: ?*ActiveSession = null;
    for (server.sessions) |slot| if (slot) |session| {
        active = session;
        break;
    };
    const remote = (try active.?.native.connection.getRemoteDescription()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(remote.sdp.len != 0);
    try std.testing.expect(!sdp_identity.hasIdentity(remote.sdp));
    try std.testing.expect(std.mem.indexOf(u8, remote.sdp, "a=fingerprint:") != null);
}

test "an unusable session table is rejected" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19936) };
    try std.testing.expectError(
        error.InvalidArgument,
        Server.init(io, std.testing.allocator, .{ .bind_address = address, .max_sessions = 0 }),
    );
    try std.testing.expectError(
        error.InvalidArgument,
        Server.init(io, std.testing.allocator, .{ .bind_address = address, .tick_shards = 0 }),
    );
}

test "signaling peers are classified before HTTP parsing" {
    try std.testing.expectEqual(PeerProtocol.tls, classifyFirstChunk("\x16\x03\x01\x00\xf8\x01\x00\x00\xf4"));
    try std.testing.expectEqual(PeerProtocol.http, classifyFirstChunk("GET /v1/join HTTP/1.1\r\n"));
    try std.testing.expectEqual(PeerProtocol.http, classifyFirstChunk("POST /v1/join/abc HTTP/1.1\r\n"));
    try std.testing.expectEqual(PeerProtocol.http, classifyFirstChunk("\x16"));
    try std.testing.expectEqual(PeerProtocol.http, classifyFirstChunk(""));
}

test "signaling preview escapes non printable bytes and bounds output" {
    var buffer: [8]u8 = undefined;
    try std.testing.expectEqualStrings("GET", previewText(&buffer, "GET"));
    try std.testing.expectEqualStrings("GE..igno", previewText(&buffer, "GE\x00\xffignored"));
}

fn serveOnceForTest(server: *Server) void {
    server.serveOne() catch |err| log.debug("test signaling transaction ended: {s}", .{@errorName(err)});
}

fn sendAndServe(
    io: std.Io,
    server: *Server,
    address: std.Io.net.IpAddress,
    request: []const u8,
    response_buffer: []u8,
) ![]const u8 {
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var write_buffer: [512]u8 = undefined;
    var stream_writer = std.Io.net.Stream.writer(stream, io, &write_buffer);
    try stream_writer.interface.writeAll(request);
    try stream_writer.interface.flush();

    const worker = try std.Thread.spawn(.{}, serveOnceForTest, .{server});
    var stream_reader = std.Io.net.Stream.reader(stream, io, response_buffer);
    stream_reader.interface.fillMore() catch |err| {
        worker.join();
        return err;
    };
    const response = stream_reader.interface.buffered();
    worker.join();
    return response;
}

test "serveOne answers an HTTP peer" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19932) };
    var server = try Server.init(io, std.testing.allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer server.deinit();

    var response_buffer: [1024]u8 = undefined;
    const response = try sendAndServe(
        io,
        &server,
        address,
        "GET /v1/join HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n",
        &response_buffer,
    );
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, response, "protocol") != null);
}

const StatusJson = struct {
    name: []const u8,
    protocol: i32,
    version: []const u8,
    level: []const u8,
    players: usize,
    maxPlayers: u32,
    gameType: i32,
};

test "a hostile status config still yields parseable json" {
    const data: discovery.ServerData = .{
        .server_name = "A\"B\\C\nD\rE\tF\x01G",
        .level_name = "level \"quoted\"",
        .game_version = "1.2\t3",
        .protocol = 4422,
        .game_type = .adventure,
    };
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeStatusBody(&out.writer, data, 3, 10);

    const parsed = try std.json.parseFromSlice(StatusJson, std.testing.allocator, out.written(), .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(data.server_name, parsed.value.name);
    try std.testing.expectEqualStrings(data.game_version, parsed.value.version);
    try std.testing.expectEqualStrings(data.level_name, parsed.value.level);
    try std.testing.expectEqual(data.protocol, parsed.value.protocol);
    try std.testing.expectEqual(@as(usize, 3), parsed.value.players);
    try std.testing.expectEqual(@as(u32, 10), parsed.value.maxPlayers);
    try std.testing.expectEqual(@as(i32, 2), parsed.value.gameType);
}

test "the status body fits its buffer at the documented limits" {
    const data: discovery.ServerData = .{
        .server_name = "\\" ** max_server_name_bytes,
        .level_name = "\\" ** max_level_name_bytes,
        .game_version = "\\" ** max_game_version_bytes,
    };
    var body: [status_body_bytes]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&body);
    try writeStatusBody(&writer, data, 0, 0);
    try std.testing.expect(writer.buffered().len < status_body_bytes);
}

test "an overflowing status body can fall back to a parseable error" {
    var body: [8]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&body);
    try std.testing.expectError(
        error.WriteFailed,
        writeStatusBody(&writer, .{ .server_name = "name", .level_name = "level" }, 0, 0),
    );

    const parsed = try std.json.parseFromSlice(struct { @"error": []const u8 }, std.testing.allocator, status_unavailable_body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("status unavailable", parsed.value.@"error");
}

test "invalid server data is refused before listening" {
    const io = std.testing.io;
    const cases = [_]discovery.ServerData{
        .{ .server_name = "bad \xff", .level_name = "level" },
        .{ .server_name = "name", .level_name = "bad \x01" },
        .{ .server_name = "name", .level_name = "level", .game_version = "1.2\n3" },
        .{ .server_name = "n" ** (max_server_name_bytes + 1), .level_name = "level" },
        .{ .server_name = "name", .level_name = "l" ** (max_level_name_bytes + 1) },
        .{ .server_name = "name", .level_name = "level", .game_version = "v" ** (max_game_version_bytes + 1) },
    };
    for (cases) |data| {
        try std.testing.expectError(error.InvalidServerData, Server.init(io, std.testing.allocator, .{
            .bind_address = .{ .ip4 = std.Io.net.Ip4Address.loopback(19987) },
            .server_data = data,
        }));
    }
}

test "the status endpoint serves escaped json over http" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19986) };
    const data: discovery.ServerData = .{
        .server_name = "A\"B\\C",
        .level_name = "level \"quoted\"",
        .game_version = "1.2\"3",
    };
    var server = try Server.init(io, std.testing.allocator, .{ .bind_address = address, .server_data = data, .accept_unverified_identity = true });
    defer server.deinit();

    var response_buffer: [2048]u8 = undefined;
    const response = try sendAndServe(
        io,
        &server,
        address,
        "GET /v1/join HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n",
        &response_buffer,
    );
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expect(std.mem.indexOf(u8, response, "content-type: application/json") != null);
    const split = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.TestUnexpectedResult;
    const parsed = try std.json.parseFromSlice(StatusJson, std.testing.allocator, response[split + 4 ..], .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(data.server_name, parsed.value.name);
    try std.testing.expectEqualStrings(data.level_name, parsed.value.level);
    try std.testing.expectEqualStrings(data.game_version, parsed.value.version);
}

test "serveOne answers a TLS probe with a handshake failure alert" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19933) };
    var server = try Server.init(io, std.testing.allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer server.deinit();

    var response_buffer: [64]u8 = undefined;
    const response = try sendAndServe(
        io,
        &server,
        address,
        "\x16\x03\x01\x00\xf8\x01\x00\x00\xf4",
        &response_buffer,
    );
    try std.testing.expectEqualSlices(u8, &tls_handshake_failure_alert, response);
}

test "a keep-alive peer sends the offer on the same connection as the capability GET" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19934) };
    var server = try Server.init(io, std.testing.allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer server.deinit();

    const worker = try std.Thread.spawn(.{}, serveOnceForTest, .{&server});
    defer worker.join();

    var client: std.http.Client = .{ .allocator = std.testing.allocator, .io = io };
    defer client.deinit();

    var redirect_buffer: [1024]u8 = undefined;
    var transfer_buffer: [64]u8 = undefined;
    {
        var request = try client.request(.GET, try std.Uri.parse("http://127.0.0.1:19934/v1/join"), .{
            .redirect_behavior = .not_allowed,
        });
        defer request.deinit();
        try request.sendBodiless();
        var response = try request.receiveHead(&redirect_buffer);
        try std.testing.expectEqual(std.http.Status.ok, response.head.status);
        var body_buffer: [1024]u8 = undefined;
        var body_writer: std.Io.Writer = .fixed(&body_buffer);
        const reader = response.reader(&transfer_buffer);
        _ = reader.streamRemaining(&body_writer) catch |err| switch (err) {
            error.ReadFailed => return response.bodyErr().?,
            else => return err,
        };
        try std.testing.expect(std.mem.indexOf(u8, body_writer.buffered(), "\"protocol\"") != null);
    }

    const body = "v=0\r\n";
    {
        var request = try client.request(.POST, try std.Uri.parse("http://127.0.0.1:19934/v1/join/1"), .{
            .redirect_behavior = .not_allowed,
            .headers = .{ .content_type = .{ .override = "application/sdp" } },
        });
        defer request.deinit();
        request.transfer_encoding = .{ .content_length = body.len };
        var body_writer = try request.sendBodyUnflushed(&.{});
        try body_writer.writer.writeAll(body);
        try body_writer.end();
        try request.connection.?.flush();
        const response = try request.receiveHead(&redirect_buffer);
        try std.testing.expectEqual(std.http.Status.bad_request, response.head.status);
    }
}

fn signedOffer(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var provider = identity_mod.Provider.init(io, .{});
    const sdp = "v=0\r\n" ++
        "a=ice-ufrag:occupancy0\r\n" ++
        "a=fingerprint:sha-256 AA:BB:CC:DD\r\n" ++
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=max-message-size:65536\r\n";
    return provider.addToSdp(allocator, sdp);
}

fn countOne(_: *anyopaque) usize {
    return 1;
}

fn latestSession(server: *const Server) ?*ActiveSession {
    var found: ?*ActiveSession = null;
    for (server.sessions) |slot| if (slot) |active| {
        found = active;
    };
    return found;
}

fn keyDigest(public_key: std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    const der = identity_verify.spkiDer(public_key);
    std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});
    return digest;
}

fn jwksFor(allocator: std.mem.Allocator, public_key: std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey) ![]u8 {
    const point = public_key.toUncompressedSec1();
    var x_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    var y_buffer: [std.base64.url_safe_no_pad.Encoder.calcSize(48)]u8 = undefined;
    const x = std.base64.url_safe_no_pad.Encoder.encode(&x_buffer, point[1..49]);
    const y = std.base64.url_safe_no_pad.Encoder.encode(&y_buffer, point[49..97]);
    return std.fmt.allocPrint(
        allocator,
        "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-384\",\"kid\":\"test\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}",
        .{ x, y },
    );
}

fn joinResponse(
    io: std.Io,
    server: *Server,
    address: std.Io.net.IpAddress,
    offer: []const u8,
    network: []const u8,
    response_buffer: []u8,
) ![]const u8 {
    var request_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&request_buffer);
    try writer.print(
        "POST /v1/join/{s} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: {d}\r\nconnection: close\r\n\r\n",
        .{ network, offer.len },
    );
    try writer.writeAll(offer);
    return sendAndServe(io, server, address, writer.buffered(), response_buffer);
}

test "the answer announces the limit the server negotiated" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20004) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const body_start = lan_srv.real_offer.len - "a=max-message-size:262144\r\n".len;
    const cases = [_]struct { line: []const u8, expected: u32 }{
        .{ .line = "", .expected = 65536 },
        .{ .line = "a=max-message-size:1048576\r\n", .expected = 262144 },
        .{ .line = "a=max-message-size:32768\r\n", .expected = 32768 },
    };
    for (cases) |case| {
        var sdp_buffer: [2048]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&sdp_buffer);
        try writer.writeAll(lan_srv.real_offer[0..body_start]);
        try writer.writeAll(case.line);
        const offer = try provider.addToSdp(allocator, writer.buffered());
        defer allocator.free(offer);

        var response_buffer: [16 * 1024]u8 = undefined;
        const response = try joinResponse(io, &server, address, offer, "limit", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
        const split = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.TestUnexpectedResult;
        const answer = response[split + 4 ..];
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, answer, "a=max-message-size:"));
        try std.testing.expectEqual(case.expected, sdp_identity.maxMessageSize(answer).?);

        const active = latestSession(&server) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(case.expected, active.max_message_size);
        server.releaseSession(active);
    }
}

test "a configured public candidate is announced and the answer still verifies" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20005) };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .public_candidate = .{ .address = "203.0.113.10", .port = 19132 },
        .ice_servers = &.{.{ .url = "stun:stun.example.test:3478" }},
    });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "nat", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    const split = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.TestUnexpectedResult;
    const answer = response[split + 4 ..];

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, answer, "typ srflx"));
    const candidate_at = std.mem.indexOf(u8, answer, " 203.0.113.10 19132 typ srflx") orelse return error.TestUnexpectedResult;
    try std.testing.expect(candidate_at < std.mem.indexOf(u8, answer, "a=end-of-candidates").?);

    var envelope = try sdp_identity.extract(answer, allocator, .{});
    defer sdp_identity.deinit(allocator, &envelope);
    var verified = try identity_verify.verifyAssertion(allocator, envelope.assertion, answer);
    defer verified.deinit(allocator);

    const active = latestSession(&server) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), active.native.iceServerCount());
    server.releaseSession(active);
}

test "a public candidate or ice server that cannot be used is refused at init" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20006) };
    try std.testing.expectError(error.InvalidPublicCandidate, Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .public_candidate = .{ .address = "203.0.113.10\r\na=x", .port = 19132 },
    }));
    try std.testing.expectError(error.InvalidPublicCandidate, Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .public_candidate = .{ .address = "203.0.113.10", .port = 0 },
    }));
    try std.testing.expectError(error.InvalidIceServer, Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .ice_servers = &.{.{ .url = "http://not-an-ice-server" }},
    }));
}

fn rawExchange(io: std.Io, address: std.Io.net.IpAddress, request: []const u8, response_buffer: []u8) ![]const u8 {
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var write_buffer: [512]u8 = undefined;
    var writer = std.Io.net.Stream.writer(stream, io, &write_buffer);
    writer.interface.writeAll(request) catch {};
    writer.interface.flush() catch {};
    var reader = std.Io.net.Stream.reader(stream, io, response_buffer);
    reader.interface.fillMore() catch return "";
    return reader.interface.buffered();
}

fn joinRequest(writer: *std.Io.Writer, offer: []const u8, network: []const u8) !void {
    try writer.print(
        "POST /v1/join/{s} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: {d}\r\nconnection: close\r\n\r\n",
        .{ network, offer.len },
    );
    try writer.writeAll(offer);
}

test "an idle connection does not keep another client out" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20007) };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .max_concurrent_requests = 2,
        .request_timeout_ms = 300,
    });
    defer {
        server.deinit();
    }
    try server.start();

    const idle = try address.connect(io, .{ .mode = .stream });
    defer idle.close(io);

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var request_buffer: [8192]u8 = undefined;
    var request_writer: std.Io.Writer = .fixed(&request_buffer);
    try joinRequest(&request_writer, offer, "idle");
    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try rawExchange(io, address, request_writer.buffered(), &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));

    var idle_buffer: [128]u8 = undefined;
    var idle_reader = std.Io.net.Stream.reader(idle, io, &idle_buffer);
    var closed = false;
    idle_reader.interface.fillMore() catch |err| switch (err) {
        error.EndOfStream => closed = true,
        else => return err,
    };
    try std.testing.expect(closed or std.mem.startsWith(u8, idle_reader.interface.buffered(), "HTTP/1.1 408"));
}

test "headers past the configured limit are refused with a 400" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20008) };
    var server = try Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .max_header_size = 2048,
        .max_network_id_bytes = 64,
        .max_concurrent_requests = 1,
        .request_timeout_ms = 2_000,
    });
    defer server.deinit();
    try server.start();

    var request: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer request.deinit();
    try request.writer.writeAll("GET /v1/join HTTP/1.1\r\nhost: 127.0.0.1\r\nX-Pad: ");
    try request.writer.writeAll("a" ** 4096);
    try request.writer.writeAll("\r\n\r\n");

    var response_buffer: [512]u8 = undefined;
    const response = try rawExchange(io, address, request.written(), &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
}

test "a gathering timeout is answered as a gateway timeout" {
    try std.testing.expectEqual(std.http.Status.bad_request, setupFailureStatus(error.InvalidDescription));
    try std.testing.expectEqual(std.http.Status.bad_request, setupFailureStatus(error.InvalidState));
    try std.testing.expectEqual(std.http.Status.gateway_timeout, setupFailureStatus(error.GatheringTimeout));
    try std.testing.expectEqual(std.http.Status.internal_server_error, setupFailureStatus(error.OutOfMemory));
}

test "a second join in the same second is refused with 429" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20010) };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .max_concurrent_requests = 1,
        .rate_limit = .{ .joins_per_minute = 60, .burst = 1 },
    });
    defer {
        server.deinit();
    }
    try server.start();

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var request_buffer: [8192]u8 = undefined;
    var request_writer: std.Io.Writer = .fixed(&request_buffer);
    try joinRequest(&request_writer, offer, "limit");

    var first_buffer: [16 * 1024]u8 = undefined;
    const first = try rawExchange(io, address, request_writer.buffered(), &first_buffer);
    try std.testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200"));

    var second_buffer: [512]u8 = undefined;
    const second = try rawExchange(io, address, request_writer.buffered(), &second_buffer);
    try std.testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 429"));
    try std.testing.expect(std.mem.indexOf(u8, second, "retry-after: 1") != null);
}

test "an established session is judged by the disconnect grace, not the establishment timeout" {
    const config: Config = .{ .establish_timeout_ms = 15_000, .disconnect_timeout_ms = 3_000 };
    try std.testing.expectEqual(@as(i64, 3_000), peerGoneTimeout(config, true));
    try std.testing.expectEqual(@as(i64, 15_000), peerGoneTimeout(config, false));
}

test "a session that never connects is released when its deadline expires" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20021) };
    var counter = CloseCounter{};
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .establish_timeout_ms = 0,
        .handler = counter.handler(),
    });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);
    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "idle", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), counter.opened);

    server.tick();
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), counter.closed);
}

const CloseCounter = struct {
    opened: usize = 0,
    closed: usize = 0,

    fn handler(self: *CloseCounter) peer_mod.MessageHandler {
        return .{
            .ctx = self,
            .on_open = onOpen,
            .on_message = onMessage,
            .on_close = onClose,
        };
    }

    fn onOpen(ctx: *anyopaque, _: *peer_mod.PeerHandle) void {
        const self: *CloseCounter = @ptrCast(@alignCast(ctx));
        self.opened += 1;
    }

    fn onMessage(_: *anyopaque, _: *peer_mod.PeerHandle, _: peer_mod.ChannelKind, _: []const u8) ?[]const u8 {
        return null;
    }

    fn onClose(ctx: *anyopaque, _: *peer_mod.PeerHandle) void {
        const self: *CloseCounter = @ptrCast(@alignCast(ctx));
        self.closed += 1;
    }
};

const JoinWorker = struct {
    io: std.Io,
    address: std.Io.net.IpAddress,
    offer: []const u8,
    client: u8 = 0,
    buffer: [16 * 1024]u8 = undefined,
    status: u16 = 0,

    fn run(self: *JoinWorker) void {
        var request_buffer: [8192]u8 = undefined;
        var id_buffer: [24]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buffer, "parallel-{d}", .{self.client}) catch return;
        var writer: std.Io.Writer = .fixed(&request_buffer);
        joinRequest(&writer, self.offer, id) catch return;
        const response = rawExchange(self.io, self.address, writer.buffered(), &self.buffer) catch return;
        if (response.len < 12) return;
        self.status = std.fmt.parseInt(u16, response[9..12], 10) catch 0;
    }
};

test "more joins than workers all complete" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20011) };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .max_concurrent_requests = 4,
        .max_sessions = 16,
    });
    defer {
        server.deinit();
    }
    try server.start();

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var workers: [8]JoinWorker = undefined;
    var threads: [8]std.Thread = undefined;
    for (&workers, 0..) |*worker, index| worker.* = .{ .io = io, .address = address, .offer = offer, .client = @intCast(index) };
    for (&workers, 0..) |*worker, index| threads[index] = try std.Thread.spawn(.{}, JoinWorker.run, .{worker});
    for (threads) |thread| thread.join();
    for (workers) |worker| try std.testing.expectEqual(@as(u16, 200), worker.status);
    try std.testing.expectEqual(@as(usize, 8), server.sessionCount());
}

test "an occupancy provider refuses joins the shard table alone would accept" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19945) };
    var marker: u8 = 0;
    var server = try Server.init(io, std.testing.allocator, .{
        .bind_address = address,
        .server_data = .{ .server_name = "capped", .level_name = "capped", .max_player_count = 1 },
        .occupancy = .{ .ctx = &marker, .count = countOne },
        .accept_unverified_identity = true,
    });
    defer server.deinit();

    const offer = try signedOffer(std.testing.allocator, io);
    defer std.testing.allocator.free(offer);

    var request_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&request_buffer);
    try writer.print(
        "POST /v1/join/42 HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/sdp\r\n" ++
            "content-length: {d}\r\nconnection: close\r\n\r\n",
        .{offer.len},
    );
    try writer.writeAll(offer);

    var response_buffer: [1024]u8 = undefined;
    const response = try sendAndServe(io, &server, address, writer.buffered(), &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 503"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Server is full") != null);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
}

test "a join inspects the peer claim in either cpk form" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19981) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer {
        server.deinit();
    }

    for ([_]identity_mod.Provider.CpkEncoding{ .jwk, .base64_der }) |form| {
        var provider = identity_mod.Provider.init(io, .{ .cpk_encoding = form });
        const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
        defer allocator.free(offer);

        var response_buffer: [16 * 1024]u8 = undefined;
        const response = try joinResponse(io, &server, address, offer, @tagName(form), &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
        try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());

        const active = latestSession(&server) orelse return error.TestUnexpectedResult;
        const verified = active.identity orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(form, verified.form);
        try std.testing.expectEqualSlices(u8, &keyDigest(provider.key_pair.public_key), &verified.key_sha256);
        try std.testing.expect(!verified.anchored);
    }

    const last = latestSession(&server) orelse return error.TestUnexpectedResult;
    server.releaseSession(last);
    try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());
}

test "a tampered claim is refused instead of admitted anonymously" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19982) };
    var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const signed = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(signed);

    // The detached JWS covers the fingerprint, so a digest changed after the claim
    // was made must fail even though the envelope still parses into place.
    const altered = try allocator.dupe(u8, signed);
    defer allocator.free(altered);
    const start = std.mem.indexOf(u8, altered, "a=fingerprint:") orelse return error.TestUnexpectedResult;
    const end = std.mem.indexOfScalarPos(u8, altered, start, '\r') orelse return error.TestUnexpectedResult;
    altered[end - 1] = if (altered[end - 1] == '0') '1' else '0';

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, altered, "tampered", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Identity rejected") != null);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.unverifiedCount());
}

test "signaling refuses to start without a verifier unless the laboratory mode is on" {
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20018) };
    try std.testing.expectError(error.IdentityVerifierRequired, Server.init(io, std.testing.allocator, .{ .bind_address = address }));
    var server = try Server.init(io, std.testing.allocator, .{ .bind_address = address, .accept_unverified_identity = true });
    server.deinit();
}

test "the laboratory mode admits a self-signed claim and counts it as unverified" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20019) };
    var probe: PolicyProbe = .{ .allow = true };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .accept_unverified_identity = true,
        .identity_policy = probe.policy(),
    });
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "lab", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), probe.seen);
    try std.testing.expect(probe.seen_form == null);
    try std.testing.expectEqual(@as(usize, 1), server.unverifiedCount());
    try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());
    const active = latestSession(&server) orelse return error.TestUnexpectedResult;
    const identity = active.identity orelse return error.TestUnexpectedResult;
    try std.testing.expect(!identity.anchored);
    server.releaseSession(active);
}

test "an unreachable jwks answers 503 instead of admitting the claim" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(20020) };
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_uri = "http://127.0.0.1:1/keys" });
    defer verifier.deinit();
    var server = try verifiedServer(io, allocator, address, &verifier, null);
    defer server.deinit();

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "jwks-down", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 503"));
    try std.testing.expect(std.mem.indexOf(u8, response, "Identity provider unavailable") != null);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.unverifiedCount());
}

fn verifiedServer(io: std.Io, allocator: std.mem.Allocator, address: std.Io.net.IpAddress, verifier: *identity_verify.Verifier, admission: ?identity_verify.IdentityPolicy) !Server {
    return Server.init(io, allocator, .{
        .bind_address = address,
        .identity_verifier = verifier,
        .identity_policy = admission,
    });
}

test "a configured verifier admits a claim that chains to the jwks" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19983) };

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);
    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    var server = try verifiedServer(io, allocator, address, &verifier, null);
    defer {
        server.deinit();
    }

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, offer, "verified", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), server.verifiedCount());
    const active = latestSession(&server) orelse return error.TestUnexpectedResult;
    const identity = active.identity orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(provider.cpk_encoding, identity.form);
    try std.testing.expectEqualSlices(u8, &keyDigest(provider.key_pair.public_key), &identity.key_sha256);
    try std.testing.expect(identity.anchored);
}

test "a configured verifier refuses a claim that does not verify" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19984) };

    var provider = identity_mod.Provider.init(io, .{});
    const signed = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(signed);
    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    var server = try verifiedServer(io, allocator, address, &verifier, null);
    defer {
        server.deinit();
    }

    const altered = try allocator.dupe(u8, signed);
    defer allocator.free(altered);
    const start = std.mem.indexOf(u8, altered, "a=fingerprint:") orelse return error.TestUnexpectedResult;
    const end = std.mem.indexOfScalarPos(u8, altered, start, '\r') orelse return error.TestUnexpectedResult;
    altered[end - 1] = if (altered[end - 1] == '0') '1' else '0';

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, altered, "rejected", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());
}

const PolicyProbe = struct {
    allow: bool,
    seen: usize = 0,
    seen_form: ?identity_verify.Form = null,

    fn allowFn(ctx: *anyopaque, network_id: []const u8, claims: ?*const identity_verify.Claims) bool {
        _ = network_id;
        const self: *PolicyProbe = @ptrCast(@alignCast(ctx));
        self.seen += 1;
        if (claims) |value| self.seen_form = value.form;
        return self.allow;
    }

    fn policy(self: *PolicyProbe) identity_verify.IdentityPolicy {
        return .{ .ctx = self, .allow = allowFn };
    }
};

test "an offer without identity follows require_identity and the policy" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var response_buffer: [16 * 1024]u8 = undefined;

    {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19993) };
        var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true });
        defer server.deinit();
        const response = try joinResponse(io, &server, address, lan_srv.real_offer, "closed", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, response, "Identity assertion required") != null);
        try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    }

    {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19994) };
        var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true, .require_identity = false });
        defer {
            server.deinit();
        }
        const response = try joinResponse(io, &server, address, lan_srv.real_offer, "open", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
        const active = latestSession(&server) orelse return error.TestUnexpectedResult;
        try std.testing.expect(active.identity == null);
        server.releaseSession(active);
    }

    {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19995) };
        var deny: PolicyProbe = .{ .allow = false };
        var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true, .require_identity = false, .identity_policy = deny.policy() });
        defer server.deinit();
        const response = try joinResponse(io, &server, address, lan_srv.real_offer, "denied", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, response, "Identity rejected") != null);
        try std.testing.expectEqual(@as(usize, 1), deny.seen);
        try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    }

    {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19996) };
        var allow: PolicyProbe = .{ .allow = true };
        var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true, .require_identity = true, .identity_policy = allow.policy() });
        defer server.deinit();
        const response = try joinResponse(io, &server, address, lan_srv.real_offer, "policy-cannot-open", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
        try std.testing.expect(std.mem.indexOf(u8, response, "Identity assertion required") != null);
        try std.testing.expectEqual(@as(usize, 1), allow.seen);
        try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    }

    {
        const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19997) };
        var allow: PolicyProbe = .{ .allow = true };
        var server = try Server.init(io, allocator, .{ .bind_address = address, .accept_unverified_identity = true, .require_identity = false, .identity_policy = allow.policy() });
        defer {
            server.deinit();
        }
        const response = try joinResponse(io, &server, address, lan_srv.real_offer, "policy-opens", &response_buffer);
        try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
        try std.testing.expectEqual(@as(usize, 1), allow.seen);
        const active = latestSession(&server) orelse return error.TestUnexpectedResult;
        try std.testing.expect(active.identity == null);
        server.releaseSession(active);
    }
}

test "a verifier refuses an anonymous join while the config demands identity" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const provider = identity_mod.Provider.init(io, .{});
    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19998) };
    var allow: PolicyProbe = .{ .allow = true };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .identity_verifier = &verifier,
        .identity_policy = allow.policy(),
    });
    defer server.deinit();

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, lan_srv.real_offer, "verified-closed", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 400"));
    try std.testing.expectEqual(@as(usize, 1), allow.seen);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());
}

test "a verifier admits an anonymous join once the config opens it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const provider = identity_mod.Provider.init(io, .{});
    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19999) };
    var allow: PolicyProbe = .{ .allow = true };
    var server = try Server.init(io, allocator, .{
        .bind_address = address,
        .identity_verifier = &verifier,
        .identity_policy = allow.policy(),
        .require_identity = false,
    });
    defer {
        server.deinit();
    }

    var response_buffer: [16 * 1024]u8 = undefined;
    const response = try joinResponse(io, &server, address, lan_srv.real_offer, "verified-open", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), allow.seen);
    try std.testing.expectEqual(@as(usize, 0), server.verifiedCount());
    const active = latestSession(&server) orelse return error.TestUnexpectedResult;
    try std.testing.expect(active.identity == null);
    server.releaseSession(active);
}

test "the identity policy decides admission from the verified claims" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const address: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(19985) };

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, lan_srv.real_offer);
    defer allocator.free(offer);
    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    var probe: PolicyProbe = .{ .allow = false };
    var server = try verifiedServer(io, allocator, address, &verifier, probe.policy());
    defer {
        server.deinit();
    }

    var response_buffer: [16 * 1024]u8 = undefined;
    const refused = try joinResponse(io, &server, address, offer, "denied", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, refused, "HTTP/1.1 400"));
    try std.testing.expect(std.mem.indexOf(u8, refused, "Identity rejected") != null);
    try std.testing.expectEqual(@as(usize, 0), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 1), probe.seen);
    try std.testing.expectEqual(identity_verify.Form.jwk, probe.seen_form.?);

    probe.allow = true;
    const accepted = try joinResponse(io, &server, address, offer, "allowed", &response_buffer);
    try std.testing.expect(std.mem.startsWith(u8, accepted, "HTTP/1.1 200"));
    try std.testing.expectEqual(@as(usize, 1), server.sessionCount());
    try std.testing.expectEqual(@as(usize, 2), probe.seen);
}
