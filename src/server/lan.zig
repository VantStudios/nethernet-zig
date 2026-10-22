const std = @import("std");
const builtin = @import("builtin");
const udp = @import("../platform/udp.zig");
const discovery = @import("../discovery.zig");
const policy = @import("policy.zig");
const dispatch = @import("dispatch.zig");
const ratelimit = @import("ratelimit.zig");
const framing = @import("../transport/framing.zig");
const sdp_edit = @import("../transport/sdp_edit.zig");
const wire_log = @import("wire_log.zig");
const log = @import("../log.zig");
const peer_mod = @import("../webrtc/peer.zig");
const identity_mod = @import("../identity/server.zig");
const identity_verify = @import("../identity/verify.zig");
const sdp_identity = @import("../identity/sdp.zig");
const json = @import("../json.zig");

pub const Error = error{
    SendFailed,
    InvalidArgument,
    InvalidSdp,
    MissingFingerprint,
    MissingIceCredentials,
    InvalidIdentity,
    MissingIdentity,
    OfferRejected,
    PeerSetupFailed,
    IdentityAssertionFailed,
    IdentityRejected,
    InvalidPublicCandidate,
    InvalidIceServer,
} || std.mem.Allocator.Error || discovery.Error || std.Io.Writer.Error || peer_mod.PeerError || identity_verify.Error;

const candidate_buffer_size = 512;
const ping_data = "Ping";

const datagram_buffer_bytes: usize = 65535;
const signal_buffer_bytes: usize = 16 * 1024;

pub const Config = struct {
    bind_address: u32 = 0,
    port: u16 = 7551,
    network_id: u64 = 12345678,
    server_data: discovery.ServerData = .{
        .server_name = "NetherNet Zig test server",
        .level_name = "nethernet-zig-test",
        .game_type = .creative,
        .player_count = 0,
        .max_player_count = 1,
    },
    occupancy: ?policy.PlayerSource = null,
    max_datagrams_per_tick: usize = 256,
    max_pending_connections: usize = 256,
    negotiation_timeout_ms: i64 = 30_000,
    idle_timeout_ms: i64 = 120_000,
    echo_packets: bool = true,
    handler: ?peer_mod.MessageHandler = null,
    max_message_size: u32 = framing.default_message_size,
    max_packet_bytes: usize = framing.default_max_packet_bytes,
    bind_retry_ms: i64 = 2_000,
    max_bind_attempts: usize = 5,
    discovery_replies_per_second: u32 = 16,
    cpk_encoding: identity_mod.Provider.CpkEncoding = .jwk,
    identity: ?identity_mod.Provider = null,
    identity_verifier: ?*identity_verify.Verifier = null,
    identity_policy: ?identity_verify.IdentityPolicy = null,
    require_identity: bool = false,
    ice_servers: []const peer_mod.IceServer = &.{},
    public_candidate: ?sdp_edit.PublicCandidate = null,
};

fn peerConfig(max_message_size: u32, ice_servers: []const peer_mod.IceServer) peer_mod.PeerConfig {
    return .{
        .profile = .lan_trickle,
        .event_capacity = 128,
        .max_event_payload = 262144,
        .max_message_size = max_message_size,
        .ice_servers = ice_servers,
    };
}

const Connection = struct {
    allocator: std.mem.Allocator,
    native: *peer_mod.NativePeerConnection,
    peer: peer_mod.Peer,
    handle: peer_mod.PeerHandle,
    sender_id: u64,
    address: udp.Address,
    connection_id: []u8,
    max_message_size: u32,
    assembly: framing.Channels,
    answer: ?[]u8 = null,
    opened: bool = false,
    ufrag: [128]u8 = undefined,
    ufrag_len: usize = 0,
    candidate_index: usize = 0,
    failure: ?discovery.ErrorCode = null,
    terminate: bool = false,
    established: bool = false,
    deadline_ms: i64,
    last_activity_ms: i64,

    fn deinit(self: *Connection, handler: ?peer_mod.MessageHandler) void {
        if (self.opened) dispatch.closeFor(handler, &self.handle);
        self.peer.deinit(self.allocator);
        self.native.deinit();
        self.assembly.deinit();
        if (self.answer) |answer| self.allocator.free(answer);
        self.allocator.free(self.connection_id);
        self.allocator.destroy(self);
    }

    fn ufragSlice(self: *const Connection) []const u8 {
        return self.ufrag[0..self.ufrag_len];
    }
};

const LanDispatcher = struct {
    server: *Server,
    connection: *Connection,
    kind: peer_mod.ChannelKind,

    fn onMessage(ctx: *anyopaque, message: []const u8) framing.FramingError!void {
        const self: *LanDispatcher = @ptrCast(@alignCast(ctx));
        const reply = dispatch.replyFor(
            self.server.config.handler,
            &self.connection.handle,
            self.kind,
            message,
            self.server.config.echo_packets,
        ) orelse return;
        var label_buffer: [80]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buffer, "LAN session id={d} sender={d}", .{ self.connection.handle.id, self.connection.sender_id }) catch "LAN session";
        return dispatch.sendPacket(
            self.server.segmentScratch(),
            self.connection.max_message_size,
            &self.connection.handle,
            self.kind,
            label,
            reply,
        );
    }
};

pub const Server = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    config: Config,
    socket: ?udp.Socket = null,
    bound: bool = false,
    next_bind_attempt_ms: i64 = 0,
    bind_failures: usize = 0,
    identity: identity_mod.Provider,
    connections: []?*Connection,
    connection_total: std.atomic.Value(usize) = .init(0),
    established_total: std.atomic.Value(usize) = .init(0),
    next_connection_id: u64 = 0,
    segment_scratch: []u8,
    recv_buffer: []u8,
    decode_buffer: []u8,
    signal_buffer: []u8,
    frame_buffer: []u8,
    discovery_replies: ratelimit.Limiter,
    closed: bool = false,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: Config) Error!Server {
        if (config.max_pending_connections == 0) return error.InvalidArgument;
        try peer_mod.validateIceServers(config.ice_servers);
        if (config.public_candidate) |candidate| sdp_edit.validateCandidate(candidate) catch return error.InvalidPublicCandidate;

        const segment_scratch = try allocator.alloc(u8, config.max_message_size);
        errdefer allocator.free(segment_scratch);
        const connections = try allocator.alloc(?*Connection, config.max_pending_connections);
        errdefer allocator.free(connections);
        @memset(connections, null);
        const recv_buffer = try allocator.alloc(u8, datagram_buffer_bytes);
        errdefer allocator.free(recv_buffer);
        const decode_buffer = try allocator.alloc(u8, datagram_buffer_bytes);
        errdefer allocator.free(decode_buffer);
        const signal_buffer = try allocator.alloc(u8, signal_buffer_bytes);
        errdefer allocator.free(signal_buffer);
        const frame_buffer = try allocator.alloc(u8, 32 + ((signal_buffer_bytes + 32) / 16 + 1) * 16);
        errdefer allocator.free(frame_buffer);
        var server: Server = .{
            .io = io,
            .allocator = allocator,
            .config = config,
            .identity = config.identity orelse identity_mod.Provider.init(io, .{ .cpk_encoding = config.cpk_encoding }),
            .connections = connections,
            .segment_scratch = segment_scratch,
            .recv_buffer = recv_buffer,
            .decode_buffer = decode_buffer,
            .signal_buffer = signal_buffer,
            .frame_buffer = frame_buffer,
            .discovery_replies = ratelimit.Limiter.init(io, config.discovery_replies_per_second),
        };
        server.attemptBind();
        return server;
    }

    pub fn isBound(self: *const Server) bool {
        return self.bound;
    }

    pub fn isDisabled(self: *const Server) bool {
        return self.config.max_bind_attempts != 0 and
            self.bind_failures >= self.config.max_bind_attempts and
            !self.bound;
    }

    // The Minecraft client usually holds UDP 7551 without sharing it, so the bind is
    // retried and then dropped. A shared port delivers broadcasts to every socket but a
    // unicast to one, so every reply goes to the sender's own address.
    fn attemptBind(self: *Server) void {
        if (self.bound or self.closed or self.isDisabled()) return;
        const opened = udp.Socket.open(self.io, .{
            .address = self.config.bind_address,
            .port = self.config.port,
            .reuse_address = true,
            .broadcast = true,
        }) catch |err| {
            self.bind_failures += 1;
            if (self.bind_failures == 1) {
                std.log.warn("LAN discovery cannot bind UDP 0.0.0.0:{d}: {s}", .{ self.config.port, @errorName(err) });
                if (err == error.AddressInUse) {
                    std.log.warn(
                        "UDP {d} is held by another socket, usually the Minecraft client running on this machine, which does not share it: this process asked for a " ++
                            "shareable port (SO_REUSEADDR and SO_REUSEPORT where the OS has them) and the bind was refused anyway. The LAN list will not show " ++
                            "this server; joins by IP go through the HTTP path and are unaffected. Retrying every {d} ms, {d} attempts in all.",
                        .{ self.config.port, self.config.bind_retry_ms, self.config.max_bind_attempts },
                    );
                }
            } else if (self.isDisabled()) {
                std.log.warn(
                    "LAN discovery gave up on UDP {d} after {d} attempts: {s}. Signaling and the external server list responder keep running, the LAN list stays " ++
                        "empty, and LAN discovery starts trying again only in a new process.",
                    .{ self.config.port, self.bind_failures, @errorName(err) },
                );
            } else {
                log.debug("LAN discovery bind retry failed: {s}", .{@errorName(err)});
            }
            self.next_bind_attempt_ms = self.nowMs() + self.config.bind_retry_ms;
            return;
        };
        self.socket = opened;
        self.bound = true;
        if (self.bind_failures == 0) {
            std.log.info("LAN discovery listening on 0.0.0.0:{d} networkId={d}", .{ self.config.port, self.config.network_id });
        } else {
            std.log.info(
                "LAN discovery bound UDP {d} after {d} failed attempts",
                .{ self.config.port, self.bind_failures },
            );
            self.bind_failures = 0;
        }
    }

    pub fn deinit(self: *Server) void {
        if (!self.closed) {
            if (self.socket) |*socket| socket.close();
            self.socket = null;
            self.closed = true;
        }
        for (self.connections) |*slot| if (slot.*) |connection| {
            connection.deinit(self.config.handler);
            slot.* = null;
        };
        self.allocator.free(self.connections);
        self.allocator.free(self.segment_scratch);
        self.allocator.free(self.recv_buffer);
        self.allocator.free(self.decode_buffer);
        self.allocator.free(self.signal_buffer);
        self.allocator.free(self.frame_buffer);
        self.* = undefined;
    }

    pub fn connectionCount(self: *const Server) usize {
        return self.connection_total.load(.monotonic);
    }

    pub fn playerCount(self: *const Server) usize {
        return self.established_total.load(.monotonic);
    }

    pub fn tick(self: *Server) void {
        if (self.closed) return;
        if (!self.bound) {
            if (self.isDisabled()) return;
            if (self.nowMs() < self.next_bind_attempt_ms) return;
            self.attemptBind();
            if (!self.bound) return;
        }
        self.receiveDatagrams();
        self.advanceConnections();
    }

    fn receiveDatagrams(self: *Server) void {
        const socket = if (self.socket) |*bound| bound else return;
        var count: usize = 0;
        while (count < self.config.max_datagrams_per_tick) : (count += 1) {
            const datagram = socket.receive(self.recv_buffer) catch |err| {
                std.log.warn("LAN discovery receive failed: {s}", .{@errorName(err)});
                return;
            } orelse return;
            self.handleDatagram(self.recv_buffer[0..datagram.len], datagram.from) catch |e| {
                log.debug("LAN discovery datagram ignored: {s}", .{@errorName(e)});
            };
        }
    }

    fn handleDatagram(self: *Server, frame: []const u8, source: udp.Address) Error!void {
        const packet = try discovery.decodePacketInto(self.decode_buffer, frame);
        if (packet.recovered_bytes != 0) {
            log.debug(
                "LAN discovery recovered {d} bytes past an underdeclared signal length sender={d}",
                .{ packet.recovered_bytes, packet.sender_id },
            );
        }
        if (packet.sender_id == self.config.network_id) return;
        switch (packet.kind) {
            .request => {
                if (!self.discovery_replies.allow(source.addr)) {
                    log.debug("LAN discovery request dropped: source over its reply budget", .{});
                    return;
                }
                try self.sendResponse(source);
            },
            .message => {
                if (packet.recipient_id != self.config.network_id) return;
                if (packet.data.len == 0 or std.mem.eql(u8, packet.data, ping_data)) return;
                const signal = try discovery.SignalRef.parse(packet.data);
                switch (signal.kind) {
                    .connect_request => try self.handleConnectRequest(packet.sender_id, signal, source),
                    .candidate_add => self.handleCandidate(packet.sender_id, signal, source),
                    .connect_error => self.handlePeerError(packet.sender_id, signal, source),
                    .connect_response => {},
                }
            },
            .response => {},
        }
    }

    fn handleConnectRequest(self: *Server, sender_id: u64, signal: discovery.SignalRef, source: udp.Address) Error!void {
        if (self.findConnection(sender_id, signal.connection_id) != null) return;
        if (self.connectionCount() >= self.config.max_pending_connections) {
            std.log.warn("LAN signaling refused offer sender={d}: pending limit {d} reached", .{ sender_id, self.config.max_pending_connections });
            try self.sendErrorCode(sender_id, signal.connection_id, .generic_failure, source);
            return;
        }
        const player_limit = self.config.server_data.max_player_count;
        const occupied = if (self.config.occupancy) |provider| provider.count(provider.ctx) else self.playerCount();
        if (player_limit > 0 and occupied >= @as(usize, @intCast(player_limit))) {
            std.log.warn("LAN signaling refused offer sender={d}: player limit {d} reached", .{ sender_id, player_limit });
            try self.sendErrorCode(sender_id, signal.connection_id, .generic_failure, source);
            return;
        }
        var shape_buffer: [1024]u8 = undefined;
        const shape = describeOffer(&shape_buffer, signal.data);
        var source_buffer: [48]u8 = undefined;
        const from = sourceText(&source_buffer, source);
        var network_buffer: [24]u8 = undefined;
        const network_text = std.fmt.bufPrint(&network_buffer, "{d}", .{self.config.network_id}) catch "lan";
        const identity = validateOffer(self.allocator, network_text, signal.data, .{
            .verifier = self.config.identity_verifier,
            .policy = self.config.identity_policy,
            .require_identity = self.config.require_identity,
        }) catch |err| {
            const code: discovery.ErrorCode = switch (err) {
                error.MissingIdentity, error.InvalidIdentity, error.PayloadTooLarge, error.IdentityTooLarge, error.IdentityRejected, error.UnsupportedAlgorithm, error.UnknownKey, error.ExpiredToken, error.TokenNotYetValid, error.BadTokenSignature, error.BadFingerprintSignature, error.JwksUnavailable, error.MissingCpk, error.UnsupportedCpkForm, error.UnsupportedCurve, error.InvalidCpk, error.InvalidFingerprint => .identity_not_allowed,
                error.InvalidSdp, error.MissingFingerprint, error.MissingIceCredentials => .failed_to_set_remote_description,
                else => .invalid_argument,
            };
            std.log.warn("LAN signaling refused offer from {s} sender={d}: {s} ({s})", .{ from, sender_id, @errorName(err), shape });
            try self.sendErrorCode(sender_id, signal.connection_id, code, source);
            return;
        };

        const slot = self.findFreeSlot() orelse {
            try self.sendErrorCode(sender_id, signal.connection_id, .generic_failure, source);
            return;
        };
        var failure: discovery.ErrorCode = .generic_failure;
        const connection = self.createConnection(sender_id, signal, source, &failure) catch |err| {
            std.log.warn("LAN negotiation setup failed sender={d}: {s}", .{ sender_id, @errorName(err) });
            try self.sendErrorCode(sender_id, signal.connection_id, failure, source);
            return;
        };
        dispatch.openFor(self.config.handler, &connection.handle);
        connection.opened = true;
        slot.* = connection;
        _ = self.connection_total.fetchAdd(1, .monotonic);
        std.log.info(
            "LAN CONNECTREQUEST accepted session id={d} sender={d} from {s} connection={s} offerBytes={d} answerBytes={d} identity={s} ({s})",
            .{
                connection.handle.id,
                sender_id,
                from,
                signal.connection_id,
                signal.data.len,
                if (connection.answer) |answer| answer.len else 0,
                identityLabel(identity),
                shape,
            },
        );
    }

    fn createConnection(
        self: *Server,
        sender_id: u64,
        signal: discovery.SignalRef,
        source: udp.Address,
        failure: *discovery.ErrorCode,
    ) Error!*Connection {
        const now = self.nowMs();
        const clean_offer = try sdp_identity.withoutIdentity(self.allocator, signal.data);
        defer self.allocator.free(clean_offer);
        const max_message_size = framing.negotiatedMaxMessageSize(
            sdp_identity.maxMessageSize(clean_offer),
            self.config.max_message_size,
        );
        const connection_config = peerConfig(max_message_size, self.config.ice_servers);
        const native = peer_mod.NativePeerConnection.init(self.io, self.allocator, connection_config) catch |err| {
            std.log.warn("LAN peer connection init failed: {s}", .{@errorName(err)});
            failure.* = .failed_to_create_peer_connection;
            return error.PeerSetupFailed;
        };
        errdefer native.deinit();
        const connection_id = try self.allocator.dupe(u8, signal.connection_id);
        errdefer self.allocator.free(connection_id);
        var connection_peer = peer_mod.Peer.init(self.allocator, native.connectionSpi(), connection_config) catch |err| {
            std.log.warn("LAN peer wrapper init failed: {s}", .{@errorName(err)});
            failure.* = .failed_to_create_peer_connection;
            return error.PeerSetupFailed;
        };
        errdefer connection_peer.deinit(self.allocator);

        const answer = connection_peer.acceptOffer(.{ .kind = .offer, .sdp = clean_offer }) catch |err| {
            failure.* = switch (err) {
                error.InvalidDescription => .failed_to_set_remote_description,
                error.InvalidState => .incoming_connection_ignored,
                else => .failed_to_create_answer,
            };
            std.log.warn("LAN offer rejected sender={d}: {s}", .{ sender_id, @errorName(err) });
            return err;
        };
        const stripped = try sdp_identity.withoutCandidates(self.allocator, answer.sdp);
        defer self.allocator.free(stripped);
        const edited = sdp_edit.editAnswer(self.allocator, stripped, .{
            .max_message_size = max_message_size,
            .public_candidate = self.config.public_candidate,
        }) catch |err| {
            std.log.warn("LAN answer edit failed sender={d}: {s}", .{ sender_id, @errorName(err) });
            failure.* = .failed_to_create_answer;
            return error.InvalidSdp;
        };
        defer self.allocator.free(edited);
        const signed_answer = self.identity.addToSdp(self.allocator, edited) catch |err| {
            std.log.warn("LAN identity assertion failed: {s}", .{@errorName(err)});
            failure.* = .failed_to_create_identity_assertion;
            return error.IdentityAssertionFailed;
        };
        errdefer self.allocator.free(signed_answer);

        const connection = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(connection);
        self.next_connection_id += 1;
        connection.* = .{
            .allocator = self.allocator,
            .native = native,
            .peer = connection_peer,
            .handle = .{ .id = self.next_connection_id, .peer = undefined },
            .sender_id = sender_id,
            .address = source,
            .connection_id = connection_id,
            .max_message_size = max_message_size,
            .assembly = framing.Channels.init(self.allocator, max_message_size, self.config.max_packet_bytes),
            .answer = signed_answer,
            .deadline_ms = now + self.config.negotiation_timeout_ms,
            .last_activity_ms = now,
        };
        connection.handle.peer = &connection.peer;
        log.debug("LAN offer sender={d} negotiated maxMessageSize={d}", .{ sender_id, max_message_size });
        if (sdp_identity.iceUfrag(stripped)) |ufrag| {
            const length = @min(ufrag.len, connection.ufrag.len);
            @memcpy(connection.ufrag[0..length], ufrag[0..length]);
            connection.ufrag_len = length;
        } else {
            std.log.warn("LAN answer for sender={d} carries no ice-ufrag", .{sender_id});
        }
        return connection;
    }

    /// `sender_id` and `connection_id` are cleartext, so matching them is not
    /// authentication. The source address is what a spoofer must work for; without it
    /// a third party could redirect another player's ICE candidates.
    fn ownsSource(connection: *const Connection, source: udp.Address) bool {
        return connection.address.addr == source.addr;
    }

    fn handleCandidate(self: *Server, sender_id: u64, signal: discovery.SignalRef, source: udp.Address) void {
        const connection = self.findConnection(sender_id, signal.connection_id) orelse return;
        if (!ownsSource(connection, source)) {
            log.debug("LAN signaling dropped a candidate from another source sender={d}", .{sender_id});
            return;
        }
        if (connection.established) return;
        connection.peer.addRemoteCandidate(signal.data) catch |err| {
            log.debug("LAN signaling ignored candidate sender={d}: {s}", .{ sender_id, @errorName(err) });
            return;
        };
        connection.last_activity_ms = self.nowMs();
        log.debug("LAN candidate added sender={d} connection={s}", .{ sender_id, signal.connection_id });
    }

    fn handlePeerError(self: *Server, sender_id: u64, signal: discovery.SignalRef, source: udp.Address) void {
        const connection = self.findConnection(sender_id, signal.connection_id) orelse return;
        if (!ownsSource(connection, source)) {
            log.debug("LAN signaling dropped a CONNECTERROR from another source sender={d}", .{sender_id});
            return;
        }
        std.log.info("LAN peer reported error sender={d} code={s}", .{ sender_id, signal.data });
        self.failConnection(connection, .generic_failure);
    }

    fn advanceConnections(self: *Server) void {
        const now = self.nowMs();
        for (self.connections) |*slot| {
            const connection = slot.* orelse continue;
            self.advanceConnection(connection, now) catch |err| {
                std.log.err("LAN connection sender={d} failed: {s}", .{ connection.sender_id, @errorName(err) });
                self.failConnection(connection, .generic_failure);
            };
            if (connection.failure == null and !connection.terminate and connection.peer.stateOf() != .closed) continue;
            if (connection.failure) |code| {
                if (!connection.established) {
                    self.sendErrorCode(connection.sender_id, connection.connection_id, code, connection.address) catch |err| {
                        log.debug("LAN CONNECTERROR not delivered sender={d}: {s}", .{ connection.sender_id, @errorName(err) });
                    };
                }
            }
            std.log.info("LAN connection released session id={d} sender={d} connection={s}", .{ connection.handle.id, connection.sender_id, connection.connection_id });
            _ = self.connection_total.fetchSub(1, .monotonic);
            if (connection.established) _ = self.established_total.fetchSub(1, .monotonic);
            connection.deinit(self.config.handler);
            slot.* = null;
        }
    }

    fn advanceConnection(self: *Server, connection: *Connection, now: i64) Error!void {
        connection.peer.tick() catch |err| {
            if (connection.peer.stateOf() == .closed) {
                connection.terminate = true;
            } else {
                self.failConnection(connection, failureFor(err));
            }
            return;
        };
        while (connection.peer.pollEvent()) |event| switch (event) {
            .binary => |message| {
                var hex_buffer: wire_log.HexBuffer = undefined;
                log.debug("LAN session sender={d} received {d} bytes reliability={s} hex={s}", .{
                    connection.sender_id,
                    message.data.len,
                    @tagName(message.kind),
                    wire_log.hex(&hex_buffer, message.data),
                });
                connection.last_activity_ms = now;
                const channel: framing.Channel = switch (message.kind) {
                    .reliable => .reliable,
                    .unreliable => .unreliable,
                };
                var dispatcher = LanDispatcher{ .server = self, .connection = connection, .kind = message.kind };
                connection.assembly.feed(channel, message.data, .{
                    .ctx = &dispatcher,
                    .on_message = LanDispatcher.onMessage,
                }) catch |err| std.log.warn(
                    "LAN session sender={d} framing error: {s}",
                    .{ connection.sender_id, @errorName(err) },
                );
            },
            .state_changed => |state| log.debug("LAN session sender={d} state={s}", .{ connection.sender_id, @tagName(state) }),
            .channel_opened => |kind| log.debug("LAN session sender={d} channel opened={s}", .{ connection.sender_id, @tagName(kind) }),
            .channel_closed => |kind| log.debug("LAN session sender={d} channel closed={s}", .{ connection.sender_id, @tagName(kind) }),
            .channel_attached => {},
            .failed => |err| self.failConnection(connection, failureFor(err)),
        };
        if (connection.failure != null) return;

        if (!connection.established and connection.peer.stateOf() == .connected) {
            connection.established = true;
            _ = self.established_total.fetchAdd(1, .monotonic);
            connection.last_activity_ms = now;
            std.log.info("LAN session established session id={d} sender={d} connection={s}", .{ connection.handle.id, connection.sender_id, connection.connection_id });
        }

        if (connection.answer) |answer| {
            try self.sendSignal(connection.sender_id, .connect_response, connection.connection_id, answer, connection.address);
            self.allocator.free(answer);
            connection.answer = null;
            std.log.info("LAN CONNECTRESPONSE sent sender={d} bytes={d}", .{ connection.sender_id, answer.len });
        }

        var candidate_buffer: [candidate_buffer_size]u8 = undefined;
        while (true) {
            const candidate = connection.peer.pollLocalCandidate(&candidate_buffer) catch |err| {
                log.debug("LAN candidate drain stopped sender={d}: {s}", .{ connection.sender_id, @errorName(err) });
                break;
            } orelse break;
            try self.sendLocalCandidate(connection, candidate);
        }

        if (!connection.established and now >= connection.deadline_ms) {
            std.log.warn("LAN negotiation timed out sender={d}", .{connection.sender_id});
            self.failConnection(connection, .negotiation_timeout);
            return;
        }
        if (connection.established and now >= connection.last_activity_ms + self.config.idle_timeout_ms) {
            std.log.info("LAN session idle timeout sender={d}", .{connection.sender_id});
            connection.terminate = true;
        }
    }

    fn failConnection(self: *Server, connection: *Connection, code: discovery.ErrorCode) void {
        _ = self;
        if (connection.failure != null or connection.terminate) return;
        if (connection.established) {
            connection.terminate = true;
        } else {
            connection.failure = code;
        }
    }

    fn sendLocalCandidate(self: *Server, connection: *Connection, candidate: []const u8) Error!void {
        var buffer: [candidate_buffer_size]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&buffer);
        try writeCandidateAttributes(&writer, candidate, connection.ufragSlice(), connection.candidate_index);
        connection.candidate_index += 1;
        try self.sendSignal(connection.sender_id, .candidate_add, connection.connection_id, writer.buffered(), connection.address);
        log.debug("LAN CANDIDATEADD sent sender={d} index={d}", .{ connection.sender_id, connection.candidate_index - 1 });
    }

    fn sendSignal(
        self: *Server,
        sender_id: u64,
        kind: discovery.SignalType,
        connection_id: []const u8,
        data: []const u8,
        address: udp.Address,
    ) Error!void {
        var writer: std.Io.Writer = .fixed(self.signal_buffer);
        try (discovery.Signal{ .kind = kind, .connection_id = connection_id, .data = data }).write(&writer);
        const frame = try discovery.encodeMessageInPlace(
            self.frame_buffer,
            self.config.network_id,
            sender_id,
            writer.buffered(),
        );
        try self.sendFrame(frame, address);
    }

    fn sendErrorCode(
        self: *Server,
        sender_id: u64,
        connection_id: []const u8,
        code: discovery.ErrorCode,
        address: udp.Address,
    ) Error!void {
        var buffer: [16]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{@intFromEnum(code)}) catch return error.InvalidArgument;
        log.debug("LAN CONNECTERROR sender={d} code={d}", .{ sender_id, @intFromEnum(code) });
        try self.sendSignal(sender_id, .connect_error, connection_id, text, address);
    }

    fn sendResponse(self: *Server, destination: udp.Address) Error!void {
        var data: [2048]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&data);
        var server_data = self.config.server_data;
        server_data.player_count = @intCast(@min(self.playerCount(), std.math.maxInt(i32)));
        try server_data.write(&writer);
        const frame = try discovery.encodeResponseInPlace(self.frame_buffer, self.config.network_id, writer.buffered());
        try self.sendFrame(frame, destination);
        const address = std.mem.bigToNative(u32, destination.addr);
        log.debug(
            "LAN discovery response sent bytes={d} to {d}.{d}.{d}.{d}:{d}",
            .{
                frame.len,
                (address >> 24) & 0xff,
                (address >> 16) & 0xff,
                (address >> 8) & 0xff,
                address & 0xff,
                std.mem.bigToNative(u16, destination.port),
            },
        );
    }

    fn sendFrame(self: *Server, frame: []const u8, destination: udp.Address) Error!void {
        const socket = if (self.socket) |*bound| bound else return error.SendFailed;
        socket.send(destination, frame) catch return error.SendFailed;
    }

    fn findConnection(self: *Server, sender_id: u64, connection_id: []const u8) ?*Connection {
        for (self.connections) |slot| {
            const connection = slot orelse continue;
            if (connection.sender_id == sender_id and std.mem.eql(u8, connection.connection_id, connection_id)) return connection;
        }
        return null;
    }

    fn findFreeSlot(self: *Server) ?*?*Connection {
        for (self.connections) |*slot| if (slot.* == null) return slot;
        return null;
    }

    fn nowMs(self: *Server) i64 {
        return peer_mod.nowMs(self.io);
    }

    fn segmentScratch(self: *Server) framing.Scratch {
        return .{ .ctx = self, .ensure = ensureSegmentScratch };
    }

    fn ensureSegmentScratch(ctx: *anyopaque, needed: usize) framing.FramingError![]u8 {
        const self: *Server = @ptrCast(@alignCast(ctx));
        if (self.segment_scratch.len < needed) return error.PayloadTooLarge;
        return self.segment_scratch;
    }
};

fn failureFor(err: peer_mod.PeerError) discovery.ErrorCode {
    return switch (err) {
        error.BackendFailure => .ice,
        error.InvalidDescription => .failed_to_set_remote_description,
        error.InvalidState => .incoming_connection_ignored,
        error.Backpressure => .data_channel_closed,
        error.UnsupportedChannel => .data_channel_closed,
        error.OutOfMemory => .internal_error_json_serialization,
        error.PeerClosed => .no_signaling_channel,
        error.GatheringTimeout => .ice,
    };
}

fn writeCandidateAttributes(writer: *std.Io.Writer, candidate: []const u8, ufrag: []const u8, index: usize) !void {
    if (ufrag.len != 0) {
        return writer.print("{s} generation 0 ufrag {s} network-id {d} network-cost 0", .{ candidate, ufrag, index });
    }
    return writer.print("{s} generation 0 network-id {d} network-cost 0", .{ candidate, index });
}

pub const OfferCheck = struct {
    verifier: ?*identity_verify.Verifier = null,
    policy: ?identity_verify.IdentityPolicy = null,
    require_identity: bool = false,
};

fn validateOffer(allocator: std.mem.Allocator, network_id: []const u8, offer: []const u8, check: OfferCheck) Error!?identity_verify.SessionIdentity {
    if (!std.mem.startsWith(u8, offer, "v=")) return error.InvalidSdp;
    if (std.mem.indexOf(u8, offer, "m=") == null) return error.InvalidSdp;
    if (std.mem.indexOf(u8, offer, "a=fingerprint:") == null) return error.MissingFingerprint;
    if (std.mem.indexOf(u8, offer, "a=ice-ufrag:") == null) return error.MissingIceCredentials;

    if (check.verifier) |verifier| {
        var verified = verifier.verifyOffer(offer) catch |err| switch (err) {
            error.MissingIdentity => {
                if (check.policy) |admission| {
                    if (!admission.allow(admission.ctx, network_id, null)) return error.IdentityRejected;
                }
                if (check.require_identity) return error.MissingIdentity;
                return null;
            },
            else => return err,
        };
        defer verified.deinit(allocator);
        if (check.policy) |admission| {
            if (!admission.allow(admission.ctx, network_id, &verified.claims)) return error.IdentityRejected;
        }
        return verified.sessionIdentity();
    }

    var envelope = sdp_identity.extract(offer, allocator, .{}) catch |err| switch (err) {
        error.MissingIdentity => if (check.require_identity) return error.MissingIdentity else return null,
        else => return err,
    };
    defer sdp_identity.deinit(allocator, &envelope);
    const Assertion = struct { fingerprints: []const u8, token: []const u8 };
    const parsed = std.json.parseFromSlice(Assertion, allocator, envelope.assertion, .{ .ignore_unknown_fields = true }) catch return error.InvalidIdentity;
    defer parsed.deinit();
    if (std.mem.count(u8, parsed.value.token, ".") != 2 or
        std.mem.count(u8, parsed.value.fingerprints, ".") != 2) return error.InvalidIdentity;

    var identity = identity_verify.verifyAssertion(allocator, envelope.assertion, offer) catch |err| {
        std.log.warn("LAN peer identity did not verify: {s}", .{@errorName(err)});
        return error.InvalidIdentity;
    };
    defer identity.deinit(allocator);
    if (check.policy) |admission| {
        if (!admission.allow(admission.ctx, network_id, null)) return error.IdentityRejected;
    }
    return identity.sessionIdentity();
}

fn identityLabel(identity: ?identity_verify.SessionIdentity) []const u8 {
    const value = identity orelse return "none";
    return if (value.anchored) "verified" else "unanchored";
}

fn describeOffer(buffer: []u8, offer: []const u8) []const u8 {
    var names: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&names);
    var index: usize = 0;
    while (index < offer.len) {
        const newline = std.mem.indexOfScalarPos(u8, offer, index, '\n');
        const end = newline orelse offer.len;
        const line = std.mem.trim(u8, offer[index..end], " \r\t");
        index = end + 1;
        if (line.len == 0) continue;
        const stop = std.mem.indexOfAny(u8, line, ": ") orelse line.len;
        if (writer.buffered().len + stop + 1 > names.len) break;
        writer.print("{s} ", .{line[0..stop]}) catch break;
    }
    const names_list = std.mem.trimEnd(u8, writer.buffered(), " ");
    const identity = identityShape(offer);
    if (!identity.present) {
        return std.fmt.bufPrint(
            buffer,
            "bytes={d} attributes=[{s}] identity=absent",
            .{ offer.len, names_list },
        ) catch "offer";
    }
    return std.fmt.bufPrint(
        buffer,
        "bytes={d} attributes=[{s}] identity bytes={d} dots={d} base64-json={}",
        .{ offer.len, names_list, identity.bytes, identity.dots, identity.envelope_json },
    ) catch "offer";
}

const IdentityShape = struct {
    present: bool = false,
    bytes: usize = 0,
    dots: usize = 0,
    envelope_json: bool = false,
};

fn identityShape(offer: []const u8) IdentityShape {
    const prefix = "a=identity:";
    const start = std.mem.indexOf(u8, offer, prefix) orelse return .{};
    const end = std.mem.indexOfScalarPos(u8, offer, start, '\n') orelse offer.len;
    const value = std.mem.trim(u8, offer[start + prefix.len .. end], " \r");
    var shape: IdentityShape = .{
        .present = true,
        .bytes = value.len,
        .dots = std.mem.count(u8, value, "."),
    };
    if (value.len < 8) return shape;
    var head: [6]u8 = undefined;
    std.base64.standard.Decoder.decode(&head, value[0..8]) catch return shape;
    shape.envelope_json = head[0] == '{';
    return shape;
}

fn sourceText(buffer: []u8, source: udp.Address) []const u8 {
    const address = std.mem.bigToNative(u32, source.addr);
    return std.fmt.bufPrint(
        buffer,
        "{d}.{d}.{d}.{d}:{d}",
        .{
            (address >> 24) & 0xff,
            (address >> 16) & 0xff,
            (address >> 8) & 0xff,
            address & 0xff,
            std.mem.bigToNative(u16, source.port),
        },
    ) catch "unknown";
}

test "LAN config uses NetherNet discovery defaults" {
    try std.testing.expectEqual(@as(u16, 7551), (Config{}).port);
    try std.testing.expectEqual(@as(u64, 12345678), (Config{}).network_id);
    try std.testing.expectEqual(@as(usize, 256), (Config{}).max_pending_connections);
    try std.testing.expectEqual(framing.default_message_size, (Config{}).max_message_size);
}

test "LAN discovery advertises a ServerData layout the client can parse" {
    const config = Config{};
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try config.server_data.write(&writer);
    const encoded = writer.buffered();
    try std.testing.expectEqual(discovery.ServerData.version, encoded[0]);

    const decoded = try discovery.ServerData.decode(encoded);
    try std.testing.expectEqual(@as(i32, 4422), decoded.protocol);
    try std.testing.expectEqualStrings("1.26.60", decoded.game_version);
    try std.testing.expectEqualStrings(config.server_data.level_name, decoded.level_name);
    try std.testing.expectEqual(@as(i32, 8), decoded.connection_type);
}

test "LAN offer validation admits an unsigned offer but never a forged one" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidSdp, validateOffer(allocator, "lan", "not-sdp", .{}));
    const base = "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    try std.testing.expectError(error.MissingFingerprint, validateOffer(allocator, "lan", base, .{}));
    const with_fingerprint = base ++ "a=fingerprint:sha-256 AA:BB\r\n";
    try std.testing.expectError(error.MissingIceCredentials, validateOffer(allocator, "lan", with_fingerprint, .{}));
    const unsigned = with_fingerprint ++ "a=ice-ufrag:abcd\r\n";
    try std.testing.expectEqual(@as(?identity_verify.SessionIdentity, null), try validateOffer(allocator, "lan", unsigned, .{}));
    try std.testing.expectError(error.MissingIdentity, validateOffer(allocator, "lan", unsigned, .{ .require_identity = true }));
    const forged = unsigned ++ "a=identity:not-base64\r\n";
    try std.testing.expectError(error.InvalidIdentity, validateOffer(allocator, "lan", forged, .{}));
    try std.testing.expectError(error.InvalidIdentity, validateOffer(allocator, "lan", forged, .{ .require_identity = true }));
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

const PolicyProbe = struct {
    allow: bool,
    seen: usize = 0,
    seen_claims: bool = false,

    fn allowFn(ctx: *anyopaque, network_id: []const u8, claims: ?*const identity_verify.Claims) bool {
        _ = network_id;
        const self: *PolicyProbe = @ptrCast(@alignCast(ctx));
        self.seen += 1;
        self.seen_claims = claims != null;
        return self.allow;
    }

    fn policy(self: *PolicyProbe) identity_verify.IdentityPolicy {
        return .{ .ctx = self, .allow = allowFn };
    }
};

fn offerWithForeignDetached(allocator: std.mem.Allocator, sdp: []const u8, owner: *identity_mod.Provider) ![]u8 {
    var other = identity_mod.Provider.init(std.testing.io, .{});
    const other_signed = try other.addToSdp(allocator, sdp);
    defer allocator.free(other_signed);
    const owner_signed = try owner.addToSdp(allocator, sdp);
    defer allocator.free(owner_signed);

    var owner_envelope = try sdp_identity.extract(owner_signed, allocator, .{});
    defer sdp_identity.deinit(allocator, &owner_envelope);
    var other_envelope = try sdp_identity.extract(other_signed, allocator, .{});
    defer sdp_identity.deinit(allocator, &other_envelope);

    const Assertion = struct { fingerprints: []const u8, token: []const u8 };
    const owner_assertion = try std.json.parseFromSlice(Assertion, allocator, owner_envelope.assertion, .{ .ignore_unknown_fields = true });
    defer owner_assertion.deinit();
    const other_assertion = try std.json.parseFromSlice(Assertion, allocator, other_envelope.assertion, .{ .ignore_unknown_fields = true });
    defer other_assertion.deinit();

    const assertion = try std.fmt.allocPrint(allocator, "{{\"fingerprints\":\"{s}\",\"token\":\"{s}\"}}", .{ other_assertion.value.fingerprints, owner_assertion.value.token });
    defer allocator.free(assertion);
    var envelope: std.Io.Writer.Allocating = .init(allocator);
    defer envelope.deinit();
    try envelope.writer.writeAll("{\"assertion\":\"");
    try json.writeString(&envelope.writer, assertion);
    try envelope.writer.writeAll("\",\"idp\":{\"domain\":\"self\",\"protocol\":\"default\"}}");

    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(envelope.written().len));
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, envelope.written());
    const insert_at = try sdp_identity.sessionInsertOffset(sdp);
    return std.fmt.allocPrint(allocator, "{s}a=identity:{s}\r\n{s}", .{ sdp[0..insert_at], encoded, sdp[insert_at..] });
}

test "LAN verifies a present claim without a verifier" {
    const allocator = std.testing.allocator;
    var provider = identity_mod.Provider.init(std.testing.io, .{});
    const unsigned = "v=0\r\na=ice-ufrag:abcd\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const signed = try provider.addToSdp(allocator, unsigned);
    defer allocator.free(signed);

    const identity = (try validateOffer(allocator, "lan", signed, .{})) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(provider.cpk_encoding, identity.form);
    try std.testing.expect(!identity.anchored);

    var probe: PolicyProbe = .{ .allow = false };
    try std.testing.expectError(error.IdentityRejected, validateOffer(allocator, "lan", signed, .{ .policy = probe.policy() }));
    try std.testing.expectEqual(@as(usize, 1), probe.seen);
    try std.testing.expect(!probe.seen_claims);

    probe.allow = true;
    _ = try validateOffer(allocator, "lan", signed, .{ .policy = probe.policy() });
    try std.testing.expectEqual(@as(usize, 2), probe.seen);

    const changed = try allocator.dupe(u8, signed);
    defer allocator.free(changed);
    const start = std.mem.indexOf(u8, changed, "a=fingerprint:") orelse return error.TestUnexpectedResult;
    const end = std.mem.indexOfScalarPos(u8, changed, start, '\r') orelse return error.TestUnexpectedResult;
    changed[end - 1] = if (changed[end - 1] == 'B') 'C' else 'B';
    try std.testing.expectError(error.InvalidIdentity, validateOffer(allocator, "lan", changed, .{}));

    const foreign = try offerWithForeignDetached(allocator, unsigned, &provider);
    defer allocator.free(foreign);
    try std.testing.expectError(error.InvalidIdentity, validateOffer(allocator, "lan", foreign, .{}));
}

test "LAN checks a present claim against the verifier and the policy" {
    const allocator = std.testing.allocator;
    var provider = identity_mod.Provider.init(std.testing.io, .{});
    const unsigned = "v=0\r\na=ice-ufrag:abcd\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const signed = try provider.addToSdp(allocator, unsigned);
    defer allocator.free(signed);

    const jwks = try jwksFor(allocator, provider.key_pair.public_key);
    defer allocator.free(jwks);
    var verifier = try identity_verify.Verifier.init(std.testing.io, allocator, .{ .jwks_document = jwks });
    defer verifier.deinit();

    try std.testing.expectEqual(
        @as(?identity_verify.SessionIdentity, null),
        try validateOffer(allocator, "lan", unsigned, .{ .verifier = &verifier }),
    );

    var probe: PolicyProbe = .{ .allow = false };
    try std.testing.expectError(
        error.IdentityRejected,
        validateOffer(allocator, "lan", unsigned, .{ .verifier = &verifier, .policy = probe.policy() }),
    );
    try std.testing.expectEqual(@as(usize, 1), probe.seen);
    try std.testing.expect(!probe.seen_claims);

    const identity = (try validateOffer(allocator, "lan", signed, .{ .verifier = &verifier })) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(provider.cpk_encoding, identity.form);
    try std.testing.expect(identity.anchored);

    probe.allow = true;
    _ = try validateOffer(allocator, "lan", signed, .{ .verifier = &verifier, .policy = probe.policy() });
    try std.testing.expect(probe.seen_claims);

    const changed = try allocator.dupe(u8, signed);
    defer allocator.free(changed);
    const start = std.mem.indexOf(u8, changed, "a=fingerprint:") orelse return error.TestUnexpectedResult;
    const end = std.mem.indexOfScalarPos(u8, changed, start, '\r') orelse return error.TestUnexpectedResult;
    changed[end - 1] = if (changed[end - 1] == 'B') 'C' else 'B';
    try std.testing.expectError(error.BadFingerprintSignature, validateOffer(allocator, "lan", changed, .{ .verifier = &verifier }));
}

test "an offer description names the attributes and only the identity shape" {
    var buffer: [1024]u8 = undefined;
    const unsigned = "v=0\r\na=ice-ufrag:abcd\r\na=fingerprint:sha-256 AA:BB\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const expected_unsigned = try std.fmt.allocPrint(
        std.testing.allocator,
        "bytes={d} attributes=[v=0 a=ice-ufrag a=fingerprint m=application] identity=absent",
        .{unsigned.len},
    );
    defer std.testing.allocator.free(expected_unsigned);
    try std.testing.expectEqualStrings(expected_unsigned, describeOffer(&buffer, unsigned));

    const envelope = "eyJpZHAiOnsiZG9tYWluIjoieCIsInByb3RvY29sIjoiZGVmYXVsdCJ9LCJhc3NlcnRpb24iOiJ0b2tlbiJ9";
    const signed = unsigned ++ "a=identity:" ++ envelope ++ "\r\n";
    const expected_signed = try std.fmt.allocPrint(
        std.testing.allocator,
        "bytes={d} attributes=[v=0 a=ice-ufrag a=fingerprint m=application a=identity] identity bytes={d} dots=0 base64-json=true",
        .{ signed.len, envelope.len },
    );
    defer std.testing.allocator.free(expected_signed);
    try std.testing.expectEqualStrings(expected_signed, describeOffer(&buffer, signed));

    const long_signed = unsigned ++ "a=identity:" ++ envelope ++ envelope ++ "\r\n";
    const expected_long = try std.fmt.allocPrint(
        std.testing.allocator,
        "bytes={d} attributes=[v=0 a=ice-ufrag a=fingerprint m=application a=identity] identity bytes={d} dots=0 base64-json=true",
        .{ long_signed.len, envelope.len * 2 },
    );
    defer std.testing.allocator.free(expected_long);
    try std.testing.expectEqualStrings(expected_long, describeOffer(&buffer, long_signed));

    const bare_jws = "v=0\r\na=identity:ey.ey.sig\r\n";
    const expected_jws = try std.fmt.allocPrint(
        std.testing.allocator,
        "bytes={d} attributes=[v=0 a=identity] identity bytes=9 dots=2 base64-json=false",
        .{bare_jws.len},
    );
    defer std.testing.allocator.free(expected_jws);
    try std.testing.expectEqualStrings(expected_jws, describeOffer(&buffer, bare_jws));
}

test "LAN discovery keeps serving 19132 when the discovery port is taken" {
    const io = std.testing.io;
    const port: u16 = 19935;
    var occupier = udp.Socket.open(io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = port,
        .reuse_address = false,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    var occupied = true;
    defer {
        if (occupied) occupier.close();
    }

    var server = try Server.init(io, std.testing.allocator, .{ .port = port });
    defer server.deinit();
    // Windows shares a port its `SO_REUSEADDR` asked for even when the holder did
    // not ask, so the discovery socket joins the occupier instead of being refused
    // and there is no retry loop to observe; elsewhere the bind fails until the
    // port is free.
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(server.isBound());
        server.tick();
        try std.testing.expect(server.isBound());
    } else {
        try std.testing.expect(!server.isBound());
        server.tick();
        try std.testing.expect(!server.isBound());
    }

    occupier.close();
    occupied = false;
    server.next_bind_attempt_ms = 0;
    server.tick();
    try std.testing.expect(server.isBound());
}

test "LAN discovery gives up after its attempt limit and does not come back" {
    const io = std.testing.io;
    const port: u16 = 19954;
    var occupier = udp.Socket.open(io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = port,
        .reuse_address = false,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    var occupied = true;
    defer {
        if (occupied) occupier.close();
    }

    var server = try Server.init(io, std.testing.allocator, .{ .port = port, .max_bind_attempts = 3 });
    defer server.deinit();
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(server.isBound());
        try std.testing.expect(!server.isDisabled());
        try std.testing.expectEqual(@as(usize, 0), server.bind_failures);
        server.next_bind_attempt_ms = 0;
        server.tick();
        try std.testing.expect(server.isBound());
        try std.testing.expect(!server.isDisabled());
    } else {
        try std.testing.expect(!server.isBound());
        try std.testing.expect(!server.isDisabled());
        server.next_bind_attempt_ms = 0;
        server.tick();
        try std.testing.expect(!server.isDisabled());
        server.next_bind_attempt_ms = 0;
        server.tick();
        try std.testing.expect(server.isDisabled());
        try std.testing.expectEqual(@as(usize, 3), server.bind_failures);
    }

    occupier.close();
    occupied = false;
    server.next_bind_attempt_ms = 0;
    server.tick();
    if (comptime builtin.os.tag == .windows) {
        try std.testing.expect(server.isBound());
        try std.testing.expect(!server.isDisabled());
    } else {
        try std.testing.expect(!server.isBound());
        try std.testing.expect(server.isDisabled());
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

test "an occupied slot refuses a LAN offer before any connection exists" {
    const io = std.testing.io;
    const port: u16 = 19945;
    var marker: u8 = 0;
    var server = try Server.init(io, std.testing.allocator, .{
        .port = port,
        .server_data = .{ .server_name = "capped", .level_name = "capped", .max_player_count = 1 },
        .occupancy = .{ .ctx = &marker, .count = countOne },
    });
    defer server.deinit();
    if (!server.isBound()) return error.SkipZigTest;

    const offer = try signedOffer(std.testing.allocator, io);
    defer std.testing.allocator.free(offer);
    _ = try validateOffer(std.testing.allocator, "lan", offer, .{});

    var client = udp.Socket.open(io, .{
        .address = std.mem.nativeToBig(u32, 0x7f000001),
        .port = 0,
    }) catch |err| switch (err) {
        error.AddressInUse => return error.SkipZigTest,
        else => return err,
    };
    defer client.close();
    const server_address: udp.Address = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f000001) };

    const client_id: u64 = 0x5151;
    var signal_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_request, .connection_id = "cap-0001", .data = offer }).write(&writer);
    const frame = try discovery.encodeMessage(std.testing.allocator, client_id, server.config.network_id, writer.buffered());
    defer std.testing.allocator.free(frame);
    try client.send(server_address, frame);

    var reply: ?[]u8 = null;
    var receive_buffer: [65535]u8 = undefined;
    const deadline = server.nowMs() + 2_000;
    while (reply == null and server.nowMs() < deadline) {
        server.tick();
        if (try client.receive(&receive_buffer)) |datagram| {
            reply = try std.testing.allocator.dupe(u8, receive_buffer[0..datagram.len]);
            break;
        }
        try io.sleep(.fromMilliseconds(2), .awake);
    }
    try std.testing.expect(reply != null);
    defer std.testing.allocator.free(reply.?);

    var packet = try discovery.decodePacket(std.testing.allocator, reply.?);
    defer packet.deinit(std.testing.allocator);
    try std.testing.expectEqual(discovery.PacketKind.message, packet.kind);
    try std.testing.expectEqual(client_id, packet.recipient_id);
    var error_signal = try discovery.Signal.parse(std.testing.allocator, packet.data);
    defer error_signal.deinit(std.testing.allocator);
    try std.testing.expectEqual(discovery.SignalType.connect_error, error_signal.kind);
    try std.testing.expectEqualStrings("cap-0001", error_signal.connection_id);
    try std.testing.expectEqualStrings("35", error_signal.data);
    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
}

pub const real_offer = "v=0\r\n" ++
    "o=- 1000 1779396395 IN IP4 0.0.0.0\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0\r\n" ++
    "a=fingerprint:sha-256 A4:14:A3:5D:02:35:5B:E0:C6:E0:EF:7D:D9:63:3F:30:D4:FD:43:76:50:A8:25:4A:96:25:F1:8A:0A:DC:F4:26\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "c=IN IP4 0.0.0.0\r\n" ++
    "a=setup:actpass\r\n" ++
    "a=mid:0\r\n" ++
    "a=sctp-port:5000\r\n" ++
    "a=ice-ufrag:elsfVzJM\r\n" ++
    "a=ice-pwd:/KLNLMQnQm5TWswZ9MAnalyn\r\n" ++
    "a=max-message-size:262144\r\n";

test "a real LAN session is admitted and hands its memory back on teardown" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const port: u16 = 19951;
    var server = try Server.init(io, allocator, .{ .port = port });
    if (!server.isBound()) {
        server.deinit();
        return error.SkipZigTest;
    }

    const client_id: u64 = 0x5152;
    var signal_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_request, .connection_id = "real-0001", .data = real_offer }).write(&writer);
    const frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, writer.buffered());
    defer allocator.free(frame);

    const source: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41000), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try server.handleDatagram(frame, source);
    try std.testing.expectEqual(@as(usize, 1), server.connectionCount());
    try std.testing.expectEqualStrings("real-0001", server.connections[0].?.connection_id);

    server.tick();
    try std.testing.expectEqual(@as(?[]u8, null), server.connections[0].?.answer);

    server.deinit();
}

test "the LAN backend receives the offer without its identity attribute" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const port: u16 = 19981;
    var server = try Server.init(io, allocator, .{ .port = port });
    if (!server.isBound()) {
        server.deinit();
        return error.SkipZigTest;
    }
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, real_offer);
    defer allocator.free(offer);
    try std.testing.expect(sdp_identity.hasIdentity(offer));
    _ = try validateOffer(allocator, "lan", offer, .{});

    const client_id: u64 = 0x5153;
    var signal_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_request, .connection_id = "ident-0001", .data = offer }).write(&writer);
    const frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, writer.buffered());
    defer allocator.free(frame);

    const source: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41002), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try server.handleDatagram(frame, source);
    try std.testing.expectEqual(@as(usize, 1), server.connectionCount());

    const connection = server.connections[0].?;
    const remote = (try connection.native.connection.getRemoteDescription()) orelse return error.TestUnexpectedResult;
    try std.testing.expect(remote.sdp.len != 0);
    try std.testing.expect(!sdp_identity.hasIdentity(remote.sdp));
    try std.testing.expect(std.mem.indexOf(u8, remote.sdp, "a=fingerprint:") != null);
}

test "a LAN answer announces the configured public candidate" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const port: u16 = 20012;
    var server = try Server.init(io, allocator, .{
        .port = port,
        .public_candidate = .{ .address = "203.0.113.10", .port = 19132 },
    });
    if (!server.isBound()) {
        server.deinit();
        return error.SkipZigTest;
    }
    defer {
        server.deinit();
    }

    var provider = identity_mod.Provider.init(io, .{});
    const offer = try provider.addToSdp(allocator, real_offer);
    defer allocator.free(offer);

    const client_id: u64 = 0x5154;
    var signal_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_request, .connection_id = "nat-0001", .data = offer }).write(&writer);
    const frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, writer.buffered());
    defer allocator.free(frame);

    const source: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41003), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try server.handleDatagram(frame, source);
    try std.testing.expectEqual(@as(usize, 1), server.connectionCount());

    const answer = server.connections[0].?.answer orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, answer, "typ srflx"));
    try std.testing.expect(std.mem.indexOf(u8, answer, " 203.0.113.10 19132 typ srflx") != null);
    try std.testing.expect(std.mem.indexOf(u8, answer, "typ host") == null);
    try std.testing.expect(std.mem.indexOf(u8, answer, "a=max-message-size:262144") != null);
}

pub const CountingAllocator = struct {
    child: std.mem.Allocator,
    live: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        const live = self.live.fetchAdd(len, .monotonic) + len;
        _ = self.peak.fetchMax(live, .monotonic);
        return result;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.count(memory.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.count(memory.len, new_len);
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ret_addr);
        _ = self.live.fetchSub(memory.len, .monotonic);
    }

    fn count(self: *CountingAllocator, before: usize, after: usize) void {
        const live = if (after >= before)
            self.live.fetchAdd(after - before, .monotonic) + (after - before)
        else
            self.live.fetchSub(before - after, .monotonic) - (before - after);
        _ = self.peak.fetchMax(live, .monotonic);
    }

    pub fn liveBytes(self: *const CountingAllocator) usize {
        return self.live.load(.monotonic);
    }
};

test "an idle LAN session costs a bounded slice of memory" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const port: u16 = 19952;
    var counter = CountingAllocator{ .child = allocator };
    var server = try Server.init(io, counter.allocator(), .{
        .port = port,
        .max_pending_connections = 256,
        .discovery_replies_per_second = 0,
    });
    if (!server.isBound()) {
        server.deinit();
        return error.SkipZigTest;
    }
    const baseline = counter.liveBytes();
    const source: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41001), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    const sessions: usize = 64;
    var id_buffer: [16]u8 = undefined;
    var signal_buffer: [8192]u8 = undefined;
    for (0..sessions) |index| {
        const connection_id = try std.fmt.bufPrint(&id_buffer, "scale-{d:0>4}", .{index});
        var writer: std.Io.Writer = .fixed(&signal_buffer);
        try (discovery.Signal{ .kind = .connect_request, .connection_id = connection_id, .data = real_offer }).write(&writer);
        const frame = try discovery.encodeMessage(allocator, 0x6000 + index, server.config.network_id, writer.buffered());
        defer allocator.free(frame);
        try server.handleDatagram(frame, source);
    }
    try std.testing.expectEqual(sessions, server.connectionCount());

    server.tick();
    const per_session = (counter.liveBytes() - baseline) / sessions;
    std.debug.print("capacity: {d} bytes per idle LAN session ({d} sessions)\n", .{ per_session, sessions });
    try std.testing.expect(per_session < 100 * 1024);

    server.deinit();
}

test "LAN candidate attributes follow the Zig formatter" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writeCandidateAttributes(&writer, "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host", "abcd", 3);
    try std.testing.expectEqualStrings(
        "candidate:1 1 udp 2130706431 127.0.0.1 5000 typ host generation 0 ufrag abcd network-id 3 network-cost 0",
        writer.buffered(),
    );
}

test "another source cannot add a candidate or end someone else's LAN session" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const port: u16 = 19982;
    var server = try Server.init(io, allocator, .{ .port = port });
    if (!server.isBound()) {
        server.deinit();
        return error.SkipZigTest;
    }
    defer {
        server.deinit();
    }

    const client_id: u64 = 0x5153;
    const connection_id = "spoof-0001";
    const owner: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41000), .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    const stranger: udp.Address = .{ .port = std.mem.nativeToBig(u16, 41001), .addr = std.mem.nativeToBig(u32, 0x0a000009) };

    var signal_buffer: [8192]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_request, .connection_id = connection_id, .data = real_offer }).write(&writer);
    const offer_frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, writer.buffered());
    defer allocator.free(offer_frame);
    try server.handleDatagram(offer_frame, owner);
    try std.testing.expectEqual(@as(usize, 1), server.connectionCount());
    const connection = server.connections[0].?;

    const candidate = "candidate:1 1 udp 2122000000 10.0.0.9 41000 typ host";
    var candidate_writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .candidate_add, .connection_id = connection_id, .data = candidate }).write(&candidate_writer);
    const candidate_frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, candidate_writer.buffered());
    defer allocator.free(candidate_frame);

    try server.handleDatagram(candidate_frame, stranger);
    try std.testing.expectEqual(@as(usize, 0), connection.native.remote_candidates_added);

    try server.handleDatagram(candidate_frame, owner);
    try std.testing.expectEqual(@as(usize, 1), connection.native.remote_candidates_added);

    var error_writer: std.Io.Writer = .fixed(&signal_buffer);
    try (discovery.Signal{ .kind = .connect_error, .connection_id = connection_id, .data = "35" }).write(&error_writer);
    const error_frame = try discovery.encodeMessage(allocator, client_id, server.config.network_id, error_writer.buffered());
    defer allocator.free(error_frame);

    try server.handleDatagram(error_frame, stranger);
    try std.testing.expectEqual(@as(?discovery.ErrorCode, null), connection.failure);

    try server.handleDatagram(error_frame, owner);
    try std.testing.expect(connection.failure != null);
}
