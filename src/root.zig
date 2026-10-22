const std = @import("std");

const discovery = @import("discovery.zig");
pub const discovery_protocol = discovery;
pub const log = @import("log.zig");
const sdp_identity = @import("identity/sdp.zig");
const server_identity = @import("identity/server.zig");
const identity_verify = @import("identity/verify.zig");
const server_host = @import("server/host.zig");
const server_http = @import("server/http.zig");
const server_lan = @import("server/lan.zig");
const server_policy = @import("server/policy.zig");
const server_probe = @import("server/probe.zig");
pub const probe = server_probe;
const server_motd = @import("server/motd.zig");
const http_signaling = @import("signaling/http.zig");
pub const framing = @import("transport/framing.zig");
pub const FramingProfile = framing.FramingProfile;
const peer = @import("webrtc/peer.zig");
pub const sdp_edit = @import("transport/sdp_edit.zig");

pub const Error = error{
    InvalidState,
    InvalidArgument,
    ProtocolViolation,
    Backpressure,
    PeerClosed,
    WebRtcFailure,
    SegmentTooShort,
    InvalidCountdown,
    FragmentationNotAllowed,
    PayloadTooLarge,
    EmptyPayload,
} || std.mem.Allocator.Error;

pub const Reliability = enum { reliable, unreliable };
pub const NetworkId = []const u8;
pub const CloseReason = enum {
    application,
    peer_closed,
    timeout,
    protocol_error,
    backpressure,
    backend_error,
};

pub const signaling = struct {
    pub const Error = http_signaling.Error;
    pub const Method = http_signaling.Method;
    pub const Response = http_signaling.Response;
    pub const ServerInfo = http_signaling.ServerInfo;
    pub const Transport = http_signaling.Transport;
    pub const ClientTransport = http_signaling.ClientTransport;
    pub const Joiner = http_signaling.Joiner;
};

pub const server = struct {
    pub const Config = server_http.Config;
    pub const Server = server_http.Server;
    pub const LanConfig = server_lan.Config;
    pub const LanServer = server_lan.Server;
    pub const PingConfig = server_motd.Config;
    pub const PingResponder = server_motd.Server;
    pub const Host = server_host.Host;
    pub const HostConfig = server_host.Host.Config;
    pub const RateLimitConfig = server_http.RateLimitConfig;
    pub const PlayerSource = server_policy.PlayerSource;
    pub const PingAnswer = server_motd.Pong;
    pub const queryPing = server_motd.query;
};

pub const identity = struct {
    pub const Error = sdp_identity.Error;
    pub const IdentityProvider = sdp_identity.IdentityProvider;
    pub const IdentityEnvelope = sdp_identity.IdentityEnvelope;
    pub const Limits = sdp_identity.Limits;
    pub const extract = sdp_identity.extract;
    pub const validate = sdp_identity.validate;
    pub const deinit = sdp_identity.deinit;
    pub const ServerProvider = server_identity.Provider;
    pub const CpkEncoding = server_identity.Provider.CpkEncoding;
    pub const verify = identity_verify;
    pub const VerifyError = identity_verify.Error;
    pub const Verifier = identity_verify.Verifier;
    pub const JwksClient = identity_verify.JwksClient;
    pub const Claims = identity_verify.Claims;
    pub const Verified = identity_verify.Verified;
    pub const SessionIdentity = identity_verify.SessionIdentity;
    pub const TokenKey = identity_verify.TokenKey;
    pub const IdentityPolicy = identity_verify.IdentityPolicy;
    pub const PinStore = identity_verify.PinStore;
    pub const Pin = identity_verify.Pin;
    pub const UnknownKey = identity_verify.UnknownKey;
    pub const ToFu = identity_verify.ToFu;
    pub const Trust = identity_verify.Trust;
    pub const AnswerOptions = identity_verify.AnswerOptions;
    pub const VerifiedAnswer = identity_verify.VerifiedAnswer;
    pub const verifyAnswer = identity_verify.verifyAnswer;
    pub const AnswerError = identity_verify.AnswerError;
};

pub const AcceptAnswerError = Error || identity_verify.AnswerError;

pub const SessionConfig = struct {
    network_id: NetworkId,
    framing_profile: FramingProfile = .mojang_http,
    max_payload_size: usize = 262143,
    max_segment_size: usize = 262144,
    max_receive_queue_bytes: usize = 262144,
    max_receive_queue_messages: usize = 256,
    max_send_queue_bytes: usize = 4194304,
};

pub const Packet = struct {
    data: []const u8,
    reliability: Reliability,
    slot_id: u32,
};

pub const web_rtc = struct {
    pub const PeerError = peer.PeerError;
    pub const ChannelKind = peer.ChannelKind;
    pub const PeerState = peer.PeerState;
    pub const Profile = peer.Profile;
    pub const SessionDescription = peer.SessionDescription;
    pub const PeerEvent = peer.PeerEvent;
    pub const DataChannelEvent = peer.DataChannelEvent;
    pub const DataChannel = peer.DataChannel;
    pub const PeerConnection = peer.PeerConnection;
    pub const NativePeerConnection = peer.NativePeerConnection;
    pub const PeerConfig = peer.PeerConfig;
    pub const IceServer = peer.IceServer;
    pub const Peer = peer.Peer;
    pub const PeerHandle = peer.PeerHandle;
    pub const MessageHandler = peer.MessageHandler;
    pub const MockChannel = peer.MockChannel;
    pub const MockPeerConnection = peer.MockPeerConnection;
};

pub const Session = opaque {
    pub fn create(io: std.Io, allocator: std.mem.Allocator, config: SessionConfig) Error!*Session {
        return sessionCreate(io, allocator, config);
    }

    pub fn destroy(self: *Session) void {
        sessionDestroy(self);
    }

    pub fn send(self: *Session, reliability: Reliability, payload: []const u8) Error!void {
        return sessionSend(self, reliability, payload);
    }

    pub fn poll(self: *Session) Error!?Packet {
        return sessionPoll(self);
    }

    pub fn release(self: *Session, packet: Packet) void {
        sessionReleasePacket(self, packet);
    }

    pub fn attachPeer(self: *Session, connection: *peer.Peer) Error!void {
        return sessionAttachPeer(self, connection);
    }

    pub fn createOffer(self: *Session) Error!web_rtc.SessionDescription {
        return sessionCreateOffer(self);
    }

    pub fn acceptAnswer(self: *Session, answer_sdp: []const u8, options: identity_verify.AnswerOptions) AcceptAnswerError!void {
        return sessionAcceptAnswer(self, answer_sdp, options);
    }

    pub fn acceptAnswerRaw(self: *Session, answer_sdp: []const u8) Error!void {
        return sessionAcceptAnswerRaw(self, answer_sdp);
    }

    pub fn peerIdentity(self: *Session) ?identity_verify.SessionIdentity {
        return sessionPeerIdentity(self);
    }

    pub fn tick(self: *Session) Error!void {
        return sessionTick(self);
    }

    pub fn close(self: *Session, reason: CloseReason) void {
        sessionClose(self, reason);
    }
};

const Slot = struct {
    offset: usize = 0,
    len: usize = 0,
    reliability: Reliability = .reliable,
    queued: bool = false,
    borrowed: bool = false,
};

const EmitContext = struct {
    session: *SessionImpl,
    reliability: Reliability,

    fn emit(ctx_ptr: *anyopaque, header: u8, payload: []const u8) framing.FramingError!void {
        const ctx: *EmitContext = @ptrCast(@alignCast(ctx_ptr));
        return ctx.session.enqueueSegment(ctx.reliability, header, payload);
    }
};

const SessionImpl = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    network_id: []u8,
    config: SessionConfig,
    slots: []Slot,
    queue: []u32,
    reliable_assembly_buffer: []u8,
    unreliable_assembly_buffer: []u8,
    reliable_assembler: framing.Assembler,
    unreliable_assembler: framing.Assembler,
    peer: ?*peer.Peer = null,
    wire_buffer: []u8,
    receive_arena: []u8 = &.{},
    receive_used: usize = 0,
    borrowed_bytes: usize = 0,
    queue_head: usize = 0,
    queue_tail: usize = 0,
    queue_count: usize = 0,
    queued_bytes: usize = 0,
    closed: bool = false,
    close_reason: ?CloseReason = null,
    verified_answer: ?identity_verify.VerifiedAnswer = null,

    fn deinit(self: *SessionImpl) void {
        if (self.verified_answer) |*verified| verified.deinit(self.allocator);
        self.allocator.free(self.slots);
        self.allocator.free(self.reliable_assembly_buffer);
        self.allocator.free(self.unreliable_assembly_buffer);
        self.allocator.free(self.wire_buffer);
        self.allocator.free(self.queue);
        self.allocator.free(self.receive_arena);
        self.allocator.free(self.network_id);
        self.allocator.destroy(self);
    }

    fn findFreeSlot(self: *SessionImpl) ?usize {
        for (self.slots, 0..) |slot, index| {
            if (!slot.queued and !slot.borrowed) return index;
        }
        return null;
    }

    fn canEnqueue(self: *SessionImpl, payload_len: usize) bool {
        return !self.closed and
            self.queue_count < self.queue.len and
            self.findFreeSlot() != null and
            self.queued_bytes + self.borrowed_bytes + payload_len <= self.receive_arena.len and
            self.queued_bytes + payload_len <= self.config.max_send_queue_bytes;
    }

    fn enqueuePacket(self: *SessionImpl, reliability: Reliability, payload: []const u8) Error!void {
        if (!self.canEnqueue(payload.len)) return error.Backpressure;
        if (self.receive_used + payload.len > self.receive_arena.len) {
            self.compactReceived();
            if (self.receive_used + payload.len > self.receive_arena.len) return error.Backpressure;
        }
        const slot_index = self.findFreeSlot().?;
        const slot = &self.slots[slot_index];
        slot.offset = self.receive_used;
        @memcpy(self.receive_arena[self.receive_used .. self.receive_used + payload.len], payload);
        self.receive_used += payload.len;
        slot.len = payload.len;
        slot.reliability = reliability;
        slot.queued = true;
        self.queue[self.queue_tail] = @intCast(slot_index);
        self.queue_tail = (self.queue_tail + 1) % self.queue.len;
        self.queue_count += 1;
        self.queued_bytes += payload.len;
    }

    fn compactReceived(self: *SessionImpl) void {
        if (self.borrowed_bytes != 0) return;
        var write: usize = 0;
        var remaining = self.queue_count;
        var index = self.queue_head;
        while (remaining > 0) : (remaining -= 1) {
            const slot = &self.slots[self.queue[index]];
            if (slot.len != 0 and slot.offset != write) {
                std.mem.copyForwards(u8, self.receive_arena[write .. write + slot.len], self.receive_arena[slot.offset .. slot.offset + slot.len]);
                slot.offset = write;
            }
            write += slot.len;
            index = (index + 1) % self.queue.len;
        }
        self.receive_used = write;
    }

    fn enqueueSegment(self: *SessionImpl, reliability: Reliability, header: u8, payload: []const u8) framing.FramingError!void {
        if (self.peer != null) {
            if (payload.len + 1 > self.wire_buffer.len) return error.PayloadTooLarge;
            self.wire_buffer[0] = header;
            @memcpy(self.wire_buffer[1 .. payload.len + 1], payload);
            const kind: peer.ChannelKind = if (reliability == .reliable) .reliable else .unreliable;
            self.peer.?.send(kind, self.wire_buffer[0 .. payload.len + 1]) catch |err| return switch (err) {
                error.Backpressure => error.QueueFull,
                error.InvalidDescription => error.PayloadTooLarge,
                else => error.QueueFull,
            };
            return;
        }

        const assembler = if (reliability == .reliable) &self.reliable_assembler else &self.unreliable_assembler;
        const complete = assembler.pushParts(header, payload) catch |err| return err;
        if (complete) |message| self.enqueuePacket(reliability, message) catch |err| return switch (err) {
            error.Backpressure => error.QueueFull,
            else => error.PayloadTooLarge,
        };
    }

    fn acceptPeerSegment(self: *SessionImpl, kind: peer.ChannelKind, wire: []const u8) Error!void {
        const reliability: Reliability = if (kind == .reliable) .reliable else .unreliable;
        const assembler = if (reliability == .reliable) &self.reliable_assembler else &self.unreliable_assembler;
        const complete = assembler.push(wire) catch |err| return switch (err) {
            error.SegmentTooShort => error.SegmentTooShort,
            error.InvalidCountdown => error.InvalidCountdown,
            error.FragmentationNotAllowed => error.FragmentationNotAllowed,
            error.PayloadTooLarge => error.PayloadTooLarge,
            error.EmptyPayload => error.EmptyPayload,
            error.QueueFull => error.Backpressure,
            error.InvalidLength => error.ProtocolViolation,
            error.OutOfMemory => error.OutOfMemory,
        };
        if (complete) |message| try self.enqueuePacket(reliability, message);
    }
};

fn implFromPublic(session: *Session) *SessionImpl {
    return @ptrCast(@alignCast(session));
}

fn profileMessageLimit(profile: FramingProfile) usize {
    return switch (profile) {
        .mojang_http => 262143,
        .reverse_engineered_10000 => 10000,
        .negotiated => 262143,
    };
}

pub fn sessionCreate(io: std.Io, allocator: std.mem.Allocator, config: SessionConfig) Error!*Session {
    if (config.network_id.len == 0 or config.max_payload_size == 0 or
        config.max_segment_size < 2 or config.max_receive_queue_messages == 0 or
        config.max_receive_queue_bytes == 0 or config.max_send_queue_bytes == 0)
    {
        return error.InvalidArgument;
    }
    const profile_limit = profileMessageLimit(config.framing_profile);
    if (config.max_payload_size > profile_limit or
        config.max_segment_size > profile_limit + 1)
    {
        return error.InvalidArgument;
    }
    if (config.max_receive_queue_messages > std.math.maxInt(u32)) return error.InvalidArgument;

    const impl = try allocator.create(SessionImpl);
    errdefer allocator.destroy(impl);
    impl.* = .{
        .io = io,
        .allocator = allocator,
        .network_id = try allocator.dupe(u8, config.network_id),
        .config = config,
        .slots = &.{},
        .queue = &.{},
        .reliable_assembly_buffer = &.{},
        .unreliable_assembly_buffer = &.{},
        .reliable_assembler = undefined,
        .unreliable_assembler = undefined,
        .wire_buffer = &.{},
    };
    errdefer allocator.free(impl.network_id);

    impl.slots = try allocator.alloc(Slot, config.max_receive_queue_messages);
    errdefer allocator.free(impl.slots);
    impl.queue = try allocator.alloc(u32, config.max_receive_queue_messages);
    errdefer allocator.free(impl.queue);
    impl.reliable_assembly_buffer = try allocator.alloc(u8, config.max_payload_size);
    errdefer allocator.free(impl.reliable_assembly_buffer);
    impl.unreliable_assembly_buffer = try allocator.alloc(u8, config.max_payload_size);
    errdefer allocator.free(impl.unreliable_assembly_buffer);
    impl.wire_buffer = try allocator.alloc(u8, config.max_segment_size);
    errdefer allocator.free(impl.wire_buffer);
    impl.receive_arena = try allocator.alloc(u8, config.max_receive_queue_bytes);
    errdefer allocator.free(impl.receive_arena);
    impl.reliable_assembler = .init(impl.reliable_assembly_buffer, config.max_payload_size, true);
    impl.unreliable_assembler = .init(impl.unreliable_assembly_buffer, config.max_payload_size, false);

    for (impl.slots) |*slot| slot.* = .{};

    return @ptrCast(impl);
}

pub fn sessionAttachPeer(session: *Session, connection: *peer.Peer) Error!void {
    const impl = implFromPublic(session);
    if (impl.closed or impl.peer != null) return error.InvalidState;
    impl.peer = connection;
}

pub fn sessionCreateOffer(session: *Session) Error!web_rtc.SessionDescription {
    const impl = implFromPublic(session);
    if (impl.closed) return error.PeerClosed;
    const connection = impl.peer orelse return error.InvalidState;
    connection.startOffer() catch return error.WebRtcFailure;
}

pub fn sessionAcceptAnswer(session: *Session, answer_sdp: []const u8, options: identity_verify.AnswerOptions) AcceptAnswerError!void {
    const impl = implFromPublic(session);
    if (impl.closed) return error.PeerClosed;
    if (answer_sdp.len == 0) return error.InvalidArgument;
    const connection = impl.peer orelse return error.InvalidState;

    var verified = try identity_verify.verifyAnswer(impl.io, impl.allocator, answer_sdp, options);
    errdefer verified.deinit(impl.allocator);
    connection.acceptAnswer(.{ .kind = .answer, .sdp = verified.clean_sdp }) catch return error.WebRtcFailure;
    storeVerifiedAnswer(impl, verified);
}

pub fn sessionAcceptAnswerRaw(session: *Session, answer_sdp: []const u8) Error!void {
    const impl = implFromPublic(session);
    if (impl.closed) return error.PeerClosed;
    if (answer_sdp.len == 0) return error.InvalidArgument;
    const connection = impl.peer orelse return error.InvalidState;
    connection.acceptAnswer(.{ .kind = .answer, .sdp = answer_sdp }) catch return error.WebRtcFailure;
    if (impl.verified_answer) |*previous| previous.deinit(impl.allocator);
    impl.verified_answer = null;
}

pub fn sessionPeerIdentity(session: *Session) ?identity_verify.SessionIdentity {
    const impl = implFromPublic(session);
    return if (impl.verified_answer) |verified| verified.identity else null;
}

fn storeVerifiedAnswer(impl: *SessionImpl, verified: identity_verify.VerifiedAnswer) void {
    if (impl.verified_answer) |*previous| previous.deinit(impl.allocator);
    impl.verified_answer = verified;
}

pub fn sessionTick(session: *Session) Error!void {
    const impl = implFromPublic(session);
    const connection = impl.peer orelse return;
    connection.tick() catch |err| return switch (err) {
        error.Backpressure => error.Backpressure,
        error.PeerClosed => error.PeerClosed,
        else => error.WebRtcFailure,
    };
    while (connection.pollEvent()) |event| switch (event) {
        .binary => |message| try impl.acceptPeerSegment(message.kind, message.data),
        .channel_attached => return error.WebRtcFailure,
        .failed => return error.WebRtcFailure,
        .state_changed => |state| if (state == .failed) return error.WebRtcFailure,
        .channel_closed => {},
        .channel_opened => {},
    };
}

pub fn sessionPoll(session: *Session) Error!?Packet {
    const impl = implFromPublic(session);
    if (impl.closed and impl.queue_count == 0) return error.PeerClosed;
    if (impl.queue_count == 0) return null;

    const slot_id = impl.queue[impl.queue_head];
    impl.queue_head = (impl.queue_head + 1) % impl.queue.len;
    impl.queue_count -= 1;

    const slot = &impl.slots[slot_id];
    slot.queued = false;
    slot.borrowed = true;
    impl.queued_bytes -= slot.len;
    impl.borrowed_bytes += slot.len;
    return .{
        .data = impl.receive_arena[slot.offset..][0..slot.len],
        .reliability = slot.reliability,
        .slot_id = slot_id,
    };
}

pub fn sessionSend(session: *Session, reliability: Reliability, payload: []const u8) Error!void {
    const impl = implFromPublic(session);
    if (impl.closed) return error.PeerClosed;
    if (payload.len == 0) return error.EmptyPayload;
    if (payload.len > impl.config.max_payload_size) return error.InvalidArgument;
    if (impl.peer != null) {
        if (impl.peer.?.stateOf() != .connected) return error.InvalidState;
        if (payload.len > impl.config.max_send_queue_bytes) return error.Backpressure;
    } else if (!impl.canEnqueue(payload.len)) return error.Backpressure;

    var context = EmitContext{ .session = impl, .reliability = reliability };
    framing.segment(
        payload,
        impl.config.max_segment_size,
        reliability == .reliable,
        EmitContext.emit,
        &context,
    ) catch |err| return switch (err) {
        error.QueueFull => error.Backpressure,
        error.PayloadTooLarge => error.PayloadTooLarge,
        error.FragmentationNotAllowed => error.FragmentationNotAllowed,
        error.EmptyPayload => error.EmptyPayload,
        else => error.ProtocolViolation,
    };
}

pub fn sessionReleasePacket(session: *Session, packet: Packet) void {
    const impl = implFromPublic(session);
    if (packet.slot_id >= impl.slots.len) return;
    const slot = &impl.slots[packet.slot_id];
    if (!slot.borrowed) return;
    slot.borrowed = false;
    impl.borrowed_bytes -= slot.len;
    slot.len = 0;
    if (impl.queue_count == 0 and impl.borrowed_bytes == 0) impl.receive_used = 0;
}

pub fn sessionClose(session: *Session, reason: CloseReason) void {
    const impl = implFromPublic(session);
    if (impl.closed) return;
    impl.closed = true;
    impl.close_reason = reason;
}

pub fn sessionDestroy(session: *Session) void {
    const impl = implFromPublic(session);
    if (impl.peer) |connection| connection.close();
    impl.deinit();
}

test "session loopback applies framing before delivery" {
    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{
        .network_id = "framed",
        .max_payload_size = 16,
        .max_segment_size = 5,
        .max_receive_queue_messages = 8,
        .max_receive_queue_bytes = 32,
    });
    defer sessionDestroy(session);

    try sessionSend(session, .reliable, "abcdefghijk");
    const packet = (try sessionPoll(session)).?;
    defer sessionReleasePacket(session, packet);
    try std.testing.expectEqual(Reliability.reliable, packet.reliability);
    try std.testing.expectEqualStrings("abcdefghijk", packet.data);
    try std.testing.expectEqual(@as(?Packet, null), try sessionPoll(session));
}

test "attached peer carries framed reliable traffic in both directions" {
    var backend = peer.MockPeerConnection{};
    var reliable = peer.MockChannel{ .opened = true };
    var unreliable = peer.MockChannel{ .opened = true };
    var connection = try peer.Peer.init(std.testing.allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer connection.deinit(std.testing.allocator);
    _ = try connection.startOffer();
    try connection.acceptAnswer(.{ .kind = .answer, .sdp = "answer" });
    try connection.attachChannel(.reliable, reliable.channel());
    try connection.attachChannel(.unreliable, unreliable.channel());
    reliable.push(.opened);
    unreliable.push(.opened);
    backend.push(.{ .state_changed = .connecting });

    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{
        .network_id = "peer-bridge",
        .max_payload_size = 16,
        .max_segment_size = 5,
        .max_receive_queue_messages = 4,
    });
    defer sessionDestroy(session);
    try sessionAttachPeer(session, &connection);
    try sessionTick(session);
    try std.testing.expectEqual(peer.PeerState.connected, connection.stateOf());

    try sessionSend(session, .reliable, "abcdefghijk");
    try std.testing.expectEqual(@as(usize, 14), reliable.sent_count);

    reliable.push(.{ .binary = &[_]u8{ 0, 'o', 'k' } });
    try sessionTick(session);
    const packet = (try sessionPoll(session)).?;
    defer sessionReleasePacket(session, packet);
    try std.testing.expectEqualStrings("ok", packet.data);
}

test "session rejects unreliable fragmentation and empty payload" {
    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{
        .network_id = "limits",
        .max_payload_size = 16,
        .max_segment_size = 5,
    });
    defer sessionDestroy(session);

    try std.testing.expectError(error.FragmentationNotAllowed, sessionSend(session, .unreliable, "123456"));
    try std.testing.expectError(error.EmptyPayload, sessionSend(session, .reliable, ""));
}

test {
    _ = @import("discovery.zig");
    _ = @import("log.zig");
    _ = @import("platform/udp.zig");
    _ = @import("identity/sdp.zig");
    _ = @import("identity/server.zig");
    _ = @import("identity/verify.zig");
    _ = @import("server/host.zig");
    _ = @import("server/http.zig");
    _ = @import("server/lan.zig");
    _ = @import("server/motd.zig");
    _ = @import("server/policy.zig");
    _ = @import("server/probe.zig");
    _ = @import("signaling/http.zig");
    _ = @import("transport/framing.zig");
    _ = @import("webrtc/peer.zig");
}

test "the session methods compose the same way as the free functions" {
    const session = try Session.create(std.testing.io, std.testing.allocator, .{ .network_id = "methods" });
    defer session.destroy();

    try session.send(.unreliable, "method-call");
    const packet = (try session.poll()).?;
    defer session.release(packet);
    try std.testing.expectEqualStrings("method-call", packet.data);
    try std.testing.expectEqual(Reliability.unreliable, packet.reliability);
}

test "receive packets share one bounded arena and the holes are reclaimed" {
    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{
        .network_id = "arena",
        .max_payload_size = 16,
        .max_segment_size = 17,
        .max_receive_queue_messages = 8,
        .max_receive_queue_bytes = 24,
    });
    defer sessionDestroy(session);

    try sessionSend(session, .reliable, "aaaaaaaa");
    try sessionSend(session, .reliable, "bbbbbbbb");

    const first = (try sessionPoll(session)).?;
    sessionReleasePacket(session, first);
    try std.testing.expectEqualStrings("aaaaaaaa", first.data);

    try sessionSend(session, .reliable, "cccccccc");
    try sessionSend(session, .reliable, "dddddddd");

    for ([_][]const u8{ "bbbbbbbb", "cccccccc", "dddddddd" }) |want| {
        const packet = (try sessionPoll(session)).?;
        try std.testing.expectEqualStrings(want, packet.data);
        sessionReleasePacket(session, packet);
    }
    try std.testing.expectEqual(@as(?Packet, null), try sessionPoll(session));
}

test "session close is idempotent and stops sends" {
    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{ .network_id = "close" });
    defer sessionDestroy(session);
    sessionClose(session, .application);
    sessionClose(session, .timeout);
    try std.testing.expectError(error.PeerClosed, sessionSend(session, .reliable, "x"));
}

test "a verified answer reaches the backend without identity and is kept for the caller" {
    const answer_sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    var backend = peer.MockPeerConnection{};
    var connection = try peer.Peer.init(std.testing.allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer connection.deinit(std.testing.allocator);
    _ = try connection.startOffer();

    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{ .network_id = "verified-answer" });
    defer sessionDestroy(session);
    try sessionAttachPeer(session, &connection);

    var provider = identity.ServerProvider.init(std.testing.io, .{});
    const answer = try provider.addToSdp(std.testing.allocator, answer_sdp);
    defer std.testing.allocator.free(answer);

    try sessionAcceptAnswer(session, answer, .{ .trust = .transport_authenticated });
    try std.testing.expect(backend.remote_set);
    try std.testing.expectEqualStrings(answer_sdp, backend.remote_sdp[0..backend.remote_sdp_len]);
    const stored = sessionPeerIdentity(session).?;
    try std.testing.expect(stored.anchored);
    try std.testing.expectEqualSlices(u8, &provider.keyFingerprint(), &stored.key_sha256);

    try std.testing.expectError(error.MissingIdentity, sessionAcceptAnswer(session, answer_sdp, .{ .trust = .transport_authenticated }));
    try std.testing.expectEqualStrings(answer_sdp, backend.remote_sdp[0..backend.remote_sdp_len]);

    const tampered = try std.testing.allocator.dupe(u8, answer);
    defer std.testing.allocator.free(tampered);
    const fingerprint = "a=fingerprint:sha-256 AA:BB:CC:DD";
    tampered[std.mem.indexOf(u8, tampered, fingerprint).? + fingerprint.len - 1] = 'E';
    try std.testing.expectError(error.BadFingerprintSignature, sessionAcceptAnswer(session, tampered, .{ .trust = .transport_authenticated }));
    try std.testing.expectEqualStrings(answer_sdp, backend.remote_sdp[0..backend.remote_sdp_len]);
}

test "the raw answer path passes identity through and clears the verified one" {
    const answer_sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    var backend = peer.MockPeerConnection{};
    var connection = try peer.Peer.init(std.testing.allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer connection.deinit(std.testing.allocator);
    _ = try connection.startOffer();

    const session = try sessionCreate(std.testing.io, std.testing.allocator, .{ .network_id = "raw-answer" });
    defer sessionDestroy(session);
    try sessionAttachPeer(session, &connection);

    var provider = identity.ServerProvider.init(std.testing.io, .{});
    const answer = try provider.addToSdp(std.testing.allocator, answer_sdp);
    defer std.testing.allocator.free(answer);

    try sessionAcceptAnswer(session, answer, .{ .trust = .transport_authenticated });
    try std.testing.expect(sessionPeerIdentity(session) != null);

    try sessionAcceptAnswerRaw(session, answer);
    try std.testing.expect(std.mem.indexOf(u8, backend.remote_sdp[0..backend.remote_sdp_len], "a=identity:") != null);
    try std.testing.expect(sessionPeerIdentity(session) == null);
}

test "the public identity module verifies both cpk forms" {
    const sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
    const Assertion = struct { fingerprints: []const u8, token: []const u8 };

    for ([_]identity.CpkEncoding{ .jwk, .base64_der }) |form| {
        var provider = identity.ServerProvider.init(std.testing.io, .{ .cpk_encoding = form });
        const signed = try provider.addToSdp(std.testing.allocator, sdp);
        defer std.testing.allocator.free(signed);

        var envelope = try identity.extract(signed, std.testing.allocator, .{});
        defer identity.deinit(std.testing.allocator, &envelope);
        const assertion = try std.json.parseFromSlice(Assertion, std.testing.allocator, envelope.assertion, .{});
        defer assertion.deinit();

        var verified = try identity.verify.verifyAssertion(std.testing.allocator, envelope.assertion, signed);
        defer verified.deinit(std.testing.allocator);
        try std.testing.expectEqual(form, verified.form);
    }
}
