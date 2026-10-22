const std = @import("std");
const builtin = @import("builtin");
const log = @import("../log.zig");
const native = @import("webrtc");
const ice = @import("ice");

pub const max_remote_candidates: usize = 32;

pub const max_ice_sockets: usize = 8;

fn candidateAttributeValue(text: []const u8) []const u8 {
    var value = std.mem.trim(u8, text, " \t\r\n");
    if (std.mem.startsWith(u8, value, "a=")) value = value[2..];
    if (std.mem.startsWith(u8, value, "candidate:")) value = value["candidate:".len..];
    return std.mem.trim(u8, value, " \t\r\n");
}

pub fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

pub const PeerError = error{
    InvalidState,
    InvalidDescription,
    UnsupportedChannel,
    BackendFailure,
    OutOfMemory,
    Backpressure,
    PeerClosed,
    GatheringTimeout,
};

pub const ChannelKind = enum { reliable, unreliable };
pub const PeerState = enum { new, gathering, connecting, connected, disconnected, failed, closed };

/// `id` is never reused; `user_data` is consumer-owned, attached in `on_open` and
/// freed in `on_close`. A sharded tick can show the same handle to several threads,
/// so `user_data` must be safe for that.
pub const PeerHandle = struct {
    id: u64,
    peer: *Peer,
    user_data: ?*anyopaque = null,

    pub fn send(self: *PeerHandle, kind: ChannelKind, payload: []const u8) PeerError!void {
        return self.peer.send(kind, payload);
    }
};

pub const MessageHandler = struct {
    ctx: *anyopaque,

    on_open: ?*const fn (ctx: *anyopaque, session: *PeerHandle) void = null,

    // Receives one whole NetherNet message, framing already removed. A returned slice
    // is sent back on the same channel and must stay valid until the next call.
    on_message: *const fn (ctx: *anyopaque, session: *PeerHandle, kind: ChannelKind, message: []const u8) ?[]const u8,

    on_close: ?*const fn (ctx: *anyopaque, session: *PeerHandle) void = null,
};
pub const Profile = enum { http_full_ice, lan_trickle };

pub const SessionDescription = struct {
    kind: enum { offer, answer },
    sdp: []const u8,
};

pub const PeerEvent = union(enum) {
    state_changed: PeerState,
    channel_opened: ChannelKind,
    channel_closed: ChannelKind,
    channel_attached: struct { kind: ChannelKind, channel: DataChannel },
    binary: struct { kind: ChannelKind, data: []const u8 },
    failed: PeerError,
};

pub const DataChannelEvent = union(enum) {
    opened,
    closed,
    binary: []const u8,
    failed: PeerError,
};

pub const DataChannel = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (*anyopaque, []const u8) PeerError!void,
        close: *const fn (*anyopaque) void,
        poll: *const fn (*anyopaque) PeerError!?DataChannelEvent,
    };

    pub fn send(self: DataChannel, payload: []const u8) PeerError!void {
        return self.vtable.send(self.ptr, payload);
    }

    pub fn close(self: DataChannel) void {
        self.vtable.close(self.ptr);
    }

    pub fn poll(self: DataChannel) PeerError!?DataChannelEvent {
        return self.vtable.poll(self.ptr);
    }
};

pub const PeerConnection = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        createOffer: *const fn (*anyopaque) PeerError!SessionDescription,
        completeLocal: *const fn (*anyopaque, SessionDescription) PeerError!SessionDescription,
        createAnswer: *const fn (*anyopaque) PeerError!SessionDescription,
        setLocal: *const fn (*anyopaque, SessionDescription) PeerError!void,
        setRemote: *const fn (*anyopaque, SessionDescription) PeerError!void,
        poll: *const fn (*anyopaque) PeerError!?PeerEvent,
        close: *const fn (*anyopaque) void,
        addRemoteCandidate: *const fn (*anyopaque, []const u8) PeerError!void = unsupportedAddRemoteCandidate,
        pollLocalCandidate: *const fn (*anyopaque, []u8) PeerError!?usize = noLocalCandidate,
    };

    pub fn createOffer(self: PeerConnection) PeerError!SessionDescription {
        return self.vtable.createOffer(self.ptr);
    }

    pub fn completeLocal(self: PeerConnection, description: SessionDescription) PeerError!SessionDescription {
        return self.vtable.completeLocal(self.ptr, description);
    }

    pub fn createAnswer(self: PeerConnection) PeerError!SessionDescription {
        return self.vtable.createAnswer(self.ptr);
    }

    pub fn setLocal(self: PeerConnection, description: SessionDescription) PeerError!void {
        return self.vtable.setLocal(self.ptr, description);
    }

    pub fn setRemote(self: PeerConnection, description: SessionDescription) PeerError!void {
        return self.vtable.setRemote(self.ptr, description);
    }

    pub fn poll(self: PeerConnection) PeerError!?PeerEvent {
        return self.vtable.poll(self.ptr);
    }

    pub fn close(self: PeerConnection) void {
        self.vtable.close(self.ptr);
    }

    pub fn addRemoteCandidate(self: PeerConnection, text: []const u8) PeerError!void {
        return self.vtable.addRemoteCandidate(self.ptr, text);
    }

    pub fn pollLocalCandidate(self: PeerConnection, buffer: []u8) PeerError!?[]const u8 {
        const length = try self.vtable.pollLocalCandidate(self.ptr, buffer);
        return if (length) |written| buffer[0..written] else null;
    }
};

fn unsupportedAddRemoteCandidate(_: *anyopaque, _: []const u8) PeerError!void {
    return error.UnsupportedChannel;
}

fn noLocalCandidate(_: *anyopaque, _: []u8) PeerError!?usize {
    return null;
}

pub const IceServer = ice.IceServer;

pub fn validateIceServers(servers: []const IceServer) error{InvalidIceServer}!void {
    for (servers) |server| {
        _ = ice.ParsedServerUrl.parse(server.url) catch return error.InvalidIceServer;
    }
}

pub const PeerConfig = struct {
    profile: Profile,
    max_message_size: u32 = 262144,
    event_capacity: usize = 64,
    max_event_payload: usize = 262144,
    max_event_bytes: usize = 4 * 1024 * 1024,
    ice_servers: []const IceServer = &.{},
    gather_timeout_ms: i64 = 8_000,
};

const QueuedEvent = struct {
    tag: enum { state_changed, channel_opened, channel_closed, binary, failed },
    state: PeerState = .new,
    channel: ChannelKind = .reliable,
    failure: PeerError = error.BackendFailure,
    payload_offset: usize = 0,
    payload_len: usize = 0,
};

pub const Peer = struct {
    allocator: std.mem.Allocator,
    connection: PeerConnection,
    config: PeerConfig,
    state: PeerState = .new,
    reliable: ?DataChannel = null,
    unreliable: ?DataChannel = null,
    reliable_open: bool = false,
    unreliable_open: bool = false,
    closed: bool = false,
    event_queue: []QueuedEvent,
    event_arena: []u8,
    event_arena_capacity: usize = 0,
    event_arena_used: usize = 0,
    event_head: usize = 0,
    event_tail: usize = 0,
    event_count: usize = 0,

    pub const max_event_payload: usize = 262144;
    pub const max_event_capacity: usize = 256;

    pub const initial_event_arena_bytes: usize = 4096;

    pub fn init(allocator: std.mem.Allocator, connection: PeerConnection, config: PeerConfig) !Peer {
        if (config.event_capacity == 0 or config.event_capacity > max_event_capacity) {
            return error.InvalidState;
        }
        if (config.max_event_payload == 0 or config.max_event_payload > max_event_payload) {
            return error.InvalidState;
        }
        if (config.max_event_bytes < config.max_event_payload) return error.InvalidState;

        const events = try allocator.alloc(QueuedEvent, config.event_capacity);
        errdefer allocator.free(events);
        for (events) |*event| event.* = .{ .tag = .state_changed };

        const capacity = @min(config.max_event_payload, initial_event_arena_bytes);
        const event_arena = try allocator.alloc(u8, capacity);
        errdefer allocator.free(event_arena);

        return .{
            .allocator = allocator,
            .connection = connection,
            .config = config,
            .event_queue = events,
            .event_arena = event_arena,
            .event_arena_capacity = capacity,
        };
    }

    pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
        self.close();
        allocator.free(self.event_queue);
        allocator.free(self.event_arena[0..self.event_arena_capacity]);
        self.* = undefined;
    }

    pub fn startOffer(self: *Peer) PeerError!SessionDescription {
        if (self.state != .new) return error.InvalidState;
        const offer = try self.connection.createOffer();
        try self.connection.setLocal(offer);
        try self.transition(.gathering);
        return if (self.config.profile == .http_full_ice)
            try self.connection.completeLocal(offer)
        else
            offer;
    }

    pub fn acceptOffer(self: *Peer, offer: SessionDescription) PeerError!SessionDescription {
        if (self.state != .new) return error.InvalidState;
        if (offer.kind != .offer or offer.sdp.len == 0) return error.InvalidDescription;
        try self.connection.setRemote(offer);
        var answer = try self.connection.createAnswer();
        try self.connection.setLocal(answer);
        if (self.config.profile == .http_full_ice) answer = try self.connection.completeLocal(answer);
        try self.transition(.connecting);
        return answer;
    }

    pub fn acceptAnswer(self: *Peer, answer: SessionDescription) PeerError!void {
        if (self.state != .gathering and self.state != .connecting) return error.InvalidState;
        if (answer.kind != .answer or answer.sdp.len == 0) return error.InvalidDescription;
        try self.connection.setRemote(answer);
        if (self.state == .gathering) try self.transition(.connecting);
    }

    pub fn attachChannel(self: *Peer, kind: ChannelKind, channel: DataChannel) PeerError!void {
        if (self.state == .closed or self.state == .failed) return error.InvalidState;
        const slot = switch (kind) {
            .reliable => &self.reliable,
            .unreliable => &self.unreliable,
        };
        if (slot.*) |existing| {
            if (existing.ptr == channel.ptr) return;
            return error.UnsupportedChannel;
        }
        slot.* = channel;
    }

    pub fn tick(self: *Peer) PeerError!void {
        if (self.closed) return error.PeerClosed;

        while (true) {
            const maybe_event = self.connection.poll() catch |err| switch (err) {
                error.Backpressure => {
                    std.log.warn("peer refused a duplicate channel attach", .{});
                    break;
                },
                else => return err,
            };
            const event = maybe_event orelse break;
            try self.handlePeerEvent(event);
            if (self.closed) return error.PeerClosed;
        }

        if (self.reliable) |channel| try self.pollChannel(.reliable, channel);
        if (self.unreliable) |channel| try self.pollChannel(.unreliable, channel);
        self.updateConnectedState();
    }

    pub fn pollEvent(self: *Peer) ?PeerEvent {
        if (self.event_count == 0) return null;
        const event = &self.event_queue[self.event_head];
        const result: PeerEvent = switch (event.tag) {
            .state_changed => .{ .state_changed = event.state },
            .channel_opened => .{ .channel_opened = event.channel },
            .channel_closed => .{ .channel_closed = event.channel },
            .failed => .{ .failed = event.failure },
            .binary => .{ .binary = .{ .kind = event.channel, .data = self.event_arena[event.payload_offset..][0..event.payload_len] } },
        };
        self.event_head = (self.event_head + 1) % self.event_queue.len;
        self.event_count -= 1;

        if (self.event_count == 0) self.event_arena_used = 0;
        return result;
    }
    pub fn send(self: *Peer, kind: ChannelKind, payload: []const u8) PeerError!void {
        if (self.state == .closed or self.state == .failed) return error.InvalidState;
        const open = switch (kind) {
            .reliable => self.reliable_open,
            .unreliable => self.unreliable_open,
        };
        if (!open) return error.InvalidState;

        if (payload.len > self.config.max_message_size) return error.InvalidDescription;
        const channel = switch (kind) {
            .reliable => self.reliable,
            .unreliable => self.unreliable,
        } orelse return error.InvalidState;
        try channel.send(payload);
    }

    pub fn stateOf(self: *const Peer) PeerState {
        return self.state;
    }

    pub fn addRemoteCandidate(self: *Peer, text: []const u8) PeerError!void {
        if (self.closed) return error.PeerClosed;
        return self.connection.addRemoteCandidate(text);
    }

    pub fn pollLocalCandidate(self: *Peer, buffer: []u8) PeerError!?[]const u8 {
        if (self.closed) return null;
        return self.connection.pollLocalCandidate(buffer);
    }

    pub fn close(self: *Peer) void {
        if (self.closed) return;
        self.closed = true;
        self.connection.close();
        self.transition(.closed) catch {};
    }

    fn handlePeerEvent(self: *Peer, event: PeerEvent) PeerError!void {
        switch (event) {
            .state_changed => |state| switch (state) {
                .new => {},
                .gathering => if (self.state == .new) try self.transition(.gathering),
                .connecting => if (self.state == .gathering or self.state == .disconnected) try self.transition(.connecting),
                .connected => self.updateConnectedState(),
                .disconnected => if (self.state == .connected or self.state == .connecting) try self.transition(.disconnected),
                .failed => try self.fail(error.BackendFailure),
                .closed => self.close(),
            },
            .channel_opened => |kind| try self.openChannel(kind),
            .channel_closed => |kind| try self.closeChannel(kind),
            .channel_attached => |attached| try self.attachChannel(attached.kind, attached.channel),
            .binary => |message| try self.enqueueBinary(message.kind, message.data),
            .failed => |err| try self.fail(err),
        }
    }

    fn pollChannel(self: *Peer, kind: ChannelKind, channel: DataChannel) PeerError!void {
        while (true) {
            if (self.closed) return error.PeerClosed;

            if (self.event_count == self.event_queue.len) return;

            const maybe_event = channel.poll() catch |err| switch (err) {
                error.Backpressure => {
                    std.log.warn("peer channel lost inbound events: backend ring overflowed", .{});
                    continue;
                },
                else => return err,
            };
            const event = maybe_event orelse return;

            switch (event) {
                .opened => try self.openChannel(kind),
                .closed => try self.closeChannel(kind),
                .binary => |payload| try self.enqueueBinary(kind, payload),
                .failed => |err| switch (err) {
                    error.Backpressure, error.OutOfMemory => std.log.warn(
                        "peer dropped an inbound message: {s}",
                        .{@errorName(err)},
                    ),
                    else => try self.fail(err),
                },
            }
        }
    }

    fn openChannel(self: *Peer, kind: ChannelKind) PeerError!void {
        const open = switch (kind) {
            .reliable => &self.reliable_open,
            .unreliable => &self.unreliable_open,
        };
        if (open.*) return;

        open.* = true;
        try self.enqueue(.{ .tag = .channel_opened, .channel = kind });
        self.updateConnectedState();
    }

    fn closeChannel(self: *Peer, kind: ChannelKind) PeerError!void {
        switch (kind) {
            .reliable => self.reliable_open = false,
            .unreliable => self.unreliable_open = false,
        }
        try self.enqueue(.{ .tag = .channel_closed, .channel = kind });
        if (self.state == .connected) try self.transition(.disconnected);
    }

    fn updateConnectedState(self: *Peer) void {
        if (self.state == .connecting and self.reliable_open and self.unreliable_open) {
            self.transition(.connected) catch |err| self.fail(err) catch {};
        }
    }

    fn transition(self: *Peer, next: PeerState) PeerError!void {
        if (self.state == next) return;
        const valid = switch (self.state) {
            .new => next == .gathering or next == .connecting or next == .failed or next == .closed,
            .gathering => next == .connecting or next == .failed or next == .closed,
            .connecting => next == .connected or next == .disconnected or next == .failed or next == .closed,
            .connected => next == .disconnected or next == .failed or next == .closed,
            .disconnected => next == .connecting or next == .failed or next == .closed,
            .failed => next == .closed,
            .closed => false,
        };
        if (!valid) return error.InvalidState;
        self.state = next;
        try self.enqueue(.{ .tag = .state_changed, .state = next });
    }

    fn fail(self: *Peer, err: PeerError) PeerError!void {
        if (self.state == .closed or self.state == .failed) return;
        self.enqueue(.{ .tag = .failed, .failure = err }) catch return error.Backpressure;
        self.transition(.failed) catch {};
        self.connection.close();
    }

    fn enqueueBinary(self: *Peer, kind: ChannelKind, payload: []const u8) PeerError!void {
        if (payload.len > self.config.max_event_payload) {
            std.log.warn("peer dropped a {d}-byte message: over the event budget", .{payload.len});
            return;
        }
        if (self.event_count == self.event_queue.len) {
            std.log.warn("peer dropped a {d}-byte message: event queue full", .{payload.len});
            return;
        }
        if (!self.reserveArena(payload.len)) {
            std.log.warn("peer dropped a {d}-byte message: event arena full", .{payload.len});
            return;
        }
        const offset = self.event_arena_used;
        @memcpy(self.event_arena[offset .. offset + payload.len], payload);
        self.event_arena_used += payload.len;
        self.enqueue(.{
            .tag = .binary,
            .channel = kind,
            .payload_offset = offset,
            .payload_len = payload.len,
        }) catch |err| {
            self.event_arena_used -= payload.len;
            return err;
        };
    }

    fn reserveArena(self: *Peer, needed: usize) bool {
        if (self.event_arena_used + needed <= self.event_arena_capacity) return true;
        self.compactArena();
        if (self.event_arena_used + needed <= self.event_arena_capacity) return true;
        if (self.event_arena_capacity >= self.config.max_event_bytes) return false;
        const target = @min(self.config.max_event_bytes, @max(self.event_arena_capacity * 2, needed));
        const grown = self.allocator.alloc(u8, target) catch return false;
        @memcpy(grown[0..self.event_arena_used], self.event_arena[0..self.event_arena_used]);
        self.allocator.free(self.event_arena[0..self.event_arena_capacity]);
        self.event_arena = grown;
        self.event_arena_capacity = target;
        return self.event_arena_used + needed <= target;
    }

    fn compactArena(self: *Peer) void {
        if (self.event_count == 0) {
            self.event_arena_used = 0;
            return;
        }
        var cursor: usize = 0;
        var index = self.event_head;
        for (0..self.event_count) |_| {
            const event = &self.event_queue[index];
            index = (index + 1) % self.event_queue.len;
            if (event.tag != .binary or event.payload_len == 0) continue;
            const from = event.payload_offset;
            if (from != cursor) std.mem.copyForwards(u8, self.event_arena[cursor .. cursor + event.payload_len], self.event_arena[from .. from + event.payload_len]);
            event.payload_offset = cursor;
            cursor += event.payload_len;
        }
        self.event_arena_used = cursor;
    }

    fn enqueue(self: *Peer, event: QueuedEvent) PeerError!void {
        if (self.event_count == self.event_queue.len) return error.Backpressure;
        self.event_queue[self.event_tail] = event;
        self.event_tail = (self.event_tail + 1) % self.event_queue.len;
        self.event_count += 1;
    }
};

pub const MockChannel = struct {
    opened: bool = false,
    closed: bool = false,
    next_event: ?DataChannelEvent = null,
    fail_next: ?PeerError = null,
    sent_count: usize = 0,

    pub fn channel(self: *MockChannel) DataChannel {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn push(self: *MockChannel, event: DataChannelEvent) void {
        self.next_event = event;
    }

    fn send(ptr: *anyopaque, payload: []const u8) PeerError!void {
        const self: *MockChannel = @ptrCast(@alignCast(ptr));
        if (self.closed or !self.opened) return error.InvalidState;
        self.sent_count += payload.len;
    }

    fn close(ptr: *anyopaque) void {
        const self: *MockChannel = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }

    fn poll(ptr: *anyopaque) PeerError!?DataChannelEvent {
        const self: *MockChannel = @ptrCast(@alignCast(ptr));
        if (self.fail_next) |err| {
            self.fail_next = null;
            return err;
        }
        const event = self.next_event;
        self.next_event = null;
        return event;
    }

    const vtable: DataChannel.VTable = .{
        .send = send,
        .close = close,
        .poll = poll,
    };
};

pub const NativePeerConnection = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    media_engine: native.MediaEngine,
    connection: native.PeerConnection,
    prng: std.Random.DefaultCsprng,
    profile: Profile = .http_full_ice,
    gather_timeout_ms: i64 = 8_000,
    ice_servers: []const IceServer = &.{},
    sockets: [max_ice_sockets]std.Io.net.Socket = undefined,
    socket_addrs: [max_ice_sockets]std.Io.net.IpAddress = undefined,
    socket_count: usize = 0,
    local_bound: bool = false,
    gathered_offer_sdp: ?[]u8 = null,
    pending: [pending_capacity]Pending = undefined,
    pending_head: usize = 0,
    pending_len: usize = 0,
    local_channels_created: bool = false,
    local_reliable: ?*NativeDataChannel = null,
    local_unreliable: ?*NativeDataChannel = null,
    remote_reliable: ?*NativeDataChannel = null,
    remote_unreliable: ?*NativeDataChannel = null,
    last_state: PeerState = .new,
    next_timeout_ms: i64 = std.math.maxInt(i64),
    local_candidates_sent: usize = 0,
    remote_candidates_added: usize = 0,
    pumped: bool = false,
    saw_datagram: bool = false,
    datagrams_logged: usize = 0,
    closed: bool = false,
    sockets_closed: bool = false,

    const pending_capacity: usize = 16;
    const reliable_label = "ReliableDataChannel";
    const unreliable_label = "UnreliableDataChannel";
    const max_datagrams_per_tick: usize = 32;
    const datagram_bytes = 1_500;

    const Pending = union(enum) {
        state: PeerState,
        attached: ChannelKind,
        failed: PeerError,
    };

    const Families = struct { ip4: bool = false, ip6: bool = false };

    pub fn init(io: std.Io, allocator: std.mem.Allocator, config: PeerConfig) !*NativePeerConnection {
        const self = try allocator.create(NativePeerConnection);
        errdefer allocator.destroy(self);

        self.* = .{
            .io = io,
            .allocator = allocator,
            .media_engine = native.MediaEngine.init(.{}),
            .connection = undefined,
            .prng = undefined,
            .profile = config.profile,
            .gather_timeout_ms = config.gather_timeout_ms,
            .ice_servers = config.ice_servers,
        };
        errdefer self.media_engine.deinit(allocator);
        try self.media_engine.registerDefaultCodecs(allocator);

        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
        try io.randomSecure(&seed);
        self.prng = .init(seed);
        self.connection = try native.PeerConnection.init(io, allocator, .{
            .rtc_configuration = .{ .ice_servers = config.ice_servers },
            .media_engine = &self.media_engine,
            .random = self.prng.random(),
        });
        // The backend caps an outbound message at RFC 8841's 64 KiB by default,
        // while this library negotiates up to `max_message_size` in the answer. A
        // legal segment would otherwise be refused on the way out.
        self.connection.sctp_transport.max_message_size = config.max_message_size;
        return self;
    }

    pub fn deinit(self: *NativePeerConnection) void {
        close(self);
        self.connection.deinit();
        self.closeSockets();
        if (self.gathered_offer_sdp) |sdp| self.allocator.free(sdp);
        self.gathered_offer_sdp = null;
        destroyChannel(self, &self.local_reliable);
        destroyChannel(self, &self.local_unreliable);
        destroyChannel(self, &self.remote_reliable);
        destroyChannel(self, &self.remote_unreliable);
        self.media_engine.deinit(self.allocator);
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    fn destroyChannel(self: *NativePeerConnection, slot: *?*NativeDataChannel) void {
        _ = self;
        if (slot.*) |storage| {
            storage.release();
            const allocator = storage.allocator;
            allocator.destroy(storage);
        }
        slot.* = null;
    }

    fn closeSockets(self: *NativePeerConnection) void {
        if (self.sockets_closed) return;
        self.sockets_closed = true;
        for (self.sockets[0..self.socket_count]) |*socket| socket.close(self.io);
        self.socket_count = 0;
    }

    pub fn connectionSpi(self: *NativePeerConnection) PeerConnection {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn iceServerCount(self: *const NativePeerConnection) usize {
        return self.ice_servers.len;
    }

    fn ensureLocalChannels(self: *NativePeerConnection) PeerError!void {
        if (self.local_channels_created) return;
        {
            const storage = self.allocator.create(NativeDataChannel) catch return error.OutOfMemory;
            errdefer self.allocator.destroy(storage);
            _ = try self.createChannel(storage, .reliable);
        }
        {
            const storage = self.allocator.create(NativeDataChannel) catch return error.OutOfMemory;
            errdefer self.allocator.destroy(storage);
            _ = try self.createChannel(storage, .unreliable);
        }
        self.local_channels_created = true;
    }

    pub fn createChannel(self: *NativePeerConnection, storage: *NativeDataChannel, kind: ChannelKind) PeerError!DataChannel {
        if ((kind == .reliable and self.local_reliable != null) or
            (kind == .unreliable and self.local_unreliable != null)) return error.UnsupportedChannel;
        const params: native.DataChannel.Parameters = switch (kind) {
            .reliable => .{ .ordered = true },
            .unreliable => .{ .ordered = false, .max_retransmits = 0 },
        };
        const label = switch (kind) {
            .reliable => reliable_label,
            .unreliable => unreliable_label,
        };
        const channel = self.connection.createDataChannel(label, params) catch return error.BackendFailure;
        storage.init(self.allocator, channel, kind);
        switch (kind) {
            .reliable => self.local_reliable = storage,
            .unreliable => self.local_unreliable = storage,
        }
        try self.enqueue(.{ .attached = kind });
        return storage.wrapper();
    }

    fn bindLocal(self: *NativePeerConnection, families: Families) PeerError!void {
        if (self.local_bound) return;
        self.local_bound = true;

        var iterator = ice.IfIterator.init(self.allocator, .{
            .udp4 = families.ip4,
            .udp6 = families.ip6,
        }) catch return error.BackendFailure;
        defer iterator.deinit(self.allocator);

        var addresses: [max_ice_sockets]std.Io.net.IpAddress = undefined;
        while (iterator.next()) |address| {
            if (self.socket_count == max_ice_sockets) break;
            // A link-local IPv6 address carries a scope id this iterator does not
            // provide, so binding it cannot succeed and advertising it would be a
            // candidate no client can use.
            if (isIpv6LinkLocal(address)) continue;
            const socket = address.bind(self.io, .{ .mode = .dgram }) catch continue;
            self.sockets[self.socket_count] = socket;
            self.socket_addrs[self.socket_count] = socket.address;
            addresses[self.socket_count] = socket.address;
            self.socket_count += 1;
        }

        if (self.socket_count == 0 and families.ip4) {
            const loopback: std.Io.net.IpAddress = .{ .ip4 = std.Io.net.Ip4Address.loopback(0) };
            if (loopback.bind(self.io, .{ .mode = .dgram })) |socket| {
                self.sockets[0] = socket;
                self.socket_addrs[0] = socket.address;
                addresses[0] = socket.address;
                self.socket_count = 1;
            } else |_| {}
        }
        if (self.socket_count == 0) return error.BackendFailure;

        self.addIceServers();
        self.connection.addLocalCandidates(addresses[0..self.socket_count], nowMs(self.io)) catch
            return error.BackendFailure;
    }

    fn addIceServers(self: *NativePeerConnection) void {
        for (self.ice_servers) |server| {
            const parsed = ice.ParsedServerUrl.parse(server.url) catch continue;
            if (parsed.transport != .udp) continue;
            const remote = std.Io.net.IpAddress.resolve(self.io, parsed.host, parsed.port) catch continue;
            for (self.socket_addrs[0..self.socket_count]) |local| {
                if (std.meta.activeTag(local) != std.meta.activeTag(remote)) continue;
                switch (parsed.scheme) {
                    .stun => self.connection.addStunServer(local, remote) catch {},
                    .turn => self.connection.addTurnServer(local, remote, server.username, server.credential) catch {},
                    else => {},
                }
            }
        }
    }

    fn waitForServerReflexive(self: *NativePeerConnection) void {
        if (self.ice_servers.len == 0) return;
        const start = nowMs(self.io);
        const deadline = start +| @max(self.gather_timeout_ms, 0);
        var last_len = self.candidateCount();
        var stable_since = start;
        var now = start;
        while (now < deadline) {
            self.pumpIo(now) catch return;
            self.connection.handleTimeout(now, 0) catch return;
            const len = self.candidateCount();
            if (len != last_len) {
                last_len = len;
                stable_since = now;
            } else if (now - stable_since >= 250) {
                return;
            }
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch return;
            now = nowMs(self.io);
        }
    }

    fn candidateCount(self: *const NativePeerConnection) usize {
        return self.connection.dtls_transport.ice_agent.candidates_len;
    }

    fn createOffer(ptr: *anyopaque) PeerError!SessionDescription {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        try self.ensureLocalChannels();
        try self.bindLocal(.{ .ip4 = true, .ip6 = true });
        const description = self.connection.createOffer() catch return error.BackendFailure;
        return .{ .kind = .offer, .sdp = description.sdp };
    }

    fn completeLocal(ptr: *anyopaque, description: SessionDescription) PeerError!SessionDescription {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        self.waitForServerReflexive();
        const local = (self.connection.getLocalDescription() catch return error.BackendFailure) orelse
            return error.BackendFailure;
        if (self.gathered_offer_sdp) |sdp| self.allocator.free(sdp);
        self.gathered_offer_sdp = @constCast(local.sdp);
        return .{ .kind = description.kind, .sdp = self.gathered_offer_sdp.? };
    }

    fn createAnswer(ptr: *anyopaque) PeerError!SessionDescription {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        const description = self.connection.createAnswer() catch return error.BackendFailure;
        return .{ .kind = .answer, .sdp = description.sdp };
    }

    fn setLocal(ptr: *anyopaque, description: SessionDescription) PeerError!void {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        const native_description: native.SessionDescription = .{
            .type = switch (description.kind) {
                .offer => .offer,
                .answer => .answer,
            },
            .sdp = description.sdp,
        };
        self.connection.setLocalDescription(native_description) catch return error.BackendFailure;
    }

    fn setRemote(ptr: *anyopaque, description: SessionDescription) PeerError!void {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        const native_description: native.SessionDescription = .{
            .type = switch (description.kind) {
                .offer => .offer,
                .answer => .answer,
            },
            .sdp = description.sdp,
        };
        self.connection.setRemoteDescription(native_description, nowMs(self.io)) catch
            return error.BackendFailure;
        if (description.kind == .offer) try self.bindLocal(familiesFromOffer(description.sdp));
    }

    fn poll(ptr: *anyopaque) PeerError!?PeerEvent {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.PeerClosed;

        if (!self.pumped) {
            self.pumped = true;
            try self.pump();
        }
        if (self.pending_len == 0) {
            self.pumped = false;
            return null;
        }

        const entry = self.pending[self.pending_head];
        self.pending_head = (self.pending_head + 1) % self.pending.len;
        self.pending_len -= 1;
        return switch (entry) {
            .state => |state| .{ .state_changed = state },
            .attached => |kind| .{ .channel_attached = .{
                .kind = kind,
                .channel = (self.channelFor(kind) orelse return error.BackendFailure).wrapper(),
            } },
            .failed => |err| .{ .failed = err },
        };
    }

    fn pump(self: *NativePeerConnection) PeerError!void {
        const now = nowMs(self.io);
        if (now >= self.next_timeout_ms) {
            self.connection.handleTimeout(now, 0) catch return error.BackendFailure;
            self.next_timeout_ms = self.connection.pollTimeout() orelse std.math.maxInt(i64);
        }

        try self.pumpIo(now);

        while (self.connection.pollEvent()) |event| try self.handleNativeEvent(event);
        self.next_timeout_ms = self.connection.pollTimeout() orelse std.math.maxInt(i64);
    }

    fn pumpIo(self: *NativePeerConnection, now: i64) PeerError!void {
        try self.receiveDatagrams(now);
        try self.transmit(now);
    }

    fn receiveDatagrams(self: *NativePeerConnection, now: i64) PeerError!void {
        const poll_timeout: std.Io.Timeout = .{ .duration = .{
            .clock = .awake,
            .raw = .fromMilliseconds(0),
        } };
        var buffer: [datagram_bytes]u8 = undefined;

        for (self.sockets[0..self.socket_count]) |*socket| {
            var received: usize = 0;
            while (received < max_datagrams_per_tick) : (received += 1) {
                const incoming = socket.receiveTimeout(self.io, &buffer, poll_timeout) catch |err| switch (err) {
                    error.Timeout => break,
                    error.Canceled => return error.BackendFailure,
                    else => break,
                };
                if (!self.saw_datagram) {
                    self.saw_datagram = true;
                    log.debug("peer received its first datagram bytes={d} from={f} on={f}", .{ incoming.data.len, incoming.from, socket.address });
                }
                if (self.datagrams_logged < 80) {
                    self.datagrams_logged += 1;
                    log.debug("peer datagram #{d} bytes={d} from={f}", .{ self.datagrams_logged, incoming.data.len, incoming.from });
                }
                const result = self.connection.handleRead(.{
                    .data = incoming.data,
                    .from = &incoming.from,
                    .to = &socket.address,
                }, now) catch continue;
                switch (result) {
                    .app_data => |iterator| {
                        var messages = iterator;
                        self.drainAppData(&messages) catch return error.OutOfMemory;
                    },
                    else => {},
                }
            }
        }
    }

    fn drainAppData(self: *NativePeerConnection, iterator: *native.PeerConnection.SctpMessageIterator) PeerError!void {
        while (iterator.next() catch return error.OutOfMemory) |message| {
            const data = @constCast(message.data);
            log.debug("peer app data channel_id={d} binary={} bytes={d}", .{ message.channel_id, message.binary, data.len });
            var adopted = false;
            if (self.channelById(message.channel_id) == null) {
                self.attachRemoteChannel(message.channel_id) catch |err| switch (err) {
                    error.OutOfMemory => {
                        if (data.len != 0) self.allocator.free(data);
                        return error.OutOfMemory;
                    },
                    else => {},
                };
                adopted = true;
            }
            const channel = self.channelById(message.channel_id) orelse {
                log.debug("peer app data dropped: no channel for index {d}", .{message.channel_id});
                if (data.len != 0) self.allocator.free(data);
                continue;
            };
            if (adopted) channel.pushSignal(.opened);
            channel.pushOwned(data, message.binary);
        }
    }

    fn transmit(self: *NativePeerConnection, now: i64) PeerError!void {
        var buffer: [datagram_bytes]u8 = undefined;
        while (true) {
            const message = (self.connection.pollTransmit(&buffer, now) catch
                return error.BackendFailure) orelse return;
            const socket = self.socketFor(message.from) orelse {
                log.debug("peer outbound datagram dropped: no local socket for from={f} to={f} bytes={d}", .{ message.from, message.to, message.data.len });
                continue;
            };
            socket.send(self.io, message.to, message.data) catch continue;
        }
    }

    fn socketFor(self: *NativePeerConnection, address: *const std.Io.net.IpAddress) ?*std.Io.net.Socket {
        for (self.socket_addrs[0..self.socket_count], 0..) |*local, index| {
            if (local.eql(address)) return &self.sockets[index];
        }
        return null;
    }

    fn handleNativeEvent(self: *NativePeerConnection, event: native.PeerConnection.Event) PeerError!void {
        switch (event) {
            .connection_state => |state| {
                const mapped: PeerState = switch (state) {
                    .new => .new,
                    .connecting => .connecting,
                    .connected => .connected,
                    .disconnected => .disconnected,
                    .failed => .failed,
                    .closed => .closed,
                };
                if (mapped != self.last_state) {
                    self.last_state = mapped;
                    try self.enqueue(.{ .state = mapped });
                }
            },
            .data_channel => |channel_event| switch (channel_event) {
                .new => |id| try self.attachRemoteChannel(id),
                .open => |id| if (self.channelById(id)) |channel| channel.pushSignal(.opened),
                .close => |id| if (self.channelById(id)) |channel| channel.pushSignal(.closed),
                .buffered_amount_low_threshold => {},
            },
            .candidate, .gathering_state, .negotiation_needed, .signaling_state, .track => {},
        }
    }

    fn attachRemoteChannel(self: *NativePeerConnection, id: native.DataChannel.ChannelId) PeerError!void {
        if (self.channelById(id)) |existing| {
            try self.enqueue(.{ .attached = existing.kind });
            return;
        }
        const channel = self.connection.getDataChannel(id);

        log.debug("peer remote channel id={d} label={s} stream={any}", .{ id, channel.getLabel(), channel.id });
        const kind: ChannelKind = if (std.mem.eql(u8, channel.getLabel(), reliable_label))
            .reliable
        else if (std.mem.eql(u8, channel.getLabel(), unreliable_label))
            .unreliable
        else {
            try self.enqueue(.{ .failed = error.UnsupportedChannel });
            return;
        };
        if (self.channelFor(kind) != null) {
            try self.enqueue(.{ .failed = error.Backpressure });
            return;
        }
        const storage = self.allocator.create(NativeDataChannel) catch return error.OutOfMemory;
        storage.init(self.allocator, channel, kind);
        switch (kind) {
            .reliable => self.remote_reliable = storage,
            .unreliable => self.remote_unreliable = storage,
        }
        try self.enqueue(.{ .attached = kind });
    }

    fn channelFor(self: *NativePeerConnection, kind: ChannelKind) ?*NativeDataChannel {
        return switch (kind) {
            .reliable => self.local_reliable orelse self.remote_reliable,
            .unreliable => self.local_unreliable orelse self.remote_unreliable,
        };
    }

    fn channelById(self: *NativePeerConnection, id: native.DataChannel.ChannelId) ?*NativeDataChannel {
        const all = [_]?*NativeDataChannel{
            self.local_reliable,
            self.local_unreliable,
            self.remote_reliable,
            self.remote_unreliable,
        };
        for (all) |maybe| if (maybe) |channel| {
            if (channel.channel.id == id) return channel;
        };
        return null;
    }

    fn enqueue(self: *NativePeerConnection, event: Pending) PeerError!void {
        if (self.pending_len == self.pending.len) return error.Backpressure;
        self.pending[(self.pending_head + self.pending_len) % self.pending.len] = event;
        self.pending_len += 1;
    }

    fn close(ptr: *anyopaque) void {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        if (self.closed) return;
        self.closed = true;
        self.connection.close();
    }

    fn addRemoteCandidate(ptr: *anyopaque, text: []const u8) PeerError!void {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        if (self.closed) return error.PeerClosed;
        if (self.remote_candidates_added >= max_remote_candidates) return error.Backpressure;
        const value = candidateAttributeValue(text);
        const candidate = ice.Candidate.parse(value) catch return error.InvalidDescription;
        self.connection.dtls_transport.ice_agent.addRemoteCandidate(candidate, nowMs(self.io)) catch
            return error.BackendFailure;
        self.remote_candidates_added += 1;
    }

    fn pollLocalCandidate(ptr: *anyopaque, buffer: []u8) PeerError!?usize {
        const self: *NativePeerConnection = @ptrCast(@alignCast(ptr));
        if (self.closed) return null;
        const agent = &self.connection.dtls_transport.ice_agent;
        const gathered = agent.candidates[0..agent.candidates_len];
        if (self.local_candidates_sent >= gathered.len) return null;
        const candidate = gathered[self.local_candidates_sent];
        var storage: [512]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&storage);
        writer.print("candidate:{f}", .{candidate}) catch return error.BackendFailure;
        const text = writer.buffered();
        if (text.len > buffer.len) return error.Backpressure;
        self.local_candidates_sent += 1;
        @memcpy(buffer[0..text.len], text);
        return text.len;
    }

    const vtable: PeerConnection.VTable = .{
        .createOffer = createOffer,
        .completeLocal = completeLocal,
        .createAnswer = createAnswer,
        .setLocal = setLocal,
        .setRemote = setRemote,
        .poll = poll,
        .close = close,
        .addRemoteCandidate = addRemoteCandidate,
        .pollLocalCandidate = pollLocalCandidate,
    };
};

fn isIpv6LinkLocal(address: std.Io.net.IpAddress) bool {
    return switch (address) {
        .ip6 => |ip| ip.bytes[0] == 0xfe and (ip.bytes[1] & 0xc0) == 0x80,
        else => false,
    };
}

fn familiesFromOffer(sdp: []const u8) NativePeerConnection.Families {
    var families: NativePeerConnection.Families = .{};
    var lines = std.mem.splitScalar(u8, sdp, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        const prefix = "a=candidate:";
        if (!std.mem.startsWith(u8, trimmed, prefix)) continue;
        var fields = std.mem.tokenizeScalar(u8, trimmed[prefix.len..], ' ');
        _ = fields.next() orelse continue; // foundation
        _ = fields.next() orelse continue; // component
        _ = fields.next() orelse continue; // transport
        _ = fields.next() orelse continue; // priority
        const address = fields.next() orelse continue;
        if (std.mem.indexOfScalar(u8, address, ':') != null) {
            families.ip6 = true;
        } else {
            families.ip4 = true;
        }
    }
    if (!families.ip4 and !families.ip6) families.ip4 = true;
    return families;
}

pub const NativeDataChannel = struct {
    allocator: std.mem.Allocator,
    channel: native.DataChannel,
    kind: ChannelKind,
    queue: [event_capacity]NativeEvent = undefined,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    overflowed: bool = false,
    borrowed: ?Payload = null,
    pool: [pool_bytes]u8 = undefined,
    pool_used: usize = 0,

    const event_capacity: usize = 64;
    const max_payload: usize = Peer.max_event_payload;

    pub const pool_bytes: usize = 4 * 1024;

    const Payload = union(enum) {
        pooled: struct { offset: u32, len: u32 },
        heap: []u8,
    };

    const NativeEvent = union(enum) {
        opened,
        closed,
        binary: Payload,
        failed: PeerError,
    };

    pub const Signal = enum { opened, closed };

    pub fn init(self: *NativeDataChannel, allocator: std.mem.Allocator, channel: native.DataChannel, kind: ChannelKind) void {
        self.* = .{ .allocator = allocator, .channel = channel, .kind = kind };
    }

    pub fn wrapper(self: *NativeDataChannel) DataChannel {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn freePayload(self: *NativeDataChannel, payload: Payload) void {
        switch (payload) {
            .pooled => {},
            .heap => |bytes| self.allocator.free(bytes),
        }
    }

    fn payloadSlice(self: *NativeDataChannel, payload: Payload) []const u8 {
        return switch (payload) {
            .pooled => |pooled| self.pool[pooled.offset..][0..pooled.len],
            .heap => |bytes| bytes,
        };
    }

    pub fn release(self: *NativeDataChannel) void {
        if (self.borrowed) |payload| self.freePayload(payload);
        self.borrowed = null;
        while (self.count != 0) {
            const event = &self.queue[self.head];
            self.head = (self.head + 1) % self.queue.len;
            self.count -= 1;
            switch (event.*) {
                .binary => |payload| self.freePayload(payload),
                else => {},
            }
        }
        self.head = 0;
        self.tail = 0;
        self.pool_used = 0;
    }

    pub fn pushSignal(self: *NativeDataChannel, signal: Signal) void {
        self.push(switch (signal) {
            .opened => .opened,
            .closed => .closed,
        });
    }

    /// Takes ownership of `bytes`, which the SCTP layer allocated with this peer's
    /// allocator: a message that fits the pool is copied and released, and one that
    /// does not moves into the ring without a copy.
    pub fn pushOwned(self: *NativeDataChannel, bytes: []u8, binary: bool) void {
        if (!binary) {
            self.freeOwned(bytes);
            self.push(.{ .failed = error.UnsupportedChannel });
            return;
        }
        if (bytes.len > max_payload) {
            self.freeOwned(bytes);
            self.push(.{ .failed = error.Backpressure });
            return;
        }
        if (self.count == self.queue.len) {
            self.overflowed = true;
            self.freeOwned(bytes);
            return;
        }

        const queued: NativeEvent = if (bytes.len <= pool_bytes - self.pool_used) blk: {
            const offset = self.pool_used;
            @memcpy(self.pool[offset..][0..bytes.len], bytes);
            self.pool_used += bytes.len;
            self.freeOwned(bytes);
            break :blk .{ .binary = .{ .pooled = .{
                .offset = @intCast(offset),
                .len = @intCast(bytes.len),
            } } };
        } else blk: {
            break :blk .{ .binary = .{ .heap = bytes } };
        };
        self.push(queued);
    }

    /// Zero-length messages come from the SCTP layer as a static slice, so only a
    /// real allocation is handed back.
    fn freeOwned(self: *NativeDataChannel, bytes: []u8) void {
        if (bytes.len != 0) self.allocator.free(bytes);
    }

    fn push(self: *NativeDataChannel, event: NativeEvent) void {
        if (self.count == self.queue.len) {
            self.overflowed = true;
            return;
        }
        self.queue[self.tail] = event;
        self.tail = (self.tail + 1) % self.queue.len;
        self.count += 1;
    }

    fn send(ptr: *anyopaque, payload: []const u8) PeerError!void {
        const self: *NativeDataChannel = @ptrCast(@alignCast(ptr));
        self.channel.send(payload) catch return error.BackendFailure;
    }

    fn close(ptr: *anyopaque) void {
        const self: *NativeDataChannel = @ptrCast(@alignCast(ptr));
        self.channel.close() catch {};
    }

    fn poll(ptr: *anyopaque) PeerError!?DataChannelEvent {
        const self: *NativeDataChannel = @ptrCast(@alignCast(ptr));
        if (self.borrowed) |payload| {
            self.freePayload(payload);
            self.borrowed = null;
        }
        if (self.overflowed) {
            self.overflowed = false;
            return error.Backpressure;
        }
        if (self.count == 0) {
            self.pool_used = 0;
            return null;
        }
        const event = &self.queue[self.head];
        self.head = (self.head + 1) % self.queue.len;
        self.count -= 1;
        return switch (event.*) {
            .opened => .opened,
            .closed => .closed,
            .failed => |err| .{ .failed = err },
            .binary => |payload| blk: {
                self.borrowed = payload;
                break :blk .{ .binary = self.payloadSlice(payload) };
            },
        };
    }

    const vtable: DataChannel.VTable = .{
        .send = send,
        .close = close,
        .poll = poll,
    };
};

pub const MockPeerConnection = struct {
    state: PeerState = .new,
    next_event: ?PeerEvent = null,
    local_set: bool = false,
    remote_set: bool = false,
    remote_sdp: [1024]u8 = undefined,
    remote_sdp_len: usize = 0,
    closed: bool = false,
    scripted_candidate: ?[]const u8 = null,
    accepted_candidate: [128]u8 = undefined,
    accepted_candidate_len: usize = 0,

    pub fn connection(self: *MockPeerConnection) PeerConnection {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn push(self: *MockPeerConnection, event: PeerEvent) void {
        self.next_event = event;
    }

    fn createOffer(_: *anyopaque) PeerError!SessionDescription {
        return .{ .kind = .offer, .sdp = "mock-offer" };
    }

    fn completeLocal(_: *anyopaque, offer: SessionDescription) PeerError!SessionDescription {
        return offer;
    }

    fn createAnswer(_: *anyopaque) PeerError!SessionDescription {
        return .{ .kind = .answer, .sdp = "mock-answer" };
    }

    fn setLocal(ptr: *anyopaque, description: SessionDescription) PeerError!void {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        if (description.sdp.len == 0) return error.InvalidDescription;
        self.local_set = true;
    }

    fn setRemote(ptr: *anyopaque, description: SessionDescription) PeerError!void {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        if (description.sdp.len == 0 or description.sdp.len > self.remote_sdp.len) return error.InvalidDescription;
        @memcpy(self.remote_sdp[0..description.sdp.len], description.sdp);
        self.remote_sdp_len = description.sdp.len;
        self.remote_set = true;
    }

    fn poll(ptr: *anyopaque) PeerError!?PeerEvent {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        const event = self.next_event;
        self.next_event = null;
        return event;
    }

    fn close(ptr: *anyopaque) void {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        self.closed = true;
    }

    fn addRemoteCandidate(ptr: *anyopaque, text: []const u8) PeerError!void {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        if (text.len > self.accepted_candidate.len) return error.Backpressure;
        @memcpy(self.accepted_candidate[0..text.len], text);
        self.accepted_candidate_len = text.len;
    }

    fn pollLocalCandidate(ptr: *anyopaque, buffer: []u8) PeerError!?usize {
        const self: *MockPeerConnection = @ptrCast(@alignCast(ptr));
        const text = self.scripted_candidate orelse return null;
        self.scripted_candidate = null;
        if (text.len > buffer.len) return error.Backpressure;
        @memcpy(buffer[0..text.len], text);
        return text.len;
    }

    const vtable: PeerConnection.VTable = .{
        .createOffer = createOffer,
        .completeLocal = completeLocal,
        .createAnswer = createAnswer,
        .setLocal = setLocal,
        .setRemote = setRemote,
        .poll = poll,
        .close = close,
        .addRemoteCandidate = addRemoteCandidate,
        .pollLocalCandidate = pollLocalCandidate,
    };
};

test "native peer connections complete an in-process data-channel loopback" {
    if (builtin.is_test) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const config: PeerConfig = .{
        .profile = .http_full_ice,
        .event_capacity = 32,
        .max_event_payload = 262144,
    };

    var native_offer = try NativePeerConnection.init(std.testing.io, allocator, config);
    defer native_offer.deinit();
    var native_answer = try NativePeerConnection.init(std.testing.io, allocator, config);
    defer native_answer.deinit();

    var offer_peer = try Peer.init(allocator, native_offer.connectionSpi(), config);
    defer offer_peer.deinit(allocator);
    var answer_peer = try Peer.init(allocator, native_answer.connectionSpi(), config);
    defer answer_peer.deinit(allocator);

    const offer = try offer_peer.startOffer();
    const answer = try answer_peer.acceptOffer(offer);
    try offer_peer.acceptAnswer(answer);

    var connected = false;
    var sent = false;
    var received = false;
    var iteration: usize = 0;
    while (iteration < 500) : (iteration += 1) {
        try offer_peer.tick();
        try answer_peer.tick();

        if (offer_peer.stateOf() == .connected and answer_peer.stateOf() == .connected) {
            connected = true;
            if (!sent) {
                try offer_peer.send(.reliable, "native-loopback");
                sent = true;
            }
        }

        while (answer_peer.pollEvent()) |event| switch (event) {
            .binary => |message| {
                if (std.mem.eql(u8, message.data, "native-loopback")) received = true;
            },
            else => {},
        };
        if (received) break;
        try std.testing.io.sleep(.fromMilliseconds(10), .awake);
    }

    try std.testing.expect(connected);
    try std.testing.expect(received);
}

test "peer reaches connected only after both channels open" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{};
    var unreliable = MockChannel{};
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer peer.deinit(allocator);

    _ = try peer.startOffer();
    try std.testing.expectEqual(PeerState.gathering, peer.stateOf());
    try peer.acceptAnswer(.{ .kind = .answer, .sdp = "answer" });
    try peer.attachChannel(.reliable, reliable.channel());
    try peer.attachChannel(.unreliable, unreliable.channel());
    reliable.opened = true;
    unreliable.opened = true;
    reliable.push(.opened);
    unreliable.push(.opened);
    backend.push(.{ .state_changed = .connecting });
    try peer.tick();

    try std.testing.expectEqual(PeerState.connected, peer.stateOf());
    try peer.send(.reliable, "hello");
    try std.testing.expectEqual(@as(usize, 5), reliable.sent_count);
}

test "a channel overflow loses events, not the session" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{ .opened = true };
    var unreliable = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer peer.deinit(allocator);

    _ = try peer.startOffer();
    try peer.acceptAnswer(.{ .kind = .answer, .sdp = "answer" });
    try peer.attachChannel(.reliable, reliable.channel());
    try peer.attachChannel(.unreliable, unreliable.channel());
    reliable.push(.opened);
    unreliable.push(.opened);
    backend.push(.{ .state_changed = .connecting });
    try peer.tick();
    try std.testing.expectEqual(PeerState.connected, peer.stateOf());

    reliable.fail_next = error.Backpressure;
    try peer.tick();
    try std.testing.expectEqual(PeerState.connected, peer.stateOf());

    reliable.push(.{ .binary = "after" });
    try peer.tick();
    var delivered = false;
    while (peer.pollEvent()) |event| switch (event) {
        .binary => |message| delivered = std.mem.eql(u8, message.data, "after"),
        else => {},
    };
    try std.testing.expect(delivered);
}

test "a duplicate channel open is idempotent" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{};
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .lan_trickle });
    defer peer.deinit(allocator);
    try peer.attachChannel(.reliable, reliable.channel());
    reliable.push(.opened);
    try peer.tick();
    reliable.push(.opened);
    try peer.tick();
    try std.testing.expect(peer.reliable_open);
    try std.testing.expectEqual(PeerState.new, peer.stateOf());
}

test "a repeated remote channel attach is idempotent" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var remote = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .lan_trickle });
    defer peer.deinit(allocator);

    backend.push(.{ .channel_attached = .{ .kind = .reliable, .channel = remote.channel() } });
    try peer.tick();
    backend.push(.{ .channel_attached = .{ .kind = .reliable, .channel = remote.channel() } });
    try peer.tick();

    try std.testing.expect(peer.reliable != null);
    try std.testing.expectEqual(PeerState.new, peer.stateOf());
}

test "an open channel can send before the peer finishes connecting" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{ .opened = true };
    var unreliable = MockChannel{};
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .http_full_ice });
    defer peer.deinit(allocator);

    _ = try peer.startOffer();
    try peer.acceptAnswer(.{ .kind = .answer, .sdp = "answer" });
    try peer.attachChannel(.reliable, reliable.channel());
    try peer.attachChannel(.unreliable, unreliable.channel());
    reliable.push(.opened);
    backend.push(.{ .state_changed = .connecting });
    try peer.tick();

    try std.testing.expectEqual(PeerState.connecting, peer.stateOf());
    try peer.send(.reliable, "early");
    try std.testing.expectError(error.InvalidState, peer.send(.unreliable, "late"));
    try std.testing.expectEqual(@as(usize, 5), reliable.sent_count);
}

test "remote channel attachment is adopted before channel polling" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var remote = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{ .profile = .lan_trickle });
    defer peer.deinit(allocator);

    remote.push(.opened);
    backend.push(.{ .channel_attached = .{ .kind = .reliable, .channel = remote.channel() } });
    try peer.tick();
    try std.testing.expect(peer.reliable != null);
    try std.testing.expect(peer.reliable_open);
}

test "binary callback is copied into bounded peer events" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{
        .profile = .http_full_ice,
        .event_capacity = 4,
        .max_event_payload = 16,
    });
    defer peer.deinit(allocator);
    try peer.attachChannel(.reliable, reliable.channel());
    reliable.push(.{ .binary = "payload" });
    try peer.tick();
    while (peer.pollEvent()) |event| switch (event) {
        .binary => |message| try std.testing.expectEqualStrings("payload", message.data),
        else => {},
    };
}

test "a queued event carries no inline payload buffer" {
    try std.testing.expect(@sizeOf(QueuedEvent) <= 64);
}

test "a production peer starts at a page of event arena, not a message budget" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var peer = try Peer.init(allocator, backend.connection(), .{
        .profile = .http_full_ice,
        .event_capacity = 128,
        .max_event_payload = 262144,
        .max_event_bytes = 4 * 1024 * 1024,
    });
    defer peer.deinit(allocator);
    try std.testing.expectEqual(Peer.initial_event_arena_bytes, peer.event_arena_capacity);
}

test "the event arena grows on demand and reclaims drained payloads" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{
        .profile = .http_full_ice,
        .event_capacity = 8,
        .max_event_payload = 64,
        .max_event_bytes = 256,
    });
    defer peer.deinit(allocator);
    try peer.attachChannel(.reliable, reliable.channel());

    try std.testing.expectEqual(@as(usize, 64), peer.event_arena_capacity);

    const first = [_]u8{'a'} ** 64;
    const second = [_]u8{'b'} ** 64;
    const third = [_]u8{'c'} ** 64;

    reliable.push(.{ .binary = &first });
    try peer.tick();
    reliable.push(.{ .binary = &second });
    try peer.tick();
    try std.testing.expectEqual(@as(usize, 128), peer.event_arena_capacity);

    const read_first = peer.pollEvent().?;
    try std.testing.expectEqualStrings(&first, read_first.binary.data);
    reliable.push(.{ .binary = &third });
    try peer.tick();
    try std.testing.expectEqual(@as(usize, 128), peer.event_arena_capacity);
    try std.testing.expectEqual(@as(usize, 128), peer.event_arena_used);

    const read_second = peer.pollEvent().?;
    try std.testing.expectEqualStrings(&second, read_second.binary.data);
    const read_third = peer.pollEvent().?;
    try std.testing.expectEqualStrings(&third, read_third.binary.data);
    try std.testing.expect(peer.pollEvent() == null);
    try std.testing.expectEqual(@as(usize, 0), peer.event_arena_used);
}

test "binary payloads are bounded by the event budget and a full arena drops instead of failing" {
    const allocator = std.testing.allocator;
    var backend = MockPeerConnection{};
    var reliable = MockChannel{ .opened = true };
    var peer = try Peer.init(allocator, backend.connection(), .{
        .profile = .http_full_ice,
        .event_capacity = 8,
        .max_event_payload = 48,
        .max_event_bytes = 96,
    });
    defer peer.deinit(allocator);
    try peer.attachChannel(.reliable, reliable.channel());

    const first = [_]u8{'a'} ** 48;
    const second = [_]u8{'b'} ** 48;
    reliable.push(.{ .binary = &first });
    try peer.tick();
    reliable.push(.{ .binary = &second });
    try peer.tick();

    reliable.push(.{ .binary = &first });
    try peer.tick();
    const too_big = [_]u8{'c'} ** 49;
    reliable.push(.{ .binary = &too_big });
    try peer.tick();
    try std.testing.expectEqual(PeerState.new, peer.stateOf());

    var seen: usize = 0;
    while (peer.pollEvent()) |event| switch (event) {
        .binary => |message| {
            try std.testing.expectEqual(@as(usize, 48), message.data.len);
            try std.testing.expectEqual(if (seen == 0) @as(u8, 'a') else 'b', message.data[0]);
            seen += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(usize, 2), seen);
    try std.testing.expectEqual(@as(usize, 0), peer.event_arena_used);
}

test "small inbound messages stage in the channel pool without allocating" {
    const allocator = std.testing.allocator;
    var storage: NativeDataChannel = undefined;
    storage = .{ .allocator = allocator, .channel = undefined, .kind = .reliable };

    storage.pushOwned(try allocator.dupe(u8, "eight byte"), true);
    storage.pushOwned(try allocator.dupe(u8, "second"), true);

    const first = (try storage.wrapper().poll()).?.binary;
    try std.testing.expectEqualStrings("eight byte", first);
    try std.testing.expect(@intFromPtr(first.ptr) >= @intFromPtr(&storage.pool));
    try std.testing.expect(@intFromPtr(first.ptr) < @intFromPtr(&storage.pool) + NativeDataChannel.pool_bytes);

    const second = (try storage.wrapper().poll()).?.binary;
    try std.testing.expectEqualStrings("second", second);
    // The pool is handed back at the start of the next call, which is the moment the
    // borrow above stops being valid and the ring is known to be empty.
    try std.testing.expect((try storage.wrapper().poll()) == null);
    try std.testing.expectEqual(@as(usize, 0), storage.pool_used);
}

test "a message past the channel pool falls back to the heap and is released" {
    const allocator = std.testing.allocator;
    var storage: NativeDataChannel = undefined;
    storage = .{ .allocator = allocator, .channel = undefined, .kind = .reliable };

    const big = try allocator.alloc(u8, NativeDataChannel.pool_bytes + 1);
    @memset(big, 0x7a);
    storage.pushOwned(big, true);

    const message = (try storage.wrapper().poll()).?.binary;
    try std.testing.expectEqual(big.len, message.len);
    try std.testing.expectEqual(@as(u8, 0x7a), message[0]);
    try std.testing.expect(@intFromPtr(message.ptr) < @intFromPtr(&storage.pool) or
        @intFromPtr(message.ptr) >= @intFromPtr(&storage.pool) + NativeDataChannel.pool_bytes);

    _ = try storage.wrapper().poll();
}

test "a full ring of small messages stays inside the channel pool" {
    const allocator = std.testing.allocator;
    var storage: NativeDataChannel = undefined;
    storage = .{ .allocator = allocator, .channel = undefined, .kind = .reliable };

    for (0..63) |index| {
        const message = try allocator.alloc(u8, 60);
        @memset(message, @intCast(index));
        storage.pushOwned(message, true);
    }

    var count: usize = 0;
    while (try storage.wrapper().poll()) |event| {
        const message = event.binary;
        try std.testing.expectEqual(@as(usize, 60), message.len);
        try std.testing.expect(@intFromPtr(message.ptr) >= @intFromPtr(&storage.pool));
        try std.testing.expect(@intFromPtr(message.ptr) < @intFromPtr(&storage.pool) + NativeDataChannel.pool_bytes);
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 63), count);
    try std.testing.expectEqual(@as(usize, 0), storage.pool_used);
}

test "the client's offer decides which families ICE binds" {
    const ipv4_only = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
        "a=candidate:1 1 udp 2130706431 192.168.1.5 50000 typ host\r\n";
    const v4 = familiesFromOffer(ipv4_only);
    try std.testing.expect(v4.ip4);
    try std.testing.expect(!v4.ip6);

    const dual = "a=candidate:1 1 udp 2130706431 192.168.1.5 50000 typ host\r\n" ++
        "a=candidate:2 1 udp 2130706430 2a0c:5a87::1 50000 typ host\r\n";
    const both = familiesFromOffer(dual);
    try std.testing.expect(both.ip4);
    try std.testing.expect(both.ip6);

    const none = familiesFromOffer("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    try std.testing.expect(none.ip4);
    try std.testing.expect(!none.ip6);
}

test "link-local IPv6 addresses are not offered as candidates" {
    const link_local: std.Io.net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 0,
    } };
    try std.testing.expect(isIpv6LinkLocal(link_local));

    const global: std.Io.net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x2a, 0x0c, 0x5a, 0x87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .port = 0,
    } };
    try std.testing.expect(!isIpv6LinkLocal(global));
}
