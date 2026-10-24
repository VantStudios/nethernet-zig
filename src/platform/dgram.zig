//! Unicast datagram sockets for the peer's ICE/DTLS/SCTP plane.
//!
//! The peer needs a socket it can *poll*: `receive` must return `null` when nothing
//! is queued, because it is called from a tick that must never wait. `std.Io.net`'s
//! `receiveTimeout` is the obvious API, but on Windows every timed receive is a
//! "concurrent" operation, and `std.Io.Threaded` has not implemented one for a
//! socket yet:
//!
//!     .net_receive => |*o| {
//!         // TODO integrate with overlapped I/O or equivalent to avoid this error
//!         if (concurrency) return error.ConcurrencyUnavailable;
//!
//! The call fails for every datagram — with data queued or not, with a zero or a
//! nonzero timeout — so a peer built on it is deaf on Windows and the WebRTC
//! handshake can never complete. This module drives Winsock itself there, with a
//! genuinely non-blocking socket; everywhere else `std.Io.net` keeps the timed
//! receive it already implements.
//!
//! Addresses are `std.Io.net.IpAddress` in both flavors, so the ICE agent sees no
//! difference.

const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const IpAddress = Io.net.IpAddress;

pub const Error = error{
    SocketCreateFailed,
    BindFailed,
    ReceiveFailed,
    SendFailed,
};

/// A datagram together with the address it came from. `data` borrows the buffer
/// passed to `receive`.
pub const Incoming = struct {
    data: []u8,
    from: IpAddress,
};

pub const Socket = if (builtin.os.tag == .windows) WindowsSocket else StdSocket;

/// Non-Windows: the std socket's timed receive works, and a zero timeout is the
/// poll the tick needs.
const StdSocket = struct {
    io: Io,
    handle: Io.net.Socket,
    address: IpAddress,

    pub fn bind(io: Io, address: IpAddress) Error!StdSocket {
        const handle = address.bind(io, .{ .mode = .dgram }) catch return error.BindFailed;
        return .{ .io = io, .handle = handle, .address = handle.address };
    }

    pub fn receive(self: *const StdSocket, io: Io, buffer: []u8) Error!?Incoming {
        const timeout: Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .zero } };
        const message = self.handle.receiveTimeout(io, buffer, timeout) catch |err| switch (err) {
            // A stale ICMP port-unreachable is "nothing arrived", not a dead socket.
            error.Timeout, error.PortUnreachable => return null,
            else => return error.ReceiveFailed,
        };
        return .{ .data = message.data, .from = message.from };
    }

    pub fn send(self: *const StdSocket, io: Io, to: *const IpAddress, data: []const u8) Error!void {
        self.handle.send(io, to, data) catch return error.SendFailed;
    }

    pub fn close(self: *StdSocket, io: Io) void {
        self.handle.close(io);
    }
};

/// Windows: Winsock, created and driven here because the std backend refuses a
/// timed receive. The socket is non-blocking, so `receive` is a real poll.
const WindowsSocket = struct {
    io: Io,
    handle: Win.SOCKET,
    address: IpAddress,

    pub fn bind(io: Io, address: IpAddress) Error!WindowsSocket {
        if (!Win.start()) return error.SocketCreateFailed;

        const family: c_int = switch (address) {
            .ip4 => Win.af_inet,
            .ip6 => Win.af_inet6,
        };
        const handle = Win.socket(family, Win.sock_dgram, Win.ipproto_udp);
        if (handle == Win.invalid) return error.SocketCreateFailed;
        errdefer _ = Win.closesocket(handle);

        var nonblocking: u32 = 1;
        if (Win.ioctlsocket(handle, Win.fionbio, &nonblocking) != 0) return error.SocketCreateFailed;

        var target: Win.AddressStorage = undefined;
        const to = Win.sockaddrOf(address, &target);
        if (Win.bind(handle, to.ptr, to.len) != 0) return error.BindFailed;

        // Port 0 lets the system pick; the candidate the ICE agent advertises has
        // to carry the port it actually chose.
        var bound: Win.AddressStorage = undefined;
        var bound_len: c_int = @sizeOf(Win.AddressStorage);
        if (Win.getsockname(handle, @ptrCast(&bound), &bound_len) != 0) return error.BindFailed;
        const local = Win.fromSockaddr(@ptrCast(&bound)) orelse return error.BindFailed;

        return .{ .io = io, .handle = handle, .address = local };
    }

    pub fn receive(self: *const WindowsSocket, io: Io, buffer: []u8) Error!?Incoming {
        _ = io;
        var source: Win.AddressStorage = undefined;
        var source_len: c_int = @sizeOf(Win.AddressStorage);
        const count = Win.recvfrom(
            self.handle,
            buffer.ptr,
            @intCast(buffer.len),
            0,
            @ptrCast(&source),
            &source_len,
        );
        if (count < 0) {
            return switch (Win.lastError()) {
                Win.would_block, Win.conn_reset, Win.timed_out => null,
                else => error.ReceiveFailed,
            };
        }
        const from = Win.fromSockaddr(@ptrCast(&source)) orelse return null;
        return .{ .data = buffer[0..@intCast(count)], .from = from };
    }

    pub fn send(self: *const WindowsSocket, io: Io, to: *const IpAddress, data: []const u8) Error!void {
        _ = io;
        var target: Win.AddressStorage = undefined;
        const address = Win.sockaddrOf(to.*, &target);
        const count = Win.sendto(self.handle, data.ptr, @intCast(data.len), 0, address.ptr, address.len);
        if (count >= 0) return;
        return switch (Win.lastError()) {
            // UDP is best effort: a full buffer or an ICMP rejection of an earlier
            // datagram must not tear the association down.
            Win.would_block, Win.conn_reset, Win.timed_out => {},
            else => error.SendFailed,
        };
    }

    pub fn close(self: *WindowsSocket, io: Io) void {
        _ = io;
        if (self.handle != Win.invalid) _ = Win.closesocket(self.handle);
        self.handle = Win.invalid;
    }
};

/// The calls and layouts the Windows flavor needs. `std.os.windows.ws2_32` only
/// carries the constants and structs, not the functions.
const Win = struct {
    const SOCKET = usize;
    const invalid: SOCKET = ~@as(usize, 0);
    const af_inet: c_int = 2;
    const af_inet6: c_int = 23;
    const sock_dgram: c_int = 2;
    const ipproto_udp: c_int = 17;
    const fionbio: c_long = @bitCast(@as(u32, 0x8004667e));
    const would_block: c_int = 10035;
    const conn_reset: c_int = 10054;
    const timed_out: c_int = 10060;

    const AddressStorage = std.os.windows.ws2_32.sockaddr.storage;

    extern "ws2_32" fn WSAStartup(requested: u16, data: *anyopaque) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    extern "ws2_32" fn socket(af: c_int, kind: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    extern "ws2_32" fn bind(s: SOCKET, name: *const std.os.windows.ws2_32.sockaddr, name_len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn getsockname(s: SOCKET, name: *std.os.windows.ws2_32.sockaddr, name_len: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn sendto(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int, to: *const std.os.windows.ws2_32.sockaddr, to_len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recvfrom(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int, from: *std.os.windows.ws2_32.sockaddr, from_len: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn ioctlsocket(s: SOCKET, command: c_long, argument: *u32) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;

    var started = std.atomic.Value(bool).init(false);

    fn start() bool {
        if (started.load(.acquire)) return true;
        var data: [512]u8 align(8) = undefined;
        if (WSAStartup(0x0202, @ptrCast(&data)) != 0) return false;
        started.store(true, .release);
        return true;
    }

    fn lastError() c_int {
        return WSAGetLastError();
    }

    const Target = struct {
        ptr: *const std.os.windows.ws2_32.sockaddr,
        len: c_int,
    };

    fn sockaddrOf(address: IpAddress, storage: *AddressStorage) Target {
        switch (address) {
            .ip4 => |ip| {
                const sa: *std.os.windows.ws2_32.sockaddr.in = @ptrCast(storage);
                sa.* = .{
                    .port = std.mem.nativeToBig(u16, ip.port),
                    .addr = @bitCast(ip.bytes),
                };
                return .{ .ptr = @ptrCast(sa), .len = @sizeOf(std.os.windows.ws2_32.sockaddr.in) };
            },
            .ip6 => |ip| {
                const sa: *std.os.windows.ws2_32.sockaddr.in6 = @ptrCast(storage);
                sa.* = .{
                    .port = std.mem.nativeToBig(u16, ip.port),
                    .flowinfo = std.mem.nativeToBig(u32, ip.flow),
                    .addr = ip.bytes,
                    .scope_id = ip.interface.index,
                };
                return .{ .ptr = @ptrCast(sa), .len = @sizeOf(std.os.windows.ws2_32.sockaddr.in6) };
            },
        }
    }

    fn fromSockaddr(raw: *const std.os.windows.ws2_32.sockaddr) ?IpAddress {
        if (raw.family == af_inet) {
            const sa: *const std.os.windows.ws2_32.sockaddr.in = @ptrCast(@alignCast(raw));
            return .{ .ip4 = .{
                .bytes = @bitCast(sa.addr),
                .port = std.mem.bigToNative(u16, sa.port),
            } };
        }
        if (raw.family == af_inet6) {
            const sa: *const std.os.windows.ws2_32.sockaddr.in6 = @ptrCast(@alignCast(raw));
            return .{ .ip6 = .{
                .bytes = sa.addr,
                .port = std.mem.bigToNative(u16, sa.port),
                .flow = std.mem.bigToNative(u32, sa.flowinfo),
                .interface = .{ .index = sa.scope_id },
            } };
        }
        return null;
    }
};

test "a bound socket polls without blocking and reports the datagram's source" {
    const io = std.testing.io;
    var server = try Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer server.close(io);
    try std.testing.expect(server.address.ip4.port != 0);

    var client = try Socket.bind(io, .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } });
    defer client.close(io);

    var buffer: [64]u8 = undefined;
    try std.testing.expect(try server.receive(io, &buffer) == null);

    try client.send(io, &server.address, "ping");
    var attempt: usize = 0;
    var incoming: ?Incoming = null;
    while (incoming == null and attempt < 100) : (attempt += 1) {
        incoming = try server.receive(io, &buffer);
        if (incoming == null) io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    const message = incoming orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ping", message.data);
    try std.testing.expect(message.from.eql(&client.address));
}

test "IPv6 loopback is bound and receives too" {
    const io = std.testing.io;
    const loopback6: IpAddress = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } };
    var server = Socket.bind(io, loopback6) catch return error.SkipZigTest;
    defer server.close(io);
    var client = Socket.bind(io, loopback6) catch return error.SkipZigTest;
    defer client.close(io);

    var buffer: [64]u8 = undefined;
    try std.testing.expect(try server.receive(io, &buffer) == null);

    try client.send(io, &server.address, "ping6");
    var attempt: usize = 0;
    var incoming: ?Incoming = null;
    while (incoming == null and attempt < 100) : (attempt += 1) {
        incoming = try server.receive(io, &buffer);
        if (incoming == null) io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    const message = incoming orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ping6", message.data);
}
