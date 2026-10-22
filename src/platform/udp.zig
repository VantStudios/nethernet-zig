const std = @import("std");
const builtin = @import("builtin");

const log = @import("../log.zig");

const Io = std.Io;
const linux = std.os.linux;
const ws2_32 = std.os.windows.ws2_32;

const Flavor = enum { linux, libc, winsock, io };

const libc_sockets = builtin.link_libc and switch (builtin.os.tag) {
    .driverkit,
    .ios,
    .maccatalyst,
    .macos,
    .tvos,
    .visionos,
    .watchos,
    .freebsd,
    .netbsd,
    .openbsd,
    .dragonfly,
    => true,
    else => false,
};

const flavor: Flavor = if (builtin.os.tag == .linux)
    .linux
else if (builtin.os.tag == .windows)
    .winsock
else if (libc_sockets)
    .libc
else
    .io;

const Wire = extern struct {
    family: u16 = 2, // AF_INET
    port: u16,
    addr: u32,
    zero: [8]u8 = @splat(0),
};

pub const Address = switch (flavor) {
    .linux => linux.sockaddr.in,
    .libc => std.c.sockaddr.in,
    .winsock => ws2_32.sockaddr.in,
    .io => Wire,
};

pub const Socket = struct {
    io: Io,
    handle: Handle,

    const Handle = switch (flavor) {
        .linux, .libc => std.posix.fd_t,
        .winsock => Winsock.SOCKET,
        .io => Io.net.Socket,
    };

    pub const Options = struct {
        address: u32 = 0,
        port: u16,
        reuse_address: bool = true,
        broadcast: bool = false,
    };

    pub const OpenError = error{
        AddressInUse,
        AddressUnavailable,
        SocketCreateFailed,
        BindFailed,
    };

    pub const SendError = error{SendFailed};
    pub const ReceiveError = error{ReceiveFailed};

    pub const Datagram = struct {
        len: usize,
        from: Address,
    };

    pub fn open(io: Io, options: Options) OpenError!Socket {
        return switch (comptime flavor) {
            .linux => openLinux(io, options),
            .libc => openLibc(io, options),
            .winsock => openWinsock(io, options),
            .io => openIo(io, options),
        };
    }

    fn openLinux(io: Io, options: Options) OpenError!Socket {
        const raw = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK, 0);
        if (linux.errno(raw) != .SUCCESS) return error.SocketCreateFailed;
        const fd: i32 = @bitCast(@as(u32, @truncate(raw)));
        errdefer _ = linux.close(fd);

        if (options.reuse_address) {
            setLinuxOption(fd, linux.SO.REUSEADDR);
            setLinuxOption(fd, linux.SO.REUSEPORT);
        }
        if (options.broadcast) setLinuxOption(fd, linux.SO.BROADCAST);

        const address: Address = .{
            .port = std.mem.nativeToBig(u16, options.port),
            .addr = options.address,
        };
        return switch (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(linux.sockaddr.in)))) {
            .SUCCESS => .{ .io = io, .handle = fd },
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressUnavailable,
            else => error.BindFailed,
        };
    }

    fn setLinuxOption(fd: i32, name: u32) void {
        var value: i32 = 1;
        const rc = linux.setsockopt(fd, linux.SOL.SOCKET, name, @ptrCast(&value), @sizeOf(i32));
        if (linux.errno(rc) != .SUCCESS) log.debug("UDP socket option {d} refused by the kernel", .{name});
    }

    fn openLibc(io: Io, options: Options) OpenError!Socket {
        const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.DGRAM, 0);
        if (fd < 0) return error.SocketCreateFailed;
        errdefer _ = std.c.close(fd);

        if (options.reuse_address) {
            setLibcOption(fd, std.c.SO.REUSEADDR);
            setLibcOption(fd, std.c.SO.REUSEPORT);
        }
        if (options.broadcast) setLibcOption(fd, std.c.SO.BROADCAST);

        const address: Address = .{
            .port = std.mem.nativeToBig(u16, options.port),
            .addr = options.address,
        };
        const rc = std.c.bind(fd, @ptrCast(&address), @sizeOf(Address));
        if (rc != 0) return switch (std.posix.errno(rc)) {
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressUnavailable,
            else => error.BindFailed,
        };
        return .{ .io = io, .handle = fd };
    }

    fn setLibcOption(fd: std.c.fd_t, name: u32) void {
        var value: c_int = 1;
        if (std.c.setsockopt(fd, std.c.SOL.SOCKET, name, &value, @sizeOf(c_int)) != 0) {
            log.debug("UDP socket option {d} refused: {s}", .{ name, @tagName(std.posix.errno(@as(c_int, -1))) });
        }
    }

    fn openWinsock(io: Io, options: Options) OpenError!Socket {
        if (!Winsock.start()) return error.SocketCreateFailed;
        const handle = Winsock.socket(Winsock.af_inet, Winsock.sock_dgram, 0);
        if (handle == Winsock.invalid) return error.SocketCreateFailed;
        errdefer _ = Winsock.closesocket(handle);

        if (options.reuse_address) Winsock.setOption(handle, ws2_32.SO.REUSEADDR);
        if (options.broadcast) Winsock.setOption(handle, ws2_32.SO.BROADCAST);
        var nonblocking: u32 = 1;
        _ = Winsock.ioctlsocket(handle, Winsock.fionbio, &nonblocking);

        const address: Address = .{
            .port = std.mem.nativeToBig(u16, options.port),
            .addr = options.address,
        };
        if (Winsock.bind(handle, @ptrCast(&address), @sizeOf(Address)) != 0) {
            const code = Winsock.lastError();
            return if (code == Winsock.addr_in_use or code == Winsock.access)
                error.AddressInUse
            else
                error.BindFailed;
        }
        return .{ .io = io, .handle = handle };
    }

    fn openIo(io: Io, options: Options) OpenError!Socket {
        const ip: Io.net.IpAddress = .{ .ip4 = .{
            .bytes = @bitCast(options.address),
            .port = options.port,
        } };
        const socket = ip.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
            .allow_broadcast = options.broadcast,
        }) catch |err| return switch (err) {
            error.AddressInUse => error.AddressInUse,
            error.AddressUnavailable => error.AddressUnavailable,
            error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => error.SocketCreateFailed,
            else => error.BindFailed,
        };
        return .{ .io = io, .handle = socket };
    }

    pub fn close(self: *Socket) void {
        switch (comptime flavor) {
            .linux => _ = linux.close(self.handle),
            .libc => _ = std.c.close(self.handle),
            .winsock => _ = Winsock.closesocket(self.handle),
            .io => self.handle.close(self.io),
        }
    }

    pub fn send(self: *const Socket, destination: Address, frame: []const u8) SendError!void {
        switch (comptime flavor) {
            .linux => {
                const result = linux.sendto(self.handle, frame.ptr, frame.len, 0, @ptrCast(&destination), @sizeOf(linux.sockaddr.in));
                if (linux.errno(result) != .SUCCESS) return error.SendFailed;
            },
            .libc => {
                const result = std.c.sendto(self.handle, frame.ptr, frame.len, std.c.MSG.DONTWAIT, @ptrCast(&destination), @sizeOf(Address));
                if (result < 0) return error.SendFailed;
            },
            .winsock => {
                const result = Winsock.sendto(self.handle, frame.ptr, @intCast(frame.len), 0, @ptrCast(&destination), @sizeOf(Address));
                if (result < 0) return error.SendFailed;
            },
            .io => {
                const ip = toIpAddress(destination);
                self.handle.send(self.io, &ip, frame) catch return error.SendFailed;
            },
        }
    }

    pub fn receive(self: *const Socket, buffer: []u8) ReceiveError!?Datagram {
        switch (comptime flavor) {
            .linux => {
                var source: linux.sockaddr = undefined;
                var source_len: linux.socklen_t = @sizeOf(linux.sockaddr);
                const raw = linux.recvfrom(self.handle, buffer.ptr, buffer.len, 0, &source, &source_len);
                return switch (linux.errno(raw)) {
                    .SUCCESS => .{ .len = @intCast(raw), .from = @bitCast(source) },
                    .AGAIN, .CONNRESET => null,
                    else => error.ReceiveFailed,
                };
            },
            .libc => {
                var source: Address = undefined;
                var source_len: std.c.socklen_t = @sizeOf(Address);
                // Darwin rejects `SOCK_NONBLOCK` in `socket()`, so the send and the
                // receive carry the per-call non-blocking flag instead.
                const rc = std.c.recvfrom(self.handle, buffer.ptr, buffer.len, std.c.MSG.DONTWAIT, @ptrCast(&source), &source_len);
                if (rc >= 0) return .{ .len = @intCast(rc), .from = source };
                return switch (std.posix.errno(rc)) {
                    .AGAIN, .CONNRESET, .CONNREFUSED => null,
                    else => error.ReceiveFailed,
                };
            },
            .winsock => {
                var source: Address = undefined;
                var source_len: c_int = @sizeOf(Address);
                const rc = Winsock.recvfrom(self.handle, buffer.ptr, @intCast(buffer.len), 0, @ptrCast(&source), &source_len);
                if (rc >= 0) return .{ .len = @intCast(rc), .from = source };
                const code = Winsock.lastError();
                if (code == Winsock.would_block or code == Winsock.conn_reset or code == Winsock.timed_out) return null;
                return error.ReceiveFailed;
            },
            .io => {
                const message = self.handle.receiveTimeout(self.io, buffer, .{ .duration = .{ .raw = .zero, .clock = .awake } }) catch |err| return switch (err) {
                    error.Timeout, error.PortUnreachable => null,
                    else => error.ReceiveFailed,
                };
                return .{ .len = message.data.len, .from = fromIncoming(message) };
            },
        }
    }

    fn fromIncoming(message: Io.net.IncomingMessage) Address {
        return switch (message.from) {
            .ip4 => |ip4| .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            },
            .ip6 => .{ .port = 0, .addr = 0 },
        };
    }

    fn toIpAddress(address: Address) Io.net.IpAddress {
        return .{
            .ip4 = .{
                .bytes = @bitCast(address.addr),
                .port = std.mem.bigToNative(u16, address.port),
            },
        };
    }
};

const Winsock = struct {
    /// `SOCKET` is a pointer-sized handle, and `INVALID_SOCKET` is every bit set.
    const SOCKET = usize;
    const invalid: SOCKET = ~@as(usize, 0);
    const af_inet = 2;
    const sock_dgram = 2;
    /// `FIONBIO` sets or clears non-blocking mode; `c_long` is signed, so the bit
    /// pattern is spelled out rather than the value a `u_long` would carry.
    const fionbio: c_long = @bitCast(@as(u32, 0x8004667e));
    const version: u16 = 0x0202;
    const would_block: c_int = 10035;
    const timed_out: c_int = 10060;
    const conn_reset: c_int = 10054;
    const access: c_int = 10013;
    const addr_in_use: c_int = 10048;

    extern "ws2_32" fn WSAStartup(requested: u16, data: *anyopaque) callconv(.winapi) c_int;
    extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    extern "ws2_32" fn socket(af: c_int, kind: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    extern "ws2_32" fn bind(s: SOCKET, name: *const ws2_32.sockaddr, name_len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, name: c_int, value: *const c_int, value_len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn sendto(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int, to: *const ws2_32.sockaddr, to_len: c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn recvfrom(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int, from: *ws2_32.sockaddr, from_len: *c_int) callconv(.winapi) c_int;
    extern "ws2_32" fn ioctlsocket(s: SOCKET, command: c_long, argument: *u32) callconv(.winapi) c_int;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;

    var started = std.atomic.Value(bool).init(false);

    /// Winsock must be up before the first socket exists; it is reference counted, so
    /// a racing second call is not a problem.
    fn start() bool {
        if (started.load(.acquire)) return true;
        var data: [512]u8 align(8) = undefined;
        if (WSAStartup(version, @ptrCast(&data)) != 0) return false;
        started.store(true, .release);
        return true;
    }

    fn setOption(s: SOCKET, name: c_int) void {
        var value: c_int = 1;
        if (setsockopt(s, ws2_32.SOL.SOCKET, name, &value, @sizeOf(c_int)) != 0) {
            log.debug("UDP socket option {d} refused by Winsock", .{name});
        }
    }

    fn lastError() c_int {
        return WSAGetLastError();
    }
};

test "a datagram survives a round trip through two bound sockets" {
    const port: u16 = 19_971;
    var server = try Socket.open(std.testing.io, .{ .address = loopback(), .port = port });
    defer server.close();
    var client = try Socket.open(std.testing.io, .{ .address = loopback(), .port = 0 });
    defer client.close();

    const destination: Address = .{ .port = std.mem.nativeToBig(u16, port), .addr = loopback() };
    try client.send(destination, "ping");

    var buffer: [64]u8 = undefined;
    var datagram: ?Socket.Datagram = null;
    var attempts: usize = 0;
    while (datagram == null and attempts < 200) : (attempts += 1) {
        datagram = try server.receive(&buffer);
        if (datagram == null) try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    const received = datagram orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("ping", buffer[0..received.len]);
    try std.testing.expectEqual(loopback(), received.from.addr);
    try std.testing.expect(received.from.port != 0);
}

test "a port bound without reuse is refused to a second socket" {
    const port: u16 = 19_972;
    var first = try Socket.open(std.testing.io, .{ .address = loopback(), .port = port, .reuse_address = false });
    defer first.close();

    const second = Socket.open(std.testing.io, .{ .address = loopback(), .port = port });
    try std.testing.expectError(error.AddressInUse, second);
}

test "a port is shared when both sides ask for it, in either order" {
    const first_port: u16 = 19_973;
    var ours = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = first_port });
    defer ours.close();
    var other = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = first_port });
    defer other.close();

    const second_port: u16 = 19_974;
    var other_first = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = second_port });
    defer other_first.close();
    var ours_second = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = second_port });
    defer ours_second.close();
}

test "a broadcast reaches every socket sharing the port" {
    if (comptime flavor != .linux) return error.SkipZigTest;
    const port: u16 = 19_975;
    var first = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = port, .broadcast = true });
    defer first.close();
    var second = try Socket.open(std.testing.io, .{ .address = wildcard(), .port = port, .broadcast = true });
    defer second.close();
    var sender = try Socket.open(std.testing.io, .{ .address = loopback(), .port = 0, .broadcast = true });
    defer sender.close();

    try sender.send(.{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7fffffff) }, "lan");

    var buffer: [64]u8 = undefined;
    var seen: usize = 0;
    var attempts: usize = 0;
    while (seen < 2 and attempts < 500) : (attempts += 1) {
        if (try first.receive(&buffer)) |datagram| {
            try std.testing.expectEqualStrings("lan", buffer[0..datagram.len]);
            seen += 1;
        }
        if (try second.receive(&buffer)) |datagram| {
            try std.testing.expectEqualStrings("lan", buffer[0..datagram.len]);
            seen += 1;
        }
        if (seen < 2) try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    try std.testing.expectEqual(@as(usize, 2), seen);
}

fn loopback() u32 {
    return std.mem.nativeToBig(u32, 0x7f000001);
}

fn wildcard() u32 {
    return 0;
}
