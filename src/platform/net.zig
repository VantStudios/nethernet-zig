const std = @import("std");
const builtin = @import("builtin");

pub const PeerKey = [16]u8;

pub const PeerKeyError = error{ Unsupported, Unavailable } || std.Io.Cancelable;

pub const peerKey = if (builtin.os.tag == .windows) peerKeyUnsupported else peerKeyStream;

fn peerKeyUnsupported(_: std.Io.net.Stream) PeerKeyError!PeerKey {
    return error.Unsupported;
}

fn peerKeyStream(stream: std.Io.net.Stream) PeerKeyError!PeerKey {
    return peerKeyPosix(stream.socket.handle);
}

fn peerKeyPosix(handle: std.posix.fd_t) PeerKeyError!PeerKey {
    var storage: std.posix.sockaddr.storage = undefined;
    var length: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(handle, @ptrCast(&storage), &length) catch return error.Unavailable;
    return mapAddress(&storage) orelse error.Unavailable;
}

fn mapAddress(storage: *const std.posix.sockaddr.storage) ?PeerKey {
    var key: PeerKey = @splat(0);
    switch (storage.family) {
        std.posix.AF.INET => {
            const address: *const std.posix.sockaddr.in = @ptrCast(storage);
            key[0] = 4;
            @memcpy(key[1..5], std.mem.asBytes(&address.addr));
        },
        std.posix.AF.INET6 => {
            const address: *const std.posix.sockaddr.in6 = @ptrCast(storage);
            key[0] = 6;
            @memcpy(key[1..9], address.addr[0..8]);
        },
        else => return null,
    }
    return key;
}

test "peer keys keep IPv4 whole and truncate IPv6 to its prefix" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;

    var storage: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    const v4: *std.posix.sockaddr.in = @ptrCast(&storage);
    v4.family = std.posix.AF.INET;
    v4.addr = std.mem.nativeToBig(u32, 0x7f000001);
    const key4 = mapAddress(&storage) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 4), key4[0]);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, key4[1..5]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 11), key4[5..16]);

    var storage6: std.posix.sockaddr.storage = std.mem.zeroes(std.posix.sockaddr.storage);
    const v6: *std.posix.sockaddr.in6 = @ptrCast(&storage6);
    v6.family = std.posix.AF.INET6;
    v6.addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const key6 = mapAddress(&storage6) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 6), key6[0]);
    try std.testing.expectEqualSlices(u8, v6.addr[0..8], key6[1..9]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 7), key6[9..16]);
}
