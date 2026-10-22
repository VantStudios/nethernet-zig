const std = @import("std");
const discovery = @import("../discovery.zig");

pub const max_dump = 128;

pub fn prefix(data: []const u8) []const u8 {
    return data[0..@min(data.len, max_dump)];
}

pub const HexBuffer = [max_dump * 2]u8;

pub fn hex(buffer: []u8, data: []const u8) []const u8 {
    return discovery.encodeHexLower(buffer, prefix(data));
}

test "the wire hex clamps to the leading bytes" {
    var buffer: HexBuffer = undefined;
    try std.testing.expectEqualStrings("0a1b2c", hex(&buffer, &[_]u8{ 0x0a, 0x1b, 0x2c }));
    try std.testing.expectEqualStrings("", hex(&buffer, &.{}));

    var payload: [max_dump + 3]u8 = undefined;
    @memset(&payload, 0xab);
    const encoded = hex(&buffer, &payload);
    try std.testing.expectEqual(max_dump * 2, encoded.len);
    try std.testing.expectEqualStrings("ab", encoded[0..2]);
    try std.testing.expectEqualStrings("ab", encoded[encoded.len - 2 ..]);
}
