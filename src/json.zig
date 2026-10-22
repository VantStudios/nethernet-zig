const std = @import("std");

pub fn writeString(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => if (byte < 0x20) {
            try writer.print("\\u00{x:0>2}", .{byte});
        } else {
            try writer.writeByte(byte);
        },
    };
}

pub fn isValidUtf8(value: []const u8) bool {
    return std.unicode.utf8ValidateSlice(value);
}

test "escaped strings decode back to the original bytes" {
    const hostile = "A\"B\\C\nD\rE\tF\x01G";
    var buffer: [128]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try writer.writeByte('"');
    try writeString(&writer, hostile);
    try writer.writeByte('"');

    const parsed = try std.json.parseFromSlice([]const u8, std.testing.allocator, writer.buffered(), .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(hostile, parsed.value);
}

test "invalid utf-8 is reported" {
    try std.testing.expect(isValidUtf8("plain ascii"));
    try std.testing.expect(isValidUtf8("ñandú \xf0\x9f\x8e\xae"));
    try std.testing.expect(!isValidUtf8("bad \xff"));
}
