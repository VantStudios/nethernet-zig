const std = @import("std");
const builtin = @import("builtin");

pub const options: std.Options = .{
    .log_level = if (builtin.mode == .Debug) .debug else .info,
};

pub const verbose = builtin.mode == .Debug and !builtin.is_test;

pub inline fn debug(comptime format: []const u8, args: anytype) void {
    if (comptime verbose) std.log.debug(format, args);
}

test "the log policy follows the build mode and never the test binary" {
    try std.testing.expectEqual(builtin.mode == .Debug and !builtin.is_test, verbose);
    try std.testing.expectEqual(if (builtin.mode == .Debug) std.log.Level.debug else std.log.Level.info, options.log_level);
}
