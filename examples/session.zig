const std = @import("std");
const nethernet = @import("nethernet");

pub const std_options: std.Options = nethernet.log.options;

pub fn main(init: std.process.Init) !void {
    const session = try nethernet.Session.create(init.io, init.gpa, .{ .network_id = "example" });
    defer session.destroy();

    try session.send(.reliable, "hello nethernet");
    try session.send(.unreliable, "fire and forget");

    while (try session.poll()) |packet| {
        defer session.release(packet);
        std.debug.print("{s}: {s}\n", .{ @tagName(packet.reliability), packet.data });
    }
}
