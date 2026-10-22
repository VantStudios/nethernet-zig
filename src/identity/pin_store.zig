const std = @import("std");
const json_text = @import("../json.zig");

const max_file_bytes = 1024 * 1024;
const digest_length = std.crypto.hash.sha2.Sha256.digest_length;

pub const Error = error{
    InvalidPinStore,
    UnknownOperatorKey,
    OperatorKeyChanged,
} || std.mem.Allocator.Error || std.Io.Writer.Error ||
    std.Io.File.Writer.Error || std.Io.File.OpenError ||
    std.Io.Dir.ReadFileAllocError || std.Io.Dir.CreateFileAtomicError ||
    std.Io.File.Atomic.ReplaceError;

pub const max_domain_bytes = 255;

pub const Pin = struct {
    domain: [max_domain_bytes]u8 = undefined,
    domain_len: usize = 0,
    sha256: [digest_length]u8,
    first_seen: i64,
    last_seen: i64,

    pub fn domainName(self: Pin) []const u8 {
        return self.domain[0..self.domain_len];
    }
};

pub const Options = struct {
    path: ?[]const u8 = null,
};

pub const PinStore = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    mutex: std.Io.Mutex = .init,
    pins: std.AutoHashMapUnmanaged([digest_length]u8, Pin) = .empty,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, options: Options) Error!PinStore {
        return .{
            .io = io,
            .allocator = allocator,
            .path = if (options.path) |path| try allocator.dupe(u8, path) else null,
        };
    }

    pub fn deinit(self: *PinStore) void {
        self.mutex.lockUncancelable(self.io);
        self.clear();
        self.pins.deinit(self.allocator);
        self.mutex.unlock(self.io);
        if (self.path) |path| self.allocator.free(path);
        self.* = undefined;
    }

    fn clear(self: *PinStore) void {
        self.pins.clearRetainingCapacity();
    }

    pub fn count(self: *PinStore) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pins.count();
    }

    pub fn lookup(self: *PinStore, digest: [digest_length]u8) ?Pin {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.pins.get(digest);
    }

    pub fn hasDomain(self: *PinStore, domain: []const u8) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.hasDomainLocked(domain);
    }

    fn hasDomainLocked(self: *PinStore, domain: []const u8) bool {
        var iterator = self.pins.valueIterator();
        while (iterator.next()) |pin| {
            if (std.mem.eql(u8, pin.domainName(), domain)) return true;
        }
        return false;
    }

    pub fn remember(self: *PinStore, digest: [digest_length]u8, domain: []const u8, now: i64) Error!void {
        if (!validDomain(domain)) return error.InvalidPinStore;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.pins.getPtr(digest)) |pin| {
            pin.last_seen = now;
            return;
        }
        var pin = Pin{ .sha256 = digest, .domain_len = domain.len, .first_seen = now, .last_seen = now };
        @memcpy(pin.domain[0..domain.len], domain);
        try self.pins.put(self.allocator, digest, pin);
    }

    pub fn require(self: *PinStore, digest: [digest_length]u8, domain: []const u8, allow_change: bool) Error!bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.pins.get(digest)) |pin| {
            if (!std.mem.eql(u8, pin.domainName(), domain)) return error.OperatorKeyChanged;
            return true;
        }
        if (!allow_change and self.hasDomainLocked(domain)) return error.OperatorKeyChanged;
        return error.UnknownOperatorKey;
    }

    pub fn forget(self: *PinStore, digest: [digest_length]u8) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.forgetLocked(digest);
    }

    fn forgetLocked(self: *PinStore, digest: [digest_length]u8) Error!void {
        _ = self.pins.fetchRemove(digest) orelse return error.UnknownOperatorKey;
    }

    pub fn reset(self: *PinStore) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.clear();
        if (self.path) |_| try self.saveLocked();
    }

    pub fn load(self: *PinStore) Error!void {
        const path = self.path orelse return;
        const bytes = std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(max_file_bytes)) catch |err| switch (err) {
            error.FileNotFound => return,
            error.StreamTooLong => return error.InvalidPinStore,
            else => return err,
        };
        defer self.allocator.free(bytes);

        const parsed = std.json.parseFromSlice(Stored, self.allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.InvalidPinStore;
        defer parsed.deinit();
        if (parsed.value.version != 1) return error.InvalidPinStore;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.clear();
        for (parsed.value.pins) |stored| {
            const digest = parseDigest(stored.sha256) orelse return error.InvalidPinStore;
            if (self.pins.contains(digest) or !validDomain(stored.domain)) return error.InvalidPinStore;
            var pin = Pin{
                .sha256 = digest,
                .domain_len = stored.domain.len,
                .first_seen = stored.first_seen,
                .last_seen = stored.last_seen,
            };
            @memcpy(pin.domain[0..stored.domain.len], stored.domain);
            try self.pins.put(self.allocator, digest, pin);
        }
    }

    pub fn save(self: *PinStore) Error!void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.path == null) return;
        try self.saveLocked();
    }

    fn saveLocked(self: *PinStore) Error!void {
        const path = self.path orelse return;
        var buffer: std.Io.Writer.Allocating = .init(self.allocator);
        defer buffer.deinit();
        const writer = &buffer.writer;
        try writer.writeAll("{\"version\":1,\"pins\":[");
        var first = true;
        var iterator = self.pins.iterator();
        while (iterator.next()) |entry| {
            const pin = entry.value_ptr.*;
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.writeAll("{\"domain\":\"");
            try json_text.writeString(writer, pin.domainName());
            try writer.writeByte('"');
            const hex = std.fmt.bytesToHex(pin.sha256, .lower);
            try writer.print(",\"sha256\":\"{s}\",\"first_seen\":{d},\"last_seen\":{d}", .{ hex[0..], pin.first_seen, pin.last_seen });
            try writer.writeByte('}');
        }
        try writer.writeAll("]}");

        const permissions: std.Io.File.Permissions = if (@import("builtin").os.tag == .windows)
            .default_file
        else
            .fromMode(0o600);
        var atomic = try std.Io.Dir.cwd().createFileAtomic(self.io, path, .{ .permissions = permissions, .replace = true });
        defer atomic.deinit(self.io);
        try atomic.file.writeStreamingAll(self.io, buffer.written());
        try atomic.replace(self.io);
    }
};

const StoredPin = struct {
    domain: []const u8,
    sha256: []const u8,
    first_seen: i64 = 0,
    last_seen: i64 = 0,
};

const Stored = struct {
    version: u32,
    pins: []const StoredPin,
};

fn parseDigest(text: []const u8) ?[digest_length]u8 {
    if (text.len != digest_length * 2) return null;
    var digest: [digest_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, text) catch return null;
    return digest;
}

fn validDomain(domain: []const u8) bool {
    if (domain.len == 0 or domain.len > 255) return false;
    for (domain) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    return true;
}

const testing = std.testing;

fn testStorePath(buffer: []u8) ![]const u8 {
    var random: [8]u8 = undefined;
    testing.io.random(&random);
    const suffix = std.fmt.bytesToHex(random, .lower);
    return std.fmt.bufPrint(buffer, ".zig-cache/nethernet-pins-{s}.json", .{suffix[0..]});
}

fn testDigest(seed: u8) [digest_length]u8 {
    return [_]u8{seed} ** digest_length;
}

test "a pin survives a save and a reload" {
    var path_buffer: [128]u8 = undefined;
    const path = try testStorePath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(testing.io, path) catch {};

    var store = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer store.deinit();

    try store.remember(testDigest(0x11), "self", 100);
    try store.save();

    var reloaded = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer reloaded.deinit();
    try reloaded.load();

    const pin = reloaded.lookup(testDigest(0x11)).?;
    try testing.expectEqualStrings("self", pin.domainName());
    try testing.expectEqual(@as(i64, 100), pin.first_seen);
    try testing.expectEqual(@as(usize, 1), reloaded.count());
    try testing.expect(reloaded.hasDomain("self"));

    if (@import("builtin").os.tag != .windows) {
        const stat = try dir.statFile(testing.io, path, .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    }
}

test "a corrupt store is an error, never an empty store" {
    var path_buffer: [128]u8 = undefined;
    const path = try testStorePath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(testing.io, path) catch {};

    const corrupt = "{\"version\":1,\"pins\":[{\"domain\":\"self\",\"sha256\":\"not hex\"}]}";
    try dir.writeFile(testing.io, .{ .sub_path = path, .data = corrupt });

    var store = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer store.deinit();
    try testing.expectError(error.InvalidPinStore, store.load());

    var wrong_version = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer wrong_version.deinit();
    try dir.writeFile(testing.io, .{ .sub_path = path, .data = "{\"version\":2,\"pins\":[]}" });
    try testing.expectError(error.InvalidPinStore, wrong_version.load());

    const after = try dir.readFileAlloc(testing.io, path, testing.allocator, .limited(256));
    defer testing.allocator.free(after);
    try testing.expectEqualStrings("{\"version\":2,\"pins\":[]}", after);
}

test "a missing store file is an empty store, and memory-only stores never touch disk" {
    var store = try PinStore.init(testing.io, testing.allocator, .{ .path = ".zig-cache/nethernet-pins-absent.json" });
    defer store.deinit();
    try store.load();
    try testing.expectEqual(@as(usize, 0), store.count());

    var memory = try PinStore.init(testing.io, testing.allocator, .{});
    defer memory.deinit();
    try memory.remember(testDigest(0x22), "self", 7);
    try memory.save();
    try testing.expectEqual(@as(usize, 1), memory.count());
}

test "an unknown key, a rotated key and a changed domain are told apart" {
    var store = try PinStore.init(testing.io, testing.allocator, .{});
    defer store.deinit();

    try testing.expectError(error.UnknownOperatorKey, store.require(testDigest(0x33), "self", false));
    try testing.expectError(error.UnknownOperatorKey, store.require(testDigest(0x33), "self", true));

    try store.remember(testDigest(0x33), "self", 10);
    try testing.expectEqual(true, try store.require(testDigest(0x33), "self", false));
    try testing.expectError(error.UnknownOperatorKey, store.require(testDigest(0x44), "self", true));
    try testing.expectError(error.OperatorKeyChanged, store.require(testDigest(0x44), "self", false));
    try testing.expectError(error.OperatorKeyChanged, store.require(testDigest(0x33), "other", false));

    try store.remember(testDigest(0x33), "self", 20);
    try testing.expectEqual(@as(i64, 10), store.lookup(testDigest(0x33)).?.first_seen);
    try testing.expectEqual(@as(i64, 20), store.lookup(testDigest(0x33)).?.last_seen);

    try store.forget(testDigest(0x33));
    try testing.expectEqual(@as(?Pin, null), store.lookup(testDigest(0x33)));
    try testing.expectError(error.UnknownOperatorKey, store.forget(testDigest(0x33)));
}

test "reset drops every pin and rewrites the file" {
    var path_buffer: [128]u8 = undefined;
    const path = try testStorePath(&path_buffer);
    const dir = std.Io.Dir.cwd();
    defer dir.deleteFile(testing.io, path) catch {};

    var store = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer store.deinit();
    try store.remember(testDigest(0x55), "self", 1);
    try store.save();
    try store.reset();

    var reloaded = try PinStore.init(testing.io, testing.allocator, .{ .path = path });
    defer reloaded.deinit();
    try reloaded.load();
    try testing.expectEqual(@as(usize, 0), reloaded.count());
}
