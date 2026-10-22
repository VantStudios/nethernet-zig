const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    // HOTFIX: Explicitly pass `--gc-sections` in Debug mode to strip GCC 16's
    // unsupported `.sframe` relocations in `crt1.o` (already done in Release).
    const debug_gc_sections: ?bool = if (optimize == .Debug) true else null;

    const webrtc_dependency = b.dependency("webrtc", .{
        .target = target,
        .optimize = optimize,
    });
    const media_protocols = b.dependency("media_protocols", .{
        .target = target,
        .optimize = optimize,
    });

    const nethernet_module = b.addModule("nethernet-zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{
                .name = "webrtc",
                .module = webrtc_dependency.module("webrtc"),
            },
            .{
                .name = "ice",
                .module = media_protocols.module("ice"),
            },
        },
    });

    // The UDP listener path talks to Winsock directly to ask for a shareable port.
    if (target.result.os.tag == .windows) nethernet_module.linkSystemLibrary("ws2_32", .{});

    const use_lld = target.result.os.tag != .macos and
        !(target.query.isNative() and target.result.os.tag == .linux);

    const library_tests = b.addTest(.{
        .root_module = nethernet_module,
        .use_lld = use_lld,
    });
    library_tests.link_gc_sections = debug_gc_sections;
    const run_library_tests = b.addRunArtifact(library_tests);

    const test_step = b.step("test", "Run library and example tests");
    test_step.dependOn(&run_library_tests.step);

    const serialize_test_runs = builtin.os.tag == .windows;
    var last_test_run: *std.Build.Step = &run_library_tests.step;

    const check_step = b.step("check", "Compile the library and every test artifact for the selected target");
    check_step.dependOn(&library_tests.step);

    const Example = struct { name: []const u8, source: []const u8 };
    const examples = [_]Example{
        .{ .name = "session", .source = "examples/session.zig" },
        .{ .name = "server", .source = "examples/server.zig" },
        .{ .name = "discover", .source = "examples/discover.zig" },
        .{ .name = "bench", .source = "examples/bench.zig" },
        .{ .name = "cli", .source = "examples/cli.zig" },
    };
    const examples_step = b.step("examples", "Build every example into zig-out/bin");
    examples_step.dependOn(b.getInstallStep());

    for (examples) |example| {
        const example_module = b.createModule(.{
            .root_source_file = b.path(example.source),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nethernet", .module = nethernet_module },
                .{ .name = "webrtc", .module = webrtc_dependency.module("webrtc") },
            },
        });

        const example_exe = b.addExecutable(.{
            .name = b.fmt("example-{s}", .{example.name}),
            .root_module = example_module,
            .use_lld = use_lld,
        });

        example_exe.link_gc_sections = debug_gc_sections;
        b.installArtifact(example_exe);
        examples_step.dependOn(&example_exe.step);

        const example_run_step = b.step(
            b.fmt("run-{s}", .{example.name}),
            b.fmt("Build and run the {s} example", .{example.name}),
        );
        const example_run = b.addRunArtifact(example_exe);
        if (b.args) |args| example_run.addArgs(args);
        example_run_step.dependOn(&example_run.step);

        if (std.mem.eql(u8, example.name, "cli")) {
            const run_step = b.step("run", "Build and run the CLI example");
            run_step.dependOn(&example_run.step);
        }

        const example_tests = b.addTest(.{
            .root_module = example_module,
            .use_lld = use_lld,
        });

        example_tests.link_gc_sections = debug_gc_sections;
        const run_example_tests = b.addRunArtifact(example_tests);
        if (serialize_test_runs) run_example_tests.step.dependOn(last_test_run);
        last_test_run = &run_example_tests.step;
        test_step.dependOn(&run_example_tests.step);
        check_step.dependOn(&example_tests.step);
    }
}
