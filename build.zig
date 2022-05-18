const std = @import("std");

fn add_mbedtls_deps(b: *std.build.LibExeObjStep) void {
    // macOS include paths if mbedtls is installed by homebrew on M1 macs
    // brew install mbedtls
    b.addIncludeDir("/opt/homebrew/include");
    b.addLibPath("/opt/homebrew/lib");

    b.linkSystemLibrary("mbedcrypto");
    b.linkSystemLibrary("mbedtls");
    b.linkSystemLibrary("mbedx509");
}

fn add_mbedtls(b: *std.build.LibExeObjStep) void {
    add_mbedtls_deps(b);
    b.addPackagePath("mbedtls", "src/main.zig");
}

pub fn build(b: *std.build.Builder) void {
    b.verbose_cimport = true;
    //b.verbose_cc = true;
    //b.verbose_link = true;

    const mode = b.standardReleaseOptions();
    const lib = b.addStaticLibrary("zig-mbedtls", "src/main.zig");
    add_mbedtls_deps(lib);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/main.zig");
    add_mbedtls_deps(main_tests);
    main_tests.setBuildMode(.Debug);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);

    const example = b.addExecutable("simple", "examples/simple.zig");
    add_mbedtls(example);
    example.setBuildMode(mode);
    example.install();

    const https_get = b.addExecutable("https_get", "examples/https_get.zig");
    add_mbedtls(https_get);
    https_get.setBuildMode(mode);
    https_get.install();

    const nats = b.addExecutable("nats", "examples/nats.zig");
    add_mbedtls(nats);
    nats.setBuildMode(mode);
    nats.install();

    const examples = b.step("examples", "Build examples");
    examples.dependOn(&example.step);
    examples.dependOn(&nats.step);
    examples.dependOn(&https_get.step);
}
