const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const encrypt_exe = b.addExecutable(.{
        .name = "encrypt",
        .root_source_file = b.path("encrypt.zig"),
        .target = target,
        .optimize = optimize,
    });

    const encrypt_install = b.addInstallArtifact(encrypt_exe, .{});

    const encrypt_run_cmd = b.addRunArtifact(encrypt_exe);
    encrypt_run_cmd.step.dependOn(&encrypt_install.step);

    const encrypt_run_step = b.step("run-encrypt", "Запустить программу шифрования");
    encrypt_run_step.dependOn(&encrypt_run_cmd.step);

    const decrypt_exe = b.addExecutable(.{
        .name = "decrypt",
        .root_source_file = b.path("decrypt.zig"),
        .target = target,
        .optimize = optimize,
    });

    const decrypt_install = b.addInstallArtifact(decrypt_exe, .{});

    const decrypt_run_cmd = b.addRunArtifact(decrypt_exe);
    decrypt_run_cmd.step.dependOn(&decrypt_install.step);

    const decrypt_run_step = b.step("run-decrypt", "Запустить программу дешифрования");
    decrypt_run_step.dependOn(&decrypt_run_cmd.step);

    b.getInstallStep().dependOn(&encrypt_install.step);
    b.getInstallStep().dependOn(&decrypt_install.step);
}
