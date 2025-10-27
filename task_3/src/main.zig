const std = @import("std");
const scanner = @import("scanner.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print("Usage: {s} <directory>\n", .{args[0]});
        std.debug.print("Scans EXE and DLL files for network functions.\n", .{});
        std.debug.print("Shows only files that contain network functions.\n", .{});
        return;
    }

    try scanner.scanDirectory(allocator, args[1]);
}
