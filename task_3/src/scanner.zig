const std = @import("std");
const pe = @import("pe.zig");
const imports = @import("imports.zig");

pub const ScanResult = struct {
    total_files: usize = 0,
    files_with_network_funcs: usize = 0,
};

pub fn scanDirectory(allocator: std.mem.Allocator, directory_path: []const u8) !void {
    var dir = std.fs.cwd().openDir(directory_path, .{ .iterate = true }) catch |err| {
        std.debug.print("Error opening directory: {}\n", .{err});
        return;
    };
    defer dir.close();

    var walker = try dir.walk(allocator);
    defer walker.deinit();

    const import_analyzer = imports.ImportAnalyzer.init();
    var result = ScanResult{};

    std.debug.print("Scanning EXE and DLL files in: {s}\n\n", .{directory_path});

    while (true) {
        const entry = walker.next() catch {
            continue;
        } orelse break;

        if (isSpecialSystemPath(entry.path)) {
            continue;
        }

        if (entry.kind == .file and isExecutableOrLibrary(entry.basename)) {
            result.total_files += 1;

            const has_network_funcs = analyzeAndPrintFile(allocator, entry.dir, entry.path, entry.basename, import_analyzer) catch {
                continue;
            };

            if (has_network_funcs) {
                result.files_with_network_funcs += 1;
            }
        }
    }

    std.debug.print("\nScan Summary:\n", .{});
    std.debug.print("  Total EXE/DLL files scanned: {}\n", .{result.total_files});
    std.debug.print("  Files with network functions: {}\n", .{result.files_with_network_funcs});
}

fn isSpecialSystemPath(path: []const u8) bool {
    const special_paths = [_][]const u8{
        "/proc/", "/sys/", "/dev/", "/run/",
    };

    for (special_paths) |special| {
        if (std.mem.indexOf(u8, path, special) != null) {
            return true;
        }
    }
    return false;
}

fn analyzeAndPrintFile(
    allocator: std.mem.Allocator,
    dir: std.fs.Dir,
    file_path: []const u8,
    filename: []const u8,
    import_analyzer: imports.ImportAnalyzer,
) !bool {
    const file = dir.openFile(filename, .{}) catch {
        return false;
    };
    defer file.close();

    const stat = file.stat() catch {
        return false;
    };

    if (stat.size == 0 or stat.size > 100 * 1024 * 1024) {
        return false;
    }

    const data = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch {
        return false;
    };
    defer allocator.free(data);

    var pe_file = pe.PeFile.init(allocator, data) catch {
        return false;
    };
    defer pe_file.deinit();

    if (!pe_file.isValid()) {
        return false;
    }

    const headers_parsed = pe_file.parseHeaders() catch {
        return false;
    };
    if (!headers_parsed) {
        return false;
    }

    var context = struct {
        count: usize = 0,
        file_path: []const u8,
    }{
        .file_path = file_path,
    };

    import_analyzer.findNetworkFunctions(&pe_file, &context, struct {
        fn callback(ctx: *@TypeOf(context), dll_name: []const u8, function_name: []const u8) void {
            if (ctx.count == 0) {
                std.debug.print("Found: {s}\n", .{ctx.file_path});
                std.debug.print("  Network functions:\n", .{});
            }

            std.debug.print("    {s}!{s}\n", .{ dll_name, function_name });
            ctx.count += 1;
        }
    }.callback) catch {
        return false;
    };

    if (context.count > 0) {
        std.debug.print("  Total: {}\n\n", .{context.count});
        return true;
    }

    return false;
}

fn isExecutableOrLibrary(filename: []const u8) bool {
    if (filename.len < 4) return false;

    const ext_start = filename.len - 4;
    const extension = filename[ext_start..];

    var buf: [4]u8 = undefined;
    for (extension, 0..) |char, i| {
        buf[i] = std.ascii.toLower(char);
    }

    return std.mem.eql(u8, &buf, ".exe") or
        std.mem.eql(u8, &buf, ".dll");
}
