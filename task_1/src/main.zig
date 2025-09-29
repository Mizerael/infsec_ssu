const std = @import("std");
const BUFF_SIZE = 4096;
const SIGNATURE_FILE = ".signatures";

const HashInfo = struct {
    hash: u16,
    signature: []const u8,
};

fn toU16(b1: u8, b2: u8) u16 {
    const val1: u16 = b1;
    const val2: u16 = b2;
    return val1 | (val2 << 8);
}

fn toU16LastByte(b: u8) u16 {
    const val: u16 = b;
    return val;
}

fn xor16_hash(file: std.fs.File) !u16 {
    var hash: u16 = 0;
    var buffer: [BUFF_SIZE]u8 = undefined;

    try file.seekTo(0);
    while (true) {
        const read_bytes = try file.read(buffer[0..]);
        if (read_bytes == 0) break;

        var i: usize = 0;
        while (i + 1 < read_bytes) : (i += 2) {
            const val = toU16(buffer[i], buffer[i + 1]);
            hash ^= val;
        }
        if ((read_bytes & 1) != 0) {
            const val = toU16LastByte(buffer[read_bytes - 1]);
            hash ^= val;
        }
    }
    return hash;
}

fn get_signature(file: std.fs.File, allocator: std.mem.Allocator) ![]u8 {
    const sig_len = 4;
    const file_stat = try file.stat();
    const size = file_stat.size;
    try file.seekTo(0);

    const start: usize = if (size < sig_len) 0 else (size / 2) - 2;

    var sig_buf: [4]u8 = undefined;
    try file.seekTo(start);
    const usize_size: usize = @intCast(size);
    const available: usize = usize_size - start;
    const to_read = if (available < sig_len) available else sig_len;
    const actual_read = try file.read(sig_buf[0..to_read]);

    const sig_bytes = try allocator.alloc(u8, actual_read);
    @memcpy(sig_bytes, sig_buf[0..actual_read]);

    const hex_sig = try std.fmt.allocPrint(allocator, "{x}", .{sig_bytes});
    allocator.free(sig_bytes);

    return hex_sig;
}

fn walk_and_collect(
    dir: std.fs.Dir,
    base_path: []const u8,
    allocator: std.mem.Allocator,
    map: *std.StringHashMap(HashInfo),
) !void {
    var it = dir.iterate();
    while (true) {
        const entry_res = try it.next() orelse break;

        const rel_path = std.fs.path.join(allocator, &[_][]const u8{ base_path, entry_res.name }) catch continue;

        if (entry_res.kind == .directory) {
            var subdir = try dir.openDir(entry_res.name, .{ .iterate = true });
            defer subdir.close();
            try walk_and_collect(subdir, rel_path, allocator, map);
        } else if (entry_res.kind == .file) {
            if (std.mem.endsWith(u8, rel_path, SIGNATURE_FILE)) continue;

            const file = try dir.openFile(entry_res.name, .{});
            defer file.close();

            const hash = try xor16_hash(file);
            const sig = try get_signature(file, allocator);

            try map.put(rel_path, HashInfo{
                .hash = hash,
                .signature = sig,
            });
        }
    }
}

fn contains(slice: []const u8, pattern: []const u8) bool {
    return std.mem.indexOf(u8, slice, pattern) != null;
}

fn readLine(
    reader: *std.io.BufferedReader(BUFF_SIZE, std.fs.File.Reader),
    buffer: []u8,
) !?[]const u8 {
    const line_opt = try reader.reader().readUntilDelimiterOrEof(buffer, '\n');
    if (line_opt) |line| {
        return line;
    } else {
        return null;
    }
}

fn readSignatureFile(allocator: std.mem.Allocator, path: []const u8) !?std.StringHashMap(HashInfo) {
    const cwd = std.fs.cwd();

    const file = cwd.openFile(path, .{}) catch |err| {
        const err_str = std.fmt.allocPrint(allocator, "{}", .{err}) catch "";
        defer allocator.free(err_str);

        if (contains(err_str, "FileNotFound")) {
            return null;
        } else {
            return err;
        }
    };
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var map = std.StringHashMap(HashInfo).init(allocator);

    var line_buf: [BUFF_SIZE]u8 = undefined;

    while (true) {
        const line_opt = try readLine(&buf_reader, line_buf[0..]);
        if (line_opt) |line| {
            var parts = std.mem.splitScalar(u8, line, ' ');

            const filename = parts.next() orelse break;
            const hash_str = parts.next() orelse break;
            const signature_str = parts.next() orelse break;

            if (map.get(filename) == null) {
                const key_copy = try allocator.alloc(u8, filename.len);
                @memcpy(key_copy[0..filename.len], filename);

                const hash_num = try std.fmt.parseInt(u16, hash_str, 10);

                const sig_copy = try allocator.alloc(u8, signature_str.len);
                @memcpy(sig_copy[0..signature_str.len], signature_str);
                try map.put(key_copy, HashInfo{
                    .hash = hash_num,
                    .signature = sig_copy,
                });
            }
        } else {
            break;
        }
    }

    return map;
}

fn writeSignatureFile(
    path: []const u8,
    map: *std.StringHashMap(HashInfo),
) !void {
    const cwd = std.fs.cwd();
    const file = try cwd.createFile(path, .{});
    defer file.close();

    var writer = file.writer();

    var it = map.iterator();
    while (it.next()) |entry| {
        try writer.print("{s} {d} {s}\n", .{ entry.key_ptr.*, entry.value_ptr.hash, entry.value_ptr.signature });
    }
}

fn printChanges(
    old_map: *std.StringHashMap(HashInfo),
    new_map: *std.StringHashMap(HashInfo),
) !void {
    const stdout = std.io.getStdOut().writer();

    var it = old_map.iterator();
    while (it.next()) |old_entry| {
        const old_key = old_entry.key_ptr.*;
        const new_val = new_map.get(old_key);
        if (new_val) |val| {
            if (val.hash != old_entry.value_ptr.*.hash) {
                try stdout.print("Изменён файл: {s}\n", .{old_key});
            }
        } else {
            try stdout.print("Удалён файл: {s}\n", .{old_key});
        }
    }

    var it_new = new_map.iterator();
    while (it_new.next()) |new_entry| {
        const new_key = new_entry.key_ptr.*;

        if (old_map.get(new_key) == null) {
            try stdout.print("Добавлен файл: {s}\n", .{new_key});
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var arena_alloc = std.heap.ArenaAllocator.init(gpa.allocator());
    defer arena_alloc.deinit();
    const allocator = arena_alloc.allocator();

    const cwd = std.fs.cwd();
    var dir = try cwd.openDir(".", .{ .iterate = true });
    defer dir.close();

    var new_map = std.StringHashMap(HashInfo).init(allocator);
    defer new_map.deinit();

    try walk_and_collect(dir, "", allocator, &new_map);

    const old_map = try readSignatureFile(allocator, SIGNATURE_FILE);

    if (old_map) |old_val_const| {
        const old_val: *std.StringHashMap(HashInfo) = @constCast(&old_val_const);
        try printChanges(old_val, &new_map);
    } else {
        var empty_map = std.StringHashMap(HashInfo).init(allocator);
        defer empty_map.deinit();
        try printChanges(&empty_map, &new_map);
    }

    try writeSignatureFile(SIGNATURE_FILE, &new_map);

    var count: usize = 0;
    var it = new_map.iterator();
    while (it.next()) |_| {
        count += 1;
    }
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Файлов собрано: {d}\n", .{count});
}
