const std = @import("std");

const SALT_LENGTH = 32;
const SEPARATOR = "\n\n";
const SEPARATOR_LEN = 2;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();

    try stdout.print("=== Программа дешифрования гаммированием ===\n\n", .{});

    try stdout.print("Введите путь к зашифрованному файлу: ", .{});
    var input_path_buf: [256]u8 = undefined;
    const input_path_slice = try stdin.readUntilDelimiterOrEof(&input_path_buf, '\n') orelse {
        try stdout.print("Ошибка: не введен путь к файлу\n", .{});
        return;
    };
    const input_path = std.mem.trim(u8, input_path_slice, " \t\r\n");

    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_size = try input_file.getEndPos();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const file_data = try allocator.alloc(u8, file_size);
    _ = try input_file.readAll(file_data);

    const separator_pos = findSeparator(file_data) orelse {
        try stdout.print("Ошибка: не найден разделитель '\\n\\n' после соли\n", .{});
        return;
    };

    const salt_slice = file_data[0..separator_pos];

    const encrypted_data_start = separator_pos + SEPARATOR_LEN;
    const encrypted_data = file_data[encrypted_data_start..];

    var salt: [SALT_LENGTH]u8 = undefined;
    if (salt_slice.len >= SALT_LENGTH) {
        @memcpy(salt[0..], salt_slice[0..SALT_LENGTH]);
    } else {
        @memset(salt[0..], 0);
        @memcpy(salt[0..salt_slice.len], salt_slice);
    }

    const prng = try generatePseudorandomSequence(allocator, &salt, encrypted_data.len);

    const decrypted_data = try allocator.alloc(u8, encrypted_data.len);

    for (decrypted_data, encrypted_data, prng) |*decrypted_byte, encrypted_byte, prng_byte| {
        decrypted_byte.* = encrypted_byte ^ prng_byte;
    }

    try stdout.print("\n=== Результат дешифрования ===\n\n", .{});

    var original_salt_len: usize = 0;
    for (salt, 0..) |byte, i| {
        if (byte == 0) break;
        original_salt_len = i + 1;
    }

    try stdout.print("Соль из файла: ", .{});
    if (original_salt_len > 0) {
        try stdout.print("{s}\n", .{salt[0..original_salt_len]});
    } else {
        try stdout.print("[пустая строка]\n", .{});
    }
    try stdout.print("\n", .{});

    try stdout.print("Дешифрованный текст:\n", .{});

    if (std.unicode.utf8ValidateSlice(decrypted_data)) {
        try stdout.writeAll(decrypted_data);
    } else {
        try stdout.print("[Бинарные данные, размер: {d} байт]\n", .{decrypted_data.len});
        try stdout.print("Первые 16 байт в hex: ", .{});
        const bytes_to_show = @min(16, decrypted_data.len);
        for (decrypted_data[0..bytes_to_show]) |b| {
            try stdout.print("{x:0>2} ", .{b});
        }
        if (decrypted_data.len > 16) {
            try stdout.print("...\n", .{});
        }
    }

    try stdout.print("\n", .{});
}

fn findSeparator(data: []const u8) ?usize {
    var i: usize = 0;
    while (i + 1 < data.len) {
        if (data[i] == '\n' and data[i + 1] == '\n') {
            return i;
        }
        i += 1;
    }
    return null;
}

fn generatePseudorandomSequence(allocator: std.mem.Allocator, salt: *const [SALT_LENGTH]u8, length: usize) ![]u8 {
    const prng = try allocator.alloc(u8, length);

    var seed: u64 = 0;

    for (salt, 0..) |byte, i| {
        seed +%= @as(u64, byte) << @intCast((i % 8) * 8);
    }

    const a: u64 = 6364136223846793005;
    const c: u64 = 1442695040888963407;

    var state = seed;
    for (prng) |*byte| {
        state = a *% state +% c;
        byte.* = @truncate(state >> 56);
    }

    return prng;
}
