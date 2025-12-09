const std = @import("std");

const SALT_LENGTH = 32;
const SEPARATOR = "\n\n";
const SEPARATOR_LEN = 2;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stdin = std.io.getStdIn().reader();

    try stdout.print("=== Программа шифрования гаммированием ===\n\n", .{});

    try stdout.print("Введите путь к исходному файлу: ", .{});
    var input_path_buf: [256]u8 = undefined;
    const input_path_slice = try stdin.readUntilDelimiterOrEof(&input_path_buf, '\n') orelse {
        try stdout.print("Ошибка: не введен путь к файлу\n", .{});
        return;
    };
    const input_path = std.mem.trim(u8, input_path_slice, " \t\r\n");

    try stdout.print("Введите соль (до {d} символов): ", .{SALT_LENGTH});
    var salt_input_buf: [256]u8 = undefined;
    const salt_input_slice = try stdin.readUntilDelimiterOrEof(&salt_input_buf, '\n') orelse {
        try stdout.print("Ошибка: не введена соль\n", .{});
        return;
    };
    const salt_input = std.mem.trim(u8, salt_input_slice, " \t\r\n");

    var salt: [SALT_LENGTH]u8 = undefined;

    if (salt_input.len >= SALT_LENGTH) {
        @memcpy(salt[0..], salt_input[0..SALT_LENGTH]);
    } else {
        @memset(salt[0..], 0);
        @memcpy(salt[0..salt_input.len], salt_input);
    }

    const input_file = try std.fs.cwd().openFile(input_path, .{});
    defer input_file.close();

    const file_size = try input_file.getEndPos();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const file_data = try allocator.alloc(u8, file_size);
    _ = try input_file.readAll(file_data);

    const prng = try generatePseudorandomSequence(allocator, &salt, file_data.len);

    const encrypted_data = try allocator.alloc(u8, file_data.len);

    for (encrypted_data, file_data, prng) |*encrypted_byte, original_byte, prng_byte| {
        encrypted_byte.* = original_byte ^ prng_byte;
    }

    const output_path = try std.fmt.allocPrint(allocator, "{s}.encrypted", .{input_path});

    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    try output_file.writeAll(salt_input);
    try output_file.writeAll(SEPARATOR);
    try output_file.writeAll(encrypted_data);

    try stdout.print("\n=== Результат шифрования ===\n", .{});
    try stdout.print("Исходный файл: {s}\n", .{input_path});
    try stdout.print("Зашифрованный файл: {s}\n", .{output_path});
    try stdout.print("Размер файла: {d} байт\n", .{file_size});
    try stdout.print("Соль (сохранена в файле): {s}\n", .{salt_input});
    try stdout.print("Формат файла:\nсоль{s}данные\n", .{SEPARATOR});
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
