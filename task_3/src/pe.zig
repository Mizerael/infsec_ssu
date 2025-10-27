const std = @import("std");

pub const IMAGE_DOS_SIGNATURE = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE = 0x00004550; // "PE"
pub const IMAGE_DIRECTORY_ENTRY_IMPORT = 1;

pub const ImageDosHeader = struct {
    e_magic: u16,
    e_lfanew: i32,

    pub fn read(data: []const u8) !ImageDosHeader {
        if (data.len < 64) return error.InvalidDosHeader;

        return ImageDosHeader{
            .e_magic = std.mem.readInt(u16, data[0..2], .little),
            .e_lfanew = std.mem.readInt(i32, data[60..64], .little),
        };
    }
};

pub const ImageFileHeader = struct {
    machine: u16,
    number_of_sections: u16,
    size_of_optional_header: u16,

    pub fn read(data: []const u8) !ImageFileHeader {
        if (data.len < 20) return error.InvalidFileHeader;

        return ImageFileHeader{
            .machine = std.mem.readInt(u16, data[0..2], .little),
            .number_of_sections = std.mem.readInt(u16, data[2..4], .little),
            .size_of_optional_header = std.mem.readInt(u16, data[16..18], .little),
        };
    }
};

pub const ImageDataDirectory = struct {
    virtual_address: u32,
    size: u32,

    pub fn read(data: []const u8) !ImageDataDirectory {
        if (data.len < 8) return error.InvalidDataDirectory;

        return ImageDataDirectory{
            .virtual_address = std.mem.readInt(u32, data[0..4], .little),
            .size = std.mem.readInt(u32, data[4..8], .little),
        };
    }
};

pub const ImageOptionalHeader32 = struct {
    magic: u16,
    data_directories: [16]ImageDataDirectory,

    pub fn read(data: []const u8) !ImageOptionalHeader32 {
        if (data.len < 96 + 128) return error.InvalidOptionalHeader;

        const magic = std.mem.readInt(u16, data[0..2], .little);

        var data_directories: [16]ImageDataDirectory = undefined;
        const dd_start = 96;
        for (&data_directories, 0..) |*dir, i| {
            const offset = dd_start + i * 8;
            dir.* = try ImageDataDirectory.read(data[offset..]);
        }

        return ImageOptionalHeader32{
            .magic = magic,
            .data_directories = data_directories,
        };
    }
};

pub const ImageOptionalHeader64 = struct {
    magic: u16,
    data_directories: [16]ImageDataDirectory,

    pub fn read(data: []const u8) !ImageOptionalHeader64 {
        if (data.len < 112 + 128) return error.InvalidOptionalHeader;

        const magic = std.mem.readInt(u16, data[0..2], .little);

        var data_directories: [16]ImageDataDirectory = undefined;
        const dd_start = 112;
        for (&data_directories, 0..) |*dir, i| {
            const offset = dd_start + i * 8;
            dir.* = try ImageDataDirectory.read(data[offset..]);
        }

        return ImageOptionalHeader64{
            .magic = magic,
            .data_directories = data_directories,
        };
    }
};

pub const ImageImportDescriptor = struct {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,

    pub fn read(data: []const u8) !ImageImportDescriptor {
        if (data.len < 20) return error.InvalidImportDescriptor;

        return ImageImportDescriptor{
            .original_first_thunk = std.mem.readInt(u32, data[0..4], .little),
            .time_date_stamp = std.mem.readInt(u32, data[4..8], .little),
            .forwarder_chain = std.mem.readInt(u32, data[8..12], .little),
            .name = std.mem.readInt(u32, data[12..16], .little),
            .first_thunk = std.mem.readInt(u32, data[16..20], .little),
        };
    }
};

pub const ImageThunkData32 = struct {
    address_of_data: u32,

    pub fn read(data: []const u8) !ImageThunkData32 {
        if (data.len < 4) return error.InvalidThunkData;

        return ImageThunkData32{
            .address_of_data = std.mem.readInt(u32, data[0..4], .little),
        };
    }
};

pub const SectionHeader = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    characteristics: u32,

    pub fn read(data: []const u8) !SectionHeader {
        if (data.len < 40) return error.InvalidSectionHeader;

        var name: [8]u8 = undefined;
        @memcpy(name[0..], data[0..8]);

        return SectionHeader{
            .name = name,
            .virtual_size = std.mem.readInt(u32, data[8..12], .little),
            .virtual_address = std.mem.readInt(u32, data[12..16], .little),
            .size_of_raw_data = std.mem.readInt(u32, data[16..20], .little),
            .pointer_to_raw_data = std.mem.readInt(u32, data[20..24], .little),
            .characteristics = std.mem.readInt(u32, data[36..40], .little),
        };
    }
};

pub const PeFile = struct {
    data: []const u8,
    sections: std.ArrayList(SectionHeader),
    allocator: std.mem.Allocator,
    is_64bit: bool = false,

    pub fn init(allocator: std.mem.Allocator, file_data: []const u8) !PeFile {
        const sections = std.ArrayList(SectionHeader).init(allocator);
        return PeFile{
            .data = file_data,
            .sections = sections,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PeFile) void {
        self.sections.deinit();
    }

    pub fn isValid(self: *const PeFile) bool {
        if (self.data.len < 64) return false;

        const dos_header = ImageDosHeader.read(self.data) catch return false;
        return dos_header.e_magic == IMAGE_DOS_SIGNATURE;
    }

    pub fn parseHeaders(self: *PeFile) !bool {
        if (!self.isValid()) return false;

        const dos_header = try ImageDosHeader.read(self.data);
        const nt_headers_offset = @as(usize, @intCast(dos_header.e_lfanew));

        if (nt_headers_offset + 4 + 20 > self.data.len) return false;

        // Check PE signature
        const pe_signature = std.mem.readInt(u32, self.data[nt_headers_offset..][0..4], .little);
        if (pe_signature != IMAGE_NT_SIGNATURE) return false;

        // Read File Header
        const file_header_offset = nt_headers_offset + 4;
        const file_header = try ImageFileHeader.read(self.data[file_header_offset..]);

        const optional_header_offset = file_header_offset + 20;
        self.is_64bit = (file_header.machine == 0x8664); // AMD64

        const sections_offset = optional_header_offset + file_header.size_of_optional_header;
        const sections_count = file_header.number_of_sections;

        if (sections_offset + sections_count * 40 > self.data.len) return false;

        self.sections.shrinkRetainingCapacity(0);
        var i: usize = 0;
        while (i < sections_count) : (i += 1) {
            const section_offset = sections_offset + i * 40;
            const section_data = self.data[section_offset..];
            if (section_data.len < 40) break;

            const section = try SectionHeader.read(section_data[0..40]);
            try self.sections.append(section);
        }

        return true;
    }

    pub fn getImportDirectory(self: *const PeFile) !?ImageDataDirectory {
        if (!self.isValid()) return null;

        const dos_header = try ImageDosHeader.read(self.data);
        const nt_headers_offset = @as(usize, @intCast(dos_header.e_lfanew));
        const file_header_offset = nt_headers_offset + 4;

        const optional_header_offset = file_header_offset + 20;

        if (self.is_64bit) {
            if (optional_header_offset + 240 > self.data.len) return null;
            const optional_header = try ImageOptionalHeader64.read(self.data[optional_header_offset..]);
            return optional_header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        } else {
            if (optional_header_offset + 224 > self.data.len) return null;
            const optional_header = try ImageOptionalHeader32.read(self.data[optional_header_offset..]);
            return optional_header.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        }
    }

    pub fn rvaToFileOffset(self: *const PeFile, rva: u32) ?usize {
        for (self.sections.items) |section| {
            if (rva >= section.virtual_address and rva < section.virtual_address + section.virtual_size) {
                return (rva - section.virtual_address) + section.pointer_to_raw_data;
            }
        }
        return null;
    }

    pub fn readNullTerminatedString(self: *const PeFile, offset: usize) ?[]const u8 {
        if (offset >= self.data.len) return null;

        var end = offset;
        while (end < self.data.len and self.data[end] != 0) {
            end += 1;
        }

        if (end == self.data.len) return null;
        return self.data[offset..end];
    }

    pub fn readImportDescriptor(self: *const PeFile, offset: usize) ?ImageImportDescriptor {
        if (offset + 20 > self.data.len) return null;
        return ImageImportDescriptor.read(self.data[offset..]) catch null;
    }

    pub fn readThunkData(self: *const PeFile, offset: usize) ?u64 {
        if (self.is_64bit) {
            if (offset + 8 > self.data.len) return null;
            return std.mem.readInt(u64, self.data[offset..][0..8], .little);
        } else {
            if (offset + 4 > self.data.len) return null;
            return std.mem.readInt(u32, self.data[offset..][0..4], .little);
        }
    }

    pub fn readU32(self: *const PeFile, offset: usize) ?u32 {
        if (offset + 4 > self.data.len) return null;
        return std.mem.readInt(u32, self.data[offset..][0..4], .little);
    }

    pub fn readU16(self: *const PeFile, offset: usize) ?u16 {
        if (offset + 2 > self.data.len) return null;
        return std.mem.readInt(u16, self.data[offset..][0..2], .little);
    }
};
