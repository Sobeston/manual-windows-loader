const std = @import("std");
const warn = std.debug.warn;
const win = std.os.windows;
usingnamespace @import("externs.zig");

pub const LoadedLibrary = struct {
    const Error = error{ UnresolvedImport, OutOfMemory };
    const Options = struct { rand: ?*std.rand.Random = null };
    image: []align(0x1000) u8,

    ///allocates space for image with VirtualAlloc
    ///fills image with random bytes, if options.rand is provided
    ///copies in sections
    ///resolves imports (non-recursively!)
    ///performs relocations
    ///sets page protection flags
    pub fn init(dll: []const u8, options: Options) Error!LoadedLibrary {
        //  Getting the PE headers
        //
        //
        const dos_header = LoadedLibrary.getDosHeader(dll);
        std.log.scoped(.LoadedLibrary).debug("dos_header: {}", .{dos_header.*});
        const coff_header = LoadedLibrary.getCoffHeader(dll, dos_header.*);
        std.log.scoped(.LoadedLibrary).debug("coff_header: {}", .{coff_header.*});
        const optional_header = LoadedLibrary.getOptionalHeader(dll, dos_header.*);
        std.log.scoped(.LoadedLibrary).debug("optional_header: {}", .{optional_header.*});
        const section_headers = LoadedLibrary.getSectionHeaders(dll, dos_header.*, coff_header.*);
        for (section_headers) |header, i| std.log.scoped(.LoadedLibrary).debug("header {}: {}", .{ i, header });

        //  Allocating space for the image, copying in image in sections
        //
        //
        const image = try std.heap.page_allocator.alignedAlloc(u8, 0x1000, optional_header.size_of_image);
        if (options.rand) |rand| rand.bytes(image); //used to make the image look a little different every time if the caller wants that

        for (section_headers) |section| std.mem.copy(
            u8,
            image[section.virtual_address..],
            (dll.ptr + section.pointer_to_raw_data)[0..std.mem.min(u32, &[_]u32{
                section.size_of_raw_data,
                section.virtual_size,
            })],
        );

        // Fix import table
        //
        //
        const import_directories = @ptrCast(
            [*]align(1) const Import_Directory_Table,
            image.ptr + optional_header.import_table_entry.rva,
        )[0 .. optional_header.import_table_entry.size / @sizeOf(Import_Directory_Table)];

        for (import_directories) |imp| {
            if (imp.import_lookup_table_rva == 0 or imp.import_address_table_rva == 0 or imp.name_rva == 0) continue;

            const imp_dll_name = @ptrCast([*:0]const u8, image.ptr + imp.name_rva);
            std.log.scoped(.LoadedLibrary).debug("import: {}", .{imp_dll_name});
            const imp_dll_location = GetModuleHandleA(imp_dll_name) orelse return error.UnresolvedImport; //recursive loading is not supported!

            const table = @ptrCast([*:0]usize, @alignCast(8, image.ptr + imp.import_lookup_table_rva));
            var i: usize = 0;

            while (table[i] != 0) : (i += 1) {
                const function_name = @ptrCast([*:0]const u8, image.ptr + table[i] + @sizeOf(u16));
                std.log.scoped(.LoadedLibrary).debug("func: {s}", .{function_name});

                const function = @ptrToInt(win.kernel32.GetProcAddress(imp_dll_location, function_name));

                table[i] = function;
                @ptrCast([*]usize, @alignCast(@alignOf(usize), image.ptr + imp.import_address_table_rva))[i] = function;

                std.log.scoped(.LoadedLibrary).debug("&table[i]: 0x{*}, table[i]: 0x{x}", .{ &table[i], table[i] });
            }
        }

        //  Perform relocations
        //  TODO: support different types of patches, all are currently handled the same
        //
        const reloc_tbl = optional_header.base_relocation_table_entry;
        var block = @ptrCast(
            *align(1) const RelocationBlock,
            image.ptr + reloc_tbl.rva,
        );
        var patches = @ptrCast(
            [*]align(1) const RelocationPatch,
            @ptrCast([*]const u8, block) + @sizeOf(RelocationBlock),
        )[0 .. (block.size - 8) / 2];
        while (true) {
            std.log.scoped(.LoadedLibrary).debug("block: {}", .{block.*});
            for (patches) |p| {
                std.log.scoped(.LoadedLibrary).debug("patch: {}", .{p});
                if (p.offset == 0) continue;
                @ptrCast(*align(1) [*]u8, image.ptr + block.rva + p.offset).* = image.ptr + block.rva;
            }
            block = @ptrCast(
                *align(1) const RelocationBlock,
                image.ptr + reloc_tbl.rva + @sizeOf(RelocationBlock) + @sizeOf(RelocationPatch) * patches.len,
            );
            patches = @ptrCast(
                [*]align(1) const RelocationPatch,
                @ptrCast([*]const u8, block) + @sizeOf(RelocationBlock),
            )[0 .. (block.size - 8) / 2];
            if (@ptrToInt(&patches[patches.len - 1]) + @sizeOf(RelocationPatch) >= @ptrToInt(image.ptr) + reloc_tbl.rva + reloc_tbl.size) break;
        }

        //  Give pages the correct protections
        //
        //
        for (section_headers) |section| {
            const flags = @bitCast(SectionFlags, section.characteristics);
            const page_protection: u32 = blk: { //TODO more coverage of flags
                if (flags.mem_read and flags.mem_write and flags.mem_execute) break :blk win.PAGE_EXECUTE_READWRITE;
                if (flags.mem_read and flags.mem_execute) break :blk win.PAGE_EXECUTE_READ;
                if (flags.mem_read and flags.mem_write) break :blk win.PAGE_READWRITE;
                if (flags.mem_read) break :blk win.PAGE_READONLY;
                unreachable; // this section's flags aren't handled properly yet :(. TODO: handle all cases
            };
            var junk: u32 = undefined; //page's previous protection is always RW; we don't need to know this
            if (VirtualProtect(image.ptr + section.virtual_address, section.virtual_size, page_protection, &junk) == 0) @panic("protection change failed");
        }

        return LoadedLibrary{ .image = image };
    }
    ///deallocates space for image with VirtualFree
    pub fn deinit(self: *LoadedLibrary) void {
        win.VirtualFree(self.image.ptr, 0, win.MEM_RELEASE);
        self.* = undefined;
    }
    fn findExport(self: LoadedLibrary, comptime T: type, dll: []const u8, name: []const u8) ?T {
        const exp_dir_table = @ptrCast(
            *align(1) EXPORT_DIRECTORY_TABLE,
            self.image.ptr + LoadedLibrary.getOptionalHeader(dll, LoadedLibrary.getDosHeader(dll).*).export_table_entry.rva,
        );
        std.log.scoped(.LoadedLibrary_findExport).debug("exp_dir_table: {}\n", .{exp_dir_table.*});

        const exp_names = @ptrCast(
            [*]align(1) const u32,
            self.image.ptr + exp_dir_table.namePointerRva,
        )[0..exp_dir_table.numberOfNamePointers];
        const exp_addresses = @ptrCast(
            [*]align(1) const u32,
            self.image.ptr + exp_dir_table.exportAddressTableRva,
        )[1..exp_dir_table.addressTableEntries];

        var found_func: ?T = null;
        for (exp_names) |n, i| {
            const export_name = std.mem.spanZ(@ptrCast([*:0]const u8, self.image.ptr + n));
            std.log.scoped(.LoadedLibrary_findExport).debug("export_name: {}", .{export_name});
            if (std.mem.eql(u8, export_name, name)) {
                found_func = @ptrCast(T, self.image.ptr + exp_addresses[i]);
            }
        }
        return found_func;
    }
    // TODO: add findExports(...), for efficiency
    fn getDosHeader(dll: []const u8) *const IMAGE_DOS_HEADER {
        return @ptrCast(*const IMAGE_DOS_HEADER, @alignCast(@alignOf(IMAGE_DOS_HEADER), dll.ptr));
    }
    fn getCoffHeader(dll: []const u8, dos_header: IMAGE_DOS_HEADER) *const IMAGE_FILE_HEADER {
        return @ptrCast(
            *const IMAGE_FILE_HEADER,
            @alignCast(@alignOf(IMAGE_FILE_HEADER), dll.ptr + @intCast(u32, dos_header.lfanew)),
        );
    }
    fn getOptionalHeader(dll: []const u8, dos_header: IMAGE_DOS_HEADER) *const IMAGE_OPTIONAL_HEADER {
        return @ptrCast(
            *const IMAGE_OPTIONAL_HEADER,
            @alignCast(@alignOf(IMAGE_OPTIONAL_HEADER), dll.ptr + @intCast(u32, dos_header.lfanew) + @sizeOf(IMAGE_FILE_HEADER)),
        );
    }
    fn getSectionHeaders(dll: []const u8, dos_header: IMAGE_DOS_HEADER, coff_header: IMAGE_FILE_HEADER) []const IMAGE_SECTION_HEADER {
        return @ptrCast(
            [*]const IMAGE_SECTION_HEADER,
             @alignCast(@alignOf(IMAGE_SECTION_HEADER), dll.ptr + @intCast(u32, dos_header.lfanew) + @sizeOf(IMAGE_FILE_HEADER) + @sizeOf(IMAGE_OPTIONAL_HEADER)),
        )[0..coff_header.number_of_sections];
    }
};

pub fn main() !void {
    const file = try std.fs.cwd().openFile("ghi.dll", .{});
    defer file.close();

    const dll = try std.heap.page_allocator.alloc(u8, (try file.stat()).size);
    defer std.heap.page_allocator.free(dll);
    _ = try file.readAll(dll);

    var seed: u64 = undefined;
    try std.os.getrandom(std.mem.asBytes(&seed));
    var prng = std.rand.DefaultPrng.init(seed);

    var library = try LoadedLibrary.init(dll, .{ .rand = &prng.random });
    defer library.deinit();

    (library.findExport(
        fn (c_int) callconv(.C) void,
        dll,
        "writeInt",
    ) orelse @panic("writeInt function not found!"))(1002);
}