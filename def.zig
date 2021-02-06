fn errorBox(cstr: [*:0]const u8) callconv(.C) void {
    box(cstr);
}
const u16le = std.unicode.utf8ToUtf16LeStringLiteral;
const std = @import("std");
const mem = std.mem;
const win = std.os.windows;
usingnamespace @import("externs.zig");

fn box(cstr: [*:0]const u8) void {
    const span = mem.spanZ(cstr);

    const _title = u16le("Error\n");

    const title = win.UNICODE_STRING{
        .Length = _title.len * 2,
        .MaximumLength = _title.len * 2,
        .Buffer = @intToPtr([*]u16, @ptrToInt(_title)),
    };

    var buf: [100:0]u16 = undefined;
    const len = std.unicode.utf8ToUtf16Le(&buf, span) catch unreachable;

    const error_msg = win.UNICODE_STRING{
        .Length = @intCast(c_ushort, len) * 2,
        .MaximumLength = @sizeOf(@TypeOf(buf)) - 2,
        .Buffer = &buf,
    };

    var items: [3]usize = .{
        @ptrToInt(&error_msg),
        @ptrToInt(&title),
        0x40, // MB_ICONINFORMATION
    };

    var response: HARDERROR_RESPONSE = undefined;
    _ = NtRaiseHardError(@intToEnum(win.NTSTATUS, 0x50000018), items.len, 3, &items, .OptionOk, &response);
}

comptime {
    @export(errorBox, .{ .name = "errorBox" });
}