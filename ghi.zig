const std = @import("std");

comptime {
    @export(writeInt, .{ .name = "writeInt" });
}

fn writeInt(x: c_int) callconv(.C) void {
    const file = std.fs.cwd().createFile("log.txt", .{}) catch unreachable;
    file.writer().print("my integer is \"{}\" :)", .{x}) catch unreachable;
    defer file.close();
}