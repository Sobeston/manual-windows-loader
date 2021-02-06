fn returnsTwo() callconv(.C) u8 {
    return 2;
}

comptime {
    @export(returnsTwo, .{ .name = "returnsTwo" });
}