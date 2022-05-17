const std = @import("std");
const Allocator = std.mem.Allocator;
const mbedTLS = @import("mbedtls").mbedTLS;

pub fn main() !void {
    var alloc = std.heap.ArenaAllocator.init(std.heap.page_allocator).allocator();
    var mbed = try mbedTLS.initClient(alloc, "www.google.com", "443");
    defer mbed.deinit();

    const req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    while ((try mbed.sslWrite(req)) <= 0) {}

    while (true) {
        var buf: [4096]u8 = undefined;
        var ret = try mbed.sslRead(buf[0..]);
        if (ret <= 0) break;

        var offset = @intCast(usize, ret);
        std.debug.print("{s}\n", .{buf[0..offset]});
        //std.debug.print("{d} {d}\n", .{ret, offset});
    }
}
