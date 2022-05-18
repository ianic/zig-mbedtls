const std = @import("std");
const Allocator = std.mem.Allocator;
const mbedTLS = @import("mbedtls").mbedTLS;

const net = std.x.net;
fn tcpConnect() !c_int {
    const addr = net.ip.Address.initIPv4(try std.x.os.IPv4.parse("34.159.160.56"), 4222);
    const client = try net.tcp.Client.init(.ip, .{ .close_on_exec = true });
    try client.connect(addr);
    errdefer client.deinit();

    var buf: [4096]u8 = undefined;
    var offset = try client.read(buf[0..], 0);
    std.debug.print("info: {s}", .{buf[0..offset]});

    return client.socket.fd;
}

pub fn main() !void {
    var alloc = std.heap.ArenaAllocator.init(std.heap.page_allocator).allocator();

    var fd = try tcpConnect();

    var mbed = try mbedTLS.init(alloc);
    defer mbed.deinit();
    try mbed.client();
    //try mbed.insecure();
    try mbed.systemCA();
    try mbed.setHostname("connect.ngs.global");
    try mbed.connectFd(fd);

    var ret: i32 = 0;
    ret = try mbed.sslWrite(connect_op);
    std.debug.print("ret on connect_op: {}\n", .{ret});
    ret = try mbed.sslWrite(ping_op);
    std.debug.print("ret on pong_op: {}\n", .{ret});

    ret = 0;
    while (true) {
        var buf: [1024]u8 = undefined;
        ret = try mbed.sslRead(buf[0..]);
        if (ret == 0) break;

        var offset = @intCast(usize, ret);
        std.debug.print("Bytes read {s}", .{buf[0..offset]});
    }
}

const connect_op = "CONNECT {\"verbose\":false,\"pedantic\":false,\"tls_required\":false,\"headers\":false,\"name\":\"\",\"lang\":\"zig\",\"version\":\"0.1.0\",\"protocol\":1}\r\n";
const ping_op = "PING\r\n";
