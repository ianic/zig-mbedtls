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
    const ArenaAllocator = std.heap.ArenaAllocator;
    const PageAllocator = std.heap.page_allocator;
    var arena = ArenaAllocator.init(PageAllocator);
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(arena.allocator());
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");

    //try mbed.netConnect("www.supersport.hr", "443", mbedTLS.Proto.TCP);
    //try mbed.netConnect("connect.ngs.global", "4222", mbedTLS.Proto.TCP);

    var fd = try tcpConnect();
    std.debug.print("got fd {d}\n", .{fd});
    try mbed.setFd(fd);

    try mbed.sslConfDefaults(.IS_CLIENT, .TCP, .DEFAULT);

    mbed.sslConfAuthmode(.NONE);
    mbed.sslConfRng(null); //use default
    mbed.setConfDebug(null); // use default
    mbed.sslConfCaChain(null); // use parsed CA file from earlier

    try mbed.sslSetup(); // use parsed CA file from earlier
    try mbed.setHostname("hello");
    mbed.sslSetBIO();

    try mbed.sslHandshake();
    // var run = true;
    // while (run) {
    //     const r: bool = mbed.sslHandshake() catch |err| res: {
    //         switch (err) {
    //             error.WantRead => break :res false,
    //             error.WantWrite => break :res false,
    //             else => unreachable,
    //         }
    //     };

    //     run = !r;
    // }

    // const req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    var ret: i32 = 0;
    // while (ret <= 0) {
    //     ret = try mbed.sslWrite(req);
    // }

    ret = try mbed.sslWrite(connect_op);
    std.debug.print("ret on connect_op: {}\n", .{ret});
    ret = try mbed.sslWrite(ping_op);
    std.debug.print("ret on pong_op: {}\n", .{ret});

    ret = 0;
    while (true) {
        var buf: [1024]u8 = undefined;
        ret = try mbed.sslRead(buf[0..]);
        if (ret == 0) break;
        if (ret < 0) break;
        var offset = @intCast(usize, ret);

        std.debug.print("Bytes read {s}", .{buf[0..offset]});
        break;
    }

    return;
}

const connect_op = "CONNECT {\"verbose\":false,\"pedantic\":false,\"tls_required\":false,\"headers\":false,\"name\":\"\",\"lang\":\"zig\",\"version\":\"0.1.0\",\"protocol\":1}\r\n";
const ping_op = "PING\r\n";
