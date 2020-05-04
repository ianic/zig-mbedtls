const std = @import("std");
const c = @cImport({
    @cInclude("lib/zig_ssl_config.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/net.h");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/debug.h");
});

const os = std.os;
const Allocator = std.mem.Allocator;
const c_allocator = std.heap.c_allocator;
const expectEqual = std.testing.expectEqual;
const assert = std.debug.assert;

const MBEDTLS_ERR_PK_ALLOC_FAILED   = -0x3F80;
const MBEDTLS_ERR_PK_BAD_INPUT_DATA = -0x3E80;
const MBEDTLS_ERR_PK_FILE_IO_ERROR  = -0x3E00;

const MBEDTLS_ERR_ERROR_GENERIC_ERROR       = -0x0001;
const MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED = -0x006E;

const MBEDTLS_ERR_AES_BAD_INPUT_DATA        = -0x0021;
const MBEDTLS_ERR_AES_INVALID_KEY_LENGTH    = -0x0020;
const MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH  = -0x0022;

pub const mbedTLS = struct {
    server_fd: *c.mbedtls_net_context,
    ssl_conf: *c.mbedtls_ssl_config,
    ssl: *c.mbedtls_ssl_context,
    entropy: *c.mbedtls_entropy_context,
    drbg: *c.mbedtls_ctr_drbg_context,
    ca_chain: *c.mbedtls_x509_crt,
    entropyfn: @TypeOf(c.mbedtls_entropy_func),
    allocator: *Allocator,

    pub fn init(allocator: *Allocator, cafile: []const u8) !mbedTLS {
        var net_ctx = try allocator.create(c.mbedtls_net_context);
        var entropy_ctx = try allocator.create(c.mbedtls_entropy_context);
        var ssl_config = c.zmbedtls_ssl_config_alloc();
        var ssl_ctx = try allocator.create(c.mbedtls_ssl_context);
        var drbg_ctx = try allocator.create(c.mbedtls_ctr_drbg_context);
        var ca_chain = try allocator.create(c.mbedtls_x509_crt);

        c.mbedtls_net_init(net_ctx);
        c.mbedtls_entropy_init(entropy_ctx);
        c.mbedtls_ssl_init(ssl_ctx);
        c.zmbedtls_ssl_config_init(ssl_config);
        c.mbedtls_ctr_drbg_init(drbg_ctx);
        c.mbedtls_x509_crt_init(ca_chain);

        return mbedTLS {
            .server_fd = net_ctx,
            .entropy = entropy_ctx,
            .ssl = ssl_ctx,
            .ssl_conf = @ptrCast(*c.mbedtls_ssl_config, ssl_config),
            .drbg = drbg_ctx,
            .ca_chain = ca_chain,
            .entropyfn = c.mbedtls_entropy_func,
            .allocator = allocator
        };
    }

    const X509Error = error {
        AllocationFailed,
        BadInputData,
        FileIoError,
        OutOfMemory,
    };

    pub fn x509LoadFile(self: *mbedTLS, cafile: []const u8) X509Error!void {
        const rc = c.mbedtls_x509_crt_parse_file(self.ca_chain, &cafile[0]);
        switch(rc) {
            0 => {},
            MBEDTLS_ERR_PK_ALLOC_FAILED => return error.AllocationFailed,
            MBEDTLS_ERR_PK_BAD_INPUT_DATA => return error.BadInputData,
            MBEDTLS_ERR_PK_FILE_IO_ERROR => return error.FileIoError,
            else => unreachable
        }
    }

    const SeedError = error {
        GenericError,
        Corruption,
        BadInputData,
        InvalidKeyLength,
        InvalidInputLength,
        OutOfMemory
    };

    pub fn seed(self: *mbedTLS, additional: ?[]const u8) SeedError!void {
        var rc: c_int = 1;

        if(additional) |str| {
            var custom = try std.mem.dupe(self.allocator, u8, str);
            defer self.allocator.free(custom);
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, custom.ptr, str.len);
        } else {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, 0x0, 0x0);
        }

        switch(rc) {
            0 => {},
            MBEDTLS_ERR_ERROR_GENERIC_ERROR => return error.GenericError,
            MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return error.Corruption,
            MBEDTLS_ERR_AES_BAD_INPUT_DATA => return error.BadInputData,
            MBEDTLS_ERR_AES_INVALID_KEY_LENGTH => return error.InvalidKeyLength,
            MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH => return error.InvalidInputLength,
            else => unreachable
        }
    }

    pub fn deinit(self: *mbedTLS) void {
        if(self.server_fd.fd > 0)
            os.close(self.server_fd.fd);

        c.zmbedtls_ssl_config_free(self.ssl_conf);
        self.allocator.destroy(self.server_fd);      
        self.allocator.destroy(self.entropy);      
        self.allocator.destroy(self.ssl);
        self.allocator.destroy(self.drbg);
        self.allocator.destroy(self.ca_chain);
        self.* = undefined;
    }
};

const ArenaAllocator = std.heap.ArenaAllocator;
const PageAllocator = std.heap.page_allocator;
var arena = ArenaAllocator.init(PageAllocator);

test "initialize mbedtls" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator, cafile);
    defer mbed.deinit();

    expectEqual(@as(c_int, -1), mbed.server_fd.fd);
}

test "load certificate file" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator, cafile);
    defer mbed.deinit();

    expectEqual(@as(c_int, 0), mbed.ca_chain.*.version);
    try mbed.x509LoadFile(cafile);
    expectEqual(@as(c_int, 3), mbed.ca_chain.*.version);
} 

test "run seed function" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator, cafile);
    defer mbed.deinit();
    
    try mbed.seed("SampleDevice");
    try mbed.seed(null);
}

test "can do mbedtls_ssl_config workaround" {
    var a = c.zmbedtls_ssl_config_alloc();
    c.zmbedtls_ssl_config_init(a);    
    var b = c.zmbedtls_ssl_config_defaults(a);    
    expectEqual(@as(c_int, 0), b);

    c.zmbedtls_ssl_config_free(a);
}
