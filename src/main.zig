const std = @import("std");

const c = @cImport({
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/net_sockets.h");
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/x509.h");
    @cInclude("mbedtls/debug.h");
    @cInclude("mbedtls/error.h");
});

const os = std.os;
const io = std.io;
const Allocator = std.mem.Allocator;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expect = std.testing.expect;
const assert = std.debug.assert;

pub const mbedTLS = struct {
    server_fd: *c.mbedtls_net_context,
    ssl_conf: *c.mbedtls_ssl_config,
    ssl: *c.mbedtls_ssl_context,
    entropy: *c.mbedtls_entropy_context,
    drbg: *c.mbedtls_ctr_drbg_context,
    ca_chain: *c.mbedtls_x509_crt,
    entropyfn: @TypeOf(c.mbedtls_entropy_func),
    allocator: Allocator,

    pub fn init(allocator: Allocator) !mbedTLS {
        var net_ctx = try allocator.create(c.mbedtls_net_context);
        var entropy_ctx = try allocator.create(c.mbedtls_entropy_context);
        var ssl_config = try allocator.create(c.mbedtls_ssl_config);
        var ssl_ctx = try allocator.create(c.mbedtls_ssl_context);
        var drbg_ctx = try allocator.create(c.mbedtls_ctr_drbg_context);
        var ca_chain = try allocator.create(c.mbedtls_x509_crt);

        c.mbedtls_net_init(net_ctx);
        c.mbedtls_entropy_init(entropy_ctx);
        c.mbedtls_ssl_init(ssl_ctx);
        c.mbedtls_ssl_config_init(ssl_config);
        c.mbedtls_ctr_drbg_init(drbg_ctx);
        c.mbedtls_x509_crt_init(ca_chain);

        var mbed = mbedTLS{
            .server_fd = net_ctx,
            .entropy = entropy_ctx,
            .ssl = ssl_ctx,
            .ssl_conf = ssl_config,
            .drbg = drbg_ctx,
            .ca_chain = ca_chain,
            .entropyfn = c.mbedtls_entropy_func,
            .allocator = allocator,
        };
        try mbed.ctrDrbgSeed(null);

        return mbed;
    }

    pub fn initClient(allocator: Allocator, host: [*]const u8, port: [*]const u8) !mbedTLS {
        var mbed = try init(allocator);

        try mbed.netConnect(host, port, mbedTLS.Proto.TCP);

        try mbed.sslConfDefaults(.IS_CLIENT, .TCP, .DEFAULT);
        mbed.sslConfAuthmode(.NONE);
        mbed.sslConfRng(null); //use default
        mbed.setConfDebug(null); // use default
        mbed.sslConfCaChain(null); // use parsed CA file from earlier

        try mbed.sslSetup(); // use parsed CA file from earlier
        try mbed.setHostname("hello");
        mbed.sslSetBIO();
        try mbed.sslHandshake();

        return mbed;
    }

    pub fn initClientFd(allocator: Allocator, fd: c_int) !mbedTLS {
        var mbed = try init(allocator);
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

        return mbed;
    }

    pub fn x509CrtParseFile(self: *mbedTLS, cafile: []const u8) Error!void {
        const rc = c.mbedtls_x509_crt_parse_file(self.ca_chain, &cafile[0]);
        try checkError(rc);
    }

    pub const Proto = enum(u2) { TCP, UDP };

    pub fn netConnect(self: *mbedTLS, host: [*]const u8, port: [*]const u8, proto: Proto) Error!void {
        const rc = c.mbedtls_net_connect(self.server_fd, host, port, @enumToInt(proto));
        try checkError(rc);
    }

    pub fn setFd(self: *mbedTLS, fd: c_int) !void {
        self.server_fd.fd = fd;
        const rc = c.mbedtls_net_set_block(self.server_fd);
        try checkError(rc);
    }

    pub const SSLEndpoint = enum(u2) { IS_CLIENT, IS_SERVER };
    pub const SSLPreset = enum(u2) { DEFAULT, SUITEB };

    pub fn sslConfDefaults(self: *mbedTLS, ep: SSLEndpoint, pro: Proto, pre: SSLPreset) Error!void {
        const rc = switch (pre) {
            .SUITEB => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(ep), @enumToInt(pro), c.MBEDTLS_SSL_PRESET_SUITEB),
            .DEFAULT => c.mbedtls_ssl_config_defaults(self.ssl_conf, @enumToInt(ep), @enumToInt(pro), c.MBEDTLS_SSL_PRESET_DEFAULT),
        };
        try checkError(rc);
    }

    pub const SSLVerify = enum(u2) { NONE, OPTIONAL, REQUIRED };

    pub fn sslConfAuthmode(self: *mbedTLS, verify: SSLVerify) void {
        c.mbedtls_ssl_conf_authmode(self.ssl_conf, @enumToInt(verify));
    }

    const rng_cb = fn (?*anyopaque, [*c]u8, usize) callconv(.C) c_int;

    pub fn sslConfRng(self: *mbedTLS, f_rng: ?rng_cb) void {
        if (f_rng) |cb| {
            c.mbedtls_ssl_conf_rng(self.ssl_conf, cb, self.drbg);
        } else {
            c.mbedtls_ssl_conf_rng(self.ssl_conf, c.mbedtls_ctr_drbg_random, self.drbg);
        }
    }

    fn dbgfn(ctx: ?*anyopaque, level: c_int, file: [*c]const u8, line: c_int, str: [*c]const u8) callconv(.C) void {
        _ = ctx;
        _ = level;
        std.debug.print("{s}:{}: {s}", .{ file, line, str });
    }

    const debug_fn = fn (?*anyopaque, c_int, [*c]const u8, c_int, [*c]const u8) callconv(.C) void;

    pub fn setConfDebug(self: *mbedTLS, debug: ?debug_fn) void {
        var stdout = io.getStdOut().handle;

        if (debug) |dbg| {
            c.mbedtls_ssl_conf_dbg(self.ssl_conf, dbg, &stdout);
        } else {
            c.mbedtls_ssl_conf_dbg(self.ssl_conf, dbgfn, &stdout);
        }
    }

    pub fn sslConfCaChain(self: *mbedTLS, ca_chain: ?*c.mbedtls_x509_crt) void {
        // TODO: Add CRL support
        if (ca_chain) |ca| {
            c.mbedtls_ssl_conf_ca_chain(self.ssl_conf, ca, 0);
        } else {
            c.mbedtls_ssl_conf_ca_chain(self.ssl_conf, self.ca_chain, 0);
        }
    }

    pub fn sslSetup(self: *mbedTLS) Error!void {
        const rc = c.mbedtls_ssl_setup(self.ssl, self.ssl_conf);
        try checkError(rc);
    }

    pub fn sslSetBIO(self: *mbedTLS) void {
        c.mbedtls_ssl_set_bio(self.ssl, self.server_fd, c.mbedtls_net_send, c.mbedtls_net_recv, null);
    }

    pub fn sslHandshake(self: *mbedTLS) Error!void {
        const rc = c.mbedtls_ssl_handshake(self.ssl);
        try checkError(rc);
    }

    pub fn setHostname(self: *mbedTLS, hostname: []const u8) Error!void {
        const rc = c.mbedtls_ssl_set_hostname(self.ssl, hostname.ptr);
        try checkError(rc);
    }

    pub fn ctrDrbgSeed(self: *mbedTLS, additional: ?[]const u8) Error!void {
        var rc: c_int = 1;

        if (additional) |str| {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, str.ptr, str.len);
        } else {
            rc = c.mbedtls_ctr_drbg_seed(self.drbg, self.entropyfn, self.entropy, 0x0, 0x0);
        }
        try checkError(rc);
    }

    pub fn sslWrite(self: *mbedTLS, str: []const u8) Error!i32 {
        const rc = c.mbedtls_ssl_write(self.ssl, str.ptr, str.len);
        if (rc < 0) {
            try checkError(rc);
        }
        return rc;
    }

    pub fn sslRead(self: *mbedTLS, buffer: []u8) Error!i32 {
        const rc = c.mbedtls_ssl_read(self.ssl, buffer.ptr, buffer.len);
        if (rc < 0) {
            try checkError(rc);
        }
        return rc;
    }

    pub fn deinit(self: *mbedTLS) void {
        c.mbedtls_net_close(self.server_fd);

        self.allocator.destroy(self.ssl_conf);
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
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(@as(c_int, -1), mbed.server_fd.fd);
}

test "load certificate file" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(@as(c_int, 0), mbed.ca_chain.*.version);
    try mbed.x509CrtParseFile(cafile);
    expectEqual(@as(c_int, 3), mbed.ca_chain.*.version);
}

test "run seed function" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    expectEqual(mbed.drbg.entropy_len, 0);

    // Check that it works with additional data and without
    try mbed.ctrDrbgSeed(null);
    try mbed.ctrDrbgSeed("SampleDevice");
    expectEqual(mbed.drbg.entropy_len, 48);
}

test "connect to host" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");
    expectError(error.UnknownHost, mbed.netConnect("google.zom", "443", mbedTLS.Proto.TCP));
    expectEqual(mbed.server_fd.fd, -1);

    try mbed.netConnect("google.com", "443", mbedTLS.Proto.TCP);
    expect(mbed.server_fd.fd > -1);
}

test "set hostname" {
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    const excessive =
        \\ qiqQuz2BRgENxEBUhbMTp0bimui7axuo7jy4WNbopNrNnWSkypugXLNFeionxlwAUhSxlMkVsyc6VGmRTz0gUG
        \\ A3KRDbPCUBPiM7JsdgpI7rLP8EakT5cok2gF6KkAeVr7gfHNdg4auaEDHQfcp5OcLPIQnlVzt4OWSvRl2cOX3G
        \\ V8haOdljSwnmptEWSwFWe2FVsj0s8orr5JGNi91kLrTTpPzaXSoClrGTuireAlLaGExuer1Ue7LAAypC2FWV"
    ;

    expectError(error.BadInputData, mbed.setHostname(excessive));
}

test "can write a request" {
    const cafile = "cacert.pem";
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    try mbed.x509CrtParseFile(cafile);
    try mbed.ctrDrbgSeed("SampleDevice");
    try mbed.netConnect("google.com", "443", mbedTLS.Proto.TCP);
    try mbed.setHostname("zig-mbedtls");
    const req = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

    const ret = try mbed.sslWrite(req);
    expect(ret > 0);
}

// This test is very sketchy and will break on any ssl_conf struct changes in
// mbedTLS. Disable if too much hassle too maintain
test "set ssl defaults and presets" {
    const Preset = mbedTLS.SSLPreset;
    const Endpoint = mbedTLS.SSLEndpoint;
    const Proto = mbedTLS.Proto;
    var mbed = try mbedTLS.init(&arena.allocator);
    defer mbed.deinit();

    // We cant access these by field since the struct is opaque
    // These entries in the struct is on memory address 0x170 after base
    // If 0x00500000 is the base address, then:
    // 0x100500170: 3 == unsigned char max_major_ver;
    // 0x100500171: 3 == unsigned char max_minor_ver;
    // 0x100500172: 3 == unsigned char min_major_ver;
    // 0x100500173: 1 == unsigned char min_minor_ver;
    const memaddr: usize = @ptrToInt(mbed.ssl_conf);
    const max_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x170);
    const max_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x171);
    const min_major_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x172);
    const min_minor_ver: *u2 = @intToPtr(*align(1) u2, memaddr + 0x173);

    expect(0 == max_major_ver.*);
    expect(0 == max_minor_ver.*);
    expect(0 == min_major_ver.*);
    expect(0 == min_minor_ver.*);
    try mbed.sslConfDefaults(Endpoint.IS_CLIENT, Proto.TCP, Preset.DEFAULT);
    expect(3 == max_major_ver.*);
    expect(3 == max_minor_ver.*);
    expect(3 == min_major_ver.*);
    expect(1 == min_minor_ver.*);
}

test "can do mbedtls_ssl_config workaround" {
    var a = c.zmbedtls_ssl_config_alloc();
    c.zmbedtls_ssl_config_init(a);
    var b = c.zmbedtls_ssl_config_defaults(a, 0, 0, 0);
    expectEqual(@as(c_int, 0), b);

    c.zmbedtls_ssl_config_free(a);
}

pub const Error = error{
    Unknown,
    Sha512BadInputData,
    ThreadingBadInputData,
    ThreadingMutexError,
    EntropySourceFailed,
    EntropyMaxSources,
    EntropyNoSourcesDefined,
    EntropyNoStrongSource,
    EntropyFileIoError,
    AesInvalidKeyLength,
    AesInvalidInputLength,
    AesBadInputData,
    CtrDrbgEntropySourceFailed,
    CtrDrbgRequestTooBig,
    CtrDrbgInputTooBig,
    CtrDrbgFileIoError,
    MpiFileIoError,
    MpiBadInputData,
    MpiInvalidCharacter,
    MpiBufferTooSmall,
    MpiNegativeValue,
    MpiDivisionByZero,
    MpiNotAcceptable,
    MpiAllocFailed,
    EcpBadInputData,
    EcpBufferTooSmall,
    EcpFeatureUnavailable,
    EcpVerifyFailed,
    EcpAllocFailed,
    EcpRandomFailed,
    EcpInvalidKey,
    EcpSigLenMismatch,
    EcpInProgress,
    MdFeatureUnavailable,
    MdBadInputData,
    MdAllocFailed,
    MdFileIoError,
    RsaBadInputData,
    RsaInvalidPadding,
    RsaKeyGenFailed,
    RsaKeyCheckFailed,
    RsaPublicFailed,
    RsaPrivateFailed,
    RsaVerifyFailed,
    RsaOutputTooLarge,
    RsaRngFailed,
    PkAllocFailed,
    PkTypeMismatch,
    PkBadInputData,
    PkFileIoError,
    PkKeyInvalidVersion,
    PkKeyInvalidFormat,
    PkUnknownPkAlg,
    PkPasswordRequired,
    PkPasswordMismatch,
    PkInvalidPubkey,
    PkInvalidAlg,
    PkUnknownNamedCurve,
    PkFeatureUnavailable,
    PkSigLenMismatch,
    PkBufferTooSmall,
    CipherFeatureUnavailable,
    CipherBadInputData,
    CipherAllocFailed,
    CipherInvalidPadding,
    CipherFullBlockExpected,
    CipherAuthFailed,
    CipherInvalidContext,
    Asn1OutOfData,
    Asn1UnexpectedTag,
    Asn1InvalidLength,
    Asn1LengthMismatch,
    Asn1InvalidData,
    Asn1AllocFailed,
    Asn1BufTooSmall,
    X509FeatureUnavailable,
    X509UnknownOid,
    X509InvalidFormat,
    X509InvalidVersion,
    X509InvalidSerial,
    X509InvalidAlg,
    X509InvalidName,
    X509InvalidDate,
    X509InvalidSignature,
    X509InvalidExtensions,
    X509UnknownVersion,
    X509UnknownSigAlg,
    X509SigMismatch,
    X509CertVerifyFailed,
    X509CertUnknownFormat,
    X509BadInputData,
    X509AllocFailed,
    X509FileIoError,
    X509BufferTooSmall,
    X509FatalError,
    DhmBadInputData,
    DhmReadParamsFailed,
    DhmMakeParamsFailed,
    DhmReadPublicFailed,
    DhmMakePublicFailed,
    DhmCalcSecretFailed,
    DhmInvalidFormat,
    DhmAllocFailed,
    DhmFileIoError,
    DhmSetGroupFailed,
    SslCryptoInProgress,
    SslFeatureUnavailable,
    SslBadInputData,
    SslInvalidMac,
    SslInvalidRecord,
    SslConnEof,
    SslDecodeError,
    SslNoRng,
    SslNoClientCertificate,
    SslUnsupportedExtension,
    SslNoApplicationProtocol,
    SslPrivateKeyRequired,
    SslCaChainRequired,
    SslUnexpectedMessage,
    SslFatalAlertMessage,
    SslUnrecognizedName,
    SslPeerCloseNotify,
    SslBadCertificate,
    SslAllocFailed,
    SslHwAccelFailed,
    SslHwAccelFallthrough,
    SslBadProtocolVersion,
    SslHandshakeFailure,
    SslSessionTicketExpired,
    SslPkTypeMismatch,
    SslUnknownIdentity,
    SslInternalError,
    SslCounterWrapping,
    SslWaitingServerHelloRenego,
    SslHelloVerifyRequired,
    SslBufferTooSmall,
    SslWantRead,
    SslWantWrite,
    SslTimeout,
    SslClientReconnect,
    SslUnexpectedRecord,
    SslNonFatal,
    SslIllegalParameter,
    SslContinueProcessing,
    SslAsyncInProgress,
    SslEarlyMessage,
    SslUnexpectedCid,
    SslVersionMismatch,
    SslBadConfig,
    NetSocketFailed,
    NetConnectFailed,
    NetBindFailed,
    NetListenFailed,
    NetAcceptFailed,
    NetRecvFailed,
    NetSendFailed,
    NetConnReset,
    NetUnknownHost,
    NetBufferTooSmall,
    NetInvalidContext,
    NetPollFailed,
    NetBadInputData,
    ErrorGenericError,
    ErrorCorruptionDetected,
    PlatformHwAccelFailed,
    PlatformFeatureUnsupported,
};

pub fn checkError(rc: c_int) Error!void {
    return switch (rc) {
        0 => {},
        c.MBEDTLS_ERR_SHA512_BAD_INPUT_DATA => return Error.Sha512BadInputData,
        c.MBEDTLS_ERR_THREADING_BAD_INPUT_DATA => return Error.ThreadingBadInputData,
        c.MBEDTLS_ERR_THREADING_MUTEX_ERROR => return Error.ThreadingMutexError,
        c.MBEDTLS_ERR_ENTROPY_SOURCE_FAILED => return Error.EntropySourceFailed,
        c.MBEDTLS_ERR_ENTROPY_MAX_SOURCES => return Error.EntropyMaxSources,
        c.MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED => return Error.EntropyNoSourcesDefined,
        c.MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE => return Error.EntropyNoStrongSource,
        c.MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR => return Error.EntropyFileIoError,
        c.MBEDTLS_ERR_AES_INVALID_KEY_LENGTH => return Error.AesInvalidKeyLength,
        c.MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH => return Error.AesInvalidInputLength,
        c.MBEDTLS_ERR_AES_BAD_INPUT_DATA => return Error.AesBadInputData,
        c.MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED => return Error.CtrDrbgEntropySourceFailed,
        c.MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG => return Error.CtrDrbgRequestTooBig,
        c.MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG => return Error.CtrDrbgInputTooBig,
        c.MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR => return Error.CtrDrbgFileIoError,
        c.MBEDTLS_ERR_MPI_FILE_IO_ERROR => return Error.MpiFileIoError,
        c.MBEDTLS_ERR_MPI_BAD_INPUT_DATA => return Error.MpiBadInputData,
        c.MBEDTLS_ERR_MPI_INVALID_CHARACTER => return Error.MpiInvalidCharacter,
        c.MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL => return Error.MpiBufferTooSmall,
        c.MBEDTLS_ERR_MPI_NEGATIVE_VALUE => return Error.MpiNegativeValue,
        c.MBEDTLS_ERR_MPI_DIVISION_BY_ZERO => return Error.MpiDivisionByZero,
        c.MBEDTLS_ERR_MPI_NOT_ACCEPTABLE => return Error.MpiNotAcceptable,
        c.MBEDTLS_ERR_MPI_ALLOC_FAILED => return Error.MpiAllocFailed,
        c.MBEDTLS_ERR_ECP_BAD_INPUT_DATA => return Error.EcpBadInputData,
        c.MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL => return Error.EcpBufferTooSmall,
        c.MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE => return Error.EcpFeatureUnavailable,
        c.MBEDTLS_ERR_ECP_VERIFY_FAILED => return Error.EcpVerifyFailed,
        c.MBEDTLS_ERR_ECP_ALLOC_FAILED => return Error.EcpAllocFailed,
        c.MBEDTLS_ERR_ECP_RANDOM_FAILED => return Error.EcpRandomFailed,
        c.MBEDTLS_ERR_ECP_INVALID_KEY => return Error.EcpInvalidKey,
        c.MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH => return Error.EcpSigLenMismatch,
        c.MBEDTLS_ERR_ECP_IN_PROGRESS => return Error.EcpInProgress,
        c.MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE => return Error.MdFeatureUnavailable,
        c.MBEDTLS_ERR_MD_BAD_INPUT_DATA => return Error.MdBadInputData,
        c.MBEDTLS_ERR_MD_ALLOC_FAILED => return Error.MdAllocFailed,
        c.MBEDTLS_ERR_MD_FILE_IO_ERROR => return Error.MdFileIoError,
        c.MBEDTLS_ERR_RSA_BAD_INPUT_DATA => return Error.RsaBadInputData,
        c.MBEDTLS_ERR_RSA_INVALID_PADDING => return Error.RsaInvalidPadding,
        c.MBEDTLS_ERR_RSA_KEY_GEN_FAILED => return Error.RsaKeyGenFailed,
        c.MBEDTLS_ERR_RSA_KEY_CHECK_FAILED => return Error.RsaKeyCheckFailed,
        c.MBEDTLS_ERR_RSA_PUBLIC_FAILED => return Error.RsaPublicFailed,
        c.MBEDTLS_ERR_RSA_PRIVATE_FAILED => return Error.RsaPrivateFailed,
        c.MBEDTLS_ERR_RSA_VERIFY_FAILED => return Error.RsaVerifyFailed,
        c.MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE => return Error.RsaOutputTooLarge,
        c.MBEDTLS_ERR_RSA_RNG_FAILED => return Error.RsaRngFailed,
        c.MBEDTLS_ERR_PK_ALLOC_FAILED => return Error.PkAllocFailed,
        c.MBEDTLS_ERR_PK_TYPE_MISMATCH => return Error.PkTypeMismatch,
        c.MBEDTLS_ERR_PK_BAD_INPUT_DATA => return Error.PkBadInputData,
        c.MBEDTLS_ERR_PK_FILE_IO_ERROR => return Error.PkFileIoError,
        c.MBEDTLS_ERR_PK_KEY_INVALID_VERSION => return Error.PkKeyInvalidVersion,
        c.MBEDTLS_ERR_PK_KEY_INVALID_FORMAT => return Error.PkKeyInvalidFormat,
        c.MBEDTLS_ERR_PK_UNKNOWN_PK_ALG => return Error.PkUnknownPkAlg,
        c.MBEDTLS_ERR_PK_PASSWORD_REQUIRED => return Error.PkPasswordRequired,
        c.MBEDTLS_ERR_PK_PASSWORD_MISMATCH => return Error.PkPasswordMismatch,
        c.MBEDTLS_ERR_PK_INVALID_PUBKEY => return Error.PkInvalidPubkey,
        c.MBEDTLS_ERR_PK_INVALID_ALG => return Error.PkInvalidAlg,
        c.MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE => return Error.PkUnknownNamedCurve,
        c.MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE => return Error.PkFeatureUnavailable,
        c.MBEDTLS_ERR_PK_SIG_LEN_MISMATCH => return Error.PkSigLenMismatch,
        c.MBEDTLS_ERR_PK_BUFFER_TOO_SMALL => return Error.PkBufferTooSmall,
        c.MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE => return Error.CipherFeatureUnavailable,
        c.MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA => return Error.CipherBadInputData,
        c.MBEDTLS_ERR_CIPHER_ALLOC_FAILED => return Error.CipherAllocFailed,
        c.MBEDTLS_ERR_CIPHER_INVALID_PADDING => return Error.CipherInvalidPadding,
        c.MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED => return Error.CipherFullBlockExpected,
        c.MBEDTLS_ERR_CIPHER_AUTH_FAILED => return Error.CipherAuthFailed,
        c.MBEDTLS_ERR_CIPHER_INVALID_CONTEXT => return Error.CipherInvalidContext,
        c.MBEDTLS_ERR_ASN1_OUT_OF_DATA => return Error.Asn1OutOfData,
        c.MBEDTLS_ERR_ASN1_UNEXPECTED_TAG => return Error.Asn1UnexpectedTag,
        c.MBEDTLS_ERR_ASN1_INVALID_LENGTH => return Error.Asn1InvalidLength,
        c.MBEDTLS_ERR_ASN1_LENGTH_MISMATCH => return Error.Asn1LengthMismatch,
        c.MBEDTLS_ERR_ASN1_INVALID_DATA => return Error.Asn1InvalidData,
        c.MBEDTLS_ERR_ASN1_ALLOC_FAILED => return Error.Asn1AllocFailed,
        c.MBEDTLS_ERR_ASN1_BUF_TOO_SMALL => return Error.Asn1BufTooSmall,
        c.MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE => return Error.X509FeatureUnavailable,
        c.MBEDTLS_ERR_X509_UNKNOWN_OID => return Error.X509UnknownOid,
        c.MBEDTLS_ERR_X509_INVALID_FORMAT => return Error.X509InvalidFormat,
        c.MBEDTLS_ERR_X509_INVALID_VERSION => return Error.X509InvalidVersion,
        c.MBEDTLS_ERR_X509_INVALID_SERIAL => return Error.X509InvalidSerial,
        c.MBEDTLS_ERR_X509_INVALID_ALG => return Error.X509InvalidAlg,
        c.MBEDTLS_ERR_X509_INVALID_NAME => return Error.X509InvalidName,
        c.MBEDTLS_ERR_X509_INVALID_DATE => return Error.X509InvalidDate,
        c.MBEDTLS_ERR_X509_INVALID_SIGNATURE => return Error.X509InvalidSignature,
        c.MBEDTLS_ERR_X509_INVALID_EXTENSIONS => return Error.X509InvalidExtensions,
        c.MBEDTLS_ERR_X509_UNKNOWN_VERSION => return Error.X509UnknownVersion,
        c.MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG => return Error.X509UnknownSigAlg,
        c.MBEDTLS_ERR_X509_SIG_MISMATCH => return Error.X509SigMismatch,
        c.MBEDTLS_ERR_X509_CERT_VERIFY_FAILED => return Error.X509CertVerifyFailed,
        c.MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT => return Error.X509CertUnknownFormat,
        c.MBEDTLS_ERR_X509_BAD_INPUT_DATA => return Error.X509BadInputData,
        c.MBEDTLS_ERR_X509_ALLOC_FAILED => return Error.X509AllocFailed,
        c.MBEDTLS_ERR_X509_FILE_IO_ERROR => return Error.X509FileIoError,
        c.MBEDTLS_ERR_X509_BUFFER_TOO_SMALL => return Error.X509BufferTooSmall,
        c.MBEDTLS_ERR_X509_FATAL_ERROR => return Error.X509FatalError,
        c.MBEDTLS_ERR_DHM_BAD_INPUT_DATA => return Error.DhmBadInputData,
        c.MBEDTLS_ERR_DHM_READ_PARAMS_FAILED => return Error.DhmReadParamsFailed,
        c.MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED => return Error.DhmMakeParamsFailed,
        c.MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED => return Error.DhmReadPublicFailed,
        c.MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED => return Error.DhmMakePublicFailed,
        c.MBEDTLS_ERR_DHM_CALC_SECRET_FAILED => return Error.DhmCalcSecretFailed,
        c.MBEDTLS_ERR_DHM_INVALID_FORMAT => return Error.DhmInvalidFormat,
        c.MBEDTLS_ERR_DHM_ALLOC_FAILED => return Error.DhmAllocFailed,
        c.MBEDTLS_ERR_DHM_FILE_IO_ERROR => return Error.DhmFileIoError,
        c.MBEDTLS_ERR_DHM_SET_GROUP_FAILED => return Error.DhmSetGroupFailed,
        c.MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS => return Error.SslCryptoInProgress,
        c.MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE => return Error.SslFeatureUnavailable,
        c.MBEDTLS_ERR_SSL_BAD_INPUT_DATA => return Error.SslBadInputData,
        c.MBEDTLS_ERR_SSL_INVALID_MAC => return Error.SslInvalidMac,
        c.MBEDTLS_ERR_SSL_INVALID_RECORD => return Error.SslInvalidRecord,
        c.MBEDTLS_ERR_SSL_CONN_EOF => return Error.SslConnEof,
        c.MBEDTLS_ERR_SSL_DECODE_ERROR => return Error.SslDecodeError,
        c.MBEDTLS_ERR_SSL_NO_RNG => return Error.SslNoRng,
        c.MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE => return Error.SslNoClientCertificate,
        c.MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION => return Error.SslUnsupportedExtension,
        c.MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL => return Error.SslNoApplicationProtocol,
        c.MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED => return Error.SslPrivateKeyRequired,
        c.MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED => return Error.SslCaChainRequired,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE => return Error.SslUnexpectedMessage,
        c.MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE => return Error.SslFatalAlertMessage,
        c.MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME => return Error.SslUnrecognizedName,
        c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY => return Error.SslPeerCloseNotify,
        c.MBEDTLS_ERR_SSL_BAD_CERTIFICATE => return Error.SslBadCertificate,
        c.MBEDTLS_ERR_SSL_ALLOC_FAILED => return Error.SslAllocFailed,
        c.MBEDTLS_ERR_SSL_HW_ACCEL_FAILED => return Error.SslHwAccelFailed,
        c.MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH => return Error.SslHwAccelFallthrough,
        c.MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION => return Error.SslBadProtocolVersion,
        c.MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE => return Error.SslHandshakeFailure,
        c.MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED => return Error.SslSessionTicketExpired,
        c.MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH => return Error.SslPkTypeMismatch,
        c.MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY => return Error.SslUnknownIdentity,
        c.MBEDTLS_ERR_SSL_INTERNAL_ERROR => return Error.SslInternalError,
        c.MBEDTLS_ERR_SSL_COUNTER_WRAPPING => return Error.SslCounterWrapping,
        c.MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO => return Error.SslWaitingServerHelloRenego,
        c.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED => return Error.SslHelloVerifyRequired,
        c.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL => return Error.SslBufferTooSmall,
        c.MBEDTLS_ERR_SSL_WANT_READ => return Error.SslWantRead,
        c.MBEDTLS_ERR_SSL_WANT_WRITE => return Error.SslWantWrite,
        c.MBEDTLS_ERR_SSL_TIMEOUT => return Error.SslTimeout,
        c.MBEDTLS_ERR_SSL_CLIENT_RECONNECT => return Error.SslClientReconnect,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_RECORD => return Error.SslUnexpectedRecord,
        c.MBEDTLS_ERR_SSL_NON_FATAL => return Error.SslNonFatal,
        c.MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER => return Error.SslIllegalParameter,
        c.MBEDTLS_ERR_SSL_CONTINUE_PROCESSING => return Error.SslContinueProcessing,
        c.MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS => return Error.SslAsyncInProgress,
        c.MBEDTLS_ERR_SSL_EARLY_MESSAGE => return Error.SslEarlyMessage,
        c.MBEDTLS_ERR_SSL_UNEXPECTED_CID => return Error.SslUnexpectedCid,
        c.MBEDTLS_ERR_SSL_VERSION_MISMATCH => return Error.SslVersionMismatch,
        c.MBEDTLS_ERR_SSL_BAD_CONFIG => return Error.SslBadConfig,
        c.MBEDTLS_ERR_NET_SOCKET_FAILED => return Error.NetSocketFailed,
        c.MBEDTLS_ERR_NET_CONNECT_FAILED => return Error.NetConnectFailed,
        c.MBEDTLS_ERR_NET_BIND_FAILED => return Error.NetBindFailed,
        c.MBEDTLS_ERR_NET_LISTEN_FAILED => return Error.NetListenFailed,
        c.MBEDTLS_ERR_NET_ACCEPT_FAILED => return Error.NetAcceptFailed,
        c.MBEDTLS_ERR_NET_RECV_FAILED => return Error.NetRecvFailed,
        c.MBEDTLS_ERR_NET_SEND_FAILED => return Error.NetSendFailed,
        c.MBEDTLS_ERR_NET_CONN_RESET => return Error.NetConnReset,
        c.MBEDTLS_ERR_NET_UNKNOWN_HOST => return Error.NetUnknownHost,
        c.MBEDTLS_ERR_NET_BUFFER_TOO_SMALL => return Error.NetBufferTooSmall,
        c.MBEDTLS_ERR_NET_INVALID_CONTEXT => return Error.NetInvalidContext,
        c.MBEDTLS_ERR_NET_POLL_FAILED => return Error.NetPollFailed,
        c.MBEDTLS_ERR_NET_BAD_INPUT_DATA => return Error.NetBadInputData,
        c.MBEDTLS_ERR_ERROR_GENERIC_ERROR => return Error.ErrorGenericError,
        c.MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED => return Error.ErrorCorruptionDetected,
        c.MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED => return Error.PlatformHwAccelFailed,
        c.MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED => return Error.PlatformFeatureUnsupported,
        else => Error.Unknown,
    };
}
