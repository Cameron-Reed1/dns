const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

var next_id: std.atomic.Value(u16) = .init(1);

pub const Result = struct {
    answers: []RecordData,
    authority_records: []RecordData,
    additional_records: []RecordData,

    pub fn deinit(self: *const Result, gpa: Allocator) void {
        for (self.answers) |*r| r.deinit(gpa);
        for (self.authority_records) |*r| r.deinit(gpa);
        for (self.additional_records) |*r| r.deinit(gpa);

        gpa.free(self.answers);
        gpa.free(self.authority_records);
        gpa.free(self.additional_records);
    }
};

pub const RecordType = enum(u16) {
    a = 1,
    ns = 2,
    md = 3,
    mf = 4,
    cname = 5,
    soa = 6,
    mb = 7,
    mg = 8,
    mr = 9,
    null = 10,
    wks = 11,
    ptr = 12,
    hinfo = 13,
    minfo = 14,
    mx = 15,
    txt = 16,

    aaaa = 28,
};

pub const Class = enum(u16) {
    in = 1,
};

pub const RecordData = union(RecordType) {
    a: A,
    ns: NS,
    md: MD,
    mf: MF,
    cname: CNAME,
    soa: SOA,
    mb: MB,
    mg: MG,
    mr: MR,
    null: NULL,
    wks: WKS,
    ptr: PTR,
    hinfo: HINFO,
    minfo: MINFO,
    mx: MX,
    txt: TXT,

    aaaa: AAAA,

    const A = struct {
        addr: [4]u8,
    };
    const NS = struct {
        nsdname: []const u8,
    };
    const MD = struct {
        madname: []const u8,
    };
    const MF = struct {
        madname: []const u8,
    };
    const CNAME = struct {
        cname: []const u8,
    };
    const SOA = struct {
        mname: []const u8,
        rname: []const u8,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    };
    const MB = struct {
        madname: []const u8,
    };
    const MG = struct {
        madname: []const u8,
    };
    const MR = struct {
        newname: []const u8,
    };
    const NULL = struct {
        data: []const u8,
    };
    const WKS = struct {
        addr: [4]u8,
        protocol: u8,
        bitmap: []const u8,
    };
    const PTR = struct {
        ptrdname: []const u8,
    };
    const HINFO = struct {
        cpu: []const u8,
        os: []const u8,
    };
    const MINFO = struct {
        rmailbx: []const u8,
        emailbx: []const u8,
    };
    const MX = struct {
        preference: u16,
        exchange: []const u8,
    };
    const TXT = struct {
        data: []const u8,
    };

    const AAAA = struct {
        addr: [16]u8,
    };

    pub fn parse(ctx: *MessageParseContext, rtype: RecordType, data: []const u8) !RecordData {
        return switch (rtype) {
            .a => blk: {
                if (data.len != 4) return error.InvalidRDataFormat;
                break :blk .{ .a = .{ .addr = data[0..4].* } };
            },
            .ns => blk: {
                var reader = Io.Reader.fixed(data);
                const nsdname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .ns = .{ .nsdname = nsdname } };
            },
            .md => blk: {
                var reader = Io.Reader.fixed(data);
                const madname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .md = .{ .madname = madname } };
            },
            .mf => blk: {
                var reader = Io.Reader.fixed(data);
                const madname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .mf = .{ .madname = madname } };
            },
            .cname => blk: {
                var reader = Io.Reader.fixed(data);
                const cname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .cname = .{ .cname = cname } };
            },
            .soa => blk: {
                var reader = Io.Reader.fixed(data);
                const mname = try parseDomainNameString(ctx, &reader);
                const rname = try parseDomainNameString(ctx, &reader);

                const remaining = reader.buffered();
                if (remaining.len != 20) return error.InvalidRDataFormat;

                const serial = std.mem.readInt(u32, remaining[0..4], .big);
                const refresh = std.mem.readInt(i32, remaining[4..8], .big);
                const retry = std.mem.readInt(i32, remaining[8..12], .big);
                const expire = std.mem.readInt(i32, remaining[12..16], .big);
                const minimum = std.mem.readInt(u32, remaining[16..20], .big);

                break :blk .{ .soa = .{ .mname = mname, .rname = rname, .serial = serial, .refresh = refresh, .retry = retry, .expire = expire, .minimum = minimum } };
            },
            .mb => blk: {
                var reader = Io.Reader.fixed(data);
                const madname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .mb = .{ .madname = madname } };
            },
            .mg => blk: {
                var reader = Io.Reader.fixed(data);
                const madname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .mg = .{ .madname = madname } };
            },
            .mr => blk: {
                var reader = Io.Reader.fixed(data);
                const newname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .mr = .{ .newname = newname } };
            },
            .null => .{ .null = .{ .data = data } },
            .wks => blk: {
                if (data.len < 6) return error.InvalidRDataFormat;
                break :blk .{ .wks = .{ .addr = data[0..4].*, .protocol = data[4], .bitmap = data[5..] } };
            },
            .ptr => blk: {
                var reader = Io.Reader.fixed(data);
                const ptrdname = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .ptr = .{ .ptrdname = ptrdname } };
            },
            .hinfo => blk: {
                var null_idx = std.mem.indexOfScalar(u8, data, 0) orelse return error.InvalidRDataFormat;
                const cpu = data[0..null_idx];

                const remaining_data = data[0..null_idx];
                null_idx = std.mem.indexOfScalar(u8, remaining_data, 0) orelse return error.InvalidRDataFormat;
                const os = remaining_data[0..null_idx];

                if (cpu.len + os.len + 2 != data.len) return error.InvalidRDataFormat;
                break :blk .{ .hinfo = .{ .cpu = cpu, .os = os } };
            },
            .minfo => blk: {
                var reader = Io.Reader.fixed(data);
                const rmailbx = try parseDomainNameString(ctx, &reader);
                const emailbx = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;
                break :blk .{ .minfo = .{ .rmailbx = rmailbx, .emailbx = emailbx } };
            },
            .mx => blk: {
                const preference = std.mem.readInt(u16, data[0..2], .big);

                var reader = Io.Reader.fixed(data[2..]);
                const exchange = try parseDomainNameString(ctx, &reader);
                if (reader.bufferedLen() != 0) return error.InvalidRDataFormat;

                break :blk .{ .mx = .{ .preference = preference, .exchange = exchange } };
            },
            .txt => .{ .txt = .{ .data = data } },

            .aaaa => blk: {
                if (data.len != 16) return error.InvalidRDataFormat;
                break :blk .{ .aaaa = .{ .addr = data[0..16].* } };
            },
        };
    }

    pub fn print(self: *const RecordData) void {
        switch (self.*) {
            .a => |a| std.debug.print("A: {d}.{d}.{d}.{d}\n", .{ a.addr[0], a.addr[1], a.addr[2], a.addr[3] }),
            .ns => |ns| std.debug.print("NS: {s}\n", .{ns.nsdname}),
            .md => |md| std.debug.print("MD: {s}\n", .{md.madname}),
            .mf => |mf| std.debug.print("MF: {s}\n", .{mf.madname}),
            .cname => |cname| std.debug.print("CNAME: {s}\n", .{cname.cname}),
            .soa => |soa| std.debug.print("SOA:\n\tMNAME: {s}\n\tRNAME: {s}\n\tSERIAL: {d}\n\tREFRESH: {d}\n\tRETRY: {d}\n\tEXPIRE: {d}\n\tMINIMUM: {d}\n", .{ soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum }),
            .mb => |mb| std.debug.print("MB: {s}\n", .{mb.madname}),
            .mg => |mg| std.debug.print("MG: {s}\n", .{mg.madname}),
            .mr => |mr| std.debug.print("MR: {s}\n", .{mr.newname}),
            .null => |n| std.debug.print("NULL: {any}\n", .{n.data}),
            .wks => |wks| std.debug.print("WKS:\n\tADDR: {d}.{d}.{d}.{d}\n\tPROTOCOL: {d}\n\tBITMAP: {any}\n", .{ wks.addr[0], wks.addr[1], wks.addr[2], wks.addr[3], wks.protocol, wks.bitmap }),
            .ptr => |ptr| std.debug.print("PTR: {s}\n", .{ptr.ptrdname}),
            .hinfo => |hinfo| std.debug.print("HINFO:\n\tCPU: {s}\n\tOS: {s}\n", .{ hinfo.cpu, hinfo.os }),
            .minfo => |minfo| std.debug.print("MINFO:\n\tRMAILBX: {s}\n\tEMAILBX: {s}\n", .{ minfo.rmailbx, minfo.emailbx }),
            .mx => |mx| std.debug.print("MX:\n\tPREFERENCE: {d}\n\tEXCHANGE: {s}\n", .{ mx.preference, mx.exchange }),
            .txt => |txt| std.debug.print("TXT: {s}\n", .{txt.data}),

            .aaaa => |aaaa| std.debug.print("AAAA: {x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}\n", .{ aaaa.addr[0], aaaa.addr[1], aaaa.addr[2], aaaa.addr[3], aaaa.addr[4], aaaa.addr[5], aaaa.addr[6], aaaa.addr[7], aaaa.addr[8], aaaa.addr[9], aaaa.addr[10], aaaa.addr[11], aaaa.addr[12], aaaa.addr[13], aaaa.addr[14], aaaa.addr[15] }),
        }
    }

    pub fn deinit(self: *const RecordData, gpa: Allocator) void {
        switch (self.*) {
            .a => {},
            .ns => |ns| gpa.free(ns.nsdname),
            .md => |md| gpa.free(md.madname),
            .mf => |mf| gpa.free(mf.madname),
            .cname => |cname| gpa.free(cname.cname),
            .soa => |soa| {
                gpa.free(soa.mname);
                gpa.free(soa.rname);
            },
            .mb => |mb| gpa.free(mb.madname),
            .mg => |mg| gpa.free(mg.madname),
            .mr => |mr| gpa.free(mr.newname),
            .null => {},
            .wks => {},
            .ptr => |ptr| gpa.free(ptr.ptrdname),
            .hinfo => {},
            .minfo => |minfo| {
                gpa.free(minfo.rmailbx);
                gpa.free(minfo.emailbx);
            },
            .mx => |mx| gpa.free(mx.exchange),
            .txt => {},

            .aaaa => {},
        }
    }
};

const MessageParseContext = struct {
    gpa: Allocator,
    bytes: std.ArrayList(u8) = .empty,
    reader: *Io.Reader,
    read_idx: ?usize = null,

    pub fn read(self: *MessageParseContext, n: usize) ![]const u8 {
        if (self.read_idx) |idx| {
            std.debug.assert(idx + n <= self.bytes.items.len);
            self.read_idx = idx + n;
            return self.bytes.items[idx..][0..n];
        }

        const bytes = try self.reader.take(n);
        try self.bytes.appendSlice(self.gpa, bytes);

        return self.bytes.items[self.bytes.items.len - bytes.len .. self.bytes.items.len];
    }

    pub fn readByte(self: *MessageParseContext) !u8 {
        const slice = try self.read(1);
        return slice[0];
    }

    pub fn readInt(self: *MessageParseContext, T: type) !T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return std.mem.readInt(T, (try self.read(n))[0..n], .big);
    }

    pub fn deinit(self: *MessageParseContext) void {
        self.bytes.deinit(self.gpa);
    }
};

const Message = struct {
    header: MessageHeader,
    questions: []MessageQuestion,
    answers: []ResourceRecord,
    authority_records: []ResourceRecord,
    additional_records: []ResourceRecord,

    pub fn initQuery(gpa: Allocator, name: []const u8, rec_type: RecordType) !Message {
        var header: MessageHeader = .defaultQuery;
        header.set_id();
        header.qd_count = 1;

        const questions = try gpa.alloc(MessageQuestion, 1);
        errdefer gpa.free(questions);

        questions[0] = .{
            .name = name,
            .type = rec_type,
            .class = .in,
        };

        return .{
            .header = header,
            .questions = questions,
            .answers = &.{},
            .authority_records = &.{},
            .additional_records = &.{},
        };
    }

    pub fn deinit(self: *const Message, gpa: Allocator) void {
        if (self.questions.len != 0) gpa.free(self.questions);
        if (self.answers.len != 0) gpa.free(self.answers);
        if (self.authority_records.len != 0) gpa.free(self.authority_records);
        if (self.additional_records.len != 0) gpa.free(self.additional_records);
    }

    pub fn to_bytes(self: *const Message, gpa: Allocator) ![]const u8 {
        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(gpa);

        try msg.appendSlice(gpa, &self.header.to_bytes());

        for (self.questions) |q| {
            const bytes = try q.to_bytes(gpa);
            defer gpa.free(bytes);

            try msg.appendSlice(gpa, bytes);
        }

        for (self.answers) |r| {
            const bytes = try r.to_bytes(gpa);
            defer gpa.free(bytes);

            try msg.appendSlice(gpa, bytes);
        }

        for (self.authority_records) |r| {
            const bytes = try r.to_bytes(gpa);
            defer gpa.free(bytes);

            try msg.appendSlice(gpa, bytes);
        }

        for (self.additional_records) |r| {
            const bytes = try r.to_bytes(gpa);
            defer gpa.free(bytes);

            try msg.appendSlice(gpa, bytes);
        }

        return try msg.toOwnedSlice(gpa);
    }

    pub fn read(ctx: *MessageParseContext) !Message {
        const header_bytes = try ctx.read(12);
        const header: MessageHeader = .from_bytes(header_bytes);

        const questions = try ctx.gpa.alloc(MessageQuestion, header.qd_count);
        for (questions) |*q| {
            q.* = try .read(ctx);
        }

        const answers = try ctx.gpa.alloc(ResourceRecord, header.an_count);
        for (answers) |*r| {
            r.* = try .read(ctx);
        }

        const authority_records = try ctx.gpa.alloc(ResourceRecord, header.ns_count);
        for (authority_records) |*r| {
            r.* = try .read(ctx);
        }

        const additional_records = try ctx.gpa.alloc(ResourceRecord, header.ar_count);
        for (additional_records) |*r| {
            r.* = try .read(ctx);
        }

        return Message{
            .header = header,
            .questions = questions,
            .answers = answers,
            .authority_records = authority_records,
            .additional_records = additional_records,
        };
    }
};

const MessageHeader = struct {
    id: u16,
    response: bool,
    opcode: u4,
    authoritative: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    response_code: u4,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,

    pub const defaultQuery: MessageHeader = .{
        .id = 0,
        .response = false,
        .opcode = 0,
        .authoritative = false,
        .truncation = false,
        .recursion_desired = true,
        .recursion_available = false,
        .response_code = 0,

        .qd_count = 0,
        .an_count = 0,
        .ns_count = 0,
        .ar_count = 0,
    };

    pub fn set_id(self: *MessageHeader) void {
        self.id = next_id.fetchAdd(1, .acq_rel);
    }

    pub fn to_bytes(self: *const MessageHeader) [12]u8 {
        var bytes: [12]u8 = @splat(0);

        std.mem.writeInt(u16, bytes[0..2], self.id, .big);
        bytes[2] = (@as(u8, @intFromBool(self.response)) << 7) // bit 7
            | (@as(u8, self.opcode) << 3) // bits 3-6
            | (@as(u8, @intFromBool(self.authoritative)) << 2) // bit 2
            | (@as(u8, @intFromBool(self.truncation)) << 1) // bit 1
            | (@intFromBool(self.recursion_desired)); // bit 0

        bytes[3] = (@as(u8, @intFromBool(self.recursion_available)) << 7) // bit 7
            | (self.response_code); // bits 0-3

        std.mem.writeInt(u16, bytes[4..6], self.qd_count, .big);
        std.mem.writeInt(u16, bytes[6..8], self.an_count, .big);
        std.mem.writeInt(u16, bytes[8..10], self.ns_count, .big);
        std.mem.writeInt(u16, bytes[10..12], self.ar_count, .big);

        return bytes;
    }

    pub fn from_bytes(bytes: []const u8) MessageHeader {
        std.debug.assert(bytes.len == 12);

        return .{
            .id = std.mem.readInt(u16, bytes[0..2], .big),

            .response = (bytes[2] & 0b1000_0000) != 0,
            .opcode = @intCast((bytes[2] & 0b0111_1000) >> 3),
            .authoritative = (bytes[2] & 0b0000_0100) != 0,
            .truncation = (bytes[2] & 0b0000_0010) != 0,
            .recursion_desired = (bytes[2] & 0b0000_0001) != 0,

            .recursion_available = (bytes[3] & 0b1000_0000) != 0,
            .response_code = @intCast(bytes[3] & 0b0000_1111),

            .qd_count = std.mem.readInt(u16, bytes[4..6], .big),
            .an_count = std.mem.readInt(u16, bytes[6..8], .big),
            .ns_count = std.mem.readInt(u16, bytes[8..10], .big),
            .ar_count = std.mem.readInt(u16, bytes[10..12], .big),
        };
    }
};

const MessageQuestion = struct {
    name: []const u8,
    type: RecordType,
    class: Class,

    pub fn to_bytes(self: *const MessageQuestion, gpa: Allocator) ![]const u8 {
        var name_bytes: [255]u8 = @splat(0);
        const len = serializeDomainName(self.name, &name_bytes);

        var bytes = try gpa.alloc(u8, len + 4);

        @memcpy(bytes[0..len], name_bytes[0..len]);
        std.mem.writeInt(u16, bytes[len..][0..2], @intFromEnum(self.type), .big);
        std.mem.writeInt(u16, bytes[len + 2 ..][0..2], @intFromEnum(self.class), .big);

        return bytes;
    }

    pub fn read(ctx: *MessageParseContext) !MessageQuestion {
        const name = try parseDomainName(ctx);
        errdefer ctx.gpa.free(name);

        const rtype = try ctx.readInt(u16);
        const class = try ctx.readInt(u16);

        return .{
            .name = name,
            .type = @enumFromInt(rtype),
            .class = @enumFromInt(class),
        };
    }
};

const ResourceRecord = struct {
    name: []const u8,
    type: RecordType,
    class: Class,
    ttl: u32,
    data: []const u8,

    pub fn to_bytes(self: *const ResourceRecord, gpa: Allocator) ![]const u8 {
        var name_bytes: [255]u8 = @splat(0);
        const len = serializeDomainName(self.name, &name_bytes);

        var bytes = try gpa.alloc(u8, len + 10 + self.data.len);

        @memcpy(bytes[0..len], name_bytes[0..len]);
        std.mem.writeInt(u16, bytes[len..][0..2], @intFromEnum(self.type), .big);
        std.mem.writeInt(u16, bytes[len + 2 ..][0..2], @intFromEnum(self.class), .big);
        std.mem.writeInt(u32, bytes[len + 4 ..][0..4], self.ttl, .big);
        std.mem.writeInt(u16, bytes[len + 8 ..][0..2], @intCast(self.data.len), .big);
        @memcpy(bytes[len + 10 ..][0..self.data.len], self.data);

        return bytes;
    }

    pub fn read(ctx: *MessageParseContext) !ResourceRecord {
        const name = try parseDomainName(ctx);
        errdefer ctx.gpa.free(name);

        const rtype = try ctx.readInt(u16);
        const class = try ctx.readInt(u16);

        const ttl = try ctx.readInt(u32);

        const rd_len = try ctx.readInt(u16);
        const data = try ctx.read(rd_len);

        return .{
            .name = name,
            .type = @enumFromInt(rtype),
            .class = @enumFromInt(class),
            .ttl = ttl,
            .data = data,
        };
    }
};

pub fn lookup(gpa: Allocator, io: Io, name: []const u8, rtype: RecordType, addr: Io.net.IpAddress) !Result {
    const message: Message = try .initQuery(gpa, name, rtype);
    defer message.deinit(gpa);

    const bytes = try message.to_bytes(gpa);
    defer gpa.free(bytes);

    std.debug.print("{any}\n", .{bytes});
    // const s = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    const s = try addr.connect(io, .{ .mode = .dgram, .protocol = .udp });

    var write_buf: [1024]u8 = undefined;
    var stream_writer = s.writer(io, &write_buf);
    const writer = &stream_writer.interface;

    var read_buf: [1024]u8 = undefined;
    var stream_reader = s.reader(io, &read_buf);
    const reader = &stream_reader.interface;

    // try writer.writeInt(u16, @intCast(bytes.len), .big);
    try writer.writeAll(bytes);
    try writer.flush();
    std.debug.print("Write finished\n", .{});

    var ctx: MessageParseContext = .{ .gpa = gpa, .reader = reader };
    defer ctx.deinit();

    const response: Message = try .read(&ctx);
    defer {
        for (response.questions) |q| gpa.free(q.name);
        for (response.answers) |r| gpa.free(r.name);
        for (response.authority_records) |r| gpa.free(r.name);
        for (response.additional_records) |r| gpa.free(r.name);

        response.deinit(gpa);
    }

    var answers = try gpa.alloc(RecordData, response.answers.len);
    for (response.answers, 0..) |ans, i| {
        answers[i] = try RecordData.parse(&ctx, ans.type, ans.data);
    }

    var authority_records = try gpa.alloc(RecordData, response.authority_records.len);
    for (response.authority_records, 0..) |authority, i| {
        authority_records[i] = try RecordData.parse(&ctx, authority.type, authority.data);
    }

    var additional_records = try gpa.alloc(RecordData, response.additional_records.len);
    for (response.additional_records, 0..) |additional, i| {
        additional_records[i] = try RecordData.parse(&ctx, additional.type, additional.data);
    }

    return Result{
        .answers = answers,
        .authority_records = authority_records,
        .additional_records = additional_records,
    };
}

fn serializeDomainName(name: []const u8, bytes: *[255]u8) u8 {
    var idx: u8 = 0;
    var iter = std.mem.splitScalar(u8, name, '.');

    while (iter.next()) |label| {
        bytes[idx] = @intCast(label.len);
        idx += 1;

        @memcpy(bytes[idx .. idx + label.len], label);
        idx += @intCast(label.len);
    }

    bytes[idx] = 0;
    idx += 1;

    return idx;
}

fn parseDomainName(ctx: *MessageParseContext) ![]const u8 {
    var name: std.ArrayList(u8) = .empty;

    while (true) {
        var len = try ctx.readByte();
        if (len == 0) break;

        if ((len & 0b1100_0000) == 0b1100_0000) {
            // Name ptr
            const offset_b2 = try ctx.readByte();
            const offset: u16 = ((@as(u16, len) & 0b0011_1111) << 8) | offset_b2;

            ctx.read_idx = offset;
            len = try ctx.readByte();
        } else {
            std.debug.assert((len & 0b1100_00) == 0);
        }

        const label = try ctx.read(len);

        if (name.items.len != 0) try name.append(ctx.gpa, '.');
        try name.appendSlice(ctx.gpa, label);
    }

    ctx.read_idx = null;

    return try name.toOwnedSlice(ctx.gpa);
}

fn parseDomainNameString(ctx: *MessageParseContext, str: *Io.Reader) ![]const u8 {
    var name: std.ArrayList(u8) = .empty;

    while (true) {
        var len = if (ctx.read_idx == null) try str.takeByte() else try ctx.readByte();
        if (len == 0) break;

        if ((len & 0b1100_0000) == 0b1100_0000) {
            // Name ptr
            const offset_b2 = if (ctx.read_idx == null) try str.takeByte() else try ctx.readByte();
            const offset: u16 = ((@as(u16, len) & 0b0011_1111) << 8) | offset_b2;

            ctx.read_idx = offset;
            len = try ctx.readByte();
        } else {
            std.debug.assert((len & 0b1100_00) == 0);
        }

        const label = if (ctx.read_idx == null) try str.take(len) else try ctx.read(len);

        if (name.items.len != 0) try name.append(ctx.gpa, '.');
        try name.appendSlice(ctx.gpa, label);
    }

    ctx.read_idx = null;

    return try name.toOwnedSlice(ctx.gpa);
}
