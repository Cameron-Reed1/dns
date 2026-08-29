const std = @import("std");
const config = @import("config");
const Io = std.Io;
const Allocator = std.mem.Allocator;

var next_id: std.atomic.Value(u16) = .init(1);
var nameservers: [config.max_nameservers]?Io.net.IpAddress = @splat(null);

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
        strings: []const []const u8,
    };

    const AAAA = struct {
        addr: [16]u8,
    };

    pub fn read(gpa: Allocator, ctx: *MessageParseContext, rtype: RecordType, expected_len: u16) !RecordData {
        const old_idx = ctx.read_idx;

        const result: RecordData = switch (rtype) {
            .a => .{ .a = .{ .addr = (try ctx.readArray(4)).* } },
            .ns => .{ .ns = .{ .nsdname = try parseDomainName(gpa, ctx) } },
            .md => .{ .md = .{ .madname = try parseDomainName(gpa, ctx) } },
            .mf => .{ .mf = .{ .madname = try parseDomainName(gpa, ctx) } },
            .cname => .{ .cname = .{ .cname = try parseDomainName(gpa, ctx) } },
            .soa => blk: {
                const mname = try parseDomainName(gpa, ctx);
                const rname = try parseDomainName(gpa, ctx);

                const remaining = try ctx.read(20);

                const serial = std.mem.readInt(u32, remaining[0..4], .big);
                const refresh = std.mem.readInt(i32, remaining[4..8], .big);
                const retry = std.mem.readInt(i32, remaining[8..12], .big);
                const expire = std.mem.readInt(i32, remaining[12..16], .big);
                const minimum = std.mem.readInt(u32, remaining[16..20], .big);

                break :blk .{ .soa = .{ .mname = mname, .rname = rname, .serial = serial, .refresh = refresh, .retry = retry, .expire = expire, .minimum = minimum } };
            },
            .mb => .{ .mb = .{ .madname = try parseDomainName(gpa, ctx) } },
            .mg => .{ .mg = .{ .madname = try parseDomainName(gpa, ctx) } },
            .mr => .{ .mr = .{ .newname = try parseDomainName(gpa, ctx) } },
            .null => .{ .null = .{ .data = try ctx.read(expected_len) } },
            .wks => blk: {
                const data = try ctx.read(expected_len);
                break :blk .{ .wks = .{ .addr = data[0..4].*, .protocol = data[4], .bitmap = data[5..] } };
            },
            .ptr => .{ .ptr = .{ .ptrdname = try parseDomainName(gpa, ctx) } },
            .hinfo => blk: {
                const data = try ctx.read(expected_len);
                var null_idx = std.mem.indexOfScalar(u8, data, 0) orelse return error.InvalidRDataFormat;
                const cpu = data[0..null_idx];

                const remaining_data = data[0..null_idx];
                null_idx = std.mem.indexOfScalar(u8, remaining_data, 0) orelse return error.InvalidRDataFormat;
                const os = remaining_data[0..null_idx];

                break :blk .{ .hinfo = .{ .cpu = cpu, .os = os } };
            },
            .minfo => blk: {
                const rmailbx = try parseDomainName(gpa, ctx);
                const emailbx = try parseDomainName(gpa, ctx);
                break :blk .{ .minfo = .{ .rmailbx = rmailbx, .emailbx = emailbx } };
            },
            .mx => blk: {
                const preference = try ctx.readInt(u16);
                const exchange = try parseDomainName(gpa, ctx);

                break :blk .{ .mx = .{ .preference = preference, .exchange = exchange } };
            },
            .txt => blk: {
                var strings: std.ArrayList([]const u8) = .empty;
                errdefer {
                    for (strings.items) |s| gpa.free(s);
                    strings.deinit(gpa);
                }
                var remaining_len = expected_len;

                while (remaining_len > 0) {
                    const len = try ctx.readByte();

                    const s = try ctx.read(len);
                    const string = try gpa.dupe(u8, s);
                    try strings.append(gpa, string);

                    remaining_len -= len + 1;
                }

                break :blk .{ .txt = .{ .strings = try strings.toOwnedSlice(gpa) } };
            },

            .aaaa => .{ .aaaa = .{ .addr = (try ctx.readArray(16)).* } },
        };

        if (ctx.read_idx != old_idx + expected_len) return error.InvalidRDataFormat;

        return result;
    }

    pub fn serialize(self: *const RecordData, gpa: Allocator) ![]const u8 {
        return switch (self.*) {
            .a => |a| try gpa.dupe(u8, &a.addr),
            .ns => |ns| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(ns.nsdname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .md => |md| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(md.madname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .mf => |mf| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(mf.madname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .cname => |cname| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(cname.cname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .soa => |soa| blk: {
                var buf: std.ArrayList(u8) = .empty;

                var name_buf: [255]u8 = undefined;
                const mname_len = serializeDomainName(soa.mname, &name_buf);
                try buf.appendSlice(gpa, name_buf[0..mname_len]);

                const rname_len = serializeDomainName(soa.rname, &name_buf);
                try buf.ensureUnusedCapacity(gpa, rname_len + 20);
                buf.appendSliceAssumeCapacity(name_buf[0..rname_len]);

                var ints: [20]u8 = undefined;
                std.mem.writeInt(u32, ints[0..4], soa.serial, .big);
                std.mem.writeInt(i32, ints[4..8], soa.refresh, .big);
                std.mem.writeInt(i32, ints[8..12], soa.retry, .big);
                std.mem.writeInt(i32, ints[12..16], soa.expire, .big);
                std.mem.writeInt(u32, ints[16..20], soa.minimum, .big);

                buf.appendSliceAssumeCapacity(&ints);

                break :blk try buf.toOwnedSlice(gpa);
            },
            .mb => |mb| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(mb.madname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .mg => |mg| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(mg.madname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .mr => |mr| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(mr.newname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .null => |n| try gpa.dupe(u8, n.data),
            .wks => |wks| blk: {
                var buf = try gpa.alloc(u8, 5 + wks.bitmap.len);

                @memcpy(buf[0..4], wks.addr[0..4]);
                buf[4] = wks.protocol;
                @memcpy(buf[5..][0..wks.bitmap.len], wks.bitmap);

                break :blk buf;
            },
            .ptr => |ptr| blk: {
                var buf: [255]u8 = undefined;
                const len = serializeDomainName(ptr.ptrdname, &buf);
                break :blk try gpa.dupe(u8, buf[0..len]);
            },
            .hinfo => |hinfo| blk: {
                var buf = try gpa.alloc(u8, hinfo.cpu.len + hinfo.os.len + 2);

                @memcpy(buf[0..hinfo.cpu.len], hinfo.cpu);
                buf[hinfo.cpu.len] = 0;
                @memcpy(buf[hinfo.cpu.len + 1 ..][0..hinfo.os.len], hinfo.os);
                buf[buf.len] = 0;

                break :blk buf;
            },
            .minfo => |minfo| blk: {
                var buf: std.ArrayList(u8) = .empty;

                var name_buf: [255]u8 = undefined;
                const rmailbx_len = serializeDomainName(minfo.rmailbx, &name_buf);
                try buf.appendSlice(gpa, name_buf[0..rmailbx_len]);

                const emailbx_len = serializeDomainName(minfo.emailbx, &name_buf);
                try buf.appendSlice(gpa, name_buf[0..emailbx_len]);

                break :blk try buf.toOwnedSlice(gpa);
            },
            .mx => |mx| blk: {
                var name_buf: [255]u8 = undefined;
                const len = serializeDomainName(mx.exchange, &name_buf);

                const buf = try gpa.alloc(u8, len + 2);
                std.mem.writeInt(u16, buf[0..2], mx.preference, .big);
                @memcpy(buf[2..][0..len], name_buf[0..len]);

                break :blk buf;
            },
            .txt => |txt| blk: {
                var len = txt.strings.len;
                for (txt.strings) |s| len += s.len;

                var buf = try gpa.alloc(u8, len);
                var idx: usize = 0;

                for (txt.strings) |s| {
                    buf[idx] = @intCast(s.len);
                    idx += 1;

                    @memcpy(buf[idx..][0..s.len], s);
                    idx += s.len;
                }

                break :blk buf;
            },

            .aaaa => |aaaa| try gpa.dupe(u8, &aaaa.addr),
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
            .txt => |txt| {
                std.debug.print("TXT: ", .{});
                if (txt.strings.len == 1) {
                    std.debug.print("{s}", .{txt.strings[0]});
                } else if (txt.strings.len > 1) {
                    for (txt.strings) |s| std.debug.print("\n{s}", .{s});
                }
                std.debug.print("\n", .{});
            },

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
            .txt => |txt| {
                for (txt.strings) |s| gpa.free(s);
                gpa.free(txt.strings);
            },

            .aaaa => {},
        }
    }
};

const MessageParseContext = struct {
    bytes: []const u8,
    read_idx: usize = 0,

    pub fn read(self: *MessageParseContext, n: usize) ![]const u8 {
        std.debug.assert(self.read_idx + n <= self.bytes.len);

        const idx = self.read_idx;
        self.read_idx += n;
        return self.bytes[idx..][0..n];
    }

    pub fn readArray(self: *MessageParseContext, comptime n: usize) !*const [n]u8 {
        const slice = try self.read(n);
        return slice[0..n];
    }

    pub fn readByte(self: *MessageParseContext) !u8 {
        const slice = try self.read(1);
        return slice[0];
    }

    pub fn readInt(self: *MessageParseContext, T: type) !T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        return std.mem.readInt(T, (try self.read(n))[0..n], .big);
    }
};

const Message = struct {
    nameserver: ?Io.net.IpAddress,
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
            .name = try gpa.dupe(u8, name),
            .type = rec_type,
            .class = .in,
        };

        return .{
            .nameserver = null,
            .header = header,
            .questions = questions,
            .answers = &.{},
            .authority_records = &.{},
            .additional_records = &.{},
        };
    }

    pub fn deinit(self: *const Message, gpa: Allocator) void {
        for (self.questions) |q| gpa.free(q.name);
        if (self.questions.len != 0) gpa.free(self.questions);

        for (self.answers) |r| r.deinit(gpa);
        if (self.answers.len != 0) gpa.free(self.answers);

        for (self.authority_records) |r| r.deinit(gpa);
        if (self.authority_records.len != 0) gpa.free(self.authority_records);

        for (self.additional_records) |r| r.deinit(gpa);
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

    pub fn read(gpa: Allocator, ctx: *MessageParseContext, from: Io.net.IpAddress) !Message {
        const header_bytes = try ctx.read(12);
        const header: MessageHeader = .from_bytes(header_bytes);

        const questions = try gpa.alloc(MessageQuestion, header.qd_count);
        for (questions) |*q| {
            q.* = try .read(gpa, ctx);
        }

        const answers = try gpa.alloc(ResourceRecord, header.an_count);
        for (answers) |*r| {
            r.* = try .read(gpa, ctx);
        }

        const authority_records = try gpa.alloc(ResourceRecord, header.ns_count);
        for (authority_records) |*r| {
            r.* = try .read(gpa, ctx);
        }

        const additional_records = try gpa.alloc(ResourceRecord, header.ar_count);
        for (additional_records) |*r| {
            r.* = try .read(gpa, ctx);
        }

        return Message{
            .nameserver = from,
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

    pub fn read(gpa: Allocator, ctx: *MessageParseContext) !MessageQuestion {
        const name = try parseDomainName(gpa, ctx);
        errdefer gpa.free(name);

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
    class: Class,
    ttl: u32,
    data: RecordData,

    pub fn to_bytes(self: *const ResourceRecord, gpa: Allocator) ![]const u8 {
        var name_bytes: [255]u8 = @splat(0);
        const len = serializeDomainName(self.name, &name_bytes);

        const data_bytes = try self.data.serialize(gpa);
        defer gpa.free(data_bytes);

        var bytes = try gpa.alloc(u8, len + 10 + data_bytes.len);

        @memcpy(bytes[0..len], name_bytes[0..len]);
        std.mem.writeInt(u16, bytes[len..][0..2], @intFromEnum(self.data), .big);
        std.mem.writeInt(u16, bytes[len + 2 ..][0..2], @intFromEnum(self.class), .big);
        std.mem.writeInt(u32, bytes[len + 4 ..][0..4], self.ttl, .big);
        std.mem.writeInt(u16, bytes[len + 8 ..][0..2], @intCast(data_bytes.len), .big);
        @memcpy(bytes[len + 10 ..][0..data_bytes.len], data_bytes);

        return bytes;
    }

    pub fn read(gpa: Allocator, ctx: *MessageParseContext) !ResourceRecord {
        const name = try parseDomainName(gpa, ctx);
        errdefer gpa.free(name);

        const rtype = try ctx.readInt(u16);
        const class = try ctx.readInt(u16);

        const ttl = try ctx.readInt(u32);

        const rd_len = try ctx.readInt(u16);
        const old_idx = ctx.read_idx;
        const data = try RecordData.read(gpa, ctx, @enumFromInt(rtype), rd_len);
        std.debug.assert(ctx.read_idx == old_idx + rd_len);

        return .{
            .name = name,
            .class = @enumFromInt(class),
            .ttl = ttl,
            .data = data,
        };
    }

    pub fn deinit(self: *const ResourceRecord, gpa: Allocator) void {
        gpa.free(self.name);
        self.data.deinit(gpa);
    }
};

pub fn addNameserver(addr: Io.net.IpAddress) void {
    for (0..nameservers.len) |i| {
        if (nameservers[i] != null) continue;
        nameservers[i] = addr;
        return;
    }

    unreachable;
}

var ns_idx: usize = config.max_nameservers - 1;

fn getNameserver() !Io.net.IpAddress {
    if (nameservers[0] == null) return error.NoNameServers;

    ns_idx = @mod(ns_idx + 1, config.max_nameservers);
    if (nameservers[ns_idx] == null) ns_idx = 0;

    return nameservers[ns_idx].?;
}

pub fn lookup(gpa: Allocator, io: Io, name: []const u8, rtype: RecordType) !Message {
    const message: Message = try .initQuery(gpa, name, rtype);
    defer message.deinit(gpa);

    const bytes = try message.to_bytes(gpa);
    defer gpa.free(bytes);

    const addr = try getNameserver();
    const s = try addr.connect(io, .{ .mode = .dgram, .protocol = .udp });

    try s.socket.send(io, &addr, bytes);

    var read_buf: [4096]u8 = undefined;
    const msg = try s.socket.receiveTimeout(io, &read_buf, .{ .duration = .{ .clock = .real, .raw = .fromSeconds(5) } });
    var ctx: MessageParseContext = .{ .bytes = msg.data };

    return try .read(gpa, &ctx, msg.from);
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

fn parseDomainName(gpa: Allocator, ctx: *MessageParseContext) ![]const u8 {
    var name: std.ArrayList(u8) = .empty;
    var old_idx: ?usize = null;

    while (true) {
        const len = try ctx.readByte();
        if (len == 0) break;

        if ((len & 0b1100_0000) == 0b1100_0000) {
            // Name ptr
            const offset_b2 = try ctx.readByte();
            const offset: u16 = ((@as(u16, len) & 0b0011_1111) << 8) | offset_b2;

            if (old_idx == null) old_idx = ctx.read_idx;
            ctx.read_idx = offset;
            continue;
        } else {
            std.debug.assert((len & 0b1100_0000) == 0);
        }

        const label = try ctx.read(len);

        if (name.items.len != 0) try name.append(gpa, '.');
        try name.appendSlice(gpa, label);
    }

    if (old_idx) |idx| ctx.read_idx = idx;

    return try name.toOwnedSlice(gpa);
}
