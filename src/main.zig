const std = @import("std");
const Io = std.Io;

const dns = @import("dns");

pub fn main(init: std.process.Init) !void {
    var args_iter = try init.minimal.args.iterateAllocator(init.gpa);
    defer args_iter.deinit();
    std.debug.assert(args_iter.skip()); // arg[0] should always exist

    const domain_name = args_iter.next() orelse {
        usage();
        std.process.exit(1);
    };

    const rtype_str = args_iter.next() orelse "a";
    const rtype = recordTypeFromString(rtype_str) orelse {
        std.debug.print("Unknown record type: {s}\n", .{rtype_str});
        std.process.exit(1);
    };

    while (args_iter.next()) |addr_str| {
        const addr: Io.net.IpAddress = try .parse(addr_str, 53);
        dns.addNameserver(addr);
    }

    var future = init.io.async(dns.lookup, .{ init.gpa, init.io, domain_name, rtype });
    const result = try future.await(init.io);
    defer result.deinit(init.gpa);

    std.debug.print("Got result from nameserver: {any}\n", .{result.nameserver.?});

    if (result.answers.len != 0) {
        std.debug.print("Answers:\n", .{});
        for (result.answers) |ans| {
            ans.data.print();
        }
    } else {
        std.debug.print("No answers\n", .{});
    }

    if (result.authority_records.len != 0) {
        std.debug.print("\nAuthority records:\n", .{});
        for (result.authority_records) |r| {
            r.data.print();
        }
    }

    if (result.additional_records.len != 0) {
        std.debug.print("\nAdditional records:\n", .{});
        for (result.additional_records) |r| {
            r.data.print();
        }
    }
}

fn recordTypeFromString(str: []const u8) ?dns.RecordType {
    inline for (@typeInfo(dns.RecordType).@"enum".fields) |f| {
        if (std.ascii.eqlIgnoreCase(str, f.name)) {
            return @enumFromInt(f.value);
        }
    }

    return null;
}

fn usage() void {
    std.debug.print("dns <domain name> [<record type>]\n", .{});
}
