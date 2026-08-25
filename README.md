Simple dns library for zig 0.16


## Installation


First run zig fetch:

``` bash
zig fetch --save git+https://github.com/Cameron-Reed1/dns
```

Then add the following to build.zig:

``` zig
const dns = b.dependency("dns", .{});
exe.root_module.addImport("dns", dns.module("dns"));
```


## Usage

Just configure the nameservers:

``` zig
dns.addNameserver(std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 1, 1, 1, 1 }, .port = 53 } });
```

Then call lookup:

``` zig
const result = try dns.lookup(gpa, io, "github.com", .a);
defer result.deinit(gpa);
```

Optionally, using io.async():

``` zig
var future = io.async(dns.lookup, .{ gpa, io, "ziglang.org", .aaaa });
const result = try future.await(io);
defer result.deinit(gpa);
```

Refer to [main.zig](./src/main.zig) for a full example


## TODO:

- Resend requests when necessary
- Cache results
- Implement more than RFC 1035 and RFC 3596
- Better errors!!!
