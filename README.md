Library for reading **/etc/passwd** database.  Provides a static alternative to
linking with libc and relying on NSS.

Examples
========

**open /etc/passwd database**
```zig
const passwd = @import("passwd");
const db = passwd.open_passwd(); // can use .open_passwd_file to specify path
```

**enumerate users**
```zig
var it = db.iterator();

while (it.next()) |entry| {
    std.debug.print("Login: {s}\n", .{entry.login});
    std.debug.print("Pw Hash: {s}\n", .{entry.password});
    std.debug.print("UID: {d}\n"m .{entry.uid});
    std.debug.print("GID: {d}\n"m .{entry.gid});

    for (0..4) {
        std.debug.print("Info {d}: {s}\n", .{ i + 1, entry.info[i] });
    }

    std.debug.print("Home: {s}\n", .{entry.home});
    std.debug.print("Shell: {s}\n", .{entry.shell});
}
```

**lookup user**
```zig
if (db.find("root")) |entry| {
    std.debug.print("Login: {s}\n", .{entry.login});
    std.debug.print("Pw Hash: {s}\n", .{entry.password});
    std.debug.print("UID: {d}\n"m .{entry.uid});
    std.debug.print("GID: {d}\n"m .{entry.gid});

    for (0..4) {
        std.debug.print("Info {d}: {s}\n", .{ i + 1, entry.info[i] });
    }

    std.debug.print("Home: {s}\n", .{entry.home});
    std.debug.print("Shell: {s}\n", .{entry.shell});
}
```
