const std = @import("std");

// TODO: scan implementation
// TODO: if memory runs out, free everything and fallback to slow scan

pub const GroupDatabase = struct {
    allocator: std.mem.Allocator,
    buffer: []const u8,

    pub const Entry = struct {
        name: []const u8,
        password: []const u8,
        gid: u32,
        groups: []const u8,
    };

    pub const EntryIterator = struct {
        buffer: []const u8,
        line_it: LineIterator,

        pub fn init(buffer: []const u8) EntryIterator {
            return .{
                .buffer = buffer,
                .line_it = LineIterator.init(buffer),
            };
        }

        pub fn next(this: *EntryIterator) ?Entry {
            while (this.line_it.next()) |line| {
                const entry = GroupDatabase.parse(line) catch continue;
                return entry;
            }

            return null;
        }
    };

    pub fn deinit(this: GroupDatabase) void {
        this.allocator.free(this.buffer);
    }

    pub fn find(this: GroupDatabase, name: []const u8) ?Entry {
        var it = EntryIterator.init(this.buffer);

        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                return entry;
            }
        }

        return null;
    }

    pub fn iterator(this: GroupDatabase) EntryIterator {
        return EntryIterator.init(this.buffer);
    }

    pub fn parse(entry_line: []const u8) !Entry {
        var entry: Entry = undefined;
        var field_it = FieldIterator.init(entry_line);

        entry.name = field_it.next() orelse return error.EndOfStream;
        entry.password = field_it.next() orelse return error.EndOfStream;
        const gid = field_it.next() orelse return error.EndOfStream;
        entry.groups = field_it.next() orelse return error.EndOfStream;

        if (field_it.next() != null) return error.StreamTooLong;

        entry.gid = try std.fmt.parseInt(u32, gid, 10);

        return entry;
    }
};

pub const PasswdDatabase = struct {
    allocator: std.mem.Allocator,
    buffer: []const u8,

    pub const Entry = struct {
        login: []const u8,
        password: []const u8,
        uid: u32,
        gid: u32,
        info: [5][]const u8,
        home: []const u8,
        shell: []const u8,
    };

    pub const EntryIterator = struct {
        buffer: []const u8,
        line_it: LineIterator,

        pub fn init(buffer: []const u8) EntryIterator {
            return .{
                .buffer = buffer,
                .line_it = LineIterator.init(buffer),
            };
        }

        pub fn next(this: *EntryIterator) ?Entry {
            while (this.line_it.next()) |line| {
                const entry = PasswdDatabase.parse(line) catch continue;
                return entry;
            }

            return null;
        }
    };

    pub fn deinit(this: PasswdDatabase) void {
        this.allocator.free(this.buffer);
    }

    pub fn find(this: PasswdDatabase, login: []const u8) ?Entry {
        var it = EntryIterator.init(this.buffer);

        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.login, login)) {
                return entry;
            }
        }

        return null;
    }

    pub fn iterator(this: PasswdDatabase) EntryIterator {
        return EntryIterator.init(this.buffer);
    }

    pub fn parse(entry_line: []const u8) !Entry {
        var entry: Entry = undefined;
        var field_it = FieldIterator.init(entry_line);

        entry.login = field_it.next() orelse return error.EndOfStream;
        entry.password = field_it.next() orelse return error.EndOfStream;
        const uid = field_it.next() orelse return error.EndOfStream;
        const gid = field_it.next() orelse return error.EndOfStream;
        const info = field_it.next() orelse return error.EndOfStream;
        entry.home = field_it.next() orelse return error.EndOfStream;
        entry.shell = field_it.next() orelse return error.EndOfStream;

        if (field_it.next() != null) return error.StreamTooLong;

        entry.uid = try std.fmt.parseInt(u32, uid, 10);
        entry.gid = try std.fmt.parseInt(u32, gid, 10);

        var info_it = InfoIterator.init(info);

        entry.info[0] = info_it.next() orelse "";
        entry.info[1] = info_it.next() orelse "";
        entry.info[2] = info_it.next() orelse "";
        entry.info[3] = info_it.next() orelse "";
        entry.info[4] = info_it.next() orelse "";
        // TODO: handle extra GECOS fields somehow

        return entry;
    }
};

const LineIterator = DelimitedBufferIterator(u8, '\n', .terminator);
const FieldIterator = DelimitedBufferIterator(u8, ':', .separator);
const InfoIterator = DelimitedBufferIterator(u8, ',', .separator);

const DelimitMode = enum {
    separator,
    terminator,
};

fn DelimitedBufferIterator(comptime T: type, delim: T, mode: DelimitMode) type {
    return struct {
        buffer: []const T,
        offset: usize = 0,

        pub fn init(buffer: []const T) @This() {
            return .{ .buffer = buffer };
        }

        pub fn next(this: *@This()) ?[]const T {
            const buf = this.buffer;
            const start = this.offset;

            if (start > buf.len) {
                return null;
            } else if (start == buf.len) {
                this.offset += 1;

                switch (mode) {
                    .terminator => return null,
                    .separator => {
                        if (start > 0 and buf[start - 1] == delim) {
                            return "";
                        } else {
                            return null;
                        }
                    },
                }
            } else if (std.mem.indexOfScalarPos(u8, buf, start, delim)) |end| {
                this.offset = end + 1;
                return buf[start..end];
            } else {
                this.offset = buf.len;
                return buf[start..];
            }
        }
    };
}

pub fn open_group(allocator: std.mem.Allocator) GroupDatabase {
    return open_group_file(allocator, "/etc/group");
}

pub fn open_passwd(allocator: std.mem.Allocator) PasswdDatabase {
    return open_passwd_file(allocator, "/etc/passwd");
}

pub fn open_group_file(
    allocator: std.mem.Allocator,
    path: []const u8,
) GroupDatabase {
    const buffer = read_file(allocator, path) catch &.{};

    return GroupDatabase{
        .allocator = allocator,
        .buffer = buffer,
    };
}

pub fn open_passwd_file(
    allocator: std.mem.Allocator,
    path: []const u8,
) PasswdDatabase {
    const buffer = read_file(allocator, path) catch &.{};

    return PasswdDatabase{
        .allocator = allocator,
        .buffer = buffer,
    };
}

fn read_file(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{ .lock = .shared });
    defer file.close();

    const buffer = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    return buffer;
}

test "reading group database" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const data =
        \\root:x:0:
        \\daemon:x:1:
        \\bin:x:2:
        \\--junk data--
        \\mli:x:101:foo,bar
        \\
    ;

    try tmp_dir.dir.writeFile(.{ .sub_path = "group", .data = data });
    const path = try tmp_dir.dir.realpathAlloc(allocator, "group");
    const db = open_group_file(allocator, path);

    var entry_it = db.iterator();
    var count: usize = 0;

    while (entry_it.next()) |_| {
        count += 1;
    }

    try std.testing.expectEqual(4, count);

    const root = db.find("root").?;
    const mli = db.find("mli").?;

    try std.testing.expectEqualStrings("root", root.name);
    try std.testing.expectEqualStrings("x", root.password);
    try std.testing.expectEqual(0, root.gid);
    try std.testing.expectEqualStrings("", root.groups);

    try std.testing.expectEqualStrings("mli", mli.name);
    try std.testing.expectEqualStrings("x", mli.password);
    try std.testing.expectEqual(101, mli.gid);
    try std.testing.expectEqualStrings("foo,bar", mli.groups);
}

test "reading passwd database" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const name = "Muhammad Li";
    const room = "Room 305";
    const office = "234-567-8305";
    const home = "234-987-6543";
    const email = "mli@example.com";
    const info = name ++ "," ++ room ++ "," ++ office ++ "," ++ home ++ "," ++ email;
    const data =
        \\root:x:0:0:root:/root:/bin/bash
        \\daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        \\bin:x:2:2:bin:/bin:/usr/sbin/nologin
        \\--junk data--
        \\mli:x:101:101:
    ++ info ++
        \\:/home/mli:/bin/bash
        \\
    ;

    try tmp_dir.dir.writeFile(.{ .sub_path = "passwd", .data = data });
    const path = try tmp_dir.dir.realpathAlloc(allocator, "passwd");
    const db = open_passwd_file(allocator, path);

    var entry_it = db.iterator();
    var count: usize = 0;

    while (entry_it.next()) |_| count += 1;

    try std.testing.expectEqual(4, count);

    const root = db.find("root").?;
    const mli = db.find("mli").?;

    try std.testing.expectEqualStrings("root", root.login);
    try std.testing.expectEqualStrings("x", root.password);
    try std.testing.expectEqual(0, root.uid);
    try std.testing.expectEqual(0, root.gid);
    try std.testing.expectEqualStrings("root", root.info[0]);
    try std.testing.expectEqualStrings("", root.info[1]);
    try std.testing.expectEqualStrings("", root.info[2]);
    try std.testing.expectEqualStrings("", root.info[3]);
    try std.testing.expectEqualStrings("", root.info[4]);
    try std.testing.expectEqualStrings("/root", root.home);
    try std.testing.expectEqualStrings("/bin/bash", root.shell);

    try std.testing.expectEqualStrings("mli", mli.login);
    try std.testing.expectEqualStrings("x", mli.password);
    try std.testing.expectEqual(101, mli.uid);
    try std.testing.expectEqual(101, mli.gid);
    try std.testing.expectEqualStrings(name, mli.info[0]);
    try std.testing.expectEqualStrings(room, mli.info[1]);
    try std.testing.expectEqualStrings(office, mli.info[2]);
    try std.testing.expectEqualStrings(home, mli.info[3]);
    try std.testing.expectEqualStrings(email, mli.info[4]);
    try std.testing.expectEqualStrings("/home/mli", mli.home);
    try std.testing.expectEqualStrings("/bin/bash", mli.shell);
}
