const std = @import("std");
const windows = std.os.windows;
const kernel32 = windows.kernel32;
const flags = @import("flags");

// Configuration
const IGNORE_EMPTY_MESSAGES = true;

const OutputFormat = enum {
    plain_text,
    json,
};

// Command line options
const Flags = struct {
    pub const description =
        \\Captures messages sent by applications using OutputDebugStringA and prints them.
        \\
        \\Example:
        \\  debuglog                   # Print messages from all processes
        \\  debuglog -p 1234           # Print messages from process with PID 1234
        \\  debuglog -- app.exe --foo  # Launch `app.exe --foo` and print only its messages.
        \\
        \\Messages are printed to stdout by default, or to stderr when spawning a subprocess.
    ;

    pub const descriptions = .{
        .pid = "Filter messages to show only those from the specified process ID",
        .stderr = "Send output to stderr",
        .stdout = "Send output to stdout",
        .file = "Send output to the specified file",
        .json = "Output messages in JSON format",
    };

    pub const switches = .{
        .pid = 'p',
        .stderr = 'e',
        .stdout = 'o',
        .file = 'f',
        .json = 'j',
    };

    pid: ?u32 = null,
    stderr: bool = false,
    stdout: bool = false,
    file: ?[]const u8 = null,
    json: bool = false,
    positional: struct {
        trailing: []const []const u8,
    },

    fn getOutputFormat(self: Flags) OutputFormat {
        return if (self.json) .json else .plain_text;
    }
};

// Windows API.
const BOOL = windows.BOOL;
const DWORD = windows.DWORD;
const HANDLE = windows.HANDLE;
const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
const TRUE = windows.TRUE;
const FALSE = windows.FALSE;
const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
const INFINITE = windows.INFINITE;
const WAIT_OBJECT_0 = windows.WAIT_OBJECT_0;
const WAIT_FAILED = windows.WAIT_FAILED;
const PAGE_READWRITE = windows.PAGE_READWRITE;
const WINAPI = windows.WINAPI;
const FILE_MAP_READ = 0x0004;
const WaitForSingleObject = kernel32.WaitForSingleObject;

const SECURITY_DESCRIPTOR = extern struct {
    Revision: u8,
    Sbz1: u8,
    Control: u16,
    Owner: ?*anyopaque,
    Group: ?*anyopaque,
    Sacl: ?*anyopaque,
    Dacl: ?*anyopaque,
};

extern "advapi32" fn InitializeSecurityDescriptor(
    pSecurityDescriptor: *SECURITY_DESCRIPTOR,
    dwRevision: DWORD,
) callconv(WINAPI) BOOL;

extern "kernel32" fn CreateEventA(
    lpEventAttributes: ?*SECURITY_ATTRIBUTES,
    bManualReset: BOOL,
    bInitialState: BOOL,
    lpName: ?[*:0]const u8,
) callconv(WINAPI) ?HANDLE;

extern "kernel32" fn CreateFileMappingA(
    hFile: ?HANDLE,
    lpFileMappingAttributes: ?*SECURITY_ATTRIBUTES,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: ?[*:0]const u8,
) callconv(WINAPI) ?HANDLE;

extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: usize,
) callconv(WINAPI) ?*anyopaque;

extern "kernel32" fn UnmapViewOfFile(
    lpBaseAddress: *const anyopaque,
) callconv(WINAPI) BOOL;

extern "kernel32" fn SetEvent(
    hEvent: HANDLE,
) callconv(WINAPI) BOOL;

extern "kernel32" fn CreateMutexA(
    lpMutexAttributes: ?*SECURITY_ATTRIBUTES,
    bInitialOwner: BOOL,
    lpName: ?[*:0]const u8,
) callconv(WINAPI) ?HANDLE;

extern "kernel32" fn ReleaseMutex(
    hMutex: HANDLE,
) callconv(WINAPI) BOOL;

extern "kernel32" fn GetProcessId(
    Process: HANDLE,
) callconv(WINAPI) DWORD;

extern "kernel32" fn WaitForMultipleObjects(
    nCount: DWORD,
    lpHandles: [*]const HANDLE,
    bWaitAll: BOOL,
    dwMilliseconds: DWORD,
) callconv(WINAPI) DWORD;

const DebugObjects = struct {
    const DBWIN_BUFFER_SIZE = 4096;
    const DBWIN_MUTEX_NAME = "DBWIN_MUTEX";
    const DBWIN_SHARED_MEM_NAME = "DBWIN_BUFFER";
    const DBWIN_BUFFER_READY_EVENT_NAME = "DBWIN_BUFFER_READY";
    const DBWIN_DATA_READY_EVENT_NAME = "DBWIN_DATA_READY";
    const DEBUGLOG_MUTEX_NAME = "f698ccec3d254735b2f188be68c53e80"; // Arbitrary unique name.

    debuglog_mutex: HANDLE,
    shmem_mutex: HANDLE,
    buffer_ready_event: HANDLE,
    data_ready_event: HANDLE,
    shmem_mapping: HANDLE,
    shmem: []u8,

    fn init() DebugObjects {
        const debuglog_mutex = CreateMutexA(
            null,
            FALSE, // Not initially owned
            DEBUGLOG_MUTEX_NAME,
        ) orelse {
            std.log.err("Failed to create/open {s}: {any}", .{ DEBUGLOG_MUTEX_NAME, windows.GetLastError() });
            std.process.exit(1);
        };

        if (windows.GetLastError() == windows.Win32Error.ALREADY_EXISTS) {
            std.log.err("Another instance of debuglog is already running.", .{});
            std.process.exit(1);
        }

        var sec_desc: SECURITY_DESCRIPTOR = undefined;
        if (InitializeSecurityDescriptor(&sec_desc, 1) == FALSE) {
            std.log.err("Failed to initialize security descriptor: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        }

        var sec_attrs = SECURITY_ATTRIBUTES{
            .nLength = @sizeOf(SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = &sec_desc,
            .bInheritHandle = FALSE,
        };

        const shmem_mutex = CreateMutexA(
            &sec_attrs,
            FALSE, // Not initially owned
            DBWIN_MUTEX_NAME,
        ) orelse {
            std.log.err("Failed to create/open {s}: {any}", .{ DBWIN_MUTEX_NAME, windows.GetLastError() });
            std.process.exit(1);
        };

        if (windows.GetLastError() == windows.Win32Error.ALREADY_EXISTS) {
            std.log.warn("The debug log is already open. If there are any other readers then output will be unpredictable.", .{});
        }

        // Acquire mutex for initialization
        switch (WaitForSingleObject(shmem_mutex, INFINITE)) {
            WAIT_OBJECT_0 => {},
            WAIT_FAILED => {
                std.log.err("WaitForSingleObject (DBWIN_MUTEX) failed: {any}", .{windows.GetLastError()});
                std.process.exit(1);
            },
            else => {
                std.log.err("WaitForSingleObject (DBWIN_MUTEX) returned an unexpected value", .{});
                std.process.exit(1);
            },
        }

        const buffer_ready_event = CreateEventA(
            &sec_attrs,
            FALSE, // Auto-reset event
            FALSE, // Initially non-signaled
            DBWIN_BUFFER_READY_EVENT_NAME,
        ) orelse {
            std.log.err("Failed to create/open DBWIN_BUFFER_READY event: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        };

        const data_ready_event = CreateEventA(
            &sec_attrs,
            FALSE, // Auto-reset event
            FALSE, // Initially non-signaled
            DBWIN_DATA_READY_EVENT_NAME,
        ) orelse {
            std.log.err("Failed to create/open DBWIN_DATA_READY event: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        };

        const shmem_mapping = CreateFileMappingA(
            INVALID_HANDLE_VALUE, // Use paging file
            &sec_attrs, // Default security
            PAGE_READWRITE,
            0,
            DBWIN_BUFFER_SIZE,
            DBWIN_SHARED_MEM_NAME,
        ) orelse {
            std.log.err("Failed to create/open shared memory mapping: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        };

        const shmem = MapViewOfFile(
            shmem_mapping,
            FILE_MAP_READ,
            0,
            0,
            DBWIN_BUFFER_SIZE,
        ) orelse {
            std.log.err("Failed to map view of file: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        };

        if (ReleaseMutex(shmem_mutex) == FALSE) {
            std.log.err("Failed to release DBWIN_MUTEX: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        }

        const shmem_buf = @as([*]u8, @ptrCast(shmem))[0..DBWIN_BUFFER_SIZE];

        return DebugObjects{
            .debuglog_mutex = debuglog_mutex,
            .shmem_mutex = shmem_mutex,
            .buffer_ready_event = buffer_ready_event,
            .data_ready_event = data_ready_event,
            .shmem_mapping = shmem_mapping,
            .shmem = shmem_buf,
        };
    }

    fn deinit(self: *DebugObjects) void {
        if (UnmapViewOfFile(self.shmem.ptr) == windows.FALSE) {
            std.log.err("UnmapViewOfFile: {any}", .{windows.GetLastError()});
        }

        windows.CloseHandle(self.shmem_mapping);
        windows.CloseHandle(self.data_ready_event);
        windows.CloseHandle(self.buffer_ready_event);
        windows.CloseHandle(self.shmem_mutex);
        windows.CloseHandle(self.debuglog_mutex);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(gpa.allocator());
    defer std.process.argsFree(gpa.allocator(), args);

    const colors = &flags.ColorScheme{
        .error_label = &.{ .bright_red, .bold },
        .command_name = &.{.bright_green},
        .header = &.{ .yellow, .bold },
        .usage = &.{.dim},
    };

    const flags_ = flags.parseOrExit(args, "debuglog", Flags, .{
        .colors = colors,
    });

    // Set output destination
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();
    var out = stdout;
    {
        {
            var output_options_count: u8 = 0;
            if (flags_.stderr) output_options_count += 1;
            if (flags_.stdout) output_options_count += 1;
            if (flags_.file != null) output_options_count += 1;

            if (output_options_count > 1) {
                std.log.err("Error: Only one output destination can be specified", .{});
                std.process.exit(1);
            }
        }

        if (flags_.positional.trailing.len > 0) {
            out = stderr;
        }

        if (flags_.stderr) {
            out = stderr;
        }

        if (flags_.stdout) {
            out = stdout;
        }

        if (flags_.file) |file_path| {
            const file = std.fs.cwd().createFile(file_path, .{}) catch |e| {
                std.log.err("Failed to create output file: {}", .{e});
                std.process.exit(1);
            };
            out = file.writer();
        }
    }

    // Validate that pid and subprocess are not used together
    if (flags_.pid != null and flags_.positional.trailing.len > 0) {
        std.log.err("Error: Cannot use -p option together with subprocess command", .{});
        std.process.exit(1);
    }

    var debug_objects = DebugObjects.init();
    defer debug_objects.deinit();

    var filter_pid: ?u32 = flags_.pid;
    var child: ?std.process.Child = null;

    // Launch subprocess if specified
    if (flags_.positional.trailing.len > 0) {
        var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
        const cwd_path = try std.fs.cwd().realpath(".", cwd_buf[0..]);

        std.log.debug("spawn: {s}", .{flags_.positional.trailing});
        child = std.process.Child.init(flags_.positional.trailing, gpa.allocator());
        child.?.cwd = cwd_path;
        child.?.spawn() catch |e| {
            std.log.err("Failed to spawn child process: {}", .{e});
            std.process.exit(1);
        };

        const pid = GetProcessId(child.?.id);
        if (pid == 0) {
            std.log.err("Failed to get process ID: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        }

        out = stderr;
        filter_pid = pid;
    }

    // Clean up child process on exit
    defer if (child) |_| {
        _ = child.?.kill() catch {};
        _ = child.?.wait() catch {};
    };

    const child_wait_handle_index = 1;
    var wait_handles: [2]HANDLE = undefined;
    wait_handles[0] = debug_objects.data_ready_event;
    if (child) |c| {
        wait_handles[child_wait_handle_index] = c.id;
    }
    const wait_handle_count: DWORD = if (child != null) 2 else 1;

    while (true) {
        // The buffer is available for writing.
        if (SetEvent(debug_objects.buffer_ready_event) == FALSE) {
            std.log.err("Failed to set DBWIN_BUFFER_READY event: {any}", .{windows.GetLastError()});
            std.process.exit(1);
        }

        // Wait for either the data ready event or child process exit.
        const wait_result = WaitForMultipleObjects(
            wait_handle_count,
            &wait_handles,
            FALSE,
            INFINITE,
        );

        switch (wait_result) {
            // Data ready event signalled.
            WAIT_OBJECT_0 => {
                // Read 4 byte PID followed by null-terminated message.
                const Pid = u32;
                const pid = std.mem.bytesToValue(Pid, debug_objects.shmem[0..@sizeOf(Pid)]);

                const msg_buf = debug_objects.shmem[@sizeOf(Pid)..];
                const msg_end = std.mem.indexOfScalar(u8, msg_buf, 0) orelse {
                    std.log.err("Error: Message is not null-terminated, discarding.", .{});
                    continue;
                };
                const msg = msg_buf[0..msg_end];

                if (filter_pid) |pid_to_filter| {
                    if (pid != pid_to_filter) continue;
                }

                handleMsg(out, pid, msg, flags_.getOutputFormat()) catch |e| {
                    std.log.err("Failed to handle message: {}", .{e});
                    std.process.exit(1);
                };
            },

            // Child process handle signalled.
            WAIT_OBJECT_0 + child_wait_handle_index => {
                std.log.debug("Child process exited.", .{});

                const term_state = child.?.wait() catch {
                    std.log.err("Failed to get child process exit code", .{});
                    std.process.exit(1);
                };
                switch (term_state) {
                    .Exited => |exit_code| {
                        std.process.exit(exit_code);
                    },
                    else => {
                        std.log.err("Child process exited abnormally: {}", .{term_state});
                        std.process.exit(1);
                    },
                }
            },

            WAIT_FAILED => {
                std.log.err("WaitForMultipleObjects failed: {any}", .{windows.GetLastError()});
                std.process.exit(1);
            },

            else => {
                std.log.err("WaitForMultipleObjects returned an unexpected value", .{});
                std.process.exit(1);
            },
        }
    }
}

fn handleMsg(out: anytype, pid: u32, msg: []const u8, format: OutputFormat) !void {
    const msg_trimmed = std.mem.trim(u8, msg, " \n\r\t");
    if (IGNORE_EMPTY_MESSAGES and msg_trimmed.len == 0) {
        return;
    }

    switch (format) {
        .json => {
            try std.json.stringify(.{
                .pid = pid,
                .msg = msg_trimmed,
            }, .{}, out);

            try out.print("\n", .{});
        },
        .plain_text => {
            const max_pid_len = comptime std.fmt.count("{d}", .{std.math.maxInt(u32)});
            const max_pid_len_str = std.fmt.comptimePrint("{d}", .{max_pid_len});
            try out.print("{d: >" ++ max_pid_len_str ++ "}: {s}\n", .{ pid, msg_trimmed });
        },
    }
}
