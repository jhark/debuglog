const std = @import("std");
const windows = std.os.windows;
const kernel32 = windows.kernel32;

// Configuration
const IGNORE_EMPTY_MESSAGES = true;

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

// Debug memory window constants.
const DBWIN_BUFFER_SIZE = 4096;
const DBWIN_MUTEX_NAME = "DBWIN_MUTEX";
const DBWIN_SHARED_MEM_NAME = "DBWIN_BUFFER";
const DBWIN_BUFFER_READY_EVENT_NAME = "DBWIN_BUFFER_READY";
const DBWIN_DATA_READY_EVENT_NAME = "DBWIN_DATA_READY";

pub fn main() !void {
    var sec_desc: SECURITY_DESCRIPTOR = undefined;
    if (InitializeSecurityDescriptor(&sec_desc, 1) == FALSE) {
        std.debug.print("Failed to initialize security descriptor: {any}\n", .{windows.GetLastError()});
        return;
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
        std.debug.print("Failed to create/open DBWIN_MUTEX: {any}\n", .{windows.GetLastError()});
        return;
    };
    defer _ = windows.CloseHandle(shmem_mutex);

    // Acquire mutex for initialization
    switch (WaitForSingleObject(shmem_mutex, INFINITE)) {
        WAIT_OBJECT_0 => {},
        WAIT_FAILED => {
            std.debug.print("WaitForSingleObject (DBWIN_MUTEX) failed: {any}\n", .{windows.GetLastError()});
            return;
        },
        else => {
            std.debug.print("WaitForSingleObject (DBWIN_MUTEX) returned an unexpected value\n", .{});
            return;
        },
    }

    const buffer_ready_event = CreateEventA(
        &sec_attrs,
        FALSE, // Auto-reset event
        FALSE, // Initially non-signaled
        DBWIN_BUFFER_READY_EVENT_NAME,
    ) orelse {
        std.debug.print("Failed to create/open DBWIN_BUFFER_READY event: {any}\n", .{windows.GetLastError()});
        return;
    };
    defer _ = windows.CloseHandle(buffer_ready_event);

    const data_ready_event = CreateEventA(
        &sec_attrs,
        FALSE, // Auto-reset event
        FALSE, // Initially non-signaled
        DBWIN_DATA_READY_EVENT_NAME,
    ) orelse {
        std.debug.print("Failed to create/open DBWIN_DATA_READY event: {any}\n", .{windows.GetLastError()});
        return;
    };
    defer _ = windows.CloseHandle(data_ready_event);

    const shmem_mapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE, // Use paging file
        &sec_attrs, // Default security
        PAGE_READWRITE,
        0,
        DBWIN_BUFFER_SIZE,
        DBWIN_SHARED_MEM_NAME,
    ) orelse {
        std.debug.print("Failed to create/open shared memory mapping: {any}\n", .{windows.GetLastError()});
        return;
    };
    defer _ = windows.CloseHandle(shmem_mapping);

    const shmem = MapViewOfFile(
        shmem_mapping,
        FILE_MAP_READ,
        0,
        0,
        DBWIN_BUFFER_SIZE,
    ) orelse {
        std.debug.print("Failed to map view of file: {any}\n", .{windows.GetLastError()});
        return;
    };
    defer _ = UnmapViewOfFile(shmem);

    if (ReleaseMutex(shmem_mutex) == FALSE) {
        std.debug.print("Failed to release DBWIN_MUTEX: {any}\n", .{windows.GetLastError()});
        return;
    }

    const shmem_buf = @as([*]u8, @ptrCast(shmem))[0..DBWIN_BUFFER_SIZE];
    while (true) {
        // The buffer is available for writing.
        if (SetEvent(buffer_ready_event) == FALSE) {
            std.debug.print("Failed to set DBWIN_BUFFER_READY event: {any}\n", .{windows.GetLastError()});
            return;
        }

        // Wait until the buffer has been written to.
        switch (WaitForSingleObject(data_ready_event, INFINITE)) {
            WAIT_OBJECT_0 => {},
            WAIT_FAILED => {
                std.debug.print("WaitForSingleObject (DBWIN_DATA_READY) failed: {any}\n", .{windows.GetLastError()});
                return;
            },
            else => {
                std.debug.print("WaitForSingleObject (DBWIN_DATA_READY) returned an unexpected value\n", .{});
                return;
            },
        }

        // Read 4 byte PID followed by null-terminated message.
        const Pid = u32;
        const pid = std.mem.bytesToValue(Pid, shmem_buf[0..@sizeOf(Pid)]);

        const msg_buf = shmem_buf[@sizeOf(Pid)..];
        const msg_end = std.mem.indexOfScalar(u8, msg_buf, 0) orelse {
            std.debug.print("Error: Message is not null-terminated, discarding.\n", .{});
            continue;
        };
        const msg = msg_buf[0..msg_end];

        // Print.
        const msg_trimmed = std.mem.trim(u8, msg, " \n\r\t");
        if (IGNORE_EMPTY_MESSAGES and msg_trimmed.len == 0) {
            continue;
        }

        const max_pid_len = comptime std.fmt.count("{d}", .{std.math.maxInt(u32)});
        const max_pid_len_str = std.fmt.comptimePrint("{d}", .{max_pid_len});
        std.debug.print("{d: >" ++ max_pid_len_str ++ "}: {s}\n", .{ pid, msg_trimmed });
    }
}
