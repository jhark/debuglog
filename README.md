# debuglog

A command-line tool for Windows that captures debug log messages sent to the [OutputDebugStringA](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa) API.

See also [Sysinternals' DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview).

## Requirements

- Windows.
- Zig compiler (version 0.14.0)

## Building

```sh
zig build
```

## Usage

```
Usage: debuglog [-p | --pid <pid>] [-h | --help]

Captures messages sent by applications using OutputDebugStringA and prints them to stdout.

Example:
  debuglog -p 1234    # Show only messages from process ID 1234
  debuglog            # Show messages from all processes

Options:

  -p, --pid  Filter messages to show only those from the specified process ID
  -h, --help Show this help and exit
```

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details. 