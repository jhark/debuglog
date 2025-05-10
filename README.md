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
Usage: debuglog [-p | --pid <pid>] [-e | --stderr] [-o | --stdout]
                [-f | --file <file>] [-h | --help]

Captures messages sent by applications using OutputDebugStringA and prints them.

Example:
  debuglog                   # Print messages from all processes
  debuglog -p 1234           # Print messages from process with PID 1234
  debuglog -- app.exe --foo  # Launch `app.exe --foo` and print only its messages.

Messages are printed to stdout by default, or to stderr when spawning a subprocess.

Options:

  -p, --pid    Filter messages to show only those from the specified process ID
  -e, --stderr Send output to stderr
  -o, --stdout Send output to stdout
  -f, --file   Send output to the specified file
  -h, --help   Show this help and exit
```

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details. 