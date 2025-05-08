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

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details. 