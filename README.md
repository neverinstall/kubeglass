# kubeglass

kubeglass is an eBPF-based tool for Linux that allows you to monitor and capture file descriptor writes from any running process in real-time via an interactive terminal UI.

## Features

- **Interactive TUI:** A `bubbletea`-based terminal user interface for viewing live data streams.
- **Real-time Monitoring:** Monitor any process by its PID.
- **Interactive Filtering:** Filter events by file descriptor or with a regex pattern on the payload, all within the UI.
- **Clean Output:** Toggle binary data filtering on the fly.

## Requirements

- **Linux kernel 5.8+** with eBPF support
- Root privileges (for loading eBPF programs)
- Go 1.21+
- Clang compiler

## Installation

```bash
# Clone the repository
git clone https://github.com/neverinstall/kubeglass.git
cd kubeglass

# Build the project
cd cmd/kubeglass
go generate  # Generates eBPF code
go build -o kubeglass

# Run with sudo for eBPF permissions
sudo ./kubeglass --pid <target_pid>
```

## Usage

To start monitoring a process, simply provide its PID:

```bash
sudo ./kubeglass --pid 1234
```

All other controls and filters are available within the interactive TUI.

## Command Line Options

| Option | Description |
|--------|-------------|
| `--pid` | Target process ID to monitor (required) |

## Interactive Controls

| Key | Action |
|-----|--------|
| `q` / `ctrl+c` | Quit the application |
| `?` | Toggle the help menu |
| `/` | Enter filter mode (to type a regex) |
| `enter` | Apply the regex filter |
| `esc` | Clear the current filter |
| `a` | Toggle showing all file descriptors |
| `b` | Toggle filtering of binary data |

## Use Cases

### Security & Risk Monitoring

- **Detect Data Exfiltration**: Monitor processes for unexpected file or socket writes
- **Command Injection Detection**: Watch for unexpected shell activity
- **Credential Leakage**: Monitor processes for plaintext credentials
- **Runtime Behavior Auditing**: Document process behavior for compliance
- **Container Escape Detection**: Monitor containerized applications for unexpected access

### Debugging & Operations

- **Application Debugging**: Capture unlogged application errors
- **Log Recovery**: View logs from processes not writing to standard locations
- **Hidden Communication Discovery**: Find processes writing to non-standard file descriptors
- **Performance Analysis**: Identify heavy logging impacting performance
- **Third-Party Application Monitoring**: Trace closed-source software without modifications

### Creative Applications

- **API Reverse Engineering**: Capture undocumented API responses
- **Legacy Application Forensics**: Extract data formats from systems without documentation
- **Dynamic Documentation Generation**: Generate API docs from actual network traffic
- **Algorithm Visualization**: Capture intermediate steps of algorithms
- **Multi-Process Communication Mapping**: Create a graph of process communications

## How It Works

kubeglass uses eBPF (extended Berkeley Packet Filter) technology to:

1. Attach to the kernel's syscall tracepoints
2. Monitor the `write` system call for the target process
3. Capture the data being written to file descriptors
4. Send events from the kernel to user-space via a high-performance eBPF ring buffer
5. Display the data in a real-time, interactive terminal UI

This approach is minimally invasive, with very low overhead compared to traditional debugging or tracing tools.

## Limitations

- Requires root privileges to load eBPF programs
- Cannot track file descriptors that were already closed
- Limited buffer size (240 bytes) for each write operation
- Some binary data may not display correctly
- May miss writes if the system is under extremely heavy load

## Troubleshooting

### Permission Denied

If you see `operation not permitted`, make sure you're running with sudo:

```bash
sudo ./kubeglass --pid <target_pid>
```

### eBPF Verification Failed

If you encounter eBPF verification errors, your kernel may have restrictions or lack features:

```
Loading BPF program: field TraceWrite: program trace_write: load program: invalid argument
```

Try using a more recent kernel (5.8+) or check that eBPF syscall tracepoints are enabled.

### Process Not Monitored

If you don't see any output, verify:

1. The process is still running
2. The process is actually writing to file descriptors
3. You have the correct PID

## Testing

The project includes comprehensive tests for both the Go application code and BPF program.

### Running Unit Tests

```bash
# Run Go unit tests for the main application
cd cmd/kubeglass
go test -v

# Run BPF-specific tests
cd ../../test
go test -v
```

### Running Integration Tests

Some tests require root privileges to load BPF programs:

```bash
sudo go test -v ./...
```

### Test Coverage

Generate test coverage reports:

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Docker Usage

You can also build and run kubeglass using Docker. This encapsulates dependencies but requires running the container with specific privileges to interact with the host system's kernel for eBPF operations.

### Building the Docker Image

```bash
docker build -t kubeglass .
```

### Running the Docker Container

To monitor processes on the host system, the container needs access to the host's PID namespace and privileges for eBPF.

```bash
# Example: Monitor PID 1234 on the host
sudo docker run --rm -it --pid=host --privileged kubeglass --pid 1234

# Alternatively, using specific capabilities instead of --privileged (more secure)
# Capabilities needed might vary, but typically include CAP_SYS_ADMIN and CAP_BPF
sudo docker run --rm -it --pid=host --cap-add=SYS_ADMIN --cap-add=BPF kubeglass --pid 1234
```

**Note:** Running Docker containers with `--privileged` or extensive capabilities poses security risks. Understand the implications before using these options.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Future Scope

- **Socket Monitoring**: Extend monitoring capabilities to network sockets and other I/O channels
- **Multi-Process Tracing**: Trace multiple PIDs simultaneously
- **Persistent Configuration**: Allow setting default flags in a config file.
- **Log Rotation**: Implement log rotation for long-running captures
