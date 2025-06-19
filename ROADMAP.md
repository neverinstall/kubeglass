# kubeglass Roadmap

## 2025 Vision & Goals

1. Provide a **zero-friction** CLI for tracing process I/O via eBPF.
2. Offer **production-grade** observability with minimal overhead.
3. Integrate smoothly with container and Kubernetes workflows.

## Detailed Improvement Backlog

### 1. eBPF Program

- [x] Switch to **ring buffer** (BPF_MAP_TYPE_RINGBUF) for higher throughput.
- [ ] Support **BPF perf event lost counter** and emit warnings.
- [ ] Accept dynamic **FD filter map** via userspace updates (array/hash map per FD).
- [ ] Parameterise **max payload size** (240 → configurable), use **BPF dynptr** once supported.
- [ ] Add tracepoints for `writev`, `sendto`, `sendmsg`.
- [ ] Kernel version probes & graceful fallback.

### 2. CLI

- [x] **Interactive TUI** (bubbletea) with live streams and interactive filtering.
- [ ] Persistent **config file** (`~/.config/kubeglass/config.yaml`).

### 3. Container & Kubernetes Integration

- [ ] Detect **namespaces** (mnt, net, pid) and follow PID inside containers.
- [ ] Provide a **kubectl-plugin** (`kubectl trace-fd <pod>`) that spawns kubeglass in the pod namespace.
- [ ] Helm chart & side-car deployment pattern.
- [ ] Expose metrics via **/metrics** endpoint for Prometheus.

### 4. Outputs

- [ ] **gRPC / HTTP** endpoint to stream events to observers.
- [ ] **OpenTelemetry** trace exporter (span per write call).
- [ ] File sink with automatic **log rotation** (size/time based).

### 5. Security

- [ ] Perform **seccomp / capability** drop when not root-required.
- [ ] Signed release binaries & SBOM in GoReleaser pipeline.
- [ ] End-to-end **integration tests** executed inside Ubuntu & Fedora kernels (GitHub runners + docker).
- [ ] Kernel-feature detection and early exit with helpful message.

_Last updated: 2025-06-19._
