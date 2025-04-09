package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type writeEvent struct {
	PID     uint32
	FD      uint32
	Data    [240]byte
	DataLen uint32
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memory lock limit: %v\n", err)
		os.Exit(1)
	}

	var targetPID int
	var showStdout, showStderr, showAll bool
	var targetFDs string
	var suppressRepeats bool
	var skipBinary bool
	var showExisting bool
	var tailLines int

	flag.IntVar(&targetPID, "pid", 0, "PID to trace")
	flag.BoolVar(&showStdout, "stdout", false, "Show stdout (fd 1) writes")
	flag.BoolVar(&showStderr, "stderr", false, "Show stderr (fd 2) writes")
	flag.BoolVar(&showAll, "all", true, "Show all file descriptor writes")
	flag.StringVar(&targetFDs, "fds", "", "Comma-separated list of file descriptors to monitor (overrides other fd flags)")
	flag.BoolVar(&suppressRepeats, "no-repeats", false, "Suppress repeated identical messages")
	flag.BoolVar(&skipBinary, "no-binary", false, "Skip binary data that doesn't look like text")
	flag.BoolVar(&showExisting, "existing", false, "Show existing content of FDs before tracing")
	flag.IntVar(&tailLines, "tail", 10, "Number of lines to show from existing logs")
	flag.Parse()

	if targetPID <= 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s --pid=<pid> [--stdout] [--stderr] [--all] [--fds=1,2,5] [--no-repeats] [--no-binary] [--existing] [--tail=10]\n", os.Args[0])
		os.Exit(1)
	}

	fdFilter := make(map[uint32]bool)
	if targetFDs != "" {
		showAll = false
		fdList := strings.Split(targetFDs, ",")
		for _, fdStr := range fdList {
			var fd int
			fmt.Sscanf(fdStr, "%d", &fd)
			if fd > 0 {
				fdFilter[uint32(fd)] = true
			}
		}
	} else {
		if showStdout {
			showAll = false
			fdFilter[1] = true
		}
		if showStderr {
			showAll = false
			fdFilter[2] = true
		}
	}

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", targetPID)); err != nil {
		fmt.Fprintf(os.Stderr, "Process %d does not exist\n", targetPID)
		os.Exit(1)
	}

	if showExisting {
		showExistingLogs(targetPID, fdFilter, showAll, tailLines, skipBinary)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Loading BPF program: %v\n", err)
		os.Exit(1)
	}
	defer objs.Close()

	pid := uint32(targetPID)
	if err := objs.TargetPid.Put(pid, pid); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update PID map: %v\n", err)
		os.Exit(1)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWrite, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Attaching tracepoint: %v\n", err)
		os.Exit(1)
	}
	defer tp.Close()

	// Set up perf reader
	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating perf event reader: %v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	fmt.Printf("Tracing write syscalls from PID %d... Press Ctrl-C to exit\n", targetPID)
	if !showAll {
		fmt.Printf("Filtering FDs: ")
		for fd := range fdFilter {
			fmt.Printf("%d ", fd)
		}
		fmt.Println()
	}

	// Channel to coordinate shutdown
	done := make(chan struct{})

	// Track last event for repeat suppression
	var lastEvent *writeEvent
	var lastDataStr string
	var repeatCount int

	// Process events
	go func() {
		defer close(done)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					if err == perf.ErrClosed {
						return
					}
					fmt.Fprintf(os.Stderr, "Error reading perf buffer: %v\n", err)
					time.Sleep(100 * time.Millisecond) // Avoid tight loop on errors
					continue
				}

				if record.LostSamples != 0 {
					fmt.Printf("Lost %d samples\n", record.LostSamples)
					continue
				}

				var event writeEvent
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
					continue
				}

				// Apply FD filter
				if !showAll && !fdFilter[event.FD] {
					continue
				}

				// Determine if stdout/stderr or other fd
				fdType := fdString(event.FD)

				// Format the data for display
				data := event.Data[:event.DataLen]
				dataStr := formatData(data)

				// Check if we should skip binary data
				if skipBinary && !isPrintable(data) {
					continue
				}

				// Handle repeat suppression
				if suppressRepeats && lastEvent != nil &&
					lastEvent.FD == event.FD &&
					lastDataStr == dataStr {
					repeatCount++
					continue
				}

				// If we were accumulating repeats, show the count
				if repeatCount > 0 {
					fmt.Printf("[PID %d, %s] Last message repeated %d times\n",
						lastEvent.PID, fdString(lastEvent.FD), repeatCount)
					repeatCount = 0
				}

				// Print the captured data
				fmt.Printf("[PID %d, %s] %s\n", event.PID, fdType, dataStr)

				// Save this event for repeat comparison
				if lastEvent == nil {
					lastEvent = &writeEvent{}
				}
				*lastEvent = event
				lastDataStr = dataStr
			}
		}
	}()

	<-sig
	fmt.Println("\nExiting...")

	signal.Reset(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	cancel()
	rd.Close()

	select {
	case <-done:

	case <-time.After(2 * time.Second):
		fmt.Println("Timed out waiting for cleanup, forcing exit")
	}
}

func formatData(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}

	// Check if data contains null bytes but is otherwise printable
	nullByteIndex := bytes.IndexByte(data, 0)
	containsNullByte := nullByteIndex >= 0

	// If the data is all printable ASCII or standard whitespace (except perhaps null bytes), show as string
	isPrintable := true
	for _, b := range data {
		if b == 0 {
			continue // Skip null bytes for printability check
		}
		if b != '\n' && b != '\r' && b != '\t' && !unicode.IsPrint(rune(b)) {
			isPrintable = false
			break
		}
	}

	if isPrintable {
		// If it contains null bytes, truncate at first null
		if containsNullByte {
			data = data[:nullByteIndex]
		}

		// Truncate trailing nulls and format line endings
		cleanData := bytes.TrimRight(data, "\x00")
		formattedData := strings.ReplaceAll(string(cleanData), "\n", "\\n")
		formattedData = strings.ReplaceAll(formattedData, "\r", "\\r")
		formattedData = strings.ReplaceAll(formattedData, "\t", "\\t")
		return formattedData
	}

	// For binary data, show hex dump
	maxLen := 32
	if len(data) > maxLen {
		return fmt.Sprintf("%s... (%d bytes total)", hex.Dump(data[:maxLen]), len(data))
	}
	return hex.Dump(data)
}

// isPrintable checks if the data appears to be text rather than binary
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return true
	}

	printableCount := 0
	for _, b := range data {
		if b == '\n' || b == '\r' || b == '\t' || unicode.IsPrint(rune(b)) {
			printableCount++
		}
	}

	// Consider it printable if at least 90% of chars are printable
	return float64(printableCount)/float64(len(data)) > 0.9
}

// fdString returns a descriptive name for a file descriptor
func fdString(fd uint32) string {
	switch fd {
	case 0:
		return "stdin"
	case 1:
		return "stdout"
	case 2:
		return "stderr"
	default:
		return fmt.Sprintf("fd %d", fd)
	}
}

// showExistingLogs displays existing content from process file descriptors
func showExistingLogs(pid int, fdFilter map[uint32]bool, showAll bool, tailLines int, skipBinary bool) {
	fmt.Printf("Reading existing file descriptors for PID %d:\n", pid)

	// Read /proc/PID/fd directory to get all open file descriptors
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file descriptors: %v\n", err)
		return
	}

	for _, entry := range entries {
		fdNum, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fd := uint32(fdNum)

		// Skip if not in our filter
		if !showAll && !fdFilter[fd] {
			continue
		}

		// Get file info to determine if it's a regular file
		fdPath := filepath.Join(fdDir, entry.Name())
		linkTarget, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// Skip if not a regular file or pipe
		if !strings.HasPrefix(linkTarget, "/") && !strings.Contains(linkTarget, "pipe") {
			continue
		}

		fmt.Printf("\n--- Contents of %s (FD %d) ---\n", linkTarget, fd)

		if strings.HasPrefix(linkTarget, "/") {
			// For regular files
			fileContent, err := os.ReadFile(linkTarget)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				continue
			}

			// Split into lines
			lines := bytes.Split(fileContent, []byte{'\n'})

			// Show only the last N lines
			start := 0
			if len(lines) > tailLines {
				start = len(lines) - tailLines
			}

			for i := start; i < len(lines); i++ {
				data := formatData(lines[i])
				if skipBinary && !isPrintable(lines[i]) {
					continue
				}
				fmt.Printf("[EXISTING] %s\n", data)
			}
		}
	}
	fmt.Println("\n--- Starting live capture ---")
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Werror" bpf ../../bpf/write_tracer.c
