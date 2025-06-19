package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfWriteEvent struct {
	PID     uint32
	FD      uint32
	Data    [240]byte
	DataLen uint32
}

type Event struct {
	PID     uint32 `json:"pid"`
	FD      uint32 `json:"fd"`
	Payload []byte `json:"payload"`
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove memory lock limit: %v\n", err)
		os.Exit(1)
	}

	var targetPID int
	flag.IntVar(&targetPID, "pid", 0, "PID to trace")
	flag.Parse()

	if targetPID <= 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s --pid=<pid>\n", os.Args[0])
		os.Exit(1)
	}

	if _, err := os.Stat(fmt.Sprintf("/proc/%d", targetPID)); err != nil {
		fmt.Fprintf(os.Stderr, "Process %d does not exist\n", targetPID)
		os.Exit(1)
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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating ringbuf reader: %v\n", err)
		os.Exit(1)
	}

	model := newTUIModel(ctx, rd)
	p := tea.NewProgram(model, tea.WithAltScreen())

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func formatData(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}

	nullByteIndex := bytes.IndexByte(data, 0)
	containsNullByte := nullByteIndex >= 0

	isPrintable := true
	for _, b := range data {
		if b == 0 {
			continue
		}
		if b != '\n' && b != '\r' && b != '\t' && !unicode.IsPrint(rune(b)) {
			isPrintable = false
			break
		}
	}

	if isPrintable {
		if containsNullByte {
			data = data[:nullByteIndex]
		}

		cleanData := bytes.TrimRight(data, "\x00")
		formattedData := strings.ReplaceAll(string(cleanData), "\n", "\\n")
		formattedData = strings.ReplaceAll(formattedData, "\r", "\\r")
		formattedData = strings.ReplaceAll(formattedData, "\t", "\\t")
		return formattedData
	}

	maxLen := 32
	if len(data) > maxLen {
		return fmt.Sprintf("%s... (%d bytes total)", hex.Dump(data[:maxLen]), len(data))
	}
	return hex.Dump(data)
}

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

	return float64(printableCount)/float64(len(data)) > 0.9
}

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

func showExistingLogs(pid int, fdFilter map[uint32]bool, showAll bool, tailLines int, skipBinary bool) {
	fmt.Printf("Reading existing file descriptors for PID %d:\n", pid)

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

		if !showAll && !fdFilter[fd] {
			continue
		}

		fdPath := filepath.Join(fdDir, entry.Name())
		linkTarget, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		if !strings.HasPrefix(linkTarget, "/") && !strings.Contains(linkTarget, "pipe") {
			continue
		}

		fmt.Printf("\n--- Contents of %s (FD %d) ---\n", linkTarget, fd)

		if strings.HasPrefix(linkTarget, "/") {
			fileContent, err := os.ReadFile(linkTarget)
			if err != nil {
				fmt.Printf("Error reading file: %v\n", err)
				continue
			}

			lines := bytes.Split(fileContent, []byte{'\n'})

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
