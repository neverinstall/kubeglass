package bpf_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBpfCompilation(t *testing.T) {
	_, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("Clang compiler not found, skipping BPF compilation test")
	}

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	if filepath.Base(dir) == "bpf" && filepath.Base(filepath.Dir(dir)) == "test" {
		dir = filepath.Dir(filepath.Dir(dir))
	} else if filepath.Base(dir) == "test" {
		dir = filepath.Dir(dir)
	}

	sourcePath := filepath.Join(dir, "bpf", "write_tracer.c")

	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		t.Fatalf("BPF source file not found: %s", sourcePath)
	}

	objPath := filepath.Join(os.TempDir(), "write_tracer_test.o")
	defer os.Remove(objPath)

	cmd := exec.Command("clang", "-O2", "-target", "bpf", "-c", sourcePath, "-o", objPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to compile BPF program: %v\nOutput: %s", err, string(output))
	}

	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		t.Fatalf("BPF object file was not created: %s", objPath)
	}

	t.Logf("Successfully compiled BPF program to %s", objPath)
}

func TestBpfStructures(t *testing.T) {
	cCode := `
	#include <stdio.h>
	#include <stdint.h>
	
	struct write_event_t {
		uint32_t pid;
		uint32_t fd;
		char data[240];
		uint32_t data_len;
	};
	
	int main() {
		printf("Size of write_event_t: %zu\n", sizeof(struct write_event_t));
		printf("Offset of pid: %zu\n", (size_t)&((struct write_event_t*)0)->pid);
		printf("Offset of fd: %zu\n", (size_t)&((struct write_event_t*)0)->fd);
		printf("Offset of data: %zu\n", (size_t)&((struct write_event_t*)0)->data);
		printf("Offset of data_len: %zu\n", (size_t)&((struct write_event_t*)0)->data_len);
		return 0;
	}
	`

	cFile := filepath.Join(os.TempDir(), "struct_test.c")
	exeFile := filepath.Join(os.TempDir(), "struct_test")

	defer os.Remove(cFile)
	defer os.Remove(exeFile)

	if err := os.WriteFile(cFile, []byte(cCode), 0644); err != nil {
		t.Fatalf("Failed to write C code: %v", err)
	}

	cmd := exec.Command("gcc", cFile, "-o", exeFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to compile C program: %v\nOutput: %s", err, string(output))
	}

	cmd = exec.Command(exeFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run C program: %v\nOutput: %s", err, string(output))
	}

	t.Logf("C structure information:\n%s", string(output))

	if !bytes.Contains(output, []byte("Size of write_event_t:")) {
		t.Errorf("Expected output to contain structure size information")
	}
}
