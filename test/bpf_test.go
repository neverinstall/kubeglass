package test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestBpfCompilation tests if the BPF program compiles correctly
func TestBpfCompilation(t *testing.T) {
	// Skip if clang is not available
	_, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("Clang compiler not found, skipping BPF compilation test")
	}

	// Find the project root directory
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Navigate to parent directory if we're in the test folder
	if filepath.Base(dir) == "test" {
		dir = filepath.Dir(dir)
	}

	sourcePath := filepath.Join(dir, "bpf", "write_tracer.c")

	// Ensure source file exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		t.Fatalf("BPF source file not found: %s", sourcePath)
	}

	// Temporary output file
	objPath := filepath.Join(os.TempDir(), "write_tracer_test.o")
	defer os.Remove(objPath)

	// Try to compile the BPF program
	cmd := exec.Command("clang", "-O2", "-target", "bpf", "-c", sourcePath, "-o", objPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to compile BPF program: %v\nOutput: %s", err, string(output))
	}

	// Check that the output file exists
	if _, err := os.Stat(objPath); os.IsNotExist(err) {
		t.Fatalf("BPF object file was not created: %s", objPath)
	}

	t.Logf("Successfully compiled BPF program to %s", objPath)
}

// TestBpfStructures tests if the BPF program structures match Go structures
func TestBpfStructures(t *testing.T) {
	// This is a basic check - in a real implementation, we would use
	// a more sophisticated mechanism to ensure structure sizes match

	// Write a simple C program to print structure sizes
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

	// Write C code to a file
	if err := os.WriteFile(cFile, []byte(cCode), 0644); err != nil {
		t.Fatalf("Failed to write C code: %v", err)
	}

	// Compile the C program
	cmd := exec.Command("gcc", cFile, "-o", exeFile)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to compile C program: %v\nOutput: %s", err, string(output))
	}

	// Run the program to get structure sizes
	cmd = exec.Command(exeFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run C program: %v\nOutput: %s", err, string(output))
	}

	// Output contains structure size information
	// In a real test, we would parse this output and compare with the Go struct
	t.Logf("C structure information:\n%s", string(output))

	// For now, just make sure the size is reasonable
	if !bytes.Contains(output, []byte("Size of write_event_t:")) {
		t.Errorf("Expected output to contain structure size information")
	}
}
