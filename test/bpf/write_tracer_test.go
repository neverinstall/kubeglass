package bpf_test

import (
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

	// Get project root directory
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Navigate to root if in test dir
	if filepath.Base(dir) == "bpf" && filepath.Base(filepath.Dir(dir)) == "test" {
		dir = filepath.Dir(filepath.Dir(dir))
	} else if filepath.Base(dir) == "test" {
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
