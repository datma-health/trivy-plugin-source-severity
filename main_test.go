package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWithStdin(t *testing.T) {
	// Save original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	// Define test cases
	testFiles, err := filepath.Glob("data/*.json")
	if err != nil {
		t.Fatalf("Failed to list test files: %v", err)
	}

	for _, testFile := range testFiles {
		t.Run(filepath.Base(testFile), func(t *testing.T) {
			// Open the test file
			f, err := os.Open(testFile)
			if err != nil {
				t.Fatalf("Failed to open test file %s: %v", testFile, err)
			}
			defer f.Close()

			// Set stdin to our test file
			os.Stdin = f

			// Run the function
			if err := run(); err == nil {
				t.Fatalf("test should fail with vuln")
			} else if !strings.HasPrefix(err.Error(), "plugin detected") {
				t.Fatalf("test failed with %v", err)
			}
		})
	}
}

// TestRunWithEmptyStdin simulates the case where Trivy itself fails (e.g. image
// pull error, network timeout) and produces no output at all.  Previously this
// caused run() to return an io.EOF-wrapped error which made main() call
// log.Fatal, crashing the whole pipeline without any report.
// After the fix, an empty stdin is treated as an empty (zero-finding) report
// and run() returns nil.
func TestRunWithEmptyStdin(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	w.Close() // close immediately so the reader sees EOF

	os.Stdin = r

	if err := run(); err != nil {
		t.Fatalf("run() should handle empty stdin (Trivy scan failure) gracefully, got: %v", err)
	}
}

// TestRunWithNonJSONStdin simulates the case where Trivy fails and writes a
// plain-text error message (not JSON) to stdout.  run() must still return a
// descriptive error rather than silently swallowing it.
func TestRunWithNonJSONStdin(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	if _, err := w.WriteString("FATAL: trivy scan failed: unable to pull image\n"); err != nil {
		t.Fatalf("Failed to write to pipe: %v", err)
	}
	w.Close()

	os.Stdin = r

	if err := run(); err == nil {
		t.Fatal("run() should return an error for non-JSON stdin")
	} else if !strings.HasPrefix(err.Error(), "json.NewDecoder failure") {
		t.Fatalf("expected json decode error, got: %v", err)
	}
}
