package main

import (
	"os"
	"path/filepath"
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
			if err := run(); err != nil {
				t.Fatalf("test failed with %v", err)
			}
		})
	}
}
