package reconrun

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/parsamajidipour/reconx/internal/config"
)

func TestInitCreatesRunFolder(t *testing.T) {
	tmp := t.TempDir()
	runDir, err := Init(config.Config{
		Target:     "Example.COM/",
		RunDate:    "2026-08-27",
		OutputRoot: tmp,
		Profile:    config.ProfileBalanced,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(tmp, "example.com", "2026-08-27")
	if runDir != want {
		t.Fatalf("runDir = %s, want %s", runDir, want)
	}
	for _, rel := range []string{"raw", "normalized", "screenshots", "notes", "scope.txt", "excluded.txt"} {
		if _, err := os.Stat(filepath.Join(runDir, rel)); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
}

func TestInitRelativeOutputRootUsesWorkingDirectory(t *testing.T) {
	tmp := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWD); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	runDir, err := Init(config.Config{
		Target:     "example.com",
		RunDate:    "2026-08-27",
		OutputRoot: "recon-output",
		Profile:    config.ProfileBalanced,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(tmp, "recon-output", "example.com", "2026-08-27")
	if runDir != want {
		t.Fatalf("runDir = %s, want %s", runDir, want)
	}
	if _, err := os.Stat(filepath.Join(want, "notes/run-metadata.txt")); err != nil {
		t.Fatalf("missing metadata in working directory output: %v", err)
	}
}
