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
