package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithGoBinFirstPrefersGoPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("GOPATH", tmp)

	env := WithGoBinFirst([]string{"PATH=/usr/bin"})
	if len(env) != 1 {
		t.Fatalf("env length = %d", len(env))
	}
	wantPrefix := DetectGoBin() + string(os.PathListSeparator)
	if got := env[0]; len(got) < len("PATH="+wantPrefix) || got[:len("PATH="+wantPrefix)] != "PATH="+wantPrefix {
		t.Fatalf("PATH does not start with Go bin: %q", got)
	}
}

func TestLookPathPrefersGoBin(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("GOPATH", tmp)

	goBin := DetectGoBin()
	if goBin == "" {
		t.Skip("go bin unavailable")
	}
	if err := os.MkdirAll(goBin, 0o755); err != nil {
		t.Fatal(err)
	}

	tool := filepath.Join(goBin, "reconx-test-tool")
	if err := os.WriteFile(tool, []byte("#!/usr/bin/env sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, err := LookPath("reconx-test-tool")
	if err != nil {
		t.Fatal(err)
	}
	if path != tool {
		t.Fatalf("path = %s, want %s", path, tool)
	}
}
