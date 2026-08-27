package deps

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestEnsureDoesNotInstallOptionalSystemTools(t *testing.T) {
	tmp := t.TempDir()
	goBin := filepath.Join(tmp, "go", "bin")
	if err := os.MkdirAll(goBin, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", filepath.Join(tmp, "go"))
	t.Setenv("PATH", goBin)

	for _, name := range []string{"subfinder", "dnsx", "katana"} {
		writeTool(t, filepath.Join(goBin, name), "#!/bin/sh\nexit 0\n")
	}
	writeTool(t, filepath.Join(goBin, "httpx"), "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo 'ProjectDiscovery httpx version 1.0.0'; fi\n")

	var out bytes.Buffer
	err := Manager{Root: tmp, Out: &out}.Run(Ensure)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Installing system packages") {
		t.Fatalf("optional system tool triggered apt install:\n%s", out.String())
	}
}

func writeTool(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}
