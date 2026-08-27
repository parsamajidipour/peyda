package subdomain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := map[string]string{
		"*.API.Example.COM.": "api.example.com",
		" app.example.com ":  "app.example.com",
		"https://bad.test":   "",
		"":                   "",
	}
	for input, want := range tests {
		if got := NormalizeDomain(input); got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeAndFilter(t *testing.T) {
	runDir := t.TempDir()
	for _, dir := range []string{"raw", "normalized"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, "raw/subfinder.txt"), []byte("App.Example.com\napi.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "raw/crtsh.txt"), []byte("*.api.example.com.\nstaging.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "excluded.txt"), []byte("staging.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := normalizeAndFilter(runDir)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"api.example.com", "app.example.com"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("filtered = %v", got)
	}
}

func TestScoreLiveHosts(t *testing.T) {
	runDir := t.TempDir()
	path := filepath.Join(runDir, "live-hosts.txt")
	input := strings.Join([]string{
		"https://app.example.com [200] [1000] [Home] [text/html] [React]",
		"https://admin.example.com [403] [500] [Admin] [text/html] [nginx]",
	}, "\n")
	if err := os.WriteFile(path, []byte(input+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scores, err := ScoreLiveHosts(path, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	if len(scores) != 2 {
		t.Fatalf("scores len = %d", len(scores))
	}
	if scores[0].Host != "admin.example.com" || scores[0].Score < 55 {
		t.Fatalf("top score = %+v", scores[0])
	}
}

func TestReservedTestDomain(t *testing.T) {
	if !isReservedTestDomain("example.test") {
		t.Fatal("example.test should be treated as reserved")
	}
	if isReservedTestDomain("example.com") {
		t.Fatal("example.com should not be treated as reserved")
	}
}
