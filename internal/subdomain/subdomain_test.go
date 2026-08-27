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

	got, err := normalizeAndFilter(runDir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"api.example.com", "app.example.com", "example.com", "www.example.com"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("filtered = %v", got)
	}
}

func TestNormalizeAndFilterSeedsApexAndWWW(t *testing.T) {
	runDir := t.TempDir()
	for _, dir := range []string{"raw", "normalized"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, "raw/subfinder.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "raw/crtsh.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := normalizeAndFilter(runDir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"example.com", "www.example.com"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("filtered = %v", got)
	}
}

func TestURLDiscoveredHosts(t *testing.T) {
	runDir := t.TempDir()
	for _, dir := range []string{"raw", "normalized"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	input := strings.Join([]string{
		"http://api.sooq-cars.com/",
		"https://app.sooq-cars.com/links/abc?x=1",
		"https://om.sooq-cars.com/.well-known/security.txt",
		"https://sooq-cars.com/coming-soon/",
		"https://sooq-cars.com.attacker.net/pwn",
		"not-a-url",
	}, "\n")
	if err := os.WriteFile(filepath.Join(runDir, "raw/gau-urls.txt"), []byte(input+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := strings.Join(urlDiscoveredHosts(runDir, "sooq-cars.com"), "\n")
	want := strings.Join([]string{
		"api.sooq-cars.com",
		"app.sooq-cars.com",
		"om.sooq-cars.com",
		"sooq-cars.com",
	}, "\n")
	if got != want {
		t.Fatalf("url hosts = %q, want %q", got, want)
	}
}

func TestMergeSubdomainsAddsURLHosts(t *testing.T) {
	runDir := t.TempDir()
	for _, dir := range []string{"normalized"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(runDir, "normalized/subdomains.txt"), []byte("sooq-cars.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "excluded.txt"), []byte("qa.sooq-cars.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := mergeSubdomains(runDir, []string{"api.sooq-cars.com", "qa.sooq-cars.com", "app.sooq-cars.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"api.sooq-cars.com", "app.sooq-cars.com", "sooq-cars.com"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("merged = %v", got)
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
