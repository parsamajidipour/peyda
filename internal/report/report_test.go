package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsamajidipour/reconx/internal/config"
)

func TestParseHTTPXLine(t *testing.T) {
	got := parseHTTPXLine("https://app.example.com [200] [Dashboard] [React,Cloudflare] [12432]")
	if got["url"] != "https://app.example.com" {
		t.Fatalf("url = %q", got["url"])
	}
	if got["status"] != "200" {
		t.Fatalf("status = %q", got["status"])
	}
	if got["title"] != "Dashboard" {
		t.Fatalf("title = %q", got["title"])
	}
}

func TestWriteTextIncludesHumanReadableArtifacts(t *testing.T) {
	runDir := t.TempDir()
	writeTestFile(t, filepath.Join(runDir, "normalized/subdomains.txt"), "api.example.com\napp.example.com\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/resolved-hosts.txt"), "api.example.com\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/live-hosts.txt"), "https://api.example.com [200] [API]\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/js-files.txt"), "https://api.example.com/app.js\n")
	writeTestFile(t, filepath.Join(runDir, "notes/js-leads.tsv"), "route\tsource\tauth_guess\tobject_or_action\tnext_step\n/api/v1/users\tjs/katana\tunknown\tusers\tmanual-review\n")

	cfg := config.Config{
		Target:         "example.com",
		Profile:        config.ProfileBalanced,
		ProbeRate:      25,
		CrawlRate:      10,
		CrawlDepth:     1,
		CrawlDuration:  "45s",
		MaxDomainPages: 75,
		APIRate:        20,
	}
	if err := WriteText(runDir, cfg); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(runDir, "notes/recon-report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	report := string(data)
	for _, want := range []string{
		"SUBDOMAINS",
		"1. api.example.com",
		"JAVASCRIPT FILES",
		"1. https://api.example.com/app.js",
		"JAVASCRIPT ROUTE LEADS",
		"1. /api/v1/users\tjs/katana\tunknown\tusers\tmanual-review",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("text report missing %q:\n%s", want, report)
		}
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
