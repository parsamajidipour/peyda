package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsamajidipour/peyda/internal/config"
)

func TestParseHTTPXLine(t *testing.T) {
	got := parseHTTPXLine("https://app.example.com [200] [12432] [Dashboard] [text/html] [React,Cloudflare]")
	if got["url"] != "https://app.example.com" {
		t.Fatalf("url = %q", got["url"])
	}
	if got["status"] != "200" {
		t.Fatalf("status = %q", got["status"])
	}
	if got["title"] != "Dashboard" {
		t.Fatalf("title = %q", got["title"])
	}
	if got["content_length"] != "12432" {
		t.Fatalf("content_length = %q", got["content_length"])
	}
	if got["content_type"] != "text/html" {
		t.Fatalf("content_type = %q", got["content_type"])
	}
	if got["technology"] != "React,Cloudflare" {
		t.Fatalf("technology = %q", got["technology"])
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

func TestRenderCLIOutputModes(t *testing.T) {
	runDir := t.TempDir()
	writeTestFile(t, filepath.Join(runDir, "normalized/whois.tsv"), "key\tvalue\nregistrar\tNameCheap\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/dns-records.tsv"), "type\tname\tvalue\nA\texample.com\t1.2.3.4\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/subdomains.txt"), "api.example.com\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/live-hosts.txt"), "https://api.example.com [200] [1000] [API] [text/html] [nginx]\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/open-ports.tsv"), "host\tport\tservice\tsource\napi.example.com\t443\thttps\tnaabu,nmap\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/urls.txt"), "https://api.example.com/users?id=1\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/parameters.tsv"), "name\turl\tsource\nid\thttps://api.example.com/users?id=\turl\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/js-files.txt"), "https://api.example.com/app.js\n")
	writeTestFile(t, filepath.Join(runDir, "normalized/js-endpoints.txt"), "/api/v1/users\n")

	human, err := RenderCLIOutput(runDir, config.Config{OutputFormat: "human"}, 1200_000_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[WHOIS] [registrar] NameCheap",
		"[DNS] [A] example.com -> 1.2.3.4",
		"[SUB] api.example.com",
		"[HTTP] [200] [nginx] https://api.example.com",
		"[PORT] [443/https] api.example.com",
		"[URL] https://api.example.com/users?id=1",
		"[PARAM] [id] https://api.example.com/users?id=",
		"[JS] https://api.example.com/app.js",
		"[JS-ENDPOINT] /api/v1/users",
		"Scan completed in 1.2s",
	} {
		if !strings.Contains(human, want) {
			t.Fatalf("human output missing %q:\n%s", want, human)
		}
	}

	jsonl, err := RenderCLIOutput(runDir, config.Config{OutputFormat: "jsonl"}, 1200_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonl, `"type":"subdomain"`) || !strings.Contains(jsonl, `"type":"js_endpoint"`) {
		t.Fatalf("jsonl output missing expected records:\n%s", jsonl)
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
