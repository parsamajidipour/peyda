package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/dataset"
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

func TestRenderDatasetSummaryIsConcise(t *testing.T) {
	resultDir := filepath.Join(t.TempDir(), "results", "example.com")
	summary := dataset.Summary{
		Target:          "example.com",
		Subdomains:      3,
		Resolved:        2,
		LiveHosts:       1,
		IPs:             2,
		OpenPorts:       4,
		URLs:            10,
		Parameters:      4,
		JavaScriptFiles: 2,
		Endpoints:       5,
		DurationSeconds: 121,
		ResultDir:       resultDir,
	}

	got := RenderDatasetSummary(summary, false)
	for _, want := range []string{
		"PEYDA SUMMARY",
		"Target           example.com",
		"Subdomains       3",
		"IPs              2",
		"Open ports       4",
		"Results          ",
		"Completed in     2m1s",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "[SUB]") || strings.Contains(got, "[URL]") {
		t.Fatalf("summary should not include individual records:\n%s", got)
	}
	if !strings.Contains(got, "example.com/") {
		t.Fatalf("output directory should include trailing slash:\n%s", got)
	}
}

func TestRenderDatasetOutputUsesFinalDataset(t *testing.T) {
	resultDir := t.TempDir()
	writeTestFile(t, filepath.Join(resultDir, "subdomains.txt"), "example.com\napi.example.com\n")
	writeTestFile(t, filepath.Join(resultDir, "resolved.txt"), "api.example.com\n")
	writeTestFile(t, filepath.Join(resultDir, "live.txt"), "https://api.example.com\n")
	writeTestFile(t, filepath.Join(resultDir, "ips.txt"), "1.2.3.4\n")
	writeTestFile(t, filepath.Join(resultDir, "ports.txt"), "api.example.com:443\thttps\n")
	writeTestFile(t, filepath.Join(resultDir, "urls.txt"), "https://api.example.com/users?id=1\n")
	writeTestFile(t, filepath.Join(resultDir, "parameters.txt"), "id\n")
	writeTestFile(t, filepath.Join(resultDir, "javascript.txt"), "https://api.example.com/app.js\n")
	writeTestFile(t, filepath.Join(resultDir, "endpoints.txt"), "/api/v1/users\n")
	writeTestFile(t, filepath.Join(resultDir, "dns.json"), "[]\n")
	writeTestFile(t, filepath.Join(resultDir, "http.json"), "[]\n")
	writeTestFile(t, filepath.Join(resultDir, "ports.json"), "[]\n")
	writeTestFile(t, filepath.Join(resultDir, "technologies.json"), "[]\n")

	summary := dataset.Summary{Target: "example.com", Subdomains: 2, ResultDir: resultDir}
	jsonOut, err := RenderDatasetOutput(config.Config{OutputFormat: "json"}, summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonOut, `"subdomains": [
      "example.com",
      "api.example.com"
    ]`) {
		t.Fatalf("json output did not use final dataset:\n%s", jsonOut)
	}

	jsonlOut, err := RenderDatasetOutput(config.Config{OutputFormat: "jsonl"}, summary)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonlOut, `"type":"subdomain","host":"api.example.com"`) ||
		!strings.Contains(jsonlOut, `"type":"ip","value":"1.2.3.4"`) ||
		!strings.Contains(jsonlOut, `"type":"port","host":"api.example.com","port":443,"service":"https"`) ||
		!strings.Contains(jsonlOut, `"type":"js_endpoint","endpoint":"/api/v1/users"`) {
		t.Fatalf("jsonl output did not use final dataset:\n%s", jsonlOut)
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
