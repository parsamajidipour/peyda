package dataset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestExportCreatesStableDataset(t *testing.T) {
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "runs/example.com/2026-08-27")
	resultsRoot := filepath.Join(tmp, "results")

	writeFixture(t, runDir, "normalized/subdomains.txt", strings.Join([]string{
		"app.example.com",
		"api.example.com",
		"api.example.com",
		"evil-example.com",
		"example.com.attacker.net",
	}, "\n")+"\n")
	writeFixture(t, runDir, "normalized/resolved-hosts.txt", "app.example.com\napi.example.com\napi.example.com\nnotexample.com\n")
	writeFixture(t, runDir, "normalized/resolved.txt", "api.example.com [A] [2.2.2.2]\napp.example.com [CNAME] [proxy.example.net]\n")
	writeFixture(t, runDir, "normalized/dns-records.tsv", "type\tname\tvalue\nA\texample.com\t1.2.3.4\nMX\texample.com\tmail.example.com\nA\texample.com.attacker.net\t5.6.7.8\n")
	writeFixture(t, runDir, "normalized/whois.tsv", "key\tvalue\nregistrar\tExample Registrar\ncreated\t2026-08-27T12:00:00Z\n")
	writeFixture(t, runDir, "raw/whois.txt", "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n")
	writeFixture(t, runDir, "normalized/live-hosts.txt", "https://api.example.com [301,200] [18420] [application/json] [API] [nginx,Go]\nhttps://evil-example.com [200] [1] [text/html] [Bad] [Apache]\n")
	writeFixture(t, runDir, "normalized/open-ports.tsv", "host\tport\tservice\tsource\napi.example.com\t443\thttps\tnaabu,nmap\napi.example.com\t70000\tbad\tnaabu\nexample.com.attacker.net\t443\thttps\tnaabu\n")
	writeFixture(t, runDir, "normalized/urls.txt", "https://api.example.com/users?id=1#frag\nhttps://api.example.com/users?id=1\nhttps://dashboard.example.com/\nhttps://example.com/login?redirect=/home\nhttps://example.com.attacker.net/pwn?id=1\n")
	writeFixture(t, runDir, "normalized/parameters.tsv", "name\turl\tsource\nid\thttps://api.example.com/users?id=\turl\nredirect\thttps://example.com/login?redirect=\turl\nbad name\thttps://api.example.com\turl\n")
	writeFixture(t, runDir, "normalized/js-files.txt", "https://example.com/assets/app.js\nhttps://example.com/assets/app.js\nhttps://example.com.attacker.net/app.js\n")
	writeFixture(t, runDir, "normalized/js-endpoints.txt", "/api/v1/users\nhttps://api.example.com/v1/orders\nhttps://example.com.attacker.net/v1/orders\nnot-a-route\n")
	writeFixture(t, runDir, "normalized/js-interesting-lines.txt", "raw/js/app.js:1:fetch('/api/v1/users')\n")

	summary, err := Export(Options{
		RunDir:      runDir,
		Target:      "example.com",
		ResultsRoot: resultsRoot,
		Duration:    2 * time.Second,
		CompletedAt: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	resultDir := filepath.Join(resultsRoot, "example.com")
	for _, name := range requiredFiles() {
		if _, err := os.Stat(filepath.Join(resultDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}

	assertLines(t, filepath.Join(resultDir, "subdomains.txt"), []string{"api.example.com", "app.example.com", "dashboard.example.com", "example.com"})
	assertLines(t, filepath.Join(resultDir, "resolved.txt"), []string{"api.example.com", "app.example.com", "example.com"})
	assertLines(t, filepath.Join(resultDir, "live.txt"), []string{"https://api.example.com"})
	assertLines(t, filepath.Join(resultDir, "ips.txt"), []string{"1.2.3.4", "2.2.2.2"})
	assertLines(t, filepath.Join(resultDir, "ports.txt"), []string{"api.example.com:443\thttps"})
	assertLines(t, filepath.Join(resultDir, "urls.txt"), []string{
		"https://api.example.com",
		"https://api.example.com/users?id=1",
		"https://dashboard.example.com/",
		"https://example.com/login?redirect=/home",
	})
	assertLines(t, filepath.Join(resultDir, "parameters.txt"), []string{"id", "redirect"})
	assertLines(t, filepath.Join(resultDir, "javascript.txt"), []string{"https://example.com/assets/app.js"})
	assertLines(t, filepath.Join(resultDir, "endpoints.txt"), []string{"/api/v1/users", "https://api.example.com/v1/orders"})
	reconText := readText(t, filepath.Join(resultDir, "recon.txt"))
	for _, want := range []string{
		"PEYDA RECON REPORT",
		"[WHOIS] [registrar] Example Registrar",
		"[DNS] [A] example.com -> 1.2.3.4",
		"[HTTP] [200] [Go,nginx] https://api.example.com | API",
		"[PORT] [443/https] api.example.com | source=naabu,nmap",
		"[PARAM] [id] https://api.example.com/users?id= | source=url",
		"[JS-ENDPOINT] [api,relative,user] /api/v1/users",
	} {
		if !strings.Contains(reconText, want) {
			t.Fatalf("recon.txt missing %q:\n%s", want, reconText)
		}
	}

	if summary.Subdomains != countLines(t, filepath.Join(resultDir, "subdomains.txt")) ||
		summary.Resolved != countLines(t, filepath.Join(resultDir, "resolved.txt")) ||
		summary.LiveHosts != countLines(t, filepath.Join(resultDir, "live.txt")) ||
		summary.IPs != countLines(t, filepath.Join(resultDir, "ips.txt")) ||
		summary.OpenPorts != countLines(t, filepath.Join(resultDir, "ports.txt")) ||
		summary.URLs != countLines(t, filepath.Join(resultDir, "urls.txt")) ||
		summary.Parameters != countLines(t, filepath.Join(resultDir, "parameters.txt")) ||
		summary.JavaScriptFiles != countLines(t, filepath.Join(resultDir, "javascript.txt")) ||
		summary.Endpoints != countLines(t, filepath.Join(resultDir, "endpoints.txt")) {
		t.Fatalf("summary does not match exported files: %+v", summary)
	}

	var dns []DNSAsset
	readJSON(t, filepath.Join(resultDir, "dns.json"), &dns)
	if len(dns) != 3 || dns[1].Host != "app.example.com" || !reflect.DeepEqual(dns[2].A, []string{"1.2.3.4"}) {
		t.Fatalf("dns.json = %+v", dns)
	}

	var httpAssets []HTTPAsset
	readJSON(t, filepath.Join(resultDir, "http.json"), &httpAssets)
	if len(httpAssets) != 1 ||
		httpAssets[0].Host != "api.example.com" ||
		httpAssets[0].Status != 200 ||
		httpAssets[0].Title != "API" ||
		httpAssets[0].ContentType != "application/json" {
		t.Fatalf("http.json = %+v", httpAssets)
	}

	var technologies []TechnologyAsset
	readJSON(t, filepath.Join(resultDir, "technologies.json"), &technologies)
	if len(technologies) != 1 || !reflect.DeepEqual(technologies[0].Technologies, []string{"Go", "nginx"}) {
		t.Fatalf("technologies.json = %+v", technologies)
	}

	var summaryJSON Summary
	readJSON(t, filepath.Join(resultDir, "summary.json"), &summaryJSON)
	if summaryJSON.Target != "example.com" || summaryJSON.Parameters != 2 {
		t.Fatalf("summary.json = %+v", summaryJSON)
	}
}

func TestExportCreatesPredictableEmptyDataset(t *testing.T) {
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "runs/example.com/2026-08-27")
	resultsRoot := filepath.Join(tmp, "results")

	summary, err := Export(Options{
		RunDir:      runDir,
		Target:      "example.com",
		ResultsRoot: resultsRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	resultDir := filepath.Join(resultsRoot, "example.com")
	for _, name := range requiredFiles() {
		if _, err := os.Stat(filepath.Join(resultDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	assertLines(t, filepath.Join(resultDir, "parameters.txt"), nil)
	assertLines(t, filepath.Join(resultDir, "javascript.txt"), nil)
	assertLines(t, filepath.Join(resultDir, "endpoints.txt"), nil)

	var dns []DNSAsset
	readJSON(t, filepath.Join(resultDir, "dns.json"), &dns)
	if len(dns) != 0 {
		t.Fatalf("dns.json should be empty: %+v", dns)
	}
	if summary.Subdomains != 1 || summary.Resolved != 0 || summary.Parameters != 0 {
		t.Fatalf("unexpected empty summary: %+v", summary)
	}
}

func TestExportRejectsInvalidTarget(t *testing.T) {
	_, err := Export(Options{Target: "https://bad target", ResultsRoot: t.TempDir()})
	if err == nil {
		t.Fatal("expected invalid target error")
	}
}

func requiredFiles() []string {
	return []string{
		"subdomains.txt",
		"resolved.txt",
		"live.txt",
		"ips.txt",
		"ports.txt",
		"urls.txt",
		"parameters.txt",
		"javascript.txt",
		"endpoints.txt",
		"recon.txt",
		"dns.json",
		"http.json",
		"ports.json",
		"technologies.json",
		"summary.json",
	}
}

func writeFixture(t *testing.T, runDir, rel, content string) {
	t.Helper()
	path := filepath.Join(runDir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertLines(t *testing.T, path string, want []string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(data), "\n")
	var got []string
	if text != "" {
		got = strings.Split(text, "\n")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %#v, want %#v", filepath.Base(path), got, want)
	}
	if len(want) > 0 && !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("%s does not end with newline", path)
	}
}

func readJSON(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("invalid JSON %s: %v", filepath.Base(path), err)
	}
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return 0
	}
	return len(strings.Split(text, "\n"))
}
