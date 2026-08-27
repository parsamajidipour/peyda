package report

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/dataset"
)

type Event struct {
	Type      string            `json:"type"`
	Value     string            `json:"value"`
	Source    string            `json:"source"`
	Timestamp string            `json:"timestamp"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type OutputRecord struct {
	Type       string   `json:"type"`
	Host       string   `json:"host,omitempty"`
	URL        string   `json:"url,omitempty"`
	Status     int      `json:"status,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	RecordType string   `json:"record_type,omitempty"`
	Value      string   `json:"value,omitempty"`
	Name       string   `json:"name,omitempty"`
	Port       int      `json:"port,omitempty"`
	Service    string   `json:"service,omitempty"`
	Source     string   `json:"source,omitempty"`
	Endpoint   string   `json:"endpoint,omitempty"`
}

type OutputSummary struct {
	Subdomains  int     `json:"subdomains"`
	LiveHosts   int     `json:"live_hosts"`
	IPs         int     `json:"ips"`
	OpenPorts   int     `json:"open_ports"`
	URLs        int     `json:"urls"`
	Parameters  int     `json:"parameters"`
	JavaScript  int     `json:"javascript"`
	JSEndpoints int     `json:"js_endpoints"`
	DurationSec float64 `json:"duration_sec"`
}

func WriteCLIOutput(out io.Writer, runDir string, cfg config.Config, duration time.Duration) error {
	if out == nil {
		out = io.Discard
	}
	content, err := RenderCLIOutput(runDir, cfg, duration)
	if err != nil {
		return err
	}
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, []byte(content), 0o644); err != nil {
			return err
		}
	}
	_, err = io.WriteString(out, content)
	return err
}

func WriteDatasetSummary(out io.Writer, cfg config.Config, summary dataset.Summary) error {
	return WriteDatasetOutput(out, cfg, summary)
}

func WriteDatasetOutput(out io.Writer, cfg config.Config, summary dataset.Summary) error {
	if out == nil {
		out = io.Discard
	}
	content, err := RenderDatasetOutput(cfg, summary)
	if err != nil {
		return err
	}
	if cfg.OutputFile != "" {
		if err := os.WriteFile(cfg.OutputFile, []byte(content), 0o644); err != nil {
			return err
		}
	}
	_, err = io.WriteString(out, content)
	return err
}

func RenderDatasetOutput(cfg config.Config, summary dataset.Summary) (string, error) {
	switch cfg.OutputFormat {
	case "json":
		return renderDatasetJSON(summary)
	case "jsonl":
		return renderDatasetJSONL(summary)
	default:
		return RenderDatasetSummary(summary, cfg.Silent), nil
	}
}

func RenderDatasetSummary(summary dataset.Summary, silent bool) string {
	output := displayPath(summary.ResultDir)
	if silent {
		if output == "" {
			return ""
		}
		return output + "\n"
	}

	var b strings.Builder
	fmt.Fprintln(&b, "PEYDA")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Target: %s\n\n", summary.Target)
	fmt.Fprintf(&b, "%-16s %d\n", "Subdomains", summary.Subdomains)
	fmt.Fprintf(&b, "%-16s %d\n", "Resolved", summary.Resolved)
	fmt.Fprintf(&b, "%-16s %d\n", "Live hosts", summary.LiveHosts)
	fmt.Fprintf(&b, "%-16s %d\n", "URLs", summary.URLs)
	fmt.Fprintf(&b, "%-16s %d\n", "Parameters", summary.Parameters)
	fmt.Fprintf(&b, "%-16s %d\n", "JavaScript", summary.JavaScriptFiles)
	fmt.Fprintf(&b, "%-16s %d\n\n", "Endpoints", summary.Endpoints)
	fmt.Fprintf(&b, "Output: %s\n", output)
	fmt.Fprintf(&b, "Duration: %s\n", formatDuration(time.Duration(summary.DurationSeconds*float64(time.Second))))
	return b.String()
}

func renderDatasetJSON(summary dataset.Summary) (string, error) {
	results, err := readDatasetResults(summary.ResultDir)
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"summary": summary,
		"results": results,
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func renderDatasetJSONL(summary dataset.Summary) (string, error) {
	results, err := readDatasetResults(summary.ResultDir)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, host := range results.Subdomains {
		if err := enc.Encode(OutputRecord{Type: "subdomain", Host: host}); err != nil {
			return "", err
		}
	}
	for _, host := range results.Resolved {
		if err := enc.Encode(OutputRecord{Type: "resolved", Host: host}); err != nil {
			return "", err
		}
	}
	for _, item := range results.Live {
		if err := enc.Encode(OutputRecord{Type: "http", Host: hostFromURL(item), URL: item}); err != nil {
			return "", err
		}
	}
	for _, item := range results.URLs {
		if err := enc.Encode(OutputRecord{Type: "url", URL: item}); err != nil {
			return "", err
		}
	}
	for _, name := range results.Parameters {
		if err := enc.Encode(OutputRecord{Type: "parameter", Name: name}); err != nil {
			return "", err
		}
	}
	for _, item := range results.JavaScript {
		if err := enc.Encode(OutputRecord{Type: "javascript", URL: item}); err != nil {
			return "", err
		}
	}
	for _, endpoint := range results.Endpoints {
		if err := enc.Encode(OutputRecord{Type: "js_endpoint", Endpoint: endpoint}); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

type datasetResults struct {
	Subdomains   []string `json:"subdomains"`
	Resolved     []string `json:"resolved"`
	Live         []string `json:"live"`
	URLs         []string `json:"urls"`
	Parameters   []string `json:"parameters"`
	JavaScript   []string `json:"javascript"`
	Endpoints    []string `json:"endpoints"`
	DNS          any      `json:"dns"`
	HTTP         any      `json:"http"`
	Technologies any      `json:"technologies"`
}

func readDatasetResults(resultDir string) (datasetResults, error) {
	var results datasetResults
	results.Subdomains = nonNilStrings(readLines(filepath.Join(resultDir, "subdomains.txt")))
	results.Resolved = nonNilStrings(readLines(filepath.Join(resultDir, "resolved.txt")))
	results.Live = nonNilStrings(readLines(filepath.Join(resultDir, "live.txt")))
	results.URLs = nonNilStrings(readLines(filepath.Join(resultDir, "urls.txt")))
	results.Parameters = nonNilStrings(readLines(filepath.Join(resultDir, "parameters.txt")))
	results.JavaScript = nonNilStrings(readLines(filepath.Join(resultDir, "javascript.txt")))
	results.Endpoints = nonNilStrings(readLines(filepath.Join(resultDir, "endpoints.txt")))
	results.DNS = readJSONAny(filepath.Join(resultDir, "dns.json"))
	results.HTTP = readJSONAny(filepath.Join(resultDir, "http.json"))
	results.Technologies = readJSONAny(filepath.Join(resultDir, "technologies.json"))
	return results, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func readJSONAny(path string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return []any{}
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return []any{}
	}
	return out
}

func displayPath(path string) string {
	if path == "" {
		return ""
	}
	cwd, err := os.Getwd()
	if err != nil {
		return withTrailingSlash(filepath.ToSlash(path))
	}
	rel, err := filepath.Rel(cwd, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return withTrailingSlash(filepath.ToSlash(path))
	}
	if rel == "." {
		return "."
	}
	return withTrailingSlash(filepath.ToSlash(rel))
}

func withTrailingSlash(path string) string {
	if path == "" || strings.HasSuffix(path, "/") {
		return path
	}
	return path + "/"
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func RenderCLIOutput(runDir string, cfg config.Config, duration time.Duration) (string, error) {
	records := CollectOutputRecords(runDir)
	summary := BuildOutputSummary(runDir, duration)
	switch cfg.OutputFormat {
	case "json":
		body := map[string]any{
			"target":    cfg.Target,
			"run_dir":   runDir,
			"summary":   summary,
			"results":   records,
			"generated": time.Now().UTC().Format(time.RFC3339),
		}
		data, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return "", err
		}
		return string(data) + "\n", nil
	case "jsonl":
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		for _, record := range records {
			if err := enc.Encode(record); err != nil {
				return "", err
			}
		}
		return b.String(), nil
	default:
		return renderHuman(records, summary, cfg.Silent), nil
	}
}

func CollectOutputRecords(runDir string) []OutputRecord {
	var records []OutputRecord

	for _, row := range readTSV(filepath.Join(runDir, "normalized/whois.tsv")) {
		if row["key"] != "" && row["value"] != "" {
			records = append(records, OutputRecord{Type: "whois", Name: row["key"], Value: row["value"]})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/dns-records.tsv")) {
		if row["type"] != "" && row["value"] != "" {
			records = append(records, OutputRecord{Type: "dns", Host: row["name"], RecordType: row["type"], Value: row["value"]})
		}
	}
	for _, host := range readLines(filepath.Join(runDir, "normalized/subdomains.txt")) {
		records = append(records, OutputRecord{Type: "subdomain", Host: host})
	}
	for _, line := range readLines(filepath.Join(runDir, "normalized/live-hosts.txt")) {
		fields := parseHTTPXLine(line)
		if fields["url"] == "" {
			continue
		}
		status, _ := strconv.Atoi(fields["status"])
		records = append(records, OutputRecord{
			Type:   "http",
			Host:   hostFromURL(fields["url"]),
			URL:    fields["url"],
			Status: status,
			Tech:   splitTech(fields["technology"]),
		})
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/open-ports.tsv")) {
		port, _ := strconv.Atoi(row["port"])
		if row["host"] != "" && port > 0 {
			records = append(records, OutputRecord{Type: "port", Host: row["host"], Port: port, Service: row["service"], Source: row["source"]})
		}
	}
	for _, item := range readLines(filepath.Join(runDir, "normalized/urls.txt")) {
		records = append(records, OutputRecord{Type: "url", URL: item})
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/parameters.tsv")) {
		if row["name"] != "" {
			records = append(records, OutputRecord{Type: "parameter", Name: row["name"], URL: row["url"], Source: row["source"]})
		}
	}
	for _, item := range readLines(filepath.Join(runDir, "normalized/js-files.txt")) {
		records = append(records, OutputRecord{Type: "javascript", URL: item})
	}
	for _, item := range readLines(filepath.Join(runDir, "normalized/js-endpoints.txt")) {
		records = append(records, OutputRecord{Type: "js_endpoint", Endpoint: item})
	}
	return records
}

func BuildOutputSummary(runDir string, duration time.Duration) OutputSummary {
	return OutputSummary{
		Subdomains:  countLines(filepath.Join(runDir, "normalized/subdomains.txt")),
		LiveHosts:   countLines(filepath.Join(runDir, "normalized/live-hosts.txt")),
		IPs:         countIPs(runDir),
		OpenPorts:   len(dataLines(filepath.Join(runDir, "normalized/open-ports.tsv"))),
		URLs:        countLines(filepath.Join(runDir, "normalized/urls.txt")),
		Parameters:  len(dataLines(filepath.Join(runDir, "normalized/parameters.tsv"))),
		JavaScript:  countLines(filepath.Join(runDir, "normalized/js-files.txt")),
		JSEndpoints: countLines(filepath.Join(runDir, "normalized/js-endpoints.txt")),
		DurationSec: duration.Seconds(),
	}
}

func renderHuman(records []OutputRecord, summary OutputSummary, silent bool) string {
	var b strings.Builder
	for _, record := range records {
		switch record.Type {
		case "whois":
			fmt.Fprintf(&b, "[WHOIS] [%s] %s\n", record.Name, record.Value)
		case "dns":
			fmt.Fprintf(&b, "[DNS] [%s] %s -> %s\n", record.RecordType, record.Host, record.Value)
		case "subdomain":
			fmt.Fprintf(&b, "[SUB] %s\n", record.Host)
		case "http":
			fmt.Fprintf(&b, "[HTTP] [%d] [%s] %s\n", record.Status, strings.Join(record.Tech, ","), record.URL)
		case "port":
			fmt.Fprintf(&b, "[PORT] [%d/%s] %s\n", record.Port, record.Service, record.Host)
		case "url":
			fmt.Fprintf(&b, "[URL] %s\n", record.URL)
		case "parameter":
			fmt.Fprintf(&b, "[PARAM] [%s] %s\n", record.Name, record.URL)
		case "javascript":
			fmt.Fprintf(&b, "[JS] %s\n", record.URL)
		case "js_endpoint":
			fmt.Fprintf(&b, "[JS-ENDPOINT] %s\n", record.Endpoint)
		}
	}
	if silent {
		return b.String()
	}
	fmt.Fprintf(&b, "\n%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(&b, "Scan completed in %.1fs\n\n", summary.DurationSec)
	fmt.Fprintf(&b, "%-16s %d\n", "Subdomains", summary.Subdomains)
	fmt.Fprintf(&b, "%-16s %d\n", "Live Hosts", summary.LiveHosts)
	fmt.Fprintf(&b, "%-16s %d\n", "IPs", summary.IPs)
	fmt.Fprintf(&b, "%-16s %d\n", "Open Ports", summary.OpenPorts)
	fmt.Fprintf(&b, "%-16s %d\n", "URLs", summary.URLs)
	fmt.Fprintf(&b, "%-16s %d\n", "Parameters", summary.Parameters)
	fmt.Fprintf(&b, "%-16s %d\n", "JavaScript", summary.JavaScript)
	fmt.Fprintf(&b, "%-16s %d\n", "JS Endpoints", summary.JSEndpoints)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 40))
	return b.String()
}

func countIPs(runDir string) int {
	seen := map[string]struct{}{}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/dns-records.tsv")) {
		if row["type"] == "A" || row["type"] == "AAAA" {
			seen[row["value"]] = struct{}{}
		}
	}
	ipPattern := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	for _, line := range readLines(filepath.Join(runDir, "normalized/resolved.txt")) {
		for _, match := range ipPattern.FindAllString(line, -1) {
			seen[match] = struct{}{}
		}
	}
	return len(seen)
}

func hostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func splitTech(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func WriteJSONL(runDir string) error {
	output := filepath.Join(runDir, "normalized/recon-events.jsonl")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	for _, event := range collectEvents(runDir) {
		if err := enc.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func WriteMarkdown(runDir string, cfg config.Config) error {
	output := filepath.Join(runDir, "notes/recon-summary.md")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Recon Summary\n\n")
	fmt.Fprintf(&b, "Generated: `%s`\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Run folder:\n\n```text\n%s\n```\n\n", runDir)
	fmt.Fprintf(&b, "## Run Settings\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Target | `%s` |\n", cfg.Target)
	fmt.Fprintf(&b, "| Probe rate | `%d` |\n", cfg.ProbeRate)
	fmt.Fprintf(&b, "| Crawl rate | `%d` |\n", cfg.CrawlRate)
	fmt.Fprintf(&b, "| Crawl depth | `%d` |\n", cfg.CrawlDepth)
	fmt.Fprintf(&b, "| Crawl duration | `%s` |\n", cfg.CrawlDuration)
	fmt.Fprintf(&b, "| Max domain pages | `%d` |\n", cfg.MaxDomainPages)
	fmt.Fprintf(&b, "| API probe rate | `%d` |\n\n", cfg.APIRate)

	fmt.Fprintf(&b, "## Tool Settings\n\n")
	fmt.Fprintf(&b, "| Tool | Settings |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| subfinder | `all=%t recursive=%t timeout=%d max_time=%d` |\n", cfg.Tools.Subfinder.All, cfg.Tools.Subfinder.Recursive, cfg.Tools.Subfinder.Timeout, cfg.Tools.Subfinder.MaxTime)
	fmt.Fprintf(&b, "| dnsx | `record_types=%s response=%t recon=%t trace=%t` |\n", strings.Join(cfg.Tools.DNSX.RecordTypes, ","), cfg.Tools.DNSX.Response, cfg.Tools.DNSX.Recon, cfg.Tools.DNSX.Trace)
	fmt.Fprintf(&b, "| httpx | `redirects=%t title=%t status=%t length=%t type=%t tech=%t server=%t ip=%t cname=%t asn=%t cdn=%t rt=%t http2=%t pipeline=%t tls_probe=%t tls_grab=%t all_ips=%t retries=%d timeout=%d` |\n",
		cfg.Tools.HTTPX.FollowRedirects,
		cfg.Tools.HTTPX.Title,
		cfg.Tools.HTTPX.StatusCode,
		cfg.Tools.HTTPX.ContentLength,
		cfg.Tools.HTTPX.ContentType,
		cfg.Tools.HTTPX.TechDetect,
		cfg.Tools.HTTPX.WebServer,
		cfg.Tools.HTTPX.IP,
		cfg.Tools.HTTPX.CNAME,
		cfg.Tools.HTTPX.ASN,
		cfg.Tools.HTTPX.CDN,
		cfg.Tools.HTTPX.ResponseTime,
		cfg.Tools.HTTPX.HTTP2,
		cfg.Tools.HTTPX.Pipeline,
		cfg.Tools.HTTPX.TLSProbe,
		cfg.Tools.HTTPX.TLSGrab,
		cfg.Tools.HTTPX.ProbeAllIPs,
		cfg.Tools.HTTPX.Retries,
		cfg.Tools.HTTPX.Timeout,
	)
	fmt.Fprintf(&b, "| katana | `js=%t jsluice=%t iqp=%t fsu=%t known_files=%q field_scope=%q strategy=%q headless=%t xhr=%t forms=%t tech=%t path_climb=%t kb=%t c=%d p=%d hrl=%d display_out_scope=%t` |\n\n",
		cfg.Tools.Katana.JSCrawl,
		cfg.Tools.Katana.JSLuice,
		cfg.Tools.Katana.IgnoreQueryParams,
		cfg.Tools.Katana.FilterSimilar,
		cfg.Tools.Katana.KnownFiles,
		cfg.Tools.Katana.FieldScope,
		cfg.Tools.Katana.Strategy,
		cfg.Tools.Katana.Headless,
		cfg.Tools.Katana.XHRExtraction,
		cfg.Tools.Katana.FormExtraction,
		cfg.Tools.Katana.TechDetect,
		cfg.Tools.Katana.PathClimb,
		cfg.Tools.Katana.KnowledgeBase,
		cfg.Tools.Katana.Concurrency,
		cfg.Tools.Katana.Parallelism,
		cfg.Tools.Katana.HostRateLimit,
		cfg.Tools.Katana.DisplayOutScope,
	)

	counts := map[string]int{
		"WHOIS fields":              max(0, countLines(filepath.Join(runDir, "normalized/whois.tsv"))-1),
		"DNS records":               max(0, countLines(filepath.Join(runDir, "normalized/dns-records.tsv"))-1),
		"In-scope subdomains":       countLines(filepath.Join(runDir, "normalized/subdomains.txt")),
		"Resolved hosts":            countLines(filepath.Join(runDir, "normalized/resolved-hosts.txt")),
		"Live HTTP/S services":      countLines(filepath.Join(runDir, "normalized/live-hosts.txt")),
		"IPs":                       countIPs(runDir),
		"Open ports":                len(dataLines(filepath.Join(runDir, "normalized/open-ports.tsv"))),
		"URLs":                      countLines(filepath.Join(runDir, "normalized/urls.txt")),
		"Parameters":                len(dataLines(filepath.Join(runDir, "normalized/parameters.tsv"))),
		"Interesting hosts":         countLines(filepath.Join(runDir, "notes/interesting-hosts.txt")),
		"Scored assets":             max(0, countLines(filepath.Join(runDir, "normalized/asset-scores.tsv"))-1),
		"API docs/schema probes":    countLines(filepath.Join(runDir, "normalized/api-docs-probed.txt")),
		"OpenAPI method/path pairs": countLines(filepath.Join(runDir, "normalized/openapi-methods.tsv")),
		"Cloud/secret candidates":   max(0, countLines(filepath.Join(runDir, "notes/cloud-candidates.tsv"))-1),
		"JavaScript route leads":    countLines(filepath.Join(runDir, "normalized/js-route-leads.txt")),
		"JavaScript endpoints":      countLines(filepath.Join(runDir, "normalized/js-endpoints.txt")),
		"Source map candidates":     countLines(filepath.Join(runDir, "normalized/source-map-candidates.txt")),
		"JSONL events":              countLines(filepath.Join(runDir, "normalized/recon-events.jsonl")),
	}

	fmt.Fprintf(&b, "## Counts\n\n| Artifact | Count |\n| --- | ---: |\n")
	for _, key := range []string{"WHOIS fields", "DNS records", "In-scope subdomains", "Resolved hosts", "Live HTTP/S services", "IPs", "Open ports", "URLs", "Parameters", "Interesting hosts", "Scored assets", "JavaScript route leads", "JavaScript endpoints", "Source map candidates", "API docs/schema probes", "OpenAPI method/path pairs", "Cloud/secret candidates", "JSONL events"} {
		fmt.Fprintf(&b, "| %s | %d |\n", key, counts[key])
	}
	fmt.Fprintf(&b, "\n")

	addTopSection(&b, "High-Signal Review Queue", filepath.Join(runDir, "notes/interesting-hosts.txt"), 20)
	addTopSection(&b, "Open Ports", filepath.Join(runDir, "normalized/open-ports.tsv"), 25)
	addTopSection(&b, "URLs", filepath.Join(runDir, "normalized/urls.txt"), 25)
	addTopSection(&b, "Parameters", filepath.Join(runDir, "normalized/parameters.tsv"), 25)
	addTopSection(&b, "Top Asset Scores", filepath.Join(runDir, "normalized/asset-scores.tsv"), 25)
	addTopSection(&b, "JavaScript Leads", filepath.Join(runDir, "notes/js-leads.tsv"), 25)
	addTopSection(&b, "JavaScript Endpoints", filepath.Join(runDir, "normalized/js-endpoints.txt"), 25)
	addTopSection(&b, "API Inventory", filepath.Join(runDir, "normalized/api-inventory.tsv"), 25)
	addTopSection(&b, "Cloud Candidates", filepath.Join(runDir, "notes/cloud-candidates.tsv"), 20)
	addTopSection(&b, "Wildcard DNS Check", filepath.Join(runDir, "notes/wildcard-dns-check.txt"), 10)

	fmt.Fprintf(&b, "## Next Actions\n\n")
	fmt.Fprintf(&b, "- Confirm scope and ownership before vulnerability testing.\n")
	fmt.Fprintf(&b, "- Review staging, admin, upload, API, billing, webhook, and cloud leads first.\n")
	fmt.Fprintf(&b, "- Treat JSONL events as automation input and Markdown as human review notes.\n")
	fmt.Fprintf(&b, "- Convert only validated impact into a vulnerability report.\n")

	return os.WriteFile(output, []byte(b.String()), 0o644)
}

func WriteText(runDir string, cfg config.Config) error {
	output := filepath.Join(runDir, "notes/recon-report.txt")
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "PEYDA REPORT\n")
	fmt.Fprintf(&b, "=============\n\n")
	fmt.Fprintf(&b, "Generated UTC : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Target        : %s\n", cfg.Target)
	fmt.Fprintf(&b, "Run folder    : %s\n\n", runDir)

	fmt.Fprintf(&b, "RUN SETTINGS\n")
	fmt.Fprintf(&b, "------------\n")
	fmt.Fprintf(&b, "Probe rate       : %d\n", cfg.ProbeRate)
	fmt.Fprintf(&b, "Crawl rate       : %d\n", cfg.CrawlRate)
	fmt.Fprintf(&b, "Crawl depth      : %d\n", cfg.CrawlDepth)
	fmt.Fprintf(&b, "Crawl duration   : %s\n", cfg.CrawlDuration)
	fmt.Fprintf(&b, "Max domain pages : %d\n", cfg.MaxDomainPages)
	fmt.Fprintf(&b, "API probe rate   : %d\n\n", cfg.APIRate)

	writeToolConfig(&b, cfg.Tools)
	writeCounts(&b, runDir)
	writePlainSection(&b, "WHOIS", "These WHOIS fields were extracted:", dataLines(filepath.Join(runDir, "normalized/whois.tsv")))
	writePlainSection(&b, "DNS RECORDS", "These DNS records were resolved:", dataLines(filepath.Join(runDir, "normalized/dns-records.tsv")))
	writePlainSection(&b, "SUBDOMAINS", "These subdomains were found:", readLines(filepath.Join(runDir, "normalized/subdomains.txt")))
	writePlainSection(&b, "RESOLVED HOSTS", "These hosts resolved successfully:", readLines(filepath.Join(runDir, "normalized/resolved-hosts.txt")))
	writePlainSection(&b, "LIVE HTTP/S SERVICES", "These HTTP/S services responded:", readLines(filepath.Join(runDir, "normalized/live-hosts.txt")))
	writePlainSection(&b, "OPEN PORTS", "These open ports were discovered:", dataLines(filepath.Join(runDir, "normalized/open-ports.tsv")))
	writePlainSection(&b, "URLS", "These URLs were collected from historical sources and crawling:", readLines(filepath.Join(runDir, "normalized/urls.txt")))
	writePlainSection(&b, "PARAMETERS", "These parameters were discovered from URLs or parameter probing:", dataLines(filepath.Join(runDir, "normalized/parameters.tsv")))
	writePlainSection(&b, "HIGH-SIGNAL REVIEW QUEUE", "Review these first:", readLines(filepath.Join(runDir, "notes/interesting-hosts.txt")))
	writePlainSection(&b, "JAVASCRIPT FILES", "These JavaScript files were discovered:", readLines(filepath.Join(runDir, "normalized/js-files.txt")))
	writePlainSection(&b, "JAVASCRIPT ROUTE LEADS", "These route leads were extracted from crawl/JavaScript data:", dataLines(filepath.Join(runDir, "notes/js-leads.tsv")))
	writePlainSection(&b, "JAVASCRIPT ENDPOINTS", "These endpoints were extracted from JavaScript:", readLines(filepath.Join(runDir, "normalized/js-endpoints.txt")))
	writePlainSection(&b, "SOURCE MAP CANDIDATES", "These source map candidates were found:", readLines(filepath.Join(runDir, "normalized/source-map-candidates.txt")))
	writePlainSection(&b, "API DOC/SCHEMA PROBES", "These API documentation/schema paths responded:", readLines(filepath.Join(runDir, "normalized/api-docs-probed.txt")))
	writePlainSection(&b, "API INVENTORY", "These API endpoints were parsed from schemas:", dataLines(filepath.Join(runDir, "normalized/api-inventory.tsv")))
	writePlainSection(&b, "CLOUD CANDIDATES", "These cloud or secret-looking leads were found:", dataLines(filepath.Join(runDir, "notes/cloud-candidates.tsv")))

	fmt.Fprintf(&b, "NEXT ACTIONS\n")
	fmt.Fprintf(&b, "------------\n")
	fmt.Fprintf(&b, "1. Confirm scope and ownership before vulnerability testing.\n")
	fmt.Fprintf(&b, "2. Review staging, admin, upload, API, billing, webhook, and cloud leads first.\n")
	fmt.Fprintf(&b, "3. Use JSONL for automation and this text report for quick human review.\n")
	fmt.Fprintf(&b, "4. Convert only validated impact into a vulnerability report.\n")

	return os.WriteFile(output, []byte(b.String()), 0o644)
}

func collectEvents(runDir string) []Event {
	now := time.Now().UTC().Format(time.RFC3339)
	var events []Event
	addLineEvents := func(path, typ, source string) {
		for _, line := range readLines(path) {
			events = append(events, Event{Type: typ, Value: line, Source: source, Timestamp: now})
		}
	}

	addLineEvents(filepath.Join(runDir, "normalized/subdomains.txt"), "subdomain", "normalized/subdomains.txt")
	addLineEvents(filepath.Join(runDir, "normalized/resolved-hosts.txt"), "resolved_host", "normalized/resolved-hosts.txt")
	addLineEvents(filepath.Join(runDir, "notes/interesting-hosts.txt"), "interesting_host", "notes/interesting-hosts.txt")
	addLineEvents(filepath.Join(runDir, "normalized/urls.txt"), "url", "normalized/urls.txt")
	addLineEvents(filepath.Join(runDir, "normalized/js-files.txt"), "javascript", "normalized/js-files.txt")
	addLineEvents(filepath.Join(runDir, "normalized/js-endpoints.txt"), "js_endpoint", "normalized/js-endpoints.txt")

	for _, line := range readLines(filepath.Join(runDir, "normalized/live-hosts.txt")) {
		fields := parseHTTPXLine(line)
		events = append(events, Event{Type: "live_service", Value: fields["url"], Source: "normalized/live-hosts.txt", Timestamp: now, Fields: fields})
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/whois.tsv")) {
		value := row["value"]
		if value != "" {
			events = append(events, Event{Type: "whois", Value: value, Source: "normalized/whois.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/dns-records.tsv")) {
		value := strings.TrimSpace(row["type"] + " " + row["name"] + " " + row["value"])
		if value != "" {
			events = append(events, Event{Type: "dns", Value: value, Source: "normalized/dns-records.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/open-ports.tsv")) {
		value := strings.TrimSpace(row["host"] + ":" + row["port"])
		if value != ":" {
			events = append(events, Event{Type: "port", Value: value, Source: "normalized/open-ports.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/parameters.tsv")) {
		value := row["name"]
		if value != "" {
			events = append(events, Event{Type: "parameter", Value: value, Source: "normalized/parameters.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/asset-scores.tsv")) {
		value := row["url"]
		if value != "" {
			events = append(events, Event{Type: "asset_score", Value: value, Source: "normalized/asset-scores.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/api-inventory.tsv")) {
		value := strings.TrimSpace(row["method"] + " " + row["host"] + row["path"])
		if value != "" {
			events = append(events, Event{Type: "api_endpoint", Value: value, Source: "normalized/api-inventory.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "notes/js-leads.tsv")) {
		value := row["route"]
		if value != "" {
			events = append(events, Event{Type: "js_route", Value: value, Source: "notes/js-leads.tsv", Timestamp: now, Fields: row})
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "notes/cloud-candidates.tsv")) {
		value := row["asset_or_string"]
		if value != "" {
			events = append(events, Event{Type: "cloud_candidate", Value: value, Source: "notes/cloud-candidates.tsv", Timestamp: now, Fields: row})
		}
	}
	return events
}

func parseHTTPXLine(line string) map[string]string {
	fields := map[string]string{"raw": line}
	parts := strings.Fields(line)
	if len(parts) > 0 {
		fields["url"] = parts[0]
	}
	brackets := extractBrackets(line)
	var remaining []string
	for _, value := range brackets {
		switch {
		case fields["status"] == "" && looksLikeStatus(value):
			fields["status"] = value
		case fields["content_length"] == "" && looksLikeInteger(value):
			fields["content_length"] = value
		case fields["content_type"] == "" && strings.Contains(value, "/"):
			fields["content_type"] = value
		default:
			remaining = append(remaining, value)
		}
	}
	if len(remaining) > 0 {
		fields["title"] = remaining[0]
	}
	if len(remaining) > 1 {
		fields["technology"] = remaining[len(remaining)-1]
	}
	return fields
}

func looksLikeStatus(value string) bool {
	return regexp.MustCompile(`^[0-9]{3}(,[0-9]{3})*$`).MatchString(value)
}

func looksLikeInteger(value string) bool {
	return regexp.MustCompile(`^[0-9]+$`).MatchString(value)
}

func extractBrackets(line string) []string {
	var out []string
	for {
		start := strings.Index(line, "[")
		if start < 0 {
			break
		}
		line = line[start+1:]
		end := strings.Index(line, "]")
		if end < 0 {
			break
		}
		out = append(out, line[:end])
		line = line[end+1:]
	}
	return out
}

func readTSV(path string) []map[string]string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}
	header := records[0]
	var rows []map[string]string
	for _, record := range records[1:] {
		row := map[string]string{}
		for i, key := range header {
			if i < len(record) {
				row[key] = record[i]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func addTopSection(b *strings.Builder, title, path string, limit int) {
	fmt.Fprintf(b, "## %s\n\n", title)
	lines := readLines(path)
	if len(lines) == 0 {
		fmt.Fprintf(b, "No data.\n\n")
		return
	}
	if len(lines) > limit {
		lines = lines[:limit]
	}
	fmt.Fprintf(b, "```text\n%s\n```\n\n", strings.Join(lines, "\n"))
}

func writeCounts(b *strings.Builder, runDir string) {
	counts := []struct {
		name  string
		count int
	}{
		{"Subdomains", countLines(filepath.Join(runDir, "normalized/subdomains.txt"))},
		{"Resolved hosts", countLines(filepath.Join(runDir, "normalized/resolved-hosts.txt"))},
		{"Live HTTP/S services", countLines(filepath.Join(runDir, "normalized/live-hosts.txt"))},
		{"IPs", countIPs(runDir)},
		{"Open ports", len(dataLines(filepath.Join(runDir, "normalized/open-ports.tsv")))},
		{"URLs", countLines(filepath.Join(runDir, "normalized/urls.txt"))},
		{"Parameters", len(dataLines(filepath.Join(runDir, "normalized/parameters.tsv")))},
		{"High-signal hosts", countLines(filepath.Join(runDir, "notes/interesting-hosts.txt"))},
		{"JavaScript files", countLines(filepath.Join(runDir, "normalized/js-files.txt"))},
		{"JavaScript route leads", countLines(filepath.Join(runDir, "normalized/js-route-leads.txt"))},
		{"JavaScript endpoints", countLines(filepath.Join(runDir, "normalized/js-endpoints.txt"))},
		{"API doc/schema probes", countLines(filepath.Join(runDir, "normalized/api-docs-probed.txt"))},
		{"API inventory rows", len(dataLines(filepath.Join(runDir, "normalized/api-inventory.tsv")))},
		{"Cloud candidates", len(dataLines(filepath.Join(runDir, "notes/cloud-candidates.tsv")))},
		{"JSONL events", countLines(filepath.Join(runDir, "normalized/recon-events.jsonl"))},
	}

	fmt.Fprintf(b, "COUNTS\n")
	fmt.Fprintf(b, "------\n")
	for _, item := range counts {
		fmt.Fprintf(b, "%-25s %d\n", item.name+":", item.count)
	}
	fmt.Fprintf(b, "\n")
}

func writeToolConfig(b *strings.Builder, tools config.Tools) {
	fmt.Fprintf(b, "TOOL CONFIGURATION\n")
	fmt.Fprintf(b, "------------------\n")
	fmt.Fprintf(b, "subfinder : all=%t recursive=%t timeout=%d max_time=%d\n", tools.Subfinder.All, tools.Subfinder.Recursive, tools.Subfinder.Timeout, tools.Subfinder.MaxTime)
	fmt.Fprintf(b, "dnsx      : record_types=%s response=%t recon=%t trace=%t\n", strings.Join(tools.DNSX.RecordTypes, ","), tools.DNSX.Response, tools.DNSX.Recon, tools.DNSX.Trace)
	fmt.Fprintf(b, "httpx     : redirects=%t title=%t status=%t length=%t type=%t tech=%t server=%t ip=%t cname=%t asn=%t cdn=%t rt=%t http2=%t pipeline=%t tls_probe=%t tls_grab=%t all_ips=%t retries=%d timeout=%d\n",
		tools.HTTPX.FollowRedirects,
		tools.HTTPX.Title,
		tools.HTTPX.StatusCode,
		tools.HTTPX.ContentLength,
		tools.HTTPX.ContentType,
		tools.HTTPX.TechDetect,
		tools.HTTPX.WebServer,
		tools.HTTPX.IP,
		tools.HTTPX.CNAME,
		tools.HTTPX.ASN,
		tools.HTTPX.CDN,
		tools.HTTPX.ResponseTime,
		tools.HTTPX.HTTP2,
		tools.HTTPX.Pipeline,
		tools.HTTPX.TLSProbe,
		tools.HTTPX.TLSGrab,
		tools.HTTPX.ProbeAllIPs,
		tools.HTTPX.Retries,
		tools.HTTPX.Timeout,
	)
	fmt.Fprintf(b, "katana    : js=%t jsluice=%t iqp=%t fsu=%t known_files=%q field_scope=%q strategy=%q headless=%t xhr=%t forms=%t tech=%t path_climb=%t kb=%t c=%d p=%d hrl=%d display_out_scope=%t\n\n",
		tools.Katana.JSCrawl,
		tools.Katana.JSLuice,
		tools.Katana.IgnoreQueryParams,
		tools.Katana.FilterSimilar,
		tools.Katana.KnownFiles,
		tools.Katana.FieldScope,
		tools.Katana.Strategy,
		tools.Katana.Headless,
		tools.Katana.XHRExtraction,
		tools.Katana.FormExtraction,
		tools.Katana.TechDetect,
		tools.Katana.PathClimb,
		tools.Katana.KnowledgeBase,
		tools.Katana.Concurrency,
		tools.Katana.Parallelism,
		tools.Katana.HostRateLimit,
		tools.Katana.DisplayOutScope,
	)
}

func writePlainSection(b *strings.Builder, title, intro string, lines []string) {
	fmt.Fprintf(b, "%s\n", title)
	fmt.Fprintf(b, "%s\n", strings.Repeat("-", len(title)))
	fmt.Fprintf(b, "%s\n\n", intro)
	if len(lines) == 0 {
		fmt.Fprintf(b, "No data.\n\n")
		return
	}
	for i, line := range lines {
		fmt.Fprintf(b, "%d. %s\n", i+1, line)
	}
	fmt.Fprintf(b, "\n")
}

func dataLines(path string) []string {
	lines := readLines(path)
	if len(lines) <= 1 {
		return nil
	}
	return lines[1:]
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func countLines(path string) int {
	return len(readLines(path))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
