package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/parsamajidipour/reconx/internal/config"
)

type Event struct {
	Type      string            `json:"type"`
	Value     string            `json:"value"`
	Source    string            `json:"source"`
	Timestamp string            `json:"timestamp"`
	Fields    map[string]string `json:"fields,omitempty"`
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
	fmt.Fprintf(&b, "## Run Profile\n\n")
	fmt.Fprintf(&b, "| Field | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Target | `%s` |\n", cfg.Target)
	fmt.Fprintf(&b, "| Profile | `%s` |\n", cfg.Profile)
	fmt.Fprintf(&b, "| Probe rate | `%d` |\n", cfg.ProbeRate)
	fmt.Fprintf(&b, "| Crawl rate | `%d` |\n", cfg.CrawlRate)
	fmt.Fprintf(&b, "| Crawl depth | `%d` |\n", cfg.CrawlDepth)
	fmt.Fprintf(&b, "| Crawl duration | `%s` |\n", cfg.CrawlDuration)
	fmt.Fprintf(&b, "| Max domain pages | `%d` |\n", cfg.MaxDomainPages)
	fmt.Fprintf(&b, "| API probe rate | `%d` |\n\n", cfg.APIRate)

	fmt.Fprintf(&b, "## Tool Settings\n\n")
	fmt.Fprintf(&b, "| Tool | Settings |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| subfinder | `all=%t recursive=%t` |\n", cfg.Tools.Subfinder.All, cfg.Tools.Subfinder.Recursive)
	fmt.Fprintf(&b, "| dnsx | `record_types=%s response=%t` |\n", strings.Join(cfg.Tools.DNSX.RecordTypes, ","), cfg.Tools.DNSX.Response)
	fmt.Fprintf(&b, "| httpx | `redirects=%t title=%t status=%t length=%t type=%t tech=%t` |\n",
		cfg.Tools.HTTPX.FollowRedirects,
		cfg.Tools.HTTPX.Title,
		cfg.Tools.HTTPX.StatusCode,
		cfg.Tools.HTTPX.ContentLength,
		cfg.Tools.HTTPX.ContentType,
		cfg.Tools.HTTPX.TechDetect,
	)
	fmt.Fprintf(&b, "| katana | `js=%t iqp=%t fsu=%t known_files=%q field_scope=%q strategy=%q headless=%t xhr=%t display_out_scope=%t` |\n\n",
		cfg.Tools.Katana.JSCrawl,
		cfg.Tools.Katana.IgnoreQueryParams,
		cfg.Tools.Katana.FilterSimilar,
		cfg.Tools.Katana.KnownFiles,
		cfg.Tools.Katana.FieldScope,
		cfg.Tools.Katana.Strategy,
		cfg.Tools.Katana.Headless,
		cfg.Tools.Katana.XHRExtraction,
		cfg.Tools.Katana.DisplayOutScope,
	)

	counts := map[string]int{
		"In-scope subdomains":       countLines(filepath.Join(runDir, "normalized/subdomains.txt")),
		"Resolved hosts":            countLines(filepath.Join(runDir, "normalized/resolved-hosts.txt")),
		"Live HTTP/S services":      countLines(filepath.Join(runDir, "normalized/live-hosts.txt")),
		"Interesting hosts":         countLines(filepath.Join(runDir, "notes/interesting-hosts.txt")),
		"Scored assets":             max(0, countLines(filepath.Join(runDir, "normalized/asset-scores.tsv"))-1),
		"API docs/schema probes":    countLines(filepath.Join(runDir, "normalized/api-docs-probed.txt")),
		"OpenAPI method/path pairs": countLines(filepath.Join(runDir, "normalized/openapi-methods.tsv")),
		"Cloud/secret candidates":   max(0, countLines(filepath.Join(runDir, "notes/cloud-candidates.tsv"))-1),
		"JavaScript route leads":    countLines(filepath.Join(runDir, "normalized/js-route-leads.txt")),
		"Source map candidates":     countLines(filepath.Join(runDir, "normalized/source-map-candidates.txt")),
		"JSONL events":              countLines(filepath.Join(runDir, "normalized/recon-events.jsonl")),
	}

	fmt.Fprintf(&b, "## Counts\n\n| Artifact | Count |\n| --- | ---: |\n")
	for _, key := range []string{"In-scope subdomains", "Resolved hosts", "Live HTTP/S services", "Interesting hosts", "Scored assets", "JavaScript route leads", "Source map candidates", "API docs/schema probes", "OpenAPI method/path pairs", "Cloud/secret candidates", "JSONL events"} {
		fmt.Fprintf(&b, "| %s | %d |\n", key, counts[key])
	}
	fmt.Fprintf(&b, "\n")

	addTopSection(&b, "High-Signal Review Queue", filepath.Join(runDir, "notes/interesting-hosts.txt"), 20)
	addTopSection(&b, "Top Asset Scores", filepath.Join(runDir, "normalized/asset-scores.tsv"), 25)
	addTopSection(&b, "JavaScript Leads", filepath.Join(runDir, "notes/js-leads.tsv"), 25)
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
	fmt.Fprintf(&b, "RECONX REPORT\n")
	fmt.Fprintf(&b, "=============\n\n")
	fmt.Fprintf(&b, "Generated UTC : %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Target        : %s\n", cfg.Target)
	fmt.Fprintf(&b, "Profile       : %s\n", cfg.Profile)
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
	writePlainSection(&b, "SUBDOMAINS", "These subdomains were found:", readLines(filepath.Join(runDir, "normalized/subdomains.txt")))
	writePlainSection(&b, "RESOLVED HOSTS", "These hosts resolved successfully:", readLines(filepath.Join(runDir, "normalized/resolved-hosts.txt")))
	writePlainSection(&b, "LIVE HTTP/S SERVICES", "These HTTP/S services responded:", readLines(filepath.Join(runDir, "normalized/live-hosts.txt")))
	writePlainSection(&b, "HIGH-SIGNAL REVIEW QUEUE", "Review these first:", readLines(filepath.Join(runDir, "notes/interesting-hosts.txt")))
	writePlainSection(&b, "JAVASCRIPT FILES", "These JavaScript files were discovered:", readLines(filepath.Join(runDir, "normalized/js-files.txt")))
	writePlainSection(&b, "JAVASCRIPT ROUTE LEADS", "These route leads were extracted from crawl/JavaScript data:", dataLines(filepath.Join(runDir, "notes/js-leads.tsv")))
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

	for _, line := range readLines(filepath.Join(runDir, "normalized/live-hosts.txt")) {
		fields := parseHTTPXLine(line)
		events = append(events, Event{Type: "live_service", Value: fields["url"], Source: "normalized/live-hosts.txt", Timestamp: now, Fields: fields})
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
		{"High-signal hosts", countLines(filepath.Join(runDir, "notes/interesting-hosts.txt"))},
		{"JavaScript files", countLines(filepath.Join(runDir, "normalized/js-files.txt"))},
		{"JavaScript route leads", countLines(filepath.Join(runDir, "normalized/js-route-leads.txt"))},
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
	fmt.Fprintf(b, "subfinder : all=%t recursive=%t\n", tools.Subfinder.All, tools.Subfinder.Recursive)
	fmt.Fprintf(b, "dnsx      : record_types=%s response=%t\n", strings.Join(tools.DNSX.RecordTypes, ","), tools.DNSX.Response)
	fmt.Fprintf(b, "httpx     : redirects=%t title=%t status=%t length=%t type=%t tech=%t\n",
		tools.HTTPX.FollowRedirects,
		tools.HTTPX.Title,
		tools.HTTPX.StatusCode,
		tools.HTTPX.ContentLength,
		tools.HTTPX.ContentType,
		tools.HTTPX.TechDetect,
	)
	fmt.Fprintf(b, "katana    : js=%t iqp=%t fsu=%t known_files=%q field_scope=%q strategy=%q headless=%t xhr=%t display_out_scope=%t\n\n",
		tools.Katana.JSCrawl,
		tools.Katana.IgnoreQueryParams,
		tools.Katana.FilterSimilar,
		tools.Katana.KnownFiles,
		tools.Katana.FieldScope,
		tools.Katana.Strategy,
		tools.Katana.Headless,
		tools.Katana.XHRExtraction,
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
