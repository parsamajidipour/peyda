package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	fmt.Fprintf(&b, "| API probe rate | `%d` |\n\n", cfg.APIRate)

	counts := map[string]int{
		"In-scope subdomains":       countLines(filepath.Join(runDir, "normalized/subdomains.txt")),
		"Resolved hosts":            countLines(filepath.Join(runDir, "normalized/resolved-hosts.txt")),
		"Live HTTP/S services":      countLines(filepath.Join(runDir, "normalized/live-hosts.txt")),
		"Interesting hosts":         countLines(filepath.Join(runDir, "notes/interesting-hosts.txt")),
		"Scored assets":             max(0, countLines(filepath.Join(runDir, "normalized/asset-scores.tsv"))-1),
		"API docs/schema probes":    countLines(filepath.Join(runDir, "normalized/api-docs-probed.txt")),
		"OpenAPI method/path pairs": countLines(filepath.Join(runDir, "normalized/openapi-methods.tsv")),
		"Cloud/secret candidates":   max(0, countLines(filepath.Join(runDir, "notes/cloud-candidates.tsv"))-1),
		"JSONL events":              countLines(filepath.Join(runDir, "normalized/recon-events.jsonl")),
	}

	fmt.Fprintf(&b, "## Counts\n\n| Artifact | Count |\n| --- | ---: |\n")
	for _, key := range []string{"In-scope subdomains", "Resolved hosts", "Live HTTP/S services", "Interesting hosts", "Scored assets", "API docs/schema probes", "OpenAPI method/path pairs", "Cloud/secret candidates", "JSONL events"} {
		fmt.Fprintf(&b, "| %s | %d |\n", key, counts[key])
	}
	fmt.Fprintf(&b, "\n")

	addTopSection(&b, "High-Signal Review Queue", filepath.Join(runDir, "notes/interesting-hosts.txt"), 20)
	addTopSection(&b, "Top Asset Scores", filepath.Join(runDir, "normalized/asset-scores.tsv"), 25)
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
	if len(brackets) > 0 {
		fields["status"] = brackets[0]
	}
	if len(brackets) > 1 {
		fields["title"] = brackets[1]
	}
	if len(brackets) > 2 {
		fields["technology"] = brackets[2]
	}
	return fields
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
