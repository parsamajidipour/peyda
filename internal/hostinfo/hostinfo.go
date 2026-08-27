package hostinfo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/deps"
)

type Options struct {
	RunDir string
	Target string
	Tools  config.Tools
	Out    io.Writer
}

type Result struct {
	WHOISFields int
	DNSRecords  int
}

func Run(opts Options) (Result, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	fmt.Fprintf(opts.Out, "[whois] Collecting registration metadata...\n")
	whoisFields := collectWHOIS(opts.RunDir, opts.Target, opts.Tools.WHOIS)

	fmt.Fprintf(opts.Out, "[dns] Querying DNS records with dig...\n")
	dnsRecords := collectDNS(opts.RunDir, opts.Target, opts.Tools.Dig)

	return Result{WHOISFields: whoisFields, DNSRecords: dnsRecords}, nil
}

func collectWHOIS(runDir, target string, tool config.WHOISTool) int {
	output := filepath.Join(runDir, "raw/whois.txt")
	tsv := filepath.Join(runDir, "normalized/whois.tsv")
	lines := []string{"key\tvalue"}

	path, err := deps.LookPath("whois")
	if err != nil {
		_ = writeLines(tsv, lines)
		return 0
	}
	args := []string{}
	if tool.Verbose {
		args = append(args, "--verbose")
	}
	args = append(args, target)
	data, err := runWHOIS(path, args...)
	if err != nil {
		_ = writeLines(tsv, lines)
		return 0
	}
	fields := parseWHOIS(string(data))
	if tool.Verbose && len(fields) == 0 {
		if fallback, err := runWHOIS(path, target); err == nil && len(parseWHOIS(string(fallback))) > 0 {
			data = fallback
			fields = parseWHOIS(string(data))
		}
	}
	_ = os.WriteFile(output, data, 0o644)

	keys := sortedKeys(fields)
	for _, key := range keys {
		lines = append(lines, key+"\t"+sanitize(fields[key]))
	}
	_ = writeLines(tsv, lines)
	return len(keys)
}

func runWHOIS(path string, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	return cmd.Output()
}

func parseWHOIS(data string) map[string]string {
	patterns := map[string]*regexp.Regexp{
		"registrar":    regexp.MustCompile(`(?im)^\s*Registrar(?: Name)?:\s*(.+)\s*$`),
		"created":      regexp.MustCompile(`(?im)^\s*(?:Creation Date|Created On|Registered On):\s*(.+)\s*$`),
		"expires":      regexp.MustCompile(`(?im)^\s*(?:Registry Expiry Date|Expiry Date|Expires On):\s*(.+)\s*$`),
		"updated":      regexp.MustCompile(`(?im)^\s*Updated Date:\s*(.+)\s*$`),
		"name_servers": regexp.MustCompile(`(?im)^\s*Name Server:\s*(.+)\s*$`),
	}
	fields := map[string]string{}
	for key, re := range patterns {
		matches := re.FindAllStringSubmatch(data, -1)
		if len(matches) == 0 {
			continue
		}
		var values []string
		seen := map[string]struct{}{}
		for _, match := range matches {
			value := strings.TrimSpace(match[1])
			if value == "" {
				continue
			}
			lower := strings.ToLower(value)
			if _, ok := seen[lower]; ok {
				continue
			}
			seen[lower] = struct{}{}
			values = append(values, value)
		}
		if len(values) > 0 {
			fields[key] = strings.Join(values, ",")
		}
	}
	return fields
}

func collectDNS(runDir, target string, tool config.DigTool) int {
	tsv := filepath.Join(runDir, "normalized/dns-records.tsv")
	lines := []string{"type\tname\tvalue"}
	path, err := deps.LookPath("dig")
	if err != nil {
		_ = writeLines(tsv, lines)
		return 0
	}

	recordTypes := tool.RecordTypes
	if len(recordTypes) == 0 {
		recordTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"}
	}
	for _, recordType := range recordTypes {
		recordType = strings.ToUpper(strings.TrimSpace(recordType))
		if recordType == "" {
			continue
		}
		cmd := exec.Command(path, "+short", target, recordType)
		cmd.Env = deps.WithGoBinFirst(os.Environ())
		data, err := cmd.Output()
		if err != nil {
			continue
		}
		rawPath := filepath.Join(runDir, "raw", "dig-"+strings.ToLower(recordType)+".txt")
		_ = os.WriteFile(rawPath, data, 0o644)
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			value := strings.Trim(strings.TrimSpace(scanner.Text()), `"`)
			if value == "" || strings.HasPrefix(value, ";") || strings.Contains(value, "communications error") {
				continue
			}
			lines = append(lines, strings.Join([]string{recordType, target, sanitize(value)}, "\t"))
		}
	}
	if tool.Trace {
		writeDigRaw(path, runDir, "trace", "+trace", target)
	}
	if tool.NSSearch {
		writeDigRaw(path, runDir, "nssearch", "+nssearch", target)
	}
	_ = writeLines(tsv, lines)
	return max(0, len(lines)-1)
}

func writeDigRaw(path, runDir, name string, args ...string) {
	cmd := exec.Command(path, args...)
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	data, err := cmd.Output()
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(runDir, "raw", "dig-"+name+".txt"), data, 0o644)
}

func ensureDirs(runDir string) error {
	for _, dir := range []string{"raw", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func sanitize(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
