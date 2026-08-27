package ports

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/deps"
)

type Options struct {
	RunDir string
	Rate   int
	Tools  config.Tools
	Out    io.Writer
}

type Result struct {
	OpenPorts int
}

type PortRecord struct {
	Host    string
	Port    string
	Service string
	Source  string
}

func Run(opts Options) (Result, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if opts.Rate == 0 {
		opts.Rate = 25
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	input := filepath.Join(opts.RunDir, "normalized/resolved-hosts.txt")
	rawNaabu := filepath.Join(opts.RunDir, "raw/naabu.txt")
	normalized := filepath.Join(opts.RunDir, "normalized/open-ports.tsv")
	hosts := readLines(input)
	if len(hosts) == 0 {
		_ = writePortRecords(normalized, nil)
		return Result{}, nil
	}

	fmt.Fprintf(opts.Out, "[port] Scanning open ports with naabu...\n")
	records := runNaabu(input, rawNaabu, opts.Tools.Naabu, opts.Rate)

	fmt.Fprintf(opts.Out, "[port] Enriching services with nmap...\n")
	records = enrichWithNmap(opts.RunDir, records)

	if err := writePortRecords(normalized, records); err != nil {
		return Result{}, err
	}
	return Result{OpenPorts: len(records)}, nil
}

func runNaabu(input, output string, tool config.NaabuTool, rate int) []PortRecord {
	path, err := deps.LookPath("naabu")
	if err != nil {
		_ = writeLines(output, nil)
		return nil
	}
	_ = os.Remove(output)
	args := []string{"-list", input, "-silent", "-nc", "-rate", strconv.Itoa(rate), "-o", output}
	if tool.TopPorts != "" {
		args = append(args, "-top-ports", tool.TopPorts)
	}
	if tool.ScanAllIPs {
		args = append(args, "-scan-all-ips")
	}
	if tool.ServiceDiscovery {
		args = append(args, "-service-discovery")
	}
	if tool.ServiceVersion {
		args = append(args, "-service-version")
	}
	if tool.Verify {
		args = append(args, "-verify")
	}
	if tool.Passive {
		args = append(args, "-passive")
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	if err := cmd.Run(); err != nil {
		return nil
	}
	return parseNaabu(readLines(output))
}

func parseNaabu(lines []string) []PortRecord {
	seen := map[string]PortRecord{}
	for _, line := range lines {
		host, port := splitHostPort(strings.TrimSpace(line))
		if host == "" || port == "" {
			continue
		}
		key := host + ":" + port
		seen[key] = PortRecord{Host: host, Port: port, Service: commonService(port), Source: "naabu"}
	}
	return sortedRecords(seen)
}

func splitHostPort(value string) (string, string) {
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.LastIndex(value, ":"); idx > 0 && idx < len(value)-1 {
		port := value[idx+1:]
		if regexp.MustCompile(`^[0-9]+$`).MatchString(port) {
			return value[:idx], port
		}
	}
	return "", ""
}

func enrichWithNmap(runDir string, records []PortRecord) []PortRecord {
	path, err := deps.LookPath("nmap")
	if err != nil || len(records) == 0 {
		return records
	}
	byHost := map[string][]string{}
	for _, record := range records {
		byHost[record.Host] = append(byHost[record.Host], record.Port)
	}

	serviceByKey := map[string]string{}
	for host, ports := range byHost {
		sort.Strings(ports)
		output := filepath.Join(runDir, "raw/nmap", safeName(host)+".txt")
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			continue
		}
		args := []string{"-sV", "-Pn", "-n", "--version-light", "-p", strings.Join(unique(ports), ","), host, "-oN", output}
		cmd := exec.Command(path, args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		cmd.Env = deps.WithGoBinFirst(os.Environ())
		if err := cmd.Run(); err != nil {
			continue
		}
		for _, line := range readLines(output) {
			match := regexp.MustCompile(`^([0-9]+)/tcp\s+open\s+(\S+)`).FindStringSubmatch(line)
			if len(match) == 3 {
				serviceByKey[host+":"+match[1]] = match[2]
			}
		}
	}

	for i := range records {
		if service := serviceByKey[records[i].Host+":"+records[i].Port]; service != "" {
			records[i].Service = service
			records[i].Source = "naabu,nmap"
		}
	}
	return records
}

func writePortRecords(path string, records []PortRecord) error {
	lines := []string{"host\tport\tservice\tsource"}
	for _, record := range records {
		lines = append(lines, strings.Join([]string{
			record.Host,
			record.Port,
			record.Service,
			record.Source,
		}, "\t"))
	}
	return writeLines(path, lines)
}

func commonService(port string) string {
	services := map[string]string{
		"21": "ftp", "22": "ssh", "25": "smtp", "53": "dns", "80": "http",
		"110": "pop3", "143": "imap", "443": "https", "445": "smb",
		"587": "smtp", "993": "imaps", "995": "pop3s", "3306": "mysql",
		"3389": "rdp", "5432": "postgres", "6379": "redis", "8080": "http",
		"8443": "https", "9200": "elasticsearch",
	}
	if service := services[port]; service != "" {
		return service
	}
	return "unknown"
}

func sortedRecords(records map[string]PortRecord) []PortRecord {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]PortRecord, 0, len(keys))
	for _, key := range keys {
		out = append(out, records[key])
	}
	return out
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

func ensureDirs(runDir string) error {
	for _, dir := range []string{"raw", "raw/nmap", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func safeName(value string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
	name := strings.Trim(re.ReplaceAllString(value, "_"), "_")
	if name == "" {
		return "host"
	}
	return name
}
