package dataset

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Options struct {
	RunDir      string
	Target      string
	ResultsRoot string
	Duration    time.Duration
	CompletedAt time.Time
}

type Summary struct {
	Target          string  `json:"target"`
	Subdomains      int     `json:"subdomains"`
	Resolved        int     `json:"resolved"`
	LiveHosts       int     `json:"live_hosts"`
	IPs             int     `json:"ips"`
	OpenPorts       int     `json:"open_ports"`
	URLs            int     `json:"urls"`
	JavaScriptFiles int     `json:"javascript_files"`
	Parameters      int     `json:"parameters"`
	Endpoints       int     `json:"endpoints"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	CompletedAt     string  `json:"completed_at,omitempty"`
	RunDir          string  `json:"run_dir,omitempty"`
	ResultDir       string  `json:"result_dir,omitempty"`
}

type DNSAsset struct {
	Host   string   `json:"host"`
	A      []string `json:"a"`
	AAAA   []string `json:"aaaa"`
	CNAME  []string `json:"cname"`
	MX     []string `json:"mx"`
	NS     []string `json:"ns"`
	TXT    []string `json:"txt"`
	SOA    []string `json:"soa"`
	CAA    []string `json:"caa"`
	DNSKEY []string `json:"dnskey"`
	DS     []string `json:"ds"`
}

type HTTPAsset struct {
	URL           string   `json:"url"`
	Host          string   `json:"host"`
	Status        int      `json:"status"`
	Title         string   `json:"title"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	Server        string   `json:"server"`
	IP            string   `json:"ip"`
	Redirect      string   `json:"redirect"`
	Technologies  []string `json:"technologies"`
}

type TechnologyAsset struct {
	Host         string   `json:"host"`
	Technologies []string `json:"technologies"`
}

type PortAsset struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Source  string `json:"source"`
}

type builtDataset struct {
	Target       string
	Subdomains   []string
	Resolved     []string
	Live         []string
	IPs          []string
	Ports        []PortAsset
	URLs         []string
	Parameters   []string
	JavaScript   []string
	Endpoints    []string
	DNS          []DNSAsset
	HTTP         []HTTPAsset
	Technologies []TechnologyAsset
}

func Export(opts Options) (Summary, error) {
	target := normalizeHost(opts.Target)
	if !validHost(target) {
		return Summary{}, fmt.Errorf("invalid target: %s", opts.Target)
	}
	if opts.ResultsRoot == "" {
		opts.ResultsRoot = "results"
	}
	if opts.CompletedAt.IsZero() {
		opts.CompletedAt = time.Now().UTC()
	}

	ds := build(opts.RunDir, target)
	resultDir, err := absolutePath(filepath.Join(opts.ResultsRoot, target))
	if err != nil {
		return Summary{}, err
	}
	parent := filepath.Dir(resultDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return Summary{}, err
	}
	tempDir, err := os.MkdirTemp(parent, "."+target+".tmp-")
	if err != nil {
		return Summary{}, err
	}
	defer os.RemoveAll(tempDir)

	summary := Summary{
		Target:          target,
		Subdomains:      len(ds.Subdomains),
		Resolved:        len(ds.Resolved),
		LiveHosts:       len(ds.Live),
		IPs:             len(ds.IPs),
		OpenPorts:       len(ds.Ports),
		URLs:            len(ds.URLs),
		JavaScriptFiles: len(ds.JavaScript),
		Parameters:      len(ds.Parameters),
		Endpoints:       len(ds.Endpoints),
		DurationSeconds: opts.Duration.Seconds(),
		CompletedAt:     opts.CompletedAt.Format(time.RFC3339),
		RunDir:          opts.RunDir,
		ResultDir:       resultDir,
	}

	if err := writeTextFiles(tempDir, ds); err != nil {
		return Summary{}, err
	}
	if err := writeJSONAtomic(filepath.Join(tempDir, "dns.json"), ds.DNS); err != nil {
		return Summary{}, err
	}
	if err := writeJSONAtomic(filepath.Join(tempDir, "http.json"), ds.HTTP); err != nil {
		return Summary{}, err
	}
	if err := writeJSONAtomic(filepath.Join(tempDir, "ports.json"), ds.Ports); err != nil {
		return Summary{}, err
	}
	if err := writeJSONAtomic(filepath.Join(tempDir, "technologies.json"), ds.Technologies); err != nil {
		return Summary{}, err
	}
	if err := writeJSONAtomic(filepath.Join(tempDir, "summary.json"), summary); err != nil {
		return Summary{}, err
	}

	if err := os.RemoveAll(resultDir); err != nil {
		return Summary{}, err
	}
	if err := os.Rename(tempDir, resultDir); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func build(runDir, target string) builtDataset {
	dns := buildDNS(runDir, target)
	subdomains := scopedHosts(target, readLines(filepath.Join(runDir, "normalized/subdomains.txt")))
	subdomains = addSortedUnique(subdomains, target)

	resolvedSet := map[string]struct{}{}
	for _, host := range scopedHosts(target, readLines(filepath.Join(runDir, "normalized/resolved-hosts.txt"))) {
		resolvedSet[host] = struct{}{}
	}
	for _, record := range dns {
		if len(record.A) > 0 || len(record.AAAA) > 0 || len(record.CNAME) > 0 {
			resolvedSet[record.Host] = struct{}{}
		}
	}
	resolved := sortedKeys(resolvedSet)

	live, httpAssets := buildHTTP(runDir, target)
	ports := buildPorts(runDir, target)
	ips := ipsFromDNS(dns)
	urls := scopedURLs(target, readLines(filepath.Join(runDir, "normalized/urls.txt")))
	for _, liveURL := range live {
		urls = addSortedUnique(urls, liveURL)
	}
	for _, host := range hostsFromURLs(target, urls) {
		subdomains = addSortedUnique(subdomains, host)
	}
	parameters := buildParameters(runDir, urls)
	javascript := scopedJS(target, readLines(filepath.Join(runDir, "normalized/js-files.txt")))
	endpoints := scopedEndpoints(target, readLines(filepath.Join(runDir, "normalized/js-endpoints.txt")))
	technologies := buildTechnologies(httpAssets)

	return builtDataset{
		Target:       target,
		Subdomains:   subdomains,
		Resolved:     resolved,
		Live:         live,
		IPs:          ips,
		Ports:        ports,
		URLs:         urls,
		Parameters:   parameters,
		JavaScript:   javascript,
		Endpoints:    endpoints,
		DNS:          dns,
		HTTP:         httpAssets,
		Technologies: technologies,
	}
}

func writeTextFiles(dir string, ds builtDataset) error {
	files := map[string][]string{
		"subdomains.txt": ds.Subdomains,
		"resolved.txt":   ds.Resolved,
		"live.txt":       ds.Live,
		"ips.txt":        ds.IPs,
		"ports.txt":      renderPorts(ds.Ports),
		"urls.txt":       ds.URLs,
		"parameters.txt": ds.Parameters,
		"javascript.txt": ds.JavaScript,
		"endpoints.txt":  ds.Endpoints,
	}
	for name, lines := range files {
		if err := writeLines(filepath.Join(dir, name), lines); err != nil {
			return err
		}
	}
	return nil
}

func buildPorts(runDir, target string) []PortAsset {
	seen := map[string]PortAsset{}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/open-ports.tsv")) {
		host := normalizeHost(row["host"])
		if !inScopeHost(host, target) {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSpace(row["port"]))
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		key := fmt.Sprintf("%s:%d", host, port)
		seen[key] = PortAsset{
			Host:    host,
			Port:    port,
			Service: strings.TrimSpace(row["service"]),
			Source:  strings.TrimSpace(row["source"]),
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]PortAsset, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func renderPorts(ports []PortAsset) []string {
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		service := port.Service
		if service == "" {
			service = "unknown"
		}
		out = append(out, fmt.Sprintf("%s:%d\t%s", port.Host, port.Port, service))
	}
	return out
}

func buildDNS(runDir, target string) []DNSAsset {
	byHost := map[string]*DNSAsset{}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/dns-records.tsv")) {
		host := normalizeHost(row["name"])
		if !inScopeHost(host, target) {
			continue
		}
		recordType := strings.ToUpper(strings.TrimSpace(row["type"]))
		value := strings.TrimSpace(row["value"])
		if value == "" {
			continue
		}
		addDNSValue(byHost, host, recordType, value)
	}
	for _, line := range readLines(filepath.Join(runDir, "normalized/resolved.txt")) {
		host := normalizeHost(firstField(line))
		if !inScopeHost(host, target) {
			continue
		}
		brackets := extractBrackets(line)
		if len(brackets) < 2 {
			continue
		}
		recordType := strings.ToUpper(strings.TrimSpace(brackets[0]))
		value := strings.TrimSpace(brackets[1])
		if value == "" {
			continue
		}
		addDNSValue(byHost, host, recordType, value)
	}
	assets := make([]DNSAsset, 0, len(byHost))
	for _, asset := range byHost {
		sortAssetDNS(asset)
		assets = append(assets, *asset)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Host < assets[j].Host })
	return assets
}

func addDNSValue(byHost map[string]*DNSAsset, host, recordType, value string) {
	asset := byHost[host]
	if asset == nil {
		asset = &DNSAsset{Host: host}
		byHost[host] = asset
	}
	switch recordType {
	case "A":
		asset.A = appendUnique(asset.A, value)
	case "AAAA":
		asset.AAAA = appendUnique(asset.AAAA, value)
	case "CNAME":
		asset.CNAME = appendUnique(asset.CNAME, value)
	case "MX":
		asset.MX = appendUnique(asset.MX, value)
	case "NS":
		asset.NS = appendUnique(asset.NS, value)
	case "TXT":
		asset.TXT = appendUnique(asset.TXT, value)
	case "SOA":
		asset.SOA = appendUnique(asset.SOA, value)
	case "CAA":
		asset.CAA = appendUnique(asset.CAA, value)
	case "DNSKEY":
		asset.DNSKEY = appendUnique(asset.DNSKEY, value)
	case "DS":
		asset.DS = appendUnique(asset.DS, value)
	}
}

func ipsFromDNS(records []DNSAsset) []string {
	seen := map[string]struct{}{}
	for _, record := range records {
		for _, ip := range append(record.A, record.AAAA...) {
			if ip != "" {
				seen[ip] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func buildHTTP(runDir, target string) ([]string, []HTTPAsset) {
	seenURLs := map[string]struct{}{}
	byURL := map[string]HTTPAsset{}
	for _, line := range readLines(filepath.Join(runDir, "normalized/live-hosts.txt")) {
		asset := parseHTTPAsset(line)
		if asset.URL == "" || !inScopeURL(asset.URL, target) {
			continue
		}
		normalized := normalizeURL(asset.URL)
		if normalized == "" {
			continue
		}
		asset.URL = normalized
		asset.Host = hostFromURL(normalized)
		asset.Technologies = uniqueSorted(asset.Technologies)
		seenURLs[normalized] = struct{}{}
		byURL[normalized] = asset
	}
	live := sortedKeys(seenURLs)
	httpAssets := make([]HTTPAsset, 0, len(live))
	for _, item := range live {
		httpAssets = append(httpAssets, byURL[item])
	}
	return live, httpAssets
}

func parseHTTPAsset(line string) HTTPAsset {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return HTTPAsset{}
	}
	brackets := extractBrackets(line)
	asset := HTTPAsset{URL: fields[0]}
	var remaining []string
	for _, value := range brackets {
		switch {
		case asset.Status == 0 && looksLikeStatus(value):
			asset.Status = finalStatusCode(value)
		case asset.ContentLength == 0 && looksLikeInteger(value):
			asset.ContentLength, _ = strconv.Atoi(value)
		case asset.ContentType == "" && strings.Contains(value, "/"):
			asset.ContentType = value
		default:
			remaining = append(remaining, value)
		}
	}
	if len(remaining) > 0 {
		asset.Title = remaining[0]
	}
	if len(remaining) > 1 {
		asset.Technologies = splitCSVish(remaining[len(remaining)-1])
	}
	return asset
}

func buildTechnologies(httpAssets []HTTPAsset) []TechnologyAsset {
	byHost := map[string][]string{}
	for _, asset := range httpAssets {
		if asset.Host == "" {
			continue
		}
		byHost[asset.Host] = append(byHost[asset.Host], asset.Technologies...)
		if asset.Server != "" {
			byHost[asset.Host] = append(byHost[asset.Host], asset.Server)
		}
	}
	hosts := sortedKeysFromSlices(byHost)
	out := make([]TechnologyAsset, 0, len(hosts))
	for _, host := range hosts {
		tech := uniqueSorted(byHost[host])
		if len(tech) == 0 {
			continue
		}
		out = append(out, TechnologyAsset{Host: host, Technologies: tech})
	}
	return out
}

func buildParameters(runDir string, urls []string) []string {
	seen := map[string]struct{}{}
	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		for name := range parsed.Query() {
			name = normalizeParam(name)
			if name != "" {
				seen[name] = struct{}{}
			}
		}
	}
	for _, row := range readTSV(filepath.Join(runDir, "normalized/parameters.tsv")) {
		name := normalizeParam(row["name"])
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func scopedHosts(target string, lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		host := normalizeHost(firstField(line))
		if inScopeHost(host, target) {
			seen[host] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func scopedURLs(target string, lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		clean := normalizeURL(firstField(line))
		if clean != "" && inScopeURL(clean, target) {
			seen[clean] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func hostsFromURLs(target string, urls []string) []string {
	seen := map[string]struct{}{}
	for _, rawURL := range urls {
		host := hostFromURL(rawURL)
		if inScopeHost(host, target) {
			seen[host] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func scopedJS(target string, lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		clean := normalizeURL(firstField(line))
		if clean == "" || !inScopeURL(clean, target) {
			continue
		}
		if strings.Contains(strings.ToLower(mustURLPath(clean)), ".js") {
			seen[clean] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func scopedEndpoints(target string, lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		endpoint := normalizeEndpoint(line, target)
		if endpoint != "" {
			seen[endpoint] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func normalizeEndpoint(value, target string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	value = strings.TrimRight(value, `,;`)
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
		clean := normalizeURL(value)
		if clean != "" && inScopeURL(clean, target) {
			return clean
		}
		return ""
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		if strings.Contains(value, "\\") {
			return ""
		}
		return value
	}
	return ""
}

func normalizeURL(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
		return ""
	}
	parsed.Scheme = scheme
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String()
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	return value
}

func normalizeParam(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, " \t\r\n=&?/#") {
		return ""
	}
	return value
}

func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.Contains(host, "..") {
		return false
	}
	label := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	for _, part := range strings.Split(host, ".") {
		if !label.MatchString(part) {
			return false
		}
	}
	return true
}

func inScopeHost(host, target string) bool {
	if !validHost(host) {
		return false
	}
	return host == target || strings.HasSuffix(host, "."+target)
}

func inScopeURL(rawURL, target string) bool {
	host := hostFromURL(rawURL)
	return inScopeHost(host, target)
}

func hostFromURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return normalizeHost(parsed.Hostname())
}

func mustURLPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func firstField(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func addSortedUnique(lines []string, value string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		seen[line] = struct{}{}
	}
	seen[value] = struct{}{}
	return sortedKeys(seen)
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
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
	rows, err := reader.ReadAll()
	if err != nil || len(rows) == 0 {
		return nil
	}
	header := rows[0]
	var out []map[string]string
	for _, row := range rows[1:] {
		item := map[string]string{}
		for i, key := range header {
			if i < len(row) {
				item[key] = row[i]
			}
		}
		out = append(out, item)
	}
	return out
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

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func absolutePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	return filepath.Abs(path)
}

func extractBrackets(line string) []string {
	var out []string
	re := regexp.MustCompile(`\[([^\]]*)\]`)
	for _, match := range re.FindAllStringSubmatch(line, -1) {
		out = append(out, match[1])
	}
	return out
}

func splitCSVish(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	return uniqueSorted(parts)
}

func looksLikeStatus(value string) bool {
	return regexp.MustCompile(`^[0-9]{3}(,[0-9]{3})*$`).MatchString(value)
}

func finalStatusCode(value string) int {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return 0
	}
	status, _ := strconv.Atoi(parts[len(parts)-1])
	return status
}

func looksLikeInteger(value string) bool {
	return regexp.MustCompile(`^[0-9]+$`).MatchString(value)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortAssetDNS(asset *DNSAsset) {
	sort.Strings(asset.A)
	sort.Strings(asset.AAAA)
	sort.Strings(asset.CNAME)
	sort.Strings(asset.MX)
	sort.Strings(asset.NS)
	sort.Strings(asset.TXT)
	sort.Strings(asset.SOA)
	sort.Strings(asset.CAA)
	sort.Strings(asset.DNSKEY)
	sort.Strings(asset.DS)
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return sortedKeys(seen)
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedKeysFromSlices(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
