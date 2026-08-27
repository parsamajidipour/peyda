package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/deps"
)

type Options struct {
	Root      string
	RunDir    string
	Target    string
	ProbeRate int
	Resolve   bool
	Probe     bool
	Tools     config.Tools
	Out       io.Writer
}

type Result struct {
	Subdomains       int
	ResolvedHosts    int
	LiveServices     int
	InterestingHosts int
}

type AssetScore struct {
	URL        string
	Host       string
	Status     string
	Title      string
	Technology string
	Score      int
	Reasons    []string
	Raw        string
}

func Run(opts Options) (Result, error) {
	if opts.ProbeRate == 0 {
		opts.ProbeRate = 50
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	logPath := filepath.Join(opts.RunDir, "notes/subdomain.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer logFile.Close()

	log := func(format string, args ...any) {
		fmt.Fprintf(opts.Out, format+"\n", args...)
		fmt.Fprintf(logFile, format+"\n", args...)
	}

	log("[subdomain] target=%s", opts.Target)
	log("[subdomain] resolve=%t probe=%t probe_rate=%d", opts.Resolve, opts.Probe, opts.ProbeRate)

	log("[1/7] Running subfinder...")
	if err := runSubfinder(opts); err != nil {
		log("[subdomain] subfinder skipped or failed: %v", err)
	}

	log("[2/7] Querying crt.sh...")
	crtNames, err := fetchCrtSH(opts.Target)
	if err != nil {
		log("[subdomain] crt.sh skipped: %v", err)
	}
	if err := writeLines(filepath.Join(opts.RunDir, "raw/crtsh.txt"), crtNames); err != nil {
		return Result{}, err
	}

	log("[3/7] Normalizing and applying exclusions...")
	subdomains, err := normalizeAndFilter(opts.RunDir, opts.Target)
	if err != nil {
		return Result{}, err
	}
	result := Result{Subdomains: len(subdomains)}

	if !opts.Resolve {
		log("[4/7] Resolution disabled; skipping wildcard, DNS, HTTP, and scoring.")
		return result, nil
	}

	log("[4/7] Checking wildcard DNS behavior...")
	if err := wildcardDNSCheck(opts); err != nil {
		log("[subdomain] wildcard check skipped or failed: %v", err)
	}

	log("[5/7] Resolving candidates...")
	resolvedHosts, err := resolveHosts(opts)
	if err != nil {
		return result, err
	}
	result.ResolvedHosts = len(resolvedHosts)

	if !opts.Probe {
		log("[6/7] HTTP probing disabled.")
		return result, nil
	}

	log("[6/7] Probing HTTP/S services...")
	liveServices, err := probeHTTP(opts)
	if err != nil {
		return result, err
	}
	result.LiveServices = len(liveServices)

	log("[7/7] Scoring live assets...")
	scores, err := ScoreLiveHosts(filepath.Join(opts.RunDir, "normalized/live-hosts.txt"), loadKeywords(opts.Root))
	if err != nil {
		return result, err
	}
	if err := writeScores(filepath.Join(opts.RunDir, "normalized/asset-scores.tsv"), scores); err != nil {
		return result, err
	}
	interesting := interestingLines(scores, 30)
	result.InterestingHosts = len(interesting)
	if err := writeLines(filepath.Join(opts.RunDir, "notes/interesting-hosts.txt"), interesting); err != nil {
		return result, err
	}

	log("[subdomain] subdomains=%d resolved=%d live=%d interesting=%d",
		result.Subdomains, result.ResolvedHosts, result.LiveServices, result.InterestingHosts)
	return result, nil
}

func EnrichFromURLs(opts Options) (Result, error) {
	if opts.ProbeRate == 0 {
		opts.ProbeRate = 50
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	logPath := filepath.Join(opts.RunDir, "notes/subdomain.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return Result{}, err
	}
	defer logFile.Close()

	log := func(format string, args ...any) {
		fmt.Fprintf(opts.Out, format+"\n", args...)
		fmt.Fprintf(logFile, format+"\n", args...)
	}

	hosts := urlDiscoveredHosts(opts.RunDir, opts.Target)
	if len(hosts) == 0 {
		log("[subdomain] no URL-discovered hosts to enrich")
		return Result{}, nil
	}
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/subdomains.url-hosts.txt"), hosts); err != nil {
		return Result{}, err
	}

	merged, err := mergeSubdomains(opts.RunDir, hosts)
	if err != nil {
		return Result{}, err
	}
	log("[subdomain] URL host enrichment candidates=%d total=%d", len(hosts), len(merged))

	result := Result{Subdomains: len(merged)}
	if !opts.Resolve {
		return result, nil
	}

	resolvedHosts, err := resolveHosts(opts)
	if err != nil {
		return result, err
	}
	result.ResolvedHosts = len(resolvedHosts)
	if !opts.Probe {
		return result, nil
	}

	liveServices, err := probeHTTP(opts)
	if err != nil {
		return result, err
	}
	result.LiveServices = len(liveServices)

	scores, err := ScoreLiveHosts(filepath.Join(opts.RunDir, "normalized/live-hosts.txt"), loadKeywords(opts.Root))
	if err != nil {
		return result, err
	}
	if err := writeScores(filepath.Join(opts.RunDir, "normalized/asset-scores.tsv"), scores); err != nil {
		return result, err
	}
	interesting := interestingLines(scores, 30)
	result.InterestingHosts = len(interesting)
	if err := writeLines(filepath.Join(opts.RunDir, "notes/interesting-hosts.txt"), interesting); err != nil {
		return result, err
	}
	log("[subdomain] enriched resolved=%d live=%d interesting=%d", result.ResolvedHosts, result.LiveServices, result.InterestingHosts)
	return result, nil
}

func runSubfinder(opts Options) error {
	output := filepath.Join(opts.RunDir, "raw/subfinder.txt")
	if isReservedTestDomain(opts.Target) {
		return writeLines(output, nil)
	}
	path, err := deps.LookPath("subfinder")
	if err != nil {
		return err
	}
	_ = os.Remove(output)
	args := []string{"-d", opts.Target, "-silent"}
	if opts.Tools.Subfinder.All {
		args = append(args, "-all")
	}
	if opts.Tools.Subfinder.Recursive {
		args = append(args, "-recursive")
	}
	if opts.Tools.Subfinder.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(opts.Tools.Subfinder.Timeout))
	}
	if opts.Tools.Subfinder.MaxTime > 0 {
		args = append(args, "-max-time", strconv.Itoa(opts.Tools.Subfinder.MaxTime))
	}
	args = append(args, "-o", output)
	cmd := exec.Command(path, args...)
	cmd.Dir = opts.Root
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	return cmd.Run()
}

func wildcardDNSCheck(opts Options) error {
	dnsxPath, err := deps.LookPath("dnsx")
	if err != nil {
		return err
	}
	var probes []string
	for i := 0; i < 3; i++ {
		probes = append(probes, fmt.Sprintf("does-not-exist-%d-%d.%s", time.Now().UnixNano(), i, opts.Target))
	}
	input := filepath.Join(opts.RunDir, "raw/wildcard-input.txt")
	output := filepath.Join(opts.RunDir, "notes/wildcard-dns-check.txt")
	if err := writeLines(input, probes); err != nil {
		return err
	}
	_ = os.Remove(output)
	args := dnsxArgs(opts.Tools.DNSX, input, output)
	return runTool(opts.Root, dnsxPath, args...)
}

func resolveHosts(opts Options) ([]string, error) {
	dnsxPath, err := deps.LookPath("dnsx")
	if err != nil {
		return nil, err
	}
	input := filepath.Join(opts.RunDir, "normalized/subdomains.txt")
	output := filepath.Join(opts.RunDir, "normalized/resolved.txt")
	_ = os.Remove(output)
	if err := runTool(opts.Root, dnsxPath, dnsxArgs(opts.Tools.DNSX, input, output)...); err != nil {
		return nil, err
	}
	hosts := uniqueHostsFromDNSX(readLines(output))
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/resolved-hosts.txt"), hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

func probeHTTP(opts Options) ([]string, error) {
	httpxPath, err := deps.LookPath("httpx")
	if err != nil {
		return nil, err
	}
	input := filepath.Join(opts.RunDir, "normalized/resolved-hosts.txt")
	output := filepath.Join(opts.RunDir, "normalized/live-hosts.txt")
	_ = os.Remove(output)
	fmt.Fprintf(opts.Out, "[subdomain] httpx probing started...\n")
	err = runToolWithProgress(
		opts.Root,
		httpxPath,
		output,
		"[subdomain] httpx",
		opts.Out,
		2*time.Minute,
		httpxArgs(opts.Tools.HTTPX, input, output, opts.ProbeRate)...,
	)
	if err != nil {
		return nil, err
	}
	if usesRichHTTPX(opts.Tools.HTTPX) {
		richOutput := filepath.Join(opts.RunDir, "raw/httpx-rich.jsonl")
		_ = os.Remove(richOutput)
		fmt.Fprintf(opts.Out, "[subdomain] httpx rich fingerprinting started...\n")
		_ = runToolWithProgress(
			opts.Root,
			httpxPath,
			richOutput,
			"[subdomain] httpx-rich",
			opts.Out,
			2*time.Minute,
			richHTTPXArgs(opts.Tools.HTTPX, input, richOutput, opts.ProbeRate)...,
		)
	}
	return readLines(output), nil
}

func dnsxArgs(tool config.DNSXTool, input, output string) []string {
	args := []string{"-l", input, "-silent", "-nc"}
	if tool.Recon {
		args = append(args, "-recon")
	} else {
		recordTypes := tool.RecordTypes
		if len(recordTypes) == 0 {
			recordTypes = []string{"a"}
		}
		for _, recordType := range recordTypes {
			recordType = strings.ToLower(strings.TrimSpace(recordType))
			if recordType == "" {
				continue
			}
			args = append(args, "-"+recordType)
		}
	}
	if tool.Response {
		args = append(args, "-resp")
	}
	if tool.Trace {
		args = append(args, "-trace")
	}
	return append(args, "-o", output)
}

func httpxArgs(tool config.HTTPXTool, input, output string, rate int) []string {
	args := []string{"-l", input, "-silent", "-nc"}
	if tool.Title {
		args = append(args, "-title")
	}
	if tool.StatusCode {
		args = append(args, "-status-code")
	}
	if tool.ContentLength {
		args = append(args, "-content-length")
	}
	if tool.ContentType {
		args = append(args, "-content-type")
	}
	if tool.TechDetect {
		args = append(args, "-tech-detect")
	}
	if tool.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if tool.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(tool.Retries))
	}
	if tool.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(tool.Timeout))
	}
	args = append(args, "-rl", strconv.Itoa(rate), "-o", output)
	return args
}

func richHTTPXArgs(tool config.HTTPXTool, input, output string, rate int) []string {
	args := []string{"-l", input, "-silent", "-nc", "-json"}
	args = append(args, "-status-code", "-content-length", "-content-type", "-title", "-tech-detect")
	if tool.WebServer {
		args = append(args, "-web-server")
	}
	if tool.IP {
		args = append(args, "-ip")
	}
	if tool.CNAME {
		args = append(args, "-cname")
	}
	if tool.ASN {
		args = append(args, "-asn")
	}
	if tool.CDN {
		args = append(args, "-cdn")
	}
	if tool.ResponseTime {
		args = append(args, "-response-time")
	}
	if tool.HTTP2 {
		args = append(args, "-http2")
	}
	if tool.Pipeline {
		args = append(args, "-pipeline")
	}
	if tool.TLSProbe {
		args = append(args, "-tls-probe")
	}
	if tool.TLSGrab {
		args = append(args, "-tls-grab")
	}
	if tool.ProbeAllIPs {
		args = append(args, "-probe-all-ips")
	}
	if tool.FollowRedirects {
		args = append(args, "-follow-redirects")
	}
	if tool.Retries > 0 {
		args = append(args, "-retries", strconv.Itoa(tool.Retries))
	}
	if tool.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(tool.Timeout))
	}
	args = append(args, "-rl", strconv.Itoa(rate), "-o", output)
	return args
}

func usesRichHTTPX(tool config.HTTPXTool) bool {
	return tool.WebServer || tool.IP || tool.CNAME || tool.ASN || tool.CDN ||
		tool.ResponseTime || tool.HTTP2 || tool.Pipeline || tool.TLSProbe ||
		tool.TLSGrab || tool.ProbeAllIPs
}

func runTool(root, path string, args ...string) error {
	cmd := exec.Command(path, args...)
	cmd.Dir = root
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	return cmd.Run()
}

func runToolWithProgress(root, path, output, label string, out io.Writer, timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = root
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())

	done := make(chan error, 1)
	go func() {
		done <- cmd.Run()
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if ctx.Err() == context.DeadlineExceeded {
				fmt.Fprintf(out, "%s timeout reached; continuing with partial results=%d\n", label, countLines(output))
				return nil
			}
			return err
		case <-ticker.C:
			fmt.Fprintf(out, "%s still running... results=%d\n", label, countLines(output))
		}
	}
}

func countLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}

func normalizeAndFilter(runDir, target string) ([]string, error) {
	rawSubfinder := readLines(filepath.Join(runDir, "raw/subfinder.txt"))
	rawCRT := readLines(filepath.Join(runDir, "raw/crtsh.txt"))
	excluded := readSet(filepath.Join(runDir, "excluded.txt"))

	allSet := map[string]struct{}{}
	if name := NormalizeDomain(target); name != "" {
		allSet[name] = struct{}{}
		allSet["www."+name] = struct{}{}
	}
	for _, line := range append(rawSubfinder, rawCRT...) {
		name := NormalizeDomain(line)
		if name != "" {
			allSet[name] = struct{}{}
		}
	}

	all := sortedKeys(allSet)
	filtered := make([]string, 0, len(all))
	for _, name := range all {
		if _, skip := excluded[name]; !skip {
			filtered = append(filtered, name)
		}
	}

	if err := writeLines(filepath.Join(runDir, "normalized/subdomains.all.txt"), all); err != nil {
		return nil, err
	}
	if err := writeLines(filepath.Join(runDir, "normalized/subdomains.txt"), filtered); err != nil {
		return nil, err
	}
	return filtered, nil
}

func mergeSubdomains(runDir string, additions []string) ([]string, error) {
	excluded := readSet(filepath.Join(runDir, "excluded.txt"))
	allSet := map[string]struct{}{}
	for _, line := range append(
		readLines(filepath.Join(runDir, "normalized/subdomains.all.txt")),
		readLines(filepath.Join(runDir, "normalized/subdomains.txt"))...,
	) {
		if name := NormalizeDomain(line); name != "" {
			allSet[name] = struct{}{}
		}
	}
	for _, line := range additions {
		if name := NormalizeDomain(line); name != "" {
			allSet[name] = struct{}{}
		}
	}

	all := sortedKeys(allSet)
	filtered := make([]string, 0, len(all))
	for _, name := range all {
		if _, skip := excluded[name]; !skip {
			filtered = append(filtered, name)
		}
	}
	if err := writeLines(filepath.Join(runDir, "normalized/subdomains.all.txt"), all); err != nil {
		return nil, err
	}
	if err := writeLines(filepath.Join(runDir, "normalized/subdomains.txt"), filtered); err != nil {
		return nil, err
	}
	return filtered, nil
}

func urlDiscoveredHosts(runDir, target string) []string {
	seen := map[string]struct{}{}
	for _, path := range []string{
		filepath.Join(runDir, "raw/gau-urls.txt"),
		filepath.Join(runDir, "raw/katana-urls.txt"),
		filepath.Join(runDir, "normalized/urls.txt"),
	} {
		for _, line := range readLines(path) {
			host := hostFromHTTPURL(firstField(line))
			if host != "" && inScopeHost(host, target) {
				seen[host] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func hostFromHTTPURL(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return NormalizeDomain(parsed.Hostname())
}

func firstField(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func inScopeHost(host, target string) bool {
	host = NormalizeDomain(host)
	target = NormalizeDomain(target)
	return host != "" && target != "" && (host == target || strings.HasSuffix(host, "."+target))
}

func NormalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.ContainsAny(value, " \t/") {
		return ""
	}
	return value
}

func fetchCrtSH(target string) ([]string, error) {
	if isReservedTestDomain(target) {
		return nil, fmt.Errorf("reserved test domain")
	}
	url := "https://crt.sh/?q=%25." + target + "&output=json"
	client := http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	for _, row := range rows {
		for _, item := range strings.Split(row.NameValue, "\n") {
			if name := NormalizeDomain(item); name != "" {
				seen[name] = struct{}{}
			}
		}
	}
	return sortedKeys(seen), nil
}

func isReservedTestDomain(target string) bool {
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	return strings.HasSuffix(target, ".test") ||
		strings.HasSuffix(target, ".localhost") ||
		strings.HasSuffix(target, ".invalid") ||
		target == "localhost"
}

func ScoreLiveHosts(path string, keywords []string) ([]AssetScore, error) {
	lines := readLines(path)
	scores := make([]AssetScore, 0, len(lines))
	for _, line := range lines {
		scores = append(scores, scoreLine(line, keywords))
	}
	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].Score == scores[j].Score {
			return scores[i].URL < scores[j].URL
		}
		return scores[i].Score > scores[j].Score
	})
	return scores, nil
}

func scoreLine(line string, keywords []string) AssetScore {
	fields := parseHTTPXLine(line)
	score := AssetScore{
		URL:        fields["url"],
		Host:       hostFromURL(fields["url"]),
		Status:     fields["status"],
		Title:      fields["title"],
		Technology: fields["technology"],
		Raw:        line,
	}

	searchText := strings.ToLower(strings.Join([]string{score.URL, score.Title, score.Technology, line}, " "))
	for _, keyword := range keywords {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword == "" {
			continue
		}
		if strings.Contains(searchText, keyword) {
			points := keywordWeight(keyword)
			score.Score += points
			score.Reasons = append(score.Reasons, keyword+":"+strconv.Itoa(points))
		}
	}

	switch score.Status {
	case "401", "403":
		score.Score += 20
		score.Reasons = append(score.Reasons, "restricted-status:20")
	case "500", "502", "503":
		score.Score += 10
		score.Reasons = append(score.Reasons, "server-error:10")
	}
	if score.Score == 0 {
		score.Reasons = append(score.Reasons, "baseline")
	}
	return score
}

func keywordWeight(keyword string) int {
	weights := map[string]int{
		"admin":      35,
		"billing":    35,
		"export":     30,
		"invite":     30,
		"token":      30,
		"webhook":    30,
		"swagger":    30,
		"openapi":    30,
		"graphql":    30,
		"graphiql":   30,
		"redoc":      25,
		"staging":    25,
		"debug":      25,
		"jenkins":    25,
		"grafana":    25,
		"kibana":     25,
		"s3":         20,
		"bucket":     20,
		"blob":       20,
		"cloudfront": 15,
		"api":        15,
		"login":      10,
		"sign in":    10,
		"dev":        10,
	}
	if points, ok := weights[keyword]; ok {
		return points
	}
	return 10
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
	re := regexp.MustCompile(`\[([^\]]*)\]`)
	for _, match := range re.FindAllStringSubmatch(line, -1) {
		out = append(out, match[1])
	}
	return out
}

func hostFromURL(value string) string {
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func interestingLines(scores []AssetScore, threshold int) []string {
	var lines []string
	for _, score := range scores {
		if score.Score < threshold {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d\t%s", score.URL, score.Status, score.Score, strings.Join(score.Reasons, ",")))
	}
	return lines
}

func writeScores(path string, scores []AssetScore) error {
	lines := []string{"url\thost\tstatus\ttitle\ttechnology\tscore\treasons"}
	for _, score := range scores {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%d\t%s",
			score.URL,
			score.Host,
			score.Status,
			sanitizeTSV(score.Title),
			sanitizeTSV(score.Technology),
			score.Score,
			strings.Join(score.Reasons, ","),
		))
	}
	return writeLines(path, lines)
}

func sanitizeTSV(value string) string {
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return value
}

func loadKeywords(root string) []string {
	path := filepath.Join(root, "config/high-signal-keywords.txt")
	lines := readLines(path)
	var keywords []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keywords = append(keywords, line)
	}
	if len(keywords) == 0 {
		return []string{"admin", "login", "api", "swagger", "openapi", "graphql", "staging", "debug", "s3", "bucket", "webhook", "billing", "export"}
	}
	return keywords
}

func uniqueHostsFromDNSX(lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		seen[fields[0]] = struct{}{}
	}
	return sortedKeys(seen)
}

func readSet(path string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range readLines(path) {
		if name := NormalizeDomain(line); name != "" {
			out[name] = struct{}{}
		}
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

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func ensureDirs(runDir string) error {
	for _, dir := range []string{"raw", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}
