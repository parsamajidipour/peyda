package jsrecon

import (
	"bufio"
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
	Root           string
	RunDir         string
	Target         string
	CrawlRate      int
	CrawlDepth     int
	CrawlDuration  string
	MaxDomainPages int
	Tools          config.Tools
}

type Result struct {
	LiveURLs         int
	CrawledURLs      int
	JavaScriptFiles  int
	DownloadedFiles  int
	InterestingLines int
	RouteLeads       int
}

type Lead struct {
	Route          string
	Source         string
	AuthGuess      string
	ObjectOrAction string
	NextStep       string
}

var jsURLPattern = regexp.MustCompile(`https?://[^"'<> )]+\.js[^"'<> )]*|/[^"'<> )]+\.js[^"'<> )]*`)
var routePattern = regexp.MustCompile(`(/api/[A-Za-z0-9_./{}:-]+|/v[0-9]+/[A-Za-z0-9_./{}:-]+|https?://[^"'<> ]+/(api|graphql|v[0-9])[^"'<> ]*|wss://[^"'<> ]+)`)
var interestingPattern = regexp.MustCompile(`(?i)(/api/|/v[0-9]+/|graphql|websocket|wss://|swagger|openapi|admin|internal|webhook|sourceMappingURL|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})`)
var sourceMapPattern = regexp.MustCompile(`sourceMappingURL=([^"'<> )]+)`)
var secretRedactPattern = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})`)

func Run(opts Options) (Result, error) {
	if opts.CrawlRate == 0 {
		opts.CrawlRate = 20
	}
	if opts.CrawlDepth == 0 {
		opts.CrawlDepth = 1
	}
	if opts.CrawlDuration == "" {
		opts.CrawlDuration = "45s"
	}
	if opts.MaxDomainPages == 0 {
		opts.MaxDomainPages = 75
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	logPath := filepath.Join(opts.RunDir, "notes/js-recon.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return Result{}, err
	}
	defer logFile.Close()
	log := func(format string, args ...any) {
		fmt.Printf(format+"\n", args...)
		fmt.Fprintf(logFile, format+"\n", args...)
	}

	liveHosts := filepath.Join(opts.RunDir, "normalized/live-hosts.txt")
	if _, err := os.Stat(liveHosts); err != nil {
		return Result{}, fmt.Errorf("missing %s; run peyda with balanced or deep profile first", liveHosts)
	}

	liveURLs := firstFields(readLines(liveHosts))
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/live-urls.txt"), liveURLs); err != nil {
		return Result{}, err
	}

	log("[js] Crawling live URLs with katana...")
	log("[js] crawl_rate=%d crawl_depth=%d crawl_duration=%s max_domain_pages=%d strategy=%s",
		opts.CrawlRate, opts.CrawlDepth, opts.CrawlDuration, opts.MaxDomainPages, opts.Tools.Katana.Strategy)
	if err := runKatana(opts); err != nil {
		return Result{}, err
	}
	allCrawled, scopedCrawled, err := normalizeKatanaOutput(opts.RunDir, opts.Target)
	if err != nil {
		return Result{}, err
	}
	log("[js] katana_urls=%d scoped_urls=%d", len(allCrawled), len(scopedCrawled))

	crawled := readLines(filepath.Join(opts.RunDir, "raw/katana-urls.txt"))
	log("[js] Extracting JavaScript URLs...")
	jsFiles := ExtractJSURLs(crawled, liveURLs)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/js-files.txt"), jsFiles); err != nil {
		return Result{}, err
	}

	log("[js] Downloading JavaScript files...")
	if err := resetDir(filepath.Join(opts.RunDir, "raw/js")); err != nil {
		return Result{}, err
	}
	downloaded, err := downloadJavaScript(opts.RunDir, jsFiles)
	if err != nil {
		return Result{}, err
	}

	log("[js] Extracting routes and high-signal lines...")
	interesting, routes, sourceMaps := extractFromRun(opts.RunDir, crawled)
	routes = filterRoutesInScope(routes, opts.Target)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/js-interesting-lines.txt"), interesting); err != nil {
		return Result{}, err
	}
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/js-route-leads.txt"), routes); err != nil {
		return Result{}, err
	}
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/source-map-candidates.txt"), sourceMaps); err != nil {
		return Result{}, err
	}
	if err := writeLeads(filepath.Join(opts.RunDir, "notes/js-leads.tsv"), BuildLeads(routes)); err != nil {
		return Result{}, err
	}

	result := Result{
		LiveURLs:         len(liveURLs),
		CrawledURLs:      len(crawled),
		JavaScriptFiles:  len(jsFiles),
		DownloadedFiles:  downloaded,
		InterestingLines: len(interesting),
		RouteLeads:       len(routes),
	}
	log("[js] live_urls=%d crawled=%d js_files=%d downloaded=%d routes=%d",
		result.LiveURLs, result.CrawledURLs, result.JavaScriptFiles, result.DownloadedFiles, result.RouteLeads)
	return result, nil
}

func ExtractJSURLs(lines, baseURLs []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		for _, match := range jsURLPattern.FindAllString(line, -1) {
			match = strings.TrimRight(match, `"'()`)
			if strings.HasPrefix(match, "http://") || strings.HasPrefix(match, "https://") {
				seen[match] = struct{}{}
				continue
			}
			for _, base := range baseURLs {
				if resolved := resolveRelative(base, match); resolved != "" {
					seen[resolved] = struct{}{}
				}
			}
		}
	}
	return sortedKeys(seen)
}

func BuildLeads(routes []string) []Lead {
	leads := make([]Lead, 0, len(routes))
	for _, route := range routes {
		lead := Lead{
			Route:          route,
			Source:         "js/katana",
			AuthGuess:      "unknown",
			ObjectOrAction: inferObjectOrAction(route),
			NextStep:       "manual-review",
		}
		lower := strings.ToLower(route)
		if regexp.MustCompile(`(org|tenant|workspace|account|project|user)`).MatchString(lower) {
			lead.NextStep = "authorization-matrix"
		}
		if regexp.MustCompile(`(admin|billing|export|invite|webhook|token)`).MatchString(lower) {
			lead.NextStep += ",high-signal"
		}
		leads = append(leads, lead)
	}
	return leads
}

func runKatana(opts Options) error {
	katanaPath, err := deps.LookPath("katana")
	if err != nil {
		return err
	}
	output := filepath.Join(opts.RunDir, "raw/katana-urls.txt")
	_ = os.Remove(output)
	_ = os.Remove(filepath.Join(opts.RunDir, "raw/katana-urls.all.txt"))
	input := filepath.Join(opts.RunDir, "normalized/live-urls.txt")
	cmd := exec.Command(katanaPath, katanaArgs(opts.Tools.Katana, input, output, opts)...)
	cmd.Dir = opts.Root
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	if err := cmd.Run(); err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

func katanaArgs(tool config.KatanaTool, input, output string, opts Options) []string {
	args := []string{
		"-list", input,
		"-silent",
		"-nc",
		"-d", strconv.Itoa(opts.CrawlDepth),
		"-ct", opts.CrawlDuration,
		"-mdp", strconv.Itoa(opts.MaxDomainPages),
		"-rl", strconv.Itoa(opts.CrawlRate),
	}
	if tool.JSCrawl {
		args = append(args, "-jc")
	}
	if tool.IgnoreQueryParams {
		args = append(args, "-iqp")
	}
	if tool.FilterSimilar {
		args = append(args, "-fsu")
	}
	if tool.KnownFiles != "" {
		args = append(args, "-kf", tool.KnownFiles)
	}
	if tool.FieldScope != "" {
		args = append(args, "-fs", tool.FieldScope)
	}
	if tool.Strategy != "" {
		args = append(args, "-s", tool.Strategy)
	}
	if tool.Headless {
		args = append(args, "-hl")
	}
	if tool.XHRExtraction {
		args = append(args, "-xhr")
	}
	if tool.DisplayOutScope {
		args = append(args, "-do")
	}
	return append(args, "-o", output)
}

func normalizeKatanaOutput(runDir, target string) ([]string, []string, error) {
	output := filepath.Join(runDir, "raw/katana-urls.txt")
	all := unique(readLines(output))
	if err := writeLines(filepath.Join(runDir, "raw/katana-urls.all.txt"), all); err != nil {
		return nil, nil, err
	}

	scoped := filterInScopeURLs(all, target)
	if err := writeLines(output, scoped); err != nil {
		return nil, nil, err
	}
	return all, scoped, nil
}

func filterInScopeURLs(lines []string, target string) []string {
	target = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), "*.")
	target = strings.TrimSuffix(target, ".")
	if target == "" {
		return unique(lines)
	}

	var scoped []string
	for _, line := range lines {
		cleaned := strings.TrimSpace(line)
		if cleaned == "" || strings.Contains(cleaned, `\`) || strings.Contains(strings.ToLower(cleaned), "%5c") {
			continue
		}
		parsed, err := url.Parse(cleaned)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "wss" {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		if host == target || strings.HasSuffix(host, "."+target) {
			scoped = append(scoped, cleaned)
		}
	}
	return unique(scoped)
}

func filterRoutesInScope(routes []string, target string) []string {
	target = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), "*.")
	target = strings.TrimSuffix(target, ".")
	if target == "" {
		return unique(routes)
	}

	var scoped []string
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}
		if strings.HasPrefix(route, "/") {
			scoped = append(scoped, route)
			continue
		}
		parsed, err := url.Parse(route)
		if err != nil || parsed.Host == "" {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		if host == target || strings.HasSuffix(host, "."+target) {
			scoped = append(scoped, route)
		}
	}
	return unique(scoped)
}

func resetDir(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

func downloadJavaScript(runDir string, urls []string) (int, error) {
	client := http.Client{Timeout: 20 * time.Second}
	count := 0
	for _, rawURL := range urls {
		if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
			continue
		}
		resp, err := client.Get(rawURL)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode >= 400 {
			continue
		}
		output := filepath.Join(runDir, "raw/js", safeName(rawURL))
		if err := os.WriteFile(output, body, 0o644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func extractFromRun(runDir string, crawled []string) ([]string, []string, []string) {
	var interesting []string
	routeSet := map[string]struct{}{}
	sourceMapSet := map[string]struct{}{}

	addLine := func(source string, lineNo int, line string) {
		for _, route := range routePattern.FindAllString(line, -1) {
			routeSet[route] = struct{}{}
		}
		for _, match := range sourceMapPattern.FindAllStringSubmatch(line, -1) {
			if len(match) > 1 {
				sourceMapSet[match[1]] = struct{}{}
			}
		}
		if interestingPattern.MatchString(line) {
			interesting = append(interesting, fmt.Sprintf("%s:%d:%s", source, lineNo, redactSecrets(line)))
		}
	}

	for i, line := range crawled {
		addLine("raw/katana-urls.txt", i+1, line)
	}

	jsDir := filepath.Join(runDir, "raw/js")
	_ = filepath.WalkDir(jsDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(runDir, path)
		if err != nil {
			rel = path
		}
		for lineNo, line := range readLinesWithBlanks(path) {
			addLine(filepath.ToSlash(rel), lineNo+1, line)
		}
		return nil
	})

	sort.Strings(interesting)
	return unique(interesting), sortedKeys(routeSet), sortedKeys(sourceMapSet)
}

func resolveRelative(base, relative string) string {
	parsedBase, err := url.Parse(base)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
		return ""
	}
	ref, err := url.Parse(relative)
	if err != nil {
		return ""
	}
	return parsedBase.ResolveReference(ref).String()
}

func inferObjectOrAction(route string) string {
	route = strings.TrimPrefix(route, "https://")
	route = strings.TrimPrefix(route, "http://")
	if idx := strings.Index(route, "/"); idx >= 0 {
		route = route[idx:]
	}
	segments := strings.Split(strings.Trim(route, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		return segment
	}
	return "unknown"
}

func redactSecrets(line string) string {
	return secretRedactPattern.ReplaceAllString(line, "<redacted-pattern>")
}

func firstFields(lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			seen[fields[0]] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func writeLeads(path string, leads []Lead) error {
	lines := []string{"route\tsource\tauth_guess\tobject_or_action\tnext_step"}
	for _, lead := range leads {
		lines = append(lines, strings.Join([]string{
			lead.Route,
			lead.Source,
			lead.AuthGuess,
			lead.ObjectOrAction,
			lead.NextStep,
		}, "\t"))
	}
	return writeLines(path, lines)
}

func safeName(value string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
	name := strings.Trim(re.ReplaceAllString(value, "_"), "_")
	if name == "" {
		return "bundle.js"
	}
	return name
}

func readLines(path string) []string {
	var out []string
	for _, line := range readLinesWithBlanks(path) {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func readLinesWithBlanks(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
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

func ensureDirs(runDir string) error {
	for _, dir := range []string{"raw/js", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}
