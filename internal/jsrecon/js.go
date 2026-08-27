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
	"sync"
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
	MaxJSDownloads int
	Tools          config.Tools
	Out            io.Writer
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
var routePattern = regexp.MustCompile(`(?i)(https?://[^"'<> ]+/(api|graphql|v[0-9]|auth|admin|internal|webhook|oauth)[^"'<> ]*|wss?://[^"'<> ]+|/(api|graphql|v[0-9]|auth|admin|internal|webhook|oauth|login|logout|signin|signup|users?|accounts?|members?|cars|regions|contact-us|ready-car|importer-car)[A-Za-z0-9_./{}\[\]:?=&,%+-]*)`)
var quotedEndpointPattern = regexp.MustCompile(`["']((?:https?://|wss?://|/)[^"'<>\\ ]{1,500})["']`)
var assignmentPattern = regexp.MustCompile(`(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*["']([^"']{1,500})["']`)
var concatPattern = regexp.MustCompile(`(?:^|[^\w$])concat\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*["']([^"']{1,500})["']`)
var plusConcatPattern = regexp.MustCompile(`([A-Za-z_$][A-Za-z0-9_$]*)\s*\+\s*["']([^"']{1,500})["']`)
var interestingPattern = regexp.MustCompile(`(?i)(/api/|/v[0-9]+/|graphql|websocket|wss://|swagger|openapi|admin|internal|webhook|sourceMappingURL|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})`)
var sourceMapPattern = regexp.MustCompile(`sourceMappingURL=([^"'<> )]+)`)
var secretRedactPattern = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})`)
var endpointKeywordPattern = regexp.MustCompile(`(?i)(^|/)(api|graphql|v[0-9]+|auth|admin|internal|webhook|oauth|login|logout|signin|signup|users?|accounts?|members?|cars|regions|contact-us|ready-car|importer-car|filters?|search|details?|makes?|models?|sub-models?)(/|$|[?#])`)

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
	if opts.MaxJSDownloads == 0 {
		opts.MaxJSDownloads = 500
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
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
		fmt.Fprintf(opts.Out, format+"\n", args...)
		fmt.Fprintf(logFile, format+"\n", args...)
	}

	liveHosts := filepath.Join(opts.RunDir, "normalized/live-hosts.txt")
	if _, err := os.Stat(liveHosts); err != nil {
		return Result{}, fmt.Errorf("missing %s; run peyda first", liveHosts)
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

	downloadTargets := prioritizeJavaScript(jsFiles, opts.MaxJSDownloads)
	if len(downloadTargets) < len(jsFiles) {
		log("[js] Downloading JavaScript files... total=%d selected=%d", len(jsFiles), len(downloadTargets))
	} else {
		log("[js] Downloading JavaScript files... total=%d", len(downloadTargets))
	}
	if err := resetDir(filepath.Join(opts.RunDir, "raw/js")); err != nil {
		return Result{}, err
	}
	downloaded, err := downloadJavaScript(opts.RunDir, downloadTargets, opts.Tools.Katana.Concurrency, log)
	if err != nil {
		return Result{}, err
	}

	log("[js] Extracting routes and high-signal lines...")
	interesting, routes, sourceMaps := extractFromRun(opts.RunDir, crawled, jsFiles, opts.Target)
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
			if err != nil {
				return err
			}
			file, err := os.OpenFile(output, os.O_CREATE, 0o644)
			if err != nil {
				return err
			}
			return file.Close()
		case <-ticker.C:
			fmt.Fprintf(opts.Out, "[js] katana still running... urls=%d\n", countLines(output))
		}
	}
}

func prioritizeJavaScript(urls []string, limit int) []string {
	if limit <= 0 || len(urls) <= limit {
		return urls
	}
	score := func(value string) int {
		lower := strings.ToLower(value)
		points := 0
		for _, needle := range []string{"api", "auth", "login", "user", "admin", "dashboard", "account", "payment", "checkout", "config", "env"} {
			if strings.Contains(lower, needle) {
				points += 10
			}
		}
		if strings.Contains(lower, "_next/static/chunks") || strings.Contains(lower, "/assets/") {
			points += 3
		}
		if strings.Contains(lower, "cdn-cgi") || strings.Contains(lower, "challenge-platform") {
			points -= 20
		}
		if strings.Contains(lower, ".map") {
			points -= 5
		}
		return points
	}

	prioritized := append([]string(nil), urls...)
	sort.SliceStable(prioritized, func(i, j int) bool {
		left := score(prioritized[i])
		right := score(prioritized[j])
		if left == right {
			return prioritized[i] < prioritized[j]
		}
		return left > right
	})
	return prioritized[:limit]
}

func downloadJavaScript(runDir string, urls []string, concurrency int, log func(string, ...any)) (int, error) {
	if concurrency <= 0 {
		concurrency = 5
	}
	if concurrency > 10 {
		concurrency = 10
	}

	client := &http.Client{Timeout: 10 * time.Second}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	processed := 0
	var firstErr error

	worker := func() {
		defer wg.Done()
		for rawURL := range jobs {
			ok, err := fetchJavaScript(client, runDir, rawURL)
			mu.Lock()
			processed++
			if err != nil && firstErr == nil {
				firstErr = err
			}
			if ok {
				count++
			}
			if log != nil && (processed == len(urls) || processed%100 == 0) {
				log("[js] download progress %d/%d saved=%d", processed, len(urls), count)
			}
			mu.Unlock()
		}
	}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker()
	}
	for _, rawURL := range urls {
		if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
			jobs <- rawURL
		}
	}
	close(jobs)
	wg.Wait()
	return count, firstErr
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

func fetchJavaScript(client *http.Client, runDir, rawURL string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("User-Agent", "peyda-recon")
	resp, err := client.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return false, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, nil
	}
	output := filepath.Join(runDir, "raw/js", safeName(rawURL))
	if err := os.WriteFile(output, body, 0o644); err != nil {
		return false, err
	}
	return true, nil
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
	if tool.Concurrency > 0 {
		args = append(args, "-c", strconv.Itoa(tool.Concurrency))
	}
	if tool.Parallelism > 0 {
		args = append(args, "-p", strconv.Itoa(tool.Parallelism))
	}
	if tool.HostRateLimit > 0 {
		args = append(args, "-hrl", strconv.Itoa(tool.HostRateLimit))
	}
	if tool.JSCrawl {
		args = append(args, "-jc")
	}
	if tool.JSLuice {
		args = append(args, "-jsl")
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
	if tool.FormExtraction {
		args = append(args, "-fx")
	}
	if tool.TechDetect {
		args = append(args, "-td")
	}
	if tool.PathClimb {
		args = append(args, "-pc")
	}
	if tool.KnowledgeBase {
		args = append(args, "-kb")
	}
	if tool.StoreField != "" {
		args = append(args, "-sf", tool.StoreField)
	}
	if tool.DisplayOutScope {
		args = append(args, "-do")
	}
	return append(args, "-o", output)
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
		route = normalizeRouteCandidate(route, target)
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

func extractFromRun(runDir string, crawled, jsFiles []string, target string) ([]string, []string, []string) {
	var interesting []string
	routeSet := map[string]struct{}{}
	sourceMapSet := map[string]struct{}{}

	addLine := func(source string, lineNo int, line string, bases map[string]string) {
		extractEndpointCandidates(line, target, bases, routeSet)
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
		addLine("raw/katana-urls.txt", i+1, line, map[string]string{})
	}

	for _, jsURL := range jsFiles {
		if route := nextAppRouteFromJSURL(jsURL); route != "" {
			routeSet[route] = struct{}{}
		}
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
		bases := map[string]string{}
		for lineNo, line := range readLinesWithBlanks(path) {
			addLine(filepath.ToSlash(rel), lineNo+1, line, bases)
		}
		return nil
	})

	sort.Strings(interesting)
	return unique(interesting), sortedKeys(routeSet), sortedKeys(sourceMapSet)
}

func extractEndpointCandidates(line, target string, bases map[string]string, routeSet map[string]struct{}) {
	for _, match := range assignmentPattern.FindAllStringSubmatch(line, -1) {
		if len(match) >= 3 {
			value := cleanJSToken(match[2])
			if value != "" {
				bases[match[1]] = value
				addRouteCandidate(routeSet, value, target)
			}
		}
	}
	for _, route := range routePattern.FindAllString(line, -1) {
		addRouteCandidate(routeSet, route, target)
	}
	for _, match := range quotedEndpointPattern.FindAllStringSubmatch(line, -1) {
		if len(match) >= 2 {
			addRouteCandidate(routeSet, match[1], target)
		}
	}
	for _, match := range concatPattern.FindAllStringSubmatch(line, -1) {
		if len(match) >= 3 {
			if joined := joinEndpoint(bases[match[1]], match[2]); joined != "" {
				addRouteCandidate(routeSet, joined, target)
			}
		}
	}
	for _, match := range plusConcatPattern.FindAllStringSubmatch(line, -1) {
		if len(match) >= 3 {
			if joined := joinEndpoint(bases[match[1]], match[2]); joined != "" {
				addRouteCandidate(routeSet, joined, target)
			}
		}
	}
}

func addRouteCandidate(routeSet map[string]struct{}, raw, target string) {
	if clean := normalizeRouteCandidate(raw, target); clean != "" {
		routeSet[clean] = struct{}{}
	}
}

func normalizeRouteCandidate(raw, target string) string {
	value := cleanJSToken(raw)
	value = repairRouteSeparators(value)
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}
	if isNoisyEndpointValue(value) {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return ""
		}
		host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
		target = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target)), "*.")
		target = strings.TrimSuffix(target, ".")
		if target != "" && host != target && !strings.HasSuffix(host, "."+target) {
			return ""
		}
		parsed.Fragment = ""
		if isNoisyEndpointValue(parsed.Path) || isStaticAssetPath(parsed.Path) {
			return ""
		}
		if parsed.Path == "" || parsed.Path == "/" {
			return ""
		}
		if !endpointLikePath(parsed.Path) && parsed.RawQuery == "" {
			return ""
		}
		return parsed.String()
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return ""
	}
	pathOnly := value
	if idx := strings.IndexAny(pathOnly, "?#"); idx >= 0 {
		pathOnly = pathOnly[:idx]
	}
	if isNoisyEndpointValue(pathOnly) || isStaticAssetPath(pathOnly) {
		return ""
	}
	if !endpointLikePath(pathOnly) && !looksLikeAppRoute(pathOnly) {
		return ""
	}
	return value
}

func joinEndpoint(base, suffix string) string {
	base = cleanJSToken(base)
	suffix = cleanJSToken(suffix)
	if base == "" || suffix == "" {
		return ""
	}
	if strings.HasPrefix(suffix, "http://") || strings.HasPrefix(suffix, "https://") ||
		strings.HasPrefix(suffix, "ws://") || strings.HasPrefix(suffix, "wss://") {
		return suffix
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return strings.TrimRight(base, "/") + suffix
}

func cleanJSToken(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	value = strings.ReplaceAll(value, `\/`, `/`)
	value = strings.ReplaceAll(value, `\u002F`, `/`)
	value = strings.ReplaceAll(value, `\u002f`, `/`)
	value = strings.TrimRight(value, `,;.)`)
	return value
}

func repairRouteSeparators(value string) string {
	replacements := map[string]string{
		":localeauth/":   ":locale/auth/",
		"}auth/":         "}/auth/",
		":localesign":    ":locale/sign",
		"}sign":          "}/sign",
		":localecontact": ":locale/contact",
		"}contact":       "}/contact",
	}
	for old, replacement := range replacements {
		value = strings.ReplaceAll(value, old, replacement)
	}
	return value
}

func endpointLikePath(path string) bool {
	return endpointKeywordPattern.MatchString(path)
}

func looksLikeAppRoute(path string) bool {
	if path == "/" || !strings.HasPrefix(path, "/") {
		return false
	}
	if strings.Contains(path, "{") || strings.Contains(path, "[") || strings.Contains(path, "/:") {
		return true
	}
	return false
}

func isStaticAssetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range []string{
		".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip", ".mp4", ".mp3",
	} {
		if strings.Contains(lower, ext) {
			return true
		}
	}
	return strings.Contains(lower, "/_next/static/") || strings.Contains(lower, "/assets/")
}

func isNoisyEndpointValue(value string) bool {
	if strings.ContainsAny(value, "<>") || strings.Contains(value, "([^") {
		return true
	}
	unescaped, err := url.PathUnescape(value)
	if err == nil && (strings.ContainsAny(unescaped, "<>") || strings.Contains(unescaped, "([^")) {
		return true
	}
	return false
}

func nextAppRouteFromJSURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	path, err := url.PathUnescape(parsed.Path)
	if err != nil {
		path = parsed.Path
	}
	marker := "/_next/static/chunks/app/"
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	routePath := strings.TrimPrefix(path[idx+len(marker):], "/")
	segments := strings.Split(routePath, "/")
	var route []string
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if strings.HasPrefix(segment, "page-") || strings.HasPrefix(segment, "layout-") ||
			strings.HasPrefix(segment, "loading-") || strings.HasPrefix(segment, "not-found-") ||
			strings.HasPrefix(segment, "global-error-") || strings.HasPrefix(segment, "error-") {
			break
		}
		if strings.HasPrefix(segment, "(") && strings.HasSuffix(segment, ")") {
			continue
		}
		route = append(route, strings.ReplaceAll(strings.ReplaceAll(segment, "[", "{"), "]", "}"))
	}
	if len(route) == 0 {
		return ""
	}
	return "/" + strings.Join(route, "/")
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
	scanner.Buffer(make([]byte, 1024), 32*1024*1024)
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
