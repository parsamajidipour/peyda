package apidiscovery

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/parsamajidipour/reconx/internal/deps"
)

type Options struct {
	Root      string
	RunDir    string
	ProbeRate int
}

type Result struct {
	HostCandidates    int
	DocPathCandidates int
	ProbedDocs        int
	SchemaCandidates  int
	OpenAPIMethods    int
	InventoryRows     int
}

type MethodPath struct {
	Method string
	Path   string
	Source string
}

type InventoryRow struct {
	Method        string
	Host          string
	Path          string
	Auth          string
	Object        string
	BoundaryField string
	Risk          string
	Source        string
	NextTest      string
}

func Run(opts Options) (Result, error) {
	if opts.ProbeRate == 0 {
		opts.ProbeRate = 20
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	logPath := filepath.Join(opts.RunDir, "notes/api-discovery.log")
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
		return Result{}, fmt.Errorf("missing %s; run reconx with balanced or deep profile first", liveHosts)
	}

	log("[api] run_dir=%s probe_rate=%d", opts.RunDir, opts.ProbeRate)
	log("[1/5] Extracting API-looking hosts...")
	hostCandidates := APIHostCandidates(readLines(liveHosts))
	if len(hostCandidates) == 0 {
		hostCandidates = allLiveURLs(readLines(liveHosts))
		log("[api] no API keywords matched; using all live URLs as low-confidence candidates")
	}
	if err := writeLines(filepath.Join(opts.RunDir, "notes/api-host-candidates.txt"), hostCandidates); err != nil {
		return Result{}, err
	}

	log("[2/5] Building common docs/schema path list...")
	docURLs := BuildDocURLs(hostCandidates, loadDocPaths(opts.Root))
	if err := writeLines(filepath.Join(opts.RunDir, "raw/api-doc-paths.txt"), docURLs); err != nil {
		return Result{}, err
	}

	log("[3/5] Probing docs/schema paths...")
	if err := probeDocs(opts); err != nil {
		return Result{}, err
	}
	probed := readLines(filepath.Join(opts.RunDir, "normalized/api-docs-probed.txt"))

	log("[4/5] Downloading and parsing JSON schema candidates...")
	schemaCandidates := SchemaCandidates(probed)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/schema-json-candidates.txt"), schemaCandidates); err != nil {
		return Result{}, err
	}
	methods, err := downloadAndParseSchemas(opts.RunDir, schemaCandidates, logFile)
	if err != nil {
		return Result{}, err
	}
	if err := writeMethods(filepath.Join(opts.RunDir, "normalized/openapi-methods.tsv"), methods); err != nil {
		return Result{}, err
	}

	log("[5/5] Creating endpoint inventory starter...")
	inventory := BuildInventory(methods)
	if err := writeInventory(filepath.Join(opts.RunDir, "normalized/api-inventory.tsv"), inventory); err != nil {
		return Result{}, err
	}

	result := Result{
		HostCandidates:    len(hostCandidates),
		DocPathCandidates: len(docURLs),
		ProbedDocs:        len(probed),
		SchemaCandidates:  len(schemaCandidates),
		OpenAPIMethods:    len(methods),
		InventoryRows:     len(inventory),
	}
	log("[api] hosts=%d doc_paths=%d probed=%d schemas=%d methods=%d inventory=%d",
		result.HostCandidates, result.DocPathCandidates, result.ProbedDocs,
		result.SchemaCandidates, result.OpenAPIMethods, result.InventoryRows)
	return result, nil
}

func APIHostCandidates(lines []string) []string {
	keywords := []string{"api", "graphql", "swagger", "openapi", "developer", "docs", "gateway", "redoc"}
	seen := map[string]struct{}{}
	for _, line := range lines {
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				if url := firstField(line); url != "" {
					seen[url] = struct{}{}
				}
				break
			}
		}
	}
	return sortedKeys(seen)
}

func BuildDocURLs(hosts, paths []string) []string {
	seen := map[string]struct{}{}
	for _, host := range hosts {
		host = strings.TrimRight(strings.TrimSpace(host), "/")
		if host == "" {
			continue
		}
		for _, path := range paths {
			path = strings.TrimSpace(path)
			if path == "" || strings.HasPrefix(path, "#") {
				continue
			}
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			seen[host+path] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func SchemaCandidates(probed []string) []string {
	seen := map[string]struct{}{}
	for _, line := range probed {
		fields := parseHTTPXLine(line)
		if fields["status"] != "200" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "json") ||
			strings.Contains(lower, "openapi") ||
			strings.Contains(lower, "swagger") ||
			strings.Contains(lower, "api-docs") {
			if fields["url"] != "" {
				seen[fields["url"]] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func ExtractOpenAPIMethods(data []byte, source string) ([]MethodPath, error) {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	if len(spec.Paths) == 0 {
		return nil, fmt.Errorf("no paths object")
	}

	allowed := map[string]struct{}{
		"get": {}, "post": {}, "put": {}, "patch": {}, "delete": {}, "head": {}, "options": {},
	}
	var methods []MethodPath
	for path, operations := range spec.Paths {
		for method := range operations {
			method = strings.ToLower(method)
			if _, ok := allowed[method]; ok {
				methods = append(methods, MethodPath{Method: method, Path: path, Source: source})
			}
		}
	}
	sortMethods(methods)
	return methods, nil
}

func BuildInventory(methods []MethodPath) []InventoryRow {
	rows := make([]InventoryRow, 0, len(methods))
	for _, method := range methods {
		rows = append(rows, inventoryRow(method))
	}
	return rows
}

func inventoryRow(method MethodPath) InventoryRow {
	row := InventoryRow{
		Method:        strings.ToUpper(method.Method),
		Host:          hostFromURL(method.Source),
		Path:          method.Path,
		Auth:          "unknown",
		Object:        inferObject(method.Path),
		BoundaryField: "unknown",
		Risk:          "review",
		Source:        method.Source,
		NextTest:      "manual-review",
	}

	if hasBoundaryField(method.Path) {
		row.BoundaryField = "possible"
		row.Risk = "authorization"
		row.NextTest = "authorization-matrix"
	}
	if isHighSignalPath(method.Path) {
		if row.Risk == "review" {
			row.Risk = "high-signal"
		} else {
			row.Risk += ",high-signal"
		}
	}
	return row
}

func probeDocs(opts Options) error {
	httpxPath, err := deps.LookPath("httpx")
	if err != nil {
		return err
	}
	input := filepath.Join(opts.RunDir, "raw/api-doc-paths.txt")
	output := filepath.Join(opts.RunDir, "normalized/api-docs-probed.txt")
	cmd := exec.Command(
		httpxPath,
		"-l", input,
		"-silent",
		"-status-code",
		"-title",
		"-content-type",
		"-content-length",
		"-follow-redirects",
		"-rl", strconv.Itoa(opts.ProbeRate),
		"-o", output,
	)
	cmd.Dir = opts.Root
	cmd.Stdout = os.Stdout
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

func downloadAndParseSchemas(runDir string, urls []string, log io.Writer) ([]MethodPath, error) {
	client := http.Client{Timeout: 20 * time.Second}
	var methods []MethodPath
	for _, url := range urls {
		output := filepath.Join(runDir, "raw/api", safeName(url)+".json")
		body, err := download(client, url, output)
		if err != nil {
			fmt.Fprintf(log, "[api] download skipped %s: %v\n", url, err)
			continue
		}
		extracted, err := ExtractOpenAPIMethods(body, url)
		if err != nil {
			fmt.Fprintf(log, "[api] schema skipped %s: %v\n", url, err)
			continue
		}
		methods = append(methods, extracted...)
	}
	sortMethods(methods)
	return uniqueMethods(methods), nil
}

func download(client http.Client, url, output string) ([]byte, error) {
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
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(output, body, 0o644); err != nil {
		return nil, err
	}
	return body, nil
}

func writeMethods(path string, methods []MethodPath) error {
	lines := make([]string, 0, len(methods))
	for _, method := range methods {
		lines = append(lines, strings.Join([]string{method.Method, method.Path, method.Source}, "\t"))
	}
	return writeLines(path, lines)
}

func writeInventory(path string, rows []InventoryRow) error {
	lines := []string{"method\thost\tpath\tauth\tobject\tboundary_field\trisk\tsource\tnext_test"}
	for _, row := range rows {
		lines = append(lines, strings.Join([]string{
			row.Method,
			row.Host,
			row.Path,
			row.Auth,
			row.Object,
			row.BoundaryField,
			row.Risk,
			row.Source,
			row.NextTest,
		}, "\t"))
	}
	return writeLines(path, lines)
}

func loadDocPaths(root string) []string {
	lines := readLines(filepath.Join(root, "config/api-doc-paths.txt"))
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, line)
	}
	if len(paths) == 0 {
		return []string{"/openapi.json", "/swagger.json", "/api-docs", "/docs", "/swagger-ui/", "/graphql", "/graphiql"}
	}
	return paths
}

func allLiveURLs(lines []string) []string {
	seen := map[string]struct{}{}
	for _, line := range lines {
		if url := firstField(line); url != "" {
			seen[url] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func firstField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func parseHTTPXLine(line string) map[string]string {
	fields := map[string]string{"raw": line}
	if url := firstField(line); url != "" {
		fields["url"] = url
	}
	brackets := extractBrackets(line)
	if len(brackets) > 0 {
		fields["status"] = brackets[0]
	}
	if len(brackets) > 1 {
		fields["title"] = brackets[1]
	}
	if len(brackets) > 2 {
		fields["content_type"] = brackets[2]
	}
	return fields
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

func hasBoundaryField(path string) bool {
	re := regexp.MustCompile(`\{[^}]*((org|tenant|workspace|account|project|user)[Ii]?[Dd]?)\}`)
	return re.MatchString(path)
}

func isHighSignalPath(path string) bool {
	re := regexp.MustCompile(`(?i)(export|download|bulk|invite|role|admin|billing|webhook|token)`)
	return re.MatchString(path)
}

func inferObject(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		segment := segments[i]
		if segment == "" || strings.HasPrefix(segment, "{") {
			continue
		}
		return segment
	}
	return "unknown"
}

func safeName(value string) string {
	re := regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
	return strings.Trim(re.ReplaceAllString(value, "_"), "_")
}

func uniqueMethods(methods []MethodPath) []MethodPath {
	seen := map[string]struct{}{}
	var out []MethodPath
	for _, method := range methods {
		key := method.Method + "\t" + method.Path + "\t" + method.Source
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, method)
	}
	return out
}

func sortMethods(methods []MethodPath) {
	sort.SliceStable(methods, func(i, j int) bool {
		left := methods[i].Source + "\t" + methods[i].Path + "\t" + methods[i].Method
		right := methods[j].Source + "\t" + methods[j].Path + "\t" + methods[j].Method
		return left < right
	})
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
	for _, dir := range []string{"raw/api", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}
