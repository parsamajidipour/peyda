package urlrecon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/deps"
)

type Options struct {
	RunDir  string
	Target  string
	Profile string
	Tools   config.Tools
	Out     io.Writer
}

type Result struct {
	URLs        int
	Parameters  int
	JSEndpoints int
}

func RunGau(opts Options) error {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "[url] Fetching historical URLs with gau...\n")
	return runGau(opts.RunDir, opts.Target, opts.Tools.Gau)
}

func RunPostJS(opts Options) (Result, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if err := ensureDirs(opts.RunDir); err != nil {
		return Result{}, err
	}

	fmt.Fprintf(opts.Out, "[url] Normalizing URL inventory...\n")
	urls := combineURLs(opts.RunDir)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/urls.txt"), urls); err != nil {
		return Result{}, err
	}

	fmt.Fprintf(opts.Out, "[param] Extracting parameters from URLs and Arjun...\n")
	params := extractParameters(urls)
	params = append(params, runArjun(opts.RunDir, opts.Tools.Arjun)...)
	params = uniqueRows(params)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/parameters.tsv"), append([]string{"name\turl\tsource"}, params...)); err != nil {
		return Result{}, err
	}

	fmt.Fprintf(opts.Out, "[js] Extracting JS endpoints with xnLinkFinder fallback...\n")
	endpoints := collectJSEndpoints(opts.RunDir, opts.Tools.XNLinkFinder)
	if err := writeLines(filepath.Join(opts.RunDir, "normalized/js-endpoints.txt"), endpoints); err != nil {
		return Result{}, err
	}

	return Result{URLs: len(urls), Parameters: len(params), JSEndpoints: len(endpoints)}, nil
}

func runGau(runDir, target string, tool config.GauTool) error {
	output := filepath.Join(runDir, "raw/gau-urls.txt")
	path, err := deps.LookPath("gau")
	if err != nil {
		return writeLines(output, nil)
	}
	args := []string{}
	if tool.Subs {
		args = append(args, "--subs")
	}
	if len(tool.Providers) > 0 {
		args = append(args, "--providers", strings.Join(tool.Providers, ","))
	}
	if tool.Retries > 0 {
		args = append(args, "--retries", fmt.Sprint(tool.Retries))
	}
	if tool.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprint(tool.Timeout))
	}
	if tool.Threads > 0 {
		args = append(args, "--threads", fmt.Sprint(tool.Threads))
	}
	args = append(args, target)
	cmd := exec.Command(path, args...)
	cmd.Stdout = nil
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	data, err := cmd.Output()
	if err != nil {
		return writeLines(output, nil)
	}
	return os.WriteFile(output, data, 0o644)
}

func combineURLs(runDir string) []string {
	seen := map[string]struct{}{}
	for _, path := range []string{
		filepath.Join(runDir, "raw/gau-urls.txt"),
		filepath.Join(runDir, "raw/katana-urls.txt"),
	} {
		for _, line := range readLines(path) {
			if isHTTPURL(line) {
				seen[line] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

func extractParameters(urls []string) []string {
	seen := map[string]struct{}{}
	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.RawQuery == "" {
			continue
		}
		for name := range parsed.Query() {
			if name == "" {
				continue
			}
			clean := parameterTemplate(parsed, name)
			seen[name+"\t"+clean+"\turl"] = struct{}{}
		}
	}
	return sortedKeys(seen)
}

func runArjun(runDir string, tool config.ArjunTool) []string {
	if !tool.Enabled {
		return nil
	}
	path, err := deps.LookPath("arjun")
	if err != nil {
		return nil
	}
	live := readLines(filepath.Join(runDir, "normalized/live-urls.txt"))
	if len(live) == 0 {
		return nil
	}
	output := filepath.Join(runDir, "raw/arjun.json")
	args := []string{"-i", filepath.Join(runDir, "normalized/live-urls.txt"), "-oJ", output}
	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	if err := cmd.Run(); err != nil {
		return nil
	}
	data, err := os.ReadFile(output)
	if err != nil {
		return nil
	}
	return parseArjunJSON(data)
}

func parseArjunJSON(data []byte) []string {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var walk func(any, string)
	walk = func(value any, currentURL string) {
		switch typed := value.(type) {
		case map[string]any:
			nextURL := currentURL
			for _, key := range []string{"url", "target", "endpoint"} {
				if raw, ok := typed[key].(string); ok && strings.HasPrefix(raw, "http") {
					nextURL = raw
				}
			}
			for _, key := range []string{"params", "parameters"} {
				if raw, ok := typed[key]; ok {
					walk(raw, nextURL)
				}
			}
			for _, raw := range typed {
				walk(raw, nextURL)
			}
		case []any:
			for _, item := range typed {
				walk(item, currentURL)
			}
		case string:
			if regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`).MatchString(typed) && currentURL != "" {
				seen[typed+"\t"+appendQuery(currentURL, typed)+"\tarjun"] = struct{}{}
			}
		}
	}
	walk(root, "")
	return sortedKeys(seen)
}

func collectJSEndpoints(runDir string, tool config.XNLinkFinderTool) []string {
	xn := runXNLinkFinder(runDir, tool)
	fallback := readLines(filepath.Join(runDir, "normalized/js-route-leads.txt"))
	seen := map[string]struct{}{}
	for _, line := range append(xn, fallback...) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		seen[line] = struct{}{}
	}
	return sortedKeys(seen)
}

func runXNLinkFinder(runDir string, tool config.XNLinkFinderTool) []string {
	if !tool.Enabled {
		return nil
	}
	path := lookAny("xnLinkFinder", "xnlinkfinder")
	if path == "" {
		return nil
	}
	jsDir := filepath.Join(runDir, "raw/js")
	output := filepath.Join(runDir, "raw/xnlinkfinder.txt")
	args := []string{"-i", jsDir, "-o", output}
	cmd := exec.Command(path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = deps.WithGoBinFirst(os.Environ())
	if err := cmd.Run(); err != nil {
		return nil
	}
	return readLines(output)
}

func lookAny(names ...string) string {
	for _, name := range names {
		path, err := deps.LookPath(name)
		if err == nil {
			return path
		}
	}
	return ""
}

func parameterTemplate(parsed *url.URL, name string) string {
	copyURL := *parsed
	values := copyURL.Query()
	values.Set(name, "")
	copyURL.RawQuery = values.Encode()
	return strings.ReplaceAll(copyURL.String(), name+"=", name+"=")
}

func appendQuery(rawURL, name string) string {
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	return rawURL + sep + name + "="
}

func isHTTPURL(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func ensureDirs(runDir string) error {
	for _, dir := range []string{"raw", "normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
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

func uniqueRows(rows []string) []string {
	seen := map[string]struct{}{}
	for _, row := range rows {
		seen[row] = struct{}{}
	}
	return sortedKeys(seen)
}
