package reconrun

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/parsamajidipour/peyda/internal/apidiscovery"
	"github.com/parsamajidipour/peyda/internal/cloud"
	"github.com/parsamajidipour/peyda/internal/config"
	"github.com/parsamajidipour/peyda/internal/dataset"
	"github.com/parsamajidipour/peyda/internal/deps"
	"github.com/parsamajidipour/peyda/internal/hostinfo"
	"github.com/parsamajidipour/peyda/internal/jsrecon"
	"github.com/parsamajidipour/peyda/internal/ports"
	"github.com/parsamajidipour/peyda/internal/report"
	"github.com/parsamajidipour/peyda/internal/subdomain"
	"github.com/parsamajidipour/peyda/internal/urlrecon"
)

func Run(root string, cfg config.Config) error {
	start := time.Now()
	cfg.Target = normalizeTarget(cfg.Target)
	if cfg.Target == "" {
		return errors.New("target is required")
	}
	if !validTarget(cfg.Target) {
		return fmt.Errorf("invalid target: %s", cfg.Target)
	}
	logOut := io.Discard
	statusOut := io.Discard
	if cfg.OutputFormat == "human" && !cfg.Silent {
		statusOut = os.Stdout
	}
	moduleOut := logOut
	if cfg.OutputFormat == "human" && !cfg.Silent {
		moduleOut = statusOut
	}
	status := func(message string) {
		fmt.Fprintf(statusOut, "[INF] %s\n", message)
	}

	if !cfg.SkipDeps {
		status("Preparing dependencies")
		if err := deps.Run(root, deps.Ensure, logOut); err != nil {
			return err
		}
	}

	status("Initializing workspace")
	runDir, err := Init(cfg)
	if err != nil {
		return err
	}

	status("Collecting WHOIS and DNS baseline")
	if _, err := hostinfo.Run(hostinfo.Options{
		RunDir: runDir,
		Target: cfg.Target,
		Tools:  cfg.Tools,
		Out:    moduleOut,
	}); err != nil {
		return err
	}

	status("Discovering, resolving, and probing subdomains")
	if _, err = subdomain.Run(subdomain.Options{
		Root:      root,
		RunDir:    runDir,
		Target:    cfg.Target,
		ProbeRate: cfg.ProbeRate,
		Resolve:   true,
		Probe:     true,
		Tools:     cfg.Tools,
		Out:       moduleOut,
	}); err != nil {
		return err
	}

	status("Collecting historical URLs")
	if err := urlrecon.RunGau(urlrecon.Options{
		RunDir: runDir,
		Target: cfg.Target,
		Tools:  cfg.Tools,
		Out:    logOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] gau URL collection skipped or failed: %v\n", err)
	}
	status("Enriching subdomains from URL hosts")
	if _, err := subdomain.EnrichFromURLs(subdomain.Options{
		Root:      root,
		RunDir:    runDir,
		Target:    cfg.Target,
		ProbeRate: cfg.ProbeRate,
		Resolve:   true,
		Probe:     true,
		Tools:     cfg.Tools,
		Out:       moduleOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] URL host enrichment skipped or failed: %v\n", err)
	}
	status(fmt.Sprintf(
		"Crawling live targets and extracting JavaScript (depth=%d duration=%s max_pages=%d max_js_downloads=%d)",
		cfg.CrawlDepth,
		cfg.CrawlDuration,
		cfg.MaxDomainPages,
		cfg.MaxJSDownloads,
	))
	if _, err := jsrecon.Run(jsrecon.Options{
		Root:           root,
		RunDir:         runDir,
		Target:         cfg.Target,
		CrawlRate:      cfg.CrawlRate,
		CrawlDepth:     cfg.CrawlDepth,
		CrawlDuration:  cfg.CrawlDuration,
		MaxDomainPages: cfg.MaxDomainPages,
		MaxJSDownloads: cfg.MaxJSDownloads,
		Tools:          cfg.Tools,
		Out:            moduleOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] JS recon skipped or failed: %v\n", err)
	}
	status("Normalizing URLs, parameters, and endpoints")
	if _, err := urlrecon.RunPostJS(urlrecon.Options{
		RunDir: runDir,
		Target: cfg.Target,
		Tools:  cfg.Tools,
		Out:    moduleOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] URL/parameter recon skipped or failed: %v\n", err)
	}
	status("Rechecking URL-discovered hosts")
	if _, err := subdomain.EnrichFromURLs(subdomain.Options{
		Root:      root,
		RunDir:    runDir,
		Target:    cfg.Target,
		ProbeRate: cfg.ProbeRate,
		Resolve:   true,
		Probe:     true,
		Tools:     cfg.Tools,
		Out:       moduleOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] URL host recheck skipped or failed: %v\n", err)
	}
	status("Scanning optional ports and services")
	if _, err := ports.Run(ports.Options{
		RunDir: runDir,
		Rate:   cfg.PortRate,
		Tools:  cfg.Tools,
		Out:    moduleOut,
	}); err != nil {
		fmt.Fprintf(logOut, "[peyda] port scan skipped or failed: %v\n", err)
	}
	status("Running extended API and cloud analysis")
	if _, err := apidiscovery.Run(apidiscovery.Options{
		Root:      root,
		RunDir:    runDir,
		ProbeRate: cfg.APIRate,
		Tools:     cfg.Tools,
		Out:       moduleOut,
	}); err != nil {
		return err
	}
	if _, err := cloud.RunWithOutput(runDir, logOut); err != nil {
		return err
	}

	status("Writing internal reports")
	if cfg.WriteJSONL {
		if err := report.WriteJSONL(runDir); err != nil {
			return err
		}
	}
	if err := report.WriteText(runDir, cfg); err != nil {
		return err
	}
	if err := report.WriteMarkdown(runDir, cfg); err != nil {
		return err
	}

	duration := time.Since(start)
	status("Building final dataset")
	summary, err := dataset.Export(dataset.Options{
		RunDir:      runDir,
		Target:      cfg.Target,
		ResultsRoot: cfg.ResultsRoot,
		Duration:    duration,
		CompletedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	if cfg.OutputFormat == "human" && !cfg.Silent {
		fmt.Fprintln(os.Stdout)
	}
	return report.WriteDatasetOutput(os.Stdout, cfg, summary)
}

func Init(cfg config.Config) (string, error) {
	safeTarget := normalizeTarget(cfg.Target)
	if safeTarget == "" {
		return "", errors.New("target is required")
	}
	if !validTarget(safeTarget) {
		return "", fmt.Errorf("invalid target: %s", cfg.Target)
	}
	runDate := cfg.RunDate
	if runDate == "" {
		runDate = time.Now().UTC().Format("2006-01-02")
	}
	outputRoot := cfg.OutputRoot
	if outputRoot == "" {
		outputRoot = "runs"
	}
	outputRoot, err := absolutePath(outputRoot)
	if err != nil {
		return "", err
	}

	runDir := filepath.Join(outputRoot, safeTarget, runDate)
	for _, dir := range []string{"raw", "normalized", "screenshots", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return "", err
		}
	}

	if err := os.WriteFile(filepath.Join(runDir, "scope.txt"), []byte(safeTarget+"\n"), 0o644); err != nil {
		return "", err
	}
	if cfg.ExcludedFile != "" {
		data, err := os.ReadFile(cfg.ExcludedFile)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(runDir, "excluded.txt"), data, 0o644); err != nil {
			return "", err
		}
	} else if err := os.WriteFile(filepath.Join(runDir, "excluded.txt"), nil, 0o644); err != nil {
		return "", err
	}

	meta := fmt.Sprintf(
		"target=%s\nrun_date=%s\ncreated_utc=%s\noutput_root=%s\nresults_root=%s\ncrawl_depth=%d\ncrawl_duration=%s\nmax_domain_pages=%d\n",
		safeTarget,
		runDate,
		time.Now().UTC().Format(time.RFC3339),
		outputRoot,
		cfg.ResultsRoot,
		cfg.CrawlDepth,
		cfg.CrawlDuration,
		cfg.MaxDomainPages,
	)
	if err := os.WriteFile(filepath.Join(runDir, "notes/run-metadata.txt"), []byte(meta), 0o644); err != nil {
		return "", err
	}
	return runDir, nil
}

func normalizeTarget(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, "/")
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	return value
}

func validTarget(host string) bool {
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

func absolutePath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func FindRepoRoot() (string, error) {
	if home := os.Getenv("PEYDA_HOME"); home != "" {
		if hasReconFiles(home) {
			return home, nil
		}
		return "", fmt.Errorf("PEYDA_HOME does not contain peyda files: %s", home)
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		if hasReconFiles(dir) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", errors.New("could not find repository root; run inside the repo or set PEYDA_HOME")
}

func hasReconFiles(dir string) bool {
	required := []string{"go.mod", "cmd/peyda/main.go"}
	for _, rel := range required {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}
