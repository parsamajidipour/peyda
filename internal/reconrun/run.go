package reconrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parsamajidipour/reconx/internal/apidiscovery"
	"github.com/parsamajidipour/reconx/internal/cloud"
	"github.com/parsamajidipour/reconx/internal/config"
	"github.com/parsamajidipour/reconx/internal/deps"
	"github.com/parsamajidipour/reconx/internal/jsrecon"
	"github.com/parsamajidipour/reconx/internal/report"
	"github.com/parsamajidipour/reconx/internal/subdomain"
)

func Run(root string, cfg config.Config) error {
	if !cfg.SkipDeps && cfg.Profile != config.ProfilePassive {
		if err := deps.Run(root, deps.Ensure, os.Stdout); err != nil {
			return err
		}
	}

	runDir, err := Init(cfg)
	if err != nil {
		return err
	}

	switch cfg.Profile {
	case config.ProfilePassive:
		_, err = subdomain.Run(subdomain.Options{
			Root:    root,
			RunDir:  runDir,
			Target:  cfg.Target,
			Resolve: false,
			Probe:   false,
			Tools:   cfg.Tools,
		})
	default:
		_, err = subdomain.Run(subdomain.Options{
			Root:      root,
			RunDir:    runDir,
			Target:    cfg.Target,
			ProbeRate: cfg.ProbeRate,
			Resolve:   true,
			Probe:     true,
			Tools:     cfg.Tools,
		})
	}
	if err != nil {
		return err
	}

	switch cfg.Profile {
	case config.ProfilePassive:
	default:
		if _, err := jsrecon.Run(jsrecon.Options{
			Root:           root,
			RunDir:         runDir,
			Target:         cfg.Target,
			CrawlRate:      cfg.CrawlRate,
			CrawlDepth:     cfg.CrawlDepth,
			CrawlDuration:  cfg.CrawlDuration,
			MaxDomainPages: cfg.MaxDomainPages,
			Tools:          cfg.Tools,
		}); err != nil {
			fmt.Fprintf(os.Stdout, "[reconx] JS recon skipped or failed: %v\n", err)
		}
		if _, err := apidiscovery.Run(apidiscovery.Options{
			Root:      root,
			RunDir:    runDir,
			ProbeRate: cfg.APIRate,
			Tools:     cfg.Tools,
		}); err != nil {
			return err
		}
		if _, err := cloud.Run(runDir); err != nil {
			return err
		}
	}

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

	fmt.Printf("\n[INF] Recon complete\n")
	fmt.Printf("[INF] Output directory: %s\n", runDir)
	fmt.Printf("[INF] Text report: %s\n", filepath.Join(runDir, "notes/recon-report.txt"))
	fmt.Printf("[INF] Markdown summary: %s\n", filepath.Join(runDir, "notes/recon-summary.md"))
	if cfg.WriteJSONL {
		fmt.Printf("[INF] JSONL events: %s\n", filepath.Join(runDir, "normalized/recon-events.jsonl"))
	}
	return nil
}

func Init(cfg config.Config) (string, error) {
	safeTarget := strings.TrimSuffix(strings.ToLower(cfg.Target), "/")
	if safeTarget == "" {
		return "", errors.New("target is required")
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
		"target=%s\nrun_date=%s\nprofile=%s\ncreated_utc=%s\noutput_root=%s\ncrawl_depth=%d\ncrawl_duration=%s\nmax_domain_pages=%d\n",
		safeTarget,
		runDate,
		cfg.Profile,
		time.Now().UTC().Format(time.RFC3339),
		outputRoot,
		cfg.CrawlDepth,
		cfg.CrawlDuration,
		cfg.MaxDomainPages,
	)
	if err := os.WriteFile(filepath.Join(runDir, "notes/run-metadata.txt"), []byte(meta), 0o644); err != nil {
		return "", err
	}
	return runDir, nil
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
	if home := os.Getenv("RECONX_HOME"); home != "" {
		if hasReconFiles(home) {
			return home, nil
		}
		return "", fmt.Errorf("RECONX_HOME does not contain reconx files: %s", home)
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
	return "", errors.New("could not find repository root; run inside the repo or set RECONX_HOME")
}

func hasReconFiles(dir string) bool {
	required := []string{"go.mod", "cmd/reconx/main.go"}
	for _, rel := range required {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}
