package reconrun

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parsamajidipour/peyda/internal/apidiscovery"
	"github.com/parsamajidipour/peyda/internal/cloud"
	"github.com/parsamajidipour/peyda/internal/config"
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
	logOut := io.Discard

	if !cfg.SkipDeps && cfg.Profile != config.ProfilePassive {
		if err := deps.Run(root, deps.Ensure, logOut); err != nil {
			return err
		}
	}

	runDir, err := Init(cfg)
	if err != nil {
		return err
	}

	if _, err := hostinfo.Run(hostinfo.Options{
		RunDir:  runDir,
		Target:  cfg.Target,
		Profile: cfg.Profile,
		Tools:   cfg.Tools,
		Out:     logOut,
	}); err != nil {
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
			Out:     logOut,
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
			Out:       logOut,
		})
	}
	if err != nil {
		return err
	}

	switch cfg.Profile {
	case config.ProfilePassive:
	default:
		if _, err := ports.Run(ports.Options{
			RunDir:  runDir,
			Profile: cfg.Profile,
			Rate:    cfg.PortRate,
			Tools:   cfg.Tools,
			Out:     logOut,
		}); err != nil {
			fmt.Fprintf(logOut, "[peyda] port scan skipped or failed: %v\n", err)
		}
		if err := urlrecon.RunGau(urlrecon.Options{
			RunDir:  runDir,
			Target:  cfg.Target,
			Profile: cfg.Profile,
			Tools:   cfg.Tools,
			Out:     logOut,
		}); err != nil {
			fmt.Fprintf(logOut, "[peyda] gau URL collection skipped or failed: %v\n", err)
		}
		if _, err := jsrecon.Run(jsrecon.Options{
			Root:           root,
			RunDir:         runDir,
			Target:         cfg.Target,
			CrawlRate:      cfg.CrawlRate,
			CrawlDepth:     cfg.CrawlDepth,
			CrawlDuration:  cfg.CrawlDuration,
			MaxDomainPages: cfg.MaxDomainPages,
			Tools:          cfg.Tools,
			Out:            logOut,
		}); err != nil {
			fmt.Fprintf(logOut, "[peyda] JS recon skipped or failed: %v\n", err)
		}
		if _, err := urlrecon.RunPostJS(urlrecon.Options{
			RunDir:  runDir,
			Target:  cfg.Target,
			Profile: cfg.Profile,
			Tools:   cfg.Tools,
			Out:     logOut,
		}); err != nil {
			fmt.Fprintf(logOut, "[peyda] URL/parameter recon skipped or failed: %v\n", err)
		}
		if _, err := apidiscovery.Run(apidiscovery.Options{
			Root:      root,
			RunDir:    runDir,
			ProbeRate: cfg.APIRate,
			Tools:     cfg.Tools,
			Out:       logOut,
		}); err != nil {
			return err
		}
		if _, err := cloud.RunWithOutput(runDir, logOut); err != nil {
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

	return report.WriteCLIOutput(os.Stdout, runDir, cfg, time.Since(start))
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
