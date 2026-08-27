package reconrun

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parsamajidipour/reconx/internal/config"
	"github.com/parsamajidipour/reconx/internal/deps"
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
		})
	default:
		_, err = subdomain.Run(subdomain.Options{
			Root:      root,
			RunDir:    runDir,
			Target:    cfg.Target,
			ProbeRate: cfg.ProbeRate,
			Resolve:   true,
			Probe:     true,
		})
	}
	if err != nil {
		return err
	}

	switch cfg.Profile {
	case config.ProfilePassive:
	default:
		if err := deps.RunCommand(root, os.Stdout, "scripts/js-recon-pass.sh", "-r", runDir, "-p", fmt.Sprint(cfg.CrawlRate)); err != nil {
			fmt.Fprintf(os.Stdout, "[reconx] JS recon skipped or failed: %v\n", err)
		}
		if err := deps.RunCommand(root, os.Stdout, "scripts/api-discovery-pass.sh", "-r", runDir, "-p", fmt.Sprint(cfg.APIRate)); err != nil {
			return err
		}
		if err := deps.RunCommand(root, os.Stdout, "scripts/cloud-candidate-pass.sh", "-r", runDir); err != nil {
			return err
		}
	}

	if cfg.WriteJSONL {
		if err := report.WriteJSONL(runDir); err != nil {
			return err
		}
	}
	if err := report.WriteMarkdown(runDir, cfg); err != nil {
		return err
	}

	fmt.Printf("\nRecon complete.\nSummary:\n  %s\n", filepath.Join(runDir, "notes/recon-summary.md"))
	if cfg.WriteJSONL {
		fmt.Printf("JSONL:\n  %s\n", filepath.Join(runDir, "normalized/recon-events.jsonl"))
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

	meta := fmt.Sprintf("target=%s\nrun_date=%s\nprofile=%s\ncreated_utc=%s\noutput_root=%s\n",
		safeTarget, runDate, cfg.Profile, time.Now().UTC().Format(time.RFC3339), outputRoot)
	if err := os.WriteFile(filepath.Join(runDir, "notes/run-metadata.txt"), []byte(meta), 0o644); err != nil {
		return "", err
	}
	return runDir, nil
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
