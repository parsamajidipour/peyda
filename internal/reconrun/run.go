package reconrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/parsamajidipour/reconx/internal/config"
	"github.com/parsamajidipour/reconx/internal/deps"
	"github.com/parsamajidipour/reconx/internal/report"
)

func Run(root string, cfg config.Config) error {
	if !cfg.SkipDeps {
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
		if err := passiveSubdomains(root, runDir, cfg.Target); err != nil {
			return err
		}
	default:
		if err := deps.RunCommand(root, os.Stdout, "scripts/subdomain-pass.sh", "-t", cfg.Target, "-r", runDir, "-p", fmt.Sprint(cfg.ProbeRate)); err != nil {
			return err
		}
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
	required := []string{"go.mod", "scripts/subdomain-pass.sh"}
	for _, rel := range required {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil || info.IsDir() {
			return false
		}
	}
	return true
}

func passiveSubdomains(root, runDir, target string) error {
	fmt.Println("[reconx] passive profile: collecting passive subdomain sources")
	rawDir := filepath.Join(runDir, "raw")
	normalizedDir := filepath.Join(runDir, "normalized")

	subfinderOut := filepath.Join(rawDir, "subfinder.txt")
	if _, err := exec.LookPath("subfinder"); err == nil {
		cmd := exec.Command("subfinder", "-d", target, "-all", "-recursive", "-silent", "-o", subfinderOut)
		cmd.Dir = root
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = deps.WithGoBinFirst(os.Environ())
		_ = cmd.Run()
	} else {
		_ = os.WriteFile(subfinderOut, nil, 0o644)
	}

	names, err := fetchCrtSH(target)
	if err != nil {
		fmt.Fprintf(os.Stdout, "[reconx] crt.sh skipped: %v\n", err)
	}
	crtOut := filepath.Join(rawDir, "crtsh.txt")
	_ = os.WriteFile(crtOut, []byte(strings.Join(names, "\n")), 0o644)

	collected := map[string]struct{}{}
	for _, file := range []string{subfinderOut, crtOut} {
		data, _ := os.ReadFile(file)
		for _, line := range strings.Split(string(data), "\n") {
			name := normalizeDomain(line)
			if name != "" {
				collected[name] = struct{}{}
			}
		}
	}

	list := make([]string, 0, len(collected))
	for name := range collected {
		list = append(list, name)
	}
	sort.Strings(list)
	content := strings.Join(list, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(filepath.Join(normalizedDir, "subdomains.all.txt"), []byte(content), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(normalizedDir, "subdomains.txt"), []byte(content), 0o644)
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimSuffix(value, ".")
	if value == "" || strings.ContainsAny(value, " \t/") {
		return ""
	}
	return value
}

func fetchCrtSH(target string) ([]string, error) {
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
			name := normalizeDomain(item)
			if name != "" {
				seen[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
