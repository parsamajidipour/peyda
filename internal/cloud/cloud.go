package cloud

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Result struct {
	ProviderHints int
	SecretHints   int
	Candidates    int
}

type Match struct {
	Value string
	File  string
	Line  int
	Kind  string
}

type Candidate struct {
	AssetOrString       string
	Source              string
	ProviderOrType      string
	OwnershipConfidence string
	ExposureGuess       string
	NextAction          string
}

var cloudPattern = regexp.MustCompile(`(?i)(amazonaws\.com|s3[.-]|cloudfront\.net|storage\.googleapis\.com|googleusercontent\.com|blob\.core\.windows\.net|azurewebsites\.net|digitaloceanspaces\.com|firebaseio\.com|supabase\.co|vercel\.app|netlify\.app|herokuapp\.com)`)
var secretPattern = regexp.MustCompile(`(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})`)

func Run(runDir string) (Result, error) {
	if err := ensureDirs(runDir); err != nil {
		return Result{}, err
	}

	fmt.Println("[cloud] Extracting cloud provider hints...")
	providerMatches, err := scan(runDir, cloudPattern)
	if err != nil {
		return Result{}, err
	}
	if err := writeMatches(filepath.Join(runDir, "normalized/cloud-provider-hints.txt"), providerMatches, false); err != nil {
		return Result{}, err
	}

	fmt.Println("[cloud] Extracting secret-looking strings...")
	secretMatches, err := scan(runDir, secretPattern)
	if err != nil {
		return Result{}, err
	}
	if err := writeMatches(filepath.Join(runDir, "normalized/secret-looking-strings.txt"), secretMatches, true); err != nil {
		return Result{}, err
	}

	candidates := BuildCandidates(providerMatches, secretMatches)
	if err := writeCandidates(filepath.Join(runDir, "notes/cloud-candidates.tsv"), candidates); err != nil {
		return Result{}, err
	}

	result := Result{
		ProviderHints: len(providerMatches),
		SecretHints:   len(secretMatches),
		Candidates:    len(candidates),
	}
	fmt.Printf("[cloud] provider_hints=%d secret_hints=%d candidates=%d\n",
		result.ProviderHints, result.SecretHints, result.Candidates)
	return result, nil
}

func BuildCandidates(providerMatches, secretMatches []Match) []Candidate {
	var candidates []Candidate
	for _, match := range providerMatches {
		candidates = append(candidates, Candidate{
			AssetOrString:       match.Value,
			Source:              source(match),
			ProviderOrType:      classifyProvider(match.Value),
			OwnershipConfidence: "unknown",
			ExposureGuess:       "provider-hint",
			NextAction:          "manual ownership validation",
		})
	}
	for _, match := range secretMatches {
		candidates = append(candidates, Candidate{
			AssetOrString:       "<redacted-pattern>",
			Source:              source(match),
			ProviderOrType:      classifySecret(match.Value),
			OwnershipConfidence: "unknown",
			ExposureGuess:       "secret-looking-string",
			NextAction:          "validate only with explicit permission",
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return strings.Join([]string{candidates[i].Source, candidates[i].ProviderOrType, candidates[i].AssetOrString}, "\t") <
			strings.Join([]string{candidates[j].Source, candidates[j].ProviderOrType, candidates[j].AssetOrString}, "\t")
	})
	return candidates
}

func scan(runDir string, pattern *regexp.Regexp) ([]Match, error) {
	var matches []Match
	err := filepath.WalkDir(runDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path) {
			return nil
		}

		fileMatches, err := scanFile(runDir, path, pattern)
		if err != nil {
			return nil
		}
		matches = append(matches, fileMatches...)
		return nil
	})
	sort.SliceStable(matches, func(i, j int) bool {
		return source(matches[i]) < source(matches[j])
	})
	return matches, err
}

func scanFile(runDir, path string, pattern *regexp.Regexp) ([]Match, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	rel, err := filepath.Rel(runDir, path)
	if err != nil {
		rel = path
	}

	var matches []Match
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, value := range pattern.FindAllString(line, -1) {
			matches = append(matches, Match{Value: value, File: rel, Line: lineNo})
		}
	}
	return matches, scanner.Err()
}

func shouldSkipDir(path string) bool {
	base := filepath.Base(path)
	return base == "screenshots" || base == ".git" || base == "bin" || base == ".cache"
}

func shouldSkipFile(path string) bool {
	normalized := filepath.ToSlash(path)
	skip := []string{
		"normalized/cloud-provider-hints.txt",
		"normalized/secret-looking-strings.txt",
		"notes/cloud-candidates.tsv",
		"normalized/recon-events.jsonl",
		"notes/recon-summary.md",
	}
	for _, suffix := range skip {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func classifyProvider(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "amazonaws") || strings.Contains(lower, "s3") || strings.Contains(lower, "cloudfront"):
		return "aws"
	case strings.Contains(lower, "googleapis") || strings.Contains(lower, "googleusercontent") || strings.Contains(lower, "firebase"):
		return "gcp"
	case strings.Contains(lower, "blob.core.windows") || strings.Contains(lower, "azurewebsites"):
		return "azure"
	case strings.Contains(lower, "vercel") || strings.Contains(lower, "netlify") || strings.Contains(lower, "heroku") || strings.Contains(lower, "supabase"):
		return "paas"
	default:
		return "cloud"
	}
}

func classifySecret(value string) string {
	switch {
	case strings.HasPrefix(value, "AKIA") || strings.HasPrefix(value, "ASIA"):
		return "possible-aws-key"
	case strings.Contains(value, "BEGIN PRIVATE KEY"):
		return "possible-private-key"
	case strings.HasPrefix(value, "xox"):
		return "possible-slack-token"
	case strings.HasPrefix(value, "ghp_"):
		return "possible-github-token"
	case strings.HasPrefix(value, "AIza"):
		return "possible-google-api-key"
	default:
		return "possible-secret"
	}
}

func writeMatches(path string, matches []Match, redact bool) error {
	lines := make([]string, 0, len(matches))
	for _, match := range matches {
		value := match.Value
		if redact {
			value = "<redacted-pattern>"
		}
		lines = append(lines, fmt.Sprintf("%s:%d:%s", match.File, match.Line, value))
	}
	return writeLines(path, lines)
}

func writeCandidates(path string, candidates []Candidate) error {
	lines := []string{"asset_or_string\tsource\tprovider_or_type\townership_confidence\texposure_guess\tnext_action"}
	for _, candidate := range candidates {
		lines = append(lines, strings.Join([]string{
			candidate.AssetOrString,
			candidate.Source,
			candidate.ProviderOrType,
			candidate.OwnershipConfidence,
			candidate.ExposureGuess,
			candidate.NextAction,
		}, "\t"))
	}
	return writeLines(path, lines)
}

func source(match Match) string {
	return fmt.Sprintf("%s:%d", match.File, match.Line)
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

func ensureDirs(runDir string) error {
	for _, dir := range []string{"normalized", "notes"} {
		if err := os.MkdirAll(filepath.Join(runDir, dir), 0o755); err != nil {
			return err
		}
	}
	return nil
}
