package cloud

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCandidatesClassifiesAndRedacts(t *testing.T) {
	candidates := BuildCandidates(
		[]Match{{Value: "assets.s3.amazonaws.com", File: "normalized/live-hosts.txt", Line: 2}},
		[]Match{{Value: "AKIA1234567890ABCDEF", File: "raw/app.js", Line: 4}},
	)
	if len(candidates) != 2 {
		t.Fatalf("candidates len = %d", len(candidates))
	}

	var sawAWS, sawRedacted bool
	for _, candidate := range candidates {
		if candidate.ProviderOrType == "aws" {
			sawAWS = true
		}
		if candidate.AssetOrString == "<redacted-pattern>" && candidate.ProviderOrType == "possible-aws-key" {
			sawRedacted = true
		}
	}
	if !sawAWS || !sawRedacted {
		t.Fatalf("unexpected candidates: %+v", candidates)
	}
}

func TestRunWritesCloudOutputs(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, "normalized"), 0o755); err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		"https://cdn.example.com [200] [cdn] [cloudfront.net] [100]",
		"token=ghp_abcdefghijklmnopqrstuvwxyzABCDE",
	}, "\n")
	if err := os.WriteFile(filepath.Join(runDir, "normalized/live-hosts.txt"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := Run(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProviderHints == 0 || result.SecretHints == 0 || result.Candidates < 2 {
		t.Fatalf("result = %+v", result)
	}

	candidates, err := os.ReadFile(filepath.Join(runDir, "notes/cloud-candidates.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(candidates), "ghp_abcdefghijklmnopqrstuvwxyzABCDE") {
		t.Fatal("secret-looking token was not redacted")
	}
}
