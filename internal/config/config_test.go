package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyProfileDefaults(t *testing.T) {
	tests := []struct {
		profile        string
		probe          int
		crawl          int
		crawlDepth     int
		crawlDuration  string
		maxDomainPages int
		api            int
	}{
		{ProfilePassive, 10, 0, 0, "", 0, 0},
		{ProfileBalanced, 50, 10, 1, "45s", 75, 20},
		{ProfileDeep, 100, 50, 3, "5m", 500, 50},
	}

	for _, tt := range tests {
		cfg := Config{Profile: tt.profile}
		if err := cfg.ApplyProfileDefaults(); err != nil {
			t.Fatal(err)
		}
		if cfg.ProbeRate != tt.probe ||
			cfg.CrawlRate != tt.crawl ||
			cfg.CrawlDepth != tt.crawlDepth ||
			cfg.CrawlDuration != tt.crawlDuration ||
			cfg.MaxDomainPages != tt.maxDomainPages ||
			cfg.APIRate != tt.api {
			t.Fatalf("%s defaults = probe %d crawl %d depth %d duration %q max pages %d api %d",
				tt.profile,
				cfg.ProbeRate,
				cfg.CrawlRate,
				cfg.CrawlDepth,
				cfg.CrawlDuration,
				cfg.MaxDomainPages,
				cfg.APIRate,
			)
		}
	}
}

func TestLoadMergesToolDefaultsWithOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peyda.json")
	body := `{
  "target": "example.com",
  "tools": {
    "subfinder": {
      "recursive": false
    },
    "katana": {
      "strategy": "breadth-first",
      "known_files": "robotstxt,sitemapxml"
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if !cfg.Tools.Subfinder.All {
		t.Fatal("subfinder.all default was not preserved")
	}
	if cfg.Tools.Subfinder.Recursive {
		t.Fatal("subfinder.recursive override was not applied")
	}
	if cfg.Tools.Katana.Strategy != "breadth-first" {
		t.Fatalf("katana.strategy = %q", cfg.Tools.Katana.Strategy)
	}
	if cfg.Tools.Katana.KnownFiles != "robotstxt,sitemapxml" {
		t.Fatalf("katana.known_files = %q", cfg.Tools.Katana.KnownFiles)
	}
	if !cfg.Tools.Katana.JSCrawl || !cfg.Tools.HTTPX.StatusCode || len(cfg.Tools.DNSX.RecordTypes) != 1 {
		t.Fatalf("tool defaults were not preserved: %+v", cfg.Tools)
	}
}
