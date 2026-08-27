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
		port           int
	}{
		{ProfilePassive, 10, 0, 0, "", 0, 0, 0},
		{ProfileBalance, 50, 10, 1, "45s", 75, 20, 50},
		{ProfileBalanced, 50, 10, 1, "45s", 75, 20, 50},
		{ProfileDeep, 25, 5, 5, "30m", 5000, 10, 25},
	}

	for _, tt := range tests {
		cfg := Config{Profile: tt.profile}
		if err := cfg.ApplyProfileDefaults(); err != nil {
			t.Fatal(err)
		}
		if cfg.ProbeRate != tt.probe ||
			cfg.ResultsRoot != "results" ||
			cfg.CrawlRate != tt.crawl ||
			cfg.CrawlDepth != tt.crawlDepth ||
			cfg.CrawlDuration != tt.crawlDuration ||
			cfg.MaxDomainPages != tt.maxDomainPages ||
			cfg.APIRate != tt.api ||
			cfg.PortRate != tt.port {
			t.Fatalf("%s defaults = probe %d crawl %d depth %d duration %q max pages %d api %d port %d",
				tt.profile,
				cfg.ProbeRate,
				cfg.CrawlRate,
				cfg.CrawlDepth,
				cfg.CrawlDuration,
				cfg.MaxDomainPages,
				cfg.APIRate,
				cfg.PortRate,
			)
		}
		if tt.profile == ProfileBalance && cfg.Profile != ProfileBalanced {
			t.Fatalf("balance alias was not normalized: %q", cfg.Profile)
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

func TestDeepProfileExpandsToolIntensity(t *testing.T) {
	cfg := Default()
	cfg.Profile = ProfileDeep
	if err := cfg.ApplyProfileDefaults(); err != nil {
		t.Fatal(err)
	}

	if cfg.Tools.Subfinder.Timeout != 120 || cfg.Tools.Subfinder.MaxTime != 60 {
		t.Fatalf("subfinder deep settings = %+v", cfg.Tools.Subfinder)
	}
	if !cfg.Tools.WHOIS.Verbose {
		t.Fatalf("whois deep settings = %+v", cfg.Tools.WHOIS)
	}
	if len(cfg.Tools.Dig.RecordTypes) < 9 || !cfg.Tools.Dig.Trace || !cfg.Tools.Dig.NSSearch {
		t.Fatalf("dig deep settings = %+v", cfg.Tools.Dig)
	}
	if len(cfg.Tools.DNSX.RecordTypes) < 8 || !cfg.Tools.DNSX.Trace {
		t.Fatalf("dnsx deep settings = %+v", cfg.Tools.DNSX)
	}
	if !cfg.Tools.HTTPX.TLSGrab || !cfg.Tools.HTTPX.ProbeAllIPs || cfg.Tools.HTTPX.Timeout != 20 {
		t.Fatalf("httpx deep settings = %+v", cfg.Tools.HTTPX)
	}
	if cfg.Tools.Naabu.TopPorts != "full" || !cfg.Tools.Naabu.ScanAllIPs || !cfg.Tools.Naabu.ServiceVersion {
		t.Fatalf("naabu deep settings = %+v", cfg.Tools.Naabu)
	}
	if cfg.Tools.Gau.Retries != 5 || cfg.Tools.Gau.Timeout != 120 || cfg.Tools.Gau.Threads != 1 {
		t.Fatalf("gau deep settings = %+v", cfg.Tools.Gau)
	}
	if !cfg.Tools.Katana.Headless || !cfg.Tools.Katana.XHRExtraction || cfg.Tools.Katana.KnownFiles != "all" {
		t.Fatalf("katana deep settings = %+v", cfg.Tools.Katana)
	}
}
