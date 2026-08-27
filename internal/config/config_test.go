package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyDefaultsUsesSingleDeepMode(t *testing.T) {
	cfg := Config{}
	if err := cfg.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}
	if cfg.OutputRoot != "runs" ||
		cfg.ResultsRoot != "results" ||
		cfg.ProbeRate != 25 ||
		cfg.CrawlRate != 5 ||
		cfg.CrawlDepth != 5 ||
		cfg.CrawlDuration != "30m" ||
		cfg.MaxDomainPages != 5000 ||
		cfg.APIRate != 10 ||
		cfg.PortRate != 25 {
		t.Fatalf("defaults = %+v", cfg)
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
	if !cfg.Tools.Katana.JSCrawl || !cfg.Tools.HTTPX.StatusCode || len(cfg.Tools.DNSX.RecordTypes) < 8 {
		t.Fatalf("tool defaults were not preserved: %+v", cfg.Tools)
	}
}

func TestDefaultToolsUseDeepIntensity(t *testing.T) {
	cfg := Default()
	if err := cfg.ApplyDefaults(); err != nil {
		t.Fatal(err)
	}

	if cfg.Tools.Subfinder.Timeout != 120 || cfg.Tools.Subfinder.MaxTime != 60 {
		t.Fatalf("subfinder settings = %+v", cfg.Tools.Subfinder)
	}
	if !cfg.Tools.WHOIS.Verbose {
		t.Fatalf("whois settings = %+v", cfg.Tools.WHOIS)
	}
	if len(cfg.Tools.Dig.RecordTypes) < 9 || !cfg.Tools.Dig.Trace || !cfg.Tools.Dig.NSSearch {
		t.Fatalf("dig settings = %+v", cfg.Tools.Dig)
	}
	if len(cfg.Tools.DNSX.RecordTypes) < 8 || !cfg.Tools.DNSX.Trace {
		t.Fatalf("dnsx settings = %+v", cfg.Tools.DNSX)
	}
	if !cfg.Tools.HTTPX.TLSGrab || !cfg.Tools.HTTPX.ProbeAllIPs || cfg.Tools.HTTPX.Timeout != 20 {
		t.Fatalf("httpx settings = %+v", cfg.Tools.HTTPX)
	}
	if cfg.Tools.Naabu.TopPorts != "full" || !cfg.Tools.Naabu.ScanAllIPs || !cfg.Tools.Naabu.ServiceVersion {
		t.Fatalf("naabu settings = %+v", cfg.Tools.Naabu)
	}
	if cfg.Tools.Gau.Retries != 5 || cfg.Tools.Gau.Timeout != 120 || cfg.Tools.Gau.Threads != 1 {
		t.Fatalf("gau settings = %+v", cfg.Tools.Gau)
	}
	if !cfg.Tools.Katana.Headless || !cfg.Tools.Katana.XHRExtraction || cfg.Tools.Katana.KnownFiles != "all" {
		t.Fatalf("katana settings = %+v", cfg.Tools.Katana)
	}
}
