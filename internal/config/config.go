package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	ProfilePassive  = "passive"
	ProfileBalanced = "balanced"
	ProfileDeep     = "deep"
)

type Config struct {
	Target         string `json:"target"`
	RunDate        string `json:"run_date"`
	OutputRoot     string `json:"output_root"`
	Profile        string `json:"profile"`
	ProbeRate      int    `json:"probe_rate"`
	CrawlRate      int    `json:"crawl_rate"`
	CrawlDepth     int    `json:"crawl_depth"`
	CrawlDuration  string `json:"crawl_duration"`
	MaxDomainPages int    `json:"max_domain_pages"`
	APIRate        int    `json:"api_rate"`
	ExcludedFile   string `json:"excluded_file"`
	SkipDeps       bool   `json:"skip_deps"`
	WriteJSONL     bool   `json:"write_jsonl"`
	Tools          Tools  `json:"tools"`
}

type Tools struct {
	Subfinder SubfinderTool `json:"subfinder"`
	DNSX      DNSXTool      `json:"dnsx"`
	HTTPX     HTTPXTool     `json:"httpx"`
	Katana    KatanaTool    `json:"katana"`
}

type SubfinderTool struct {
	All       bool `json:"all"`
	Recursive bool `json:"recursive"`
}

type DNSXTool struct {
	RecordTypes []string `json:"record_types"`
	Response    bool     `json:"response"`
}

type HTTPXTool struct {
	FollowRedirects bool `json:"follow_redirects"`
	Title           bool `json:"title"`
	StatusCode      bool `json:"status_code"`
	ContentLength   bool `json:"content_length"`
	ContentType     bool `json:"content_type"`
	TechDetect      bool `json:"tech_detect"`
}

type KatanaTool struct {
	JSCrawl           bool   `json:"js_crawl"`
	IgnoreQueryParams bool   `json:"ignore_query_params"`
	FilterSimilar     bool   `json:"filter_similar"`
	KnownFiles        string `json:"known_files"`
	FieldScope        string `json:"field_scope"`
	Strategy          string `json:"strategy"`
	Headless          bool   `json:"headless"`
	XHRExtraction     bool   `json:"xhr_extraction"`
	DisplayOutScope   bool   `json:"display_out_scope"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		if _, err := os.Stat(".reconx.json"); err == nil {
			path = ".reconx.json"
		}
	}
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		OutputRoot: "runs",
		Profile:    ProfileBalanced,
		WriteJSONL: true,
		Tools:      DefaultTools(),
	}
}

func DefaultTools() Tools {
	return Tools{
		Subfinder: SubfinderTool{
			All:       true,
			Recursive: true,
		},
		DNSX: DNSXTool{
			RecordTypes: []string{"a"},
			Response:    true,
		},
		HTTPX: HTTPXTool{
			FollowRedirects: true,
			Title:           true,
			StatusCode:      true,
			ContentLength:   true,
			ContentType:     true,
			TechDetect:      true,
		},
		Katana: KatanaTool{
			JSCrawl:           true,
			IgnoreQueryParams: true,
			FilterSimilar:     true,
			FieldScope:        "rdn",
			Strategy:          "depth-first",
		},
	}
}

func (c *Config) ApplyProfileDefaults() error {
	if c.OutputRoot == "" {
		c.OutputRoot = "runs"
	}
	if c.Profile == "" {
		c.Profile = ProfileBalanced
	}
	switch c.Profile {
	case ProfilePassive:
		if c.ProbeRate == 0 {
			c.ProbeRate = 10
		}
	case ProfileBalanced:
		if c.ProbeRate == 0 {
			c.ProbeRate = 50
		}
		if c.CrawlRate == 0 {
			c.CrawlRate = 10
		}
		if c.CrawlDepth == 0 {
			c.CrawlDepth = 1
		}
		if c.CrawlDuration == "" {
			c.CrawlDuration = "45s"
		}
		if c.MaxDomainPages == 0 {
			c.MaxDomainPages = 75
		}
		if c.APIRate == 0 {
			c.APIRate = 20
		}
	case ProfileDeep:
		if c.ProbeRate == 0 {
			c.ProbeRate = 100
		}
		if c.CrawlRate == 0 {
			c.CrawlRate = 50
		}
		if c.CrawlDepth == 0 {
			c.CrawlDepth = 3
		}
		if c.CrawlDuration == "" {
			c.CrawlDuration = "5m"
		}
		if c.MaxDomainPages == 0 {
			c.MaxDomainPages = 500
		}
		if c.APIRate == 0 {
			c.APIRate = 50
		}
	default:
		return errors.New("profile must be one of: passive, balanced, deep")
	}
	return nil
}

func Example() Config {
	cfg := Default()
	cfg.Target = "example.com"
	cfg.ProbeRate = 50
	cfg.CrawlRate = 10
	cfg.CrawlDepth = 1
	cfg.CrawlDuration = "45s"
	cfg.MaxDomainPages = 75
	cfg.APIRate = 20
	return cfg
}

func Write(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
