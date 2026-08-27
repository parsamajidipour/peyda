package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	ProfilePassive  = "passive"
	ProfileBalance  = "balance"
	ProfileBalanced = "balanced"
	ProfileDeep     = "deep"
)

type Config struct {
	Target         string `json:"target"`
	RunDate        string `json:"run_date"`
	OutputRoot     string `json:"output_root"`
	ResultsRoot    string `json:"results_root"`
	Profile        string `json:"profile"`
	ProbeRate      int    `json:"probe_rate"`
	CrawlRate      int    `json:"crawl_rate"`
	CrawlDepth     int    `json:"crawl_depth"`
	CrawlDuration  string `json:"crawl_duration"`
	MaxDomainPages int    `json:"max_domain_pages"`
	APIRate        int    `json:"api_rate"`
	PortRate       int    `json:"port_rate"`
	ExcludedFile   string `json:"excluded_file"`
	SkipDeps       bool   `json:"skip_deps"`
	WriteJSONL     bool   `json:"write_jsonl"`
	Tools          Tools  `json:"tools"`
	OutputFormat   string `json:"-"`
	OutputFile     string `json:"-"`
	Silent         bool   `json:"-"`
}

type Tools struct {
	WHOIS        WHOISTool        `json:"whois"`
	Dig          DigTool          `json:"dig"`
	Subfinder    SubfinderTool    `json:"subfinder"`
	DNSX         DNSXTool         `json:"dnsx"`
	HTTPX        HTTPXTool        `json:"httpx"`
	Naabu        NaabuTool        `json:"naabu"`
	Gau          GauTool          `json:"gau"`
	Katana       KatanaTool       `json:"katana"`
	Arjun        ArjunTool        `json:"arjun"`
	XNLinkFinder XNLinkFinderTool `json:"xnlinkfinder"`
}

type WHOISTool struct {
	Verbose bool `json:"verbose"`
}

type DigTool struct {
	RecordTypes []string `json:"record_types"`
	Trace       bool     `json:"trace"`
	NSSearch    bool     `json:"nssearch"`
}

type SubfinderTool struct {
	All       bool `json:"all"`
	Recursive bool `json:"recursive"`
	Timeout   int  `json:"timeout"`
	MaxTime   int  `json:"max_time"`
}

type DNSXTool struct {
	RecordTypes []string `json:"record_types"`
	Response    bool     `json:"response"`
	Recon       bool     `json:"recon"`
	Trace       bool     `json:"trace"`
}

type HTTPXTool struct {
	FollowRedirects bool `json:"follow_redirects"`
	Title           bool `json:"title"`
	StatusCode      bool `json:"status_code"`
	ContentLength   bool `json:"content_length"`
	ContentType     bool `json:"content_type"`
	TechDetect      bool `json:"tech_detect"`
	WebServer       bool `json:"web_server"`
	IP              bool `json:"ip"`
	CNAME           bool `json:"cname"`
	ASN             bool `json:"asn"`
	CDN             bool `json:"cdn"`
	ResponseTime    bool `json:"response_time"`
	HTTP2           bool `json:"http2"`
	Pipeline        bool `json:"pipeline"`
	TLSProbe        bool `json:"tls_probe"`
	TLSGrab         bool `json:"tls_grab"`
	ProbeAllIPs     bool `json:"probe_all_ips"`
	Retries         int  `json:"retries"`
	Timeout         int  `json:"timeout"`
}

type NaabuTool struct {
	TopPorts         string `json:"top_ports"`
	ScanAllIPs       bool   `json:"scan_all_ips"`
	ServiceDiscovery bool   `json:"service_discovery"`
	ServiceVersion   bool   `json:"service_version"`
	Verify           bool   `json:"verify"`
	Passive          bool   `json:"passive"`
}

type GauTool struct {
	Subs      bool     `json:"subs"`
	Providers []string `json:"providers"`
	Retries   int      `json:"retries"`
	Timeout   int      `json:"timeout"`
	Threads   int      `json:"threads"`
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
	JSLuice           bool   `json:"jsluice"`
	FormExtraction    bool   `json:"form_extraction"`
	TechDetect        bool   `json:"tech_detect"`
	PathClimb         bool   `json:"path_climb"`
	KnowledgeBase     bool   `json:"knowledge_base"`
	StoreField        string `json:"store_field"`
	Concurrency       int    `json:"concurrency"`
	Parallelism       int    `json:"parallelism"`
	HostRateLimit     int    `json:"host_rate_limit"`
}

type ArjunTool struct {
	Enabled bool `json:"enabled"`
}

type XNLinkFinderTool struct {
	Enabled bool `json:"enabled"`
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		if _, err := os.Stat(".peyda.json"); err == nil {
			path = ".peyda.json"
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
		OutputRoot:  "runs",
		ResultsRoot: "results",
		Profile:     ProfileBalanced,
		WriteJSONL:  true,
		Tools:       DefaultTools(),
	}
}

func DefaultTools() Tools {
	return Tools{
		Dig: DigTool{
			RecordTypes: []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"},
		},
		Subfinder: SubfinderTool{
			All:       true,
			Recursive: true,
			Timeout:   30,
			MaxTime:   10,
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
			CDN:             true,
			Retries:         1,
			Timeout:         10,
		},
		Naabu: NaabuTool{
			TopPorts:         "1000",
			ServiceDiscovery: true,
		},
		Gau: GauTool{
			Subs:      true,
			Providers: []string{"wayback", "commoncrawl", "otx", "urlscan"},
			Retries:   2,
			Timeout:   60,
			Threads:   2,
		},
		Katana: KatanaTool{
			JSCrawl:           true,
			IgnoreQueryParams: true,
			FilterSimilar:     true,
			FieldScope:        "rdn",
			Strategy:          "depth-first",
			Concurrency:       10,
			Parallelism:       10,
		},
		Arjun:        ArjunTool{Enabled: true},
		XNLinkFinder: XNLinkFinderTool{Enabled: true},
	}
}

func (c *Config) ApplyProfileDefaults() error {
	if c.OutputRoot == "" {
		c.OutputRoot = "runs"
	}
	if c.ResultsRoot == "" {
		c.ResultsRoot = "results"
	}
	if c.Profile == "" {
		c.Profile = ProfileBalanced
	}
	if c.Profile == ProfileBalance {
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
		if c.PortRate == 0 {
			c.PortRate = 50
		}
	case ProfileDeep:
		c.Tools.WHOIS.Verbose = true
		if sameStringsFold(c.Tools.Dig.RecordTypes, []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"}) {
			c.Tools.Dig.RecordTypes = []string{"A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"}
		}
		c.Tools.Dig.Trace = true
		c.Tools.Dig.NSSearch = true
		c.Tools.Subfinder.All = true
		c.Tools.Subfinder.Recursive = true
		if c.Tools.Subfinder.Timeout == 30 {
			c.Tools.Subfinder.Timeout = 120
		}
		if c.Tools.Subfinder.MaxTime == 10 {
			c.Tools.Subfinder.MaxTime = 60
		}
		if sameStrings(c.Tools.DNSX.RecordTypes, []string{"a"}) {
			c.Tools.DNSX.RecordTypes = []string{"a", "aaaa", "cname", "ns", "mx", "txt", "soa", "caa"}
		}
		c.Tools.DNSX.Response = true
		c.Tools.DNSX.Trace = true
		c.Tools.HTTPX.WebServer = true
		c.Tools.HTTPX.IP = true
		c.Tools.HTTPX.CNAME = true
		c.Tools.HTTPX.ASN = true
		c.Tools.HTTPX.CDN = true
		c.Tools.HTTPX.ResponseTime = true
		c.Tools.HTTPX.HTTP2 = true
		c.Tools.HTTPX.Pipeline = true
		c.Tools.HTTPX.TLSProbe = true
		c.Tools.HTTPX.TLSGrab = true
		c.Tools.HTTPX.ProbeAllIPs = true
		if c.Tools.HTTPX.Retries == 1 {
			c.Tools.HTTPX.Retries = 2
		}
		if c.Tools.HTTPX.Timeout == 10 {
			c.Tools.HTTPX.Timeout = 20
		}
		c.Tools.Naabu.TopPorts = "full"
		c.Tools.Naabu.ScanAllIPs = true
		c.Tools.Naabu.ServiceDiscovery = true
		c.Tools.Naabu.ServiceVersion = true
		c.Tools.Naabu.Verify = true
		c.Tools.Naabu.Passive = true
		if c.Tools.Gau.Retries == 2 {
			c.Tools.Gau.Retries = 5
		}
		if c.Tools.Gau.Timeout == 60 {
			c.Tools.Gau.Timeout = 120
		}
		if c.Tools.Gau.Threads == 2 {
			c.Tools.Gau.Threads = 1
		}
		c.Tools.Katana.Headless = true
		c.Tools.Katana.XHRExtraction = true
		c.Tools.Katana.JSLuice = true
		c.Tools.Katana.FormExtraction = true
		c.Tools.Katana.TechDetect = true
		c.Tools.Katana.PathClimb = true
		c.Tools.Katana.KnowledgeBase = true
		if c.Tools.Katana.KnownFiles == "" {
			c.Tools.Katana.KnownFiles = "all"
		}
		if c.Tools.Katana.Concurrency == 10 {
			c.Tools.Katana.Concurrency = 5
		}
		if c.Tools.Katana.Parallelism == 10 {
			c.Tools.Katana.Parallelism = 5
		}
		if c.Tools.Katana.HostRateLimit == 0 {
			c.Tools.Katana.HostRateLimit = 2
		}
		if c.ProbeRate == 0 {
			c.ProbeRate = 25
		}
		if c.CrawlRate == 0 {
			c.CrawlRate = 5
		}
		if c.CrawlDepth == 0 {
			c.CrawlDepth = 5
		}
		if c.CrawlDuration == "" {
			c.CrawlDuration = "30m"
		}
		if c.MaxDomainPages == 0 {
			c.MaxDomainPages = 5000
		}
		if c.APIRate == 0 {
			c.APIRate = 10
		}
		if c.PortRate == 0 {
			c.PortRate = 25
		}
	default:
		return errors.New("profile must be one of: passive, balanced, deep")
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStringsFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.ToLower(a[i]) != strings.ToLower(b[i]) {
			return false
		}
	}
	return true
}

func Example() Config {
	cfg := Default()
	cfg.Target = "example.com"
	cfg.OutputRoot = "runs"
	cfg.ResultsRoot = "results"
	cfg.ProbeRate = 50
	cfg.CrawlRate = 10
	cfg.CrawlDepth = 1
	cfg.CrawlDuration = "45s"
	cfg.MaxDomainPages = 75
	cfg.APIRate = 20
	cfg.PortRate = 50
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
