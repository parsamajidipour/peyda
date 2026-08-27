package config

import "testing"

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
