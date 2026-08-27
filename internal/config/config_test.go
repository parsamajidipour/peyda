package config

import "testing"

func TestApplyProfileDefaults(t *testing.T) {
	tests := []struct {
		profile string
		probe   int
		crawl   int
		api     int
	}{
		{ProfilePassive, 10, 0, 0},
		{ProfileBalanced, 50, 20, 20},
		{ProfileDeep, 100, 50, 50},
	}

	for _, tt := range tests {
		cfg := Config{Profile: tt.profile}
		if err := cfg.ApplyProfileDefaults(); err != nil {
			t.Fatal(err)
		}
		if cfg.ProbeRate != tt.probe || cfg.CrawlRate != tt.crawl || cfg.APIRate != tt.api {
			t.Fatalf("%s defaults = probe %d crawl %d api %d", tt.profile, cfg.ProbeRate, cfg.CrawlRate, cfg.APIRate)
		}
	}
}
