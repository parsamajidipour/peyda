package report

import "testing"

func TestParseHTTPXLine(t *testing.T) {
	got := parseHTTPXLine("https://app.example.com [200] [Dashboard] [React,Cloudflare] [12432]")
	if got["url"] != "https://app.example.com" {
		t.Fatalf("url = %q", got["url"])
	}
	if got["status"] != "200" {
		t.Fatalf("status = %q", got["status"])
	}
	if got["title"] != "Dashboard" {
		t.Fatalf("title = %q", got["title"])
	}
}
