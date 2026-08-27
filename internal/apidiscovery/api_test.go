package apidiscovery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIHostCandidates(t *testing.T) {
	lines := []string{
		"https://app.example.com [200] [Home] [React] [100]",
		"https://api.example.com [200] [API] [nginx] [200]",
		"https://docs.example.com [200] [Developer Docs] [nginx] [300]",
	}
	got := APIHostCandidates(lines)
	want := strings.Join([]string{"https://api.example.com", "https://docs.example.com"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("candidates = %v", got)
	}
}

func TestBuildDocURLs(t *testing.T) {
	got := BuildDocURLs([]string{"https://api.example.com/"}, []string{"openapi.json", "/docs"})
	want := strings.Join([]string{"https://api.example.com/docs", "https://api.example.com/openapi.json"}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("doc urls = %v", got)
	}
}

func TestSchemaCandidates(t *testing.T) {
	got := SchemaCandidates([]string{
		"https://api.example.com/openapi.json [200] [openapi] [application/json] [900]",
		"https://api.example.com/docs [200] [Docs] [text/html] [300]",
		"https://api.example.com/swagger.json [403] [Denied] [application/json] [20]",
	})
	if len(got) != 1 || got[0] != "https://api.example.com/openapi.json" {
		t.Fatalf("schema candidates = %v", got)
	}
}

func TestExtractOpenAPIMethodsAndInventory(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "sample-openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	methods, err := ExtractOpenAPIMethods(data, "https://api.example.com/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(methods) != 4 {
		t.Fatalf("methods len = %d", len(methods))
	}
	inventory := BuildInventory(methods)
	var foundBilling bool
	for _, row := range inventory {
		if row.Path == "/v1/workspaces/{workspaceId}/billing/export" {
			foundBilling = true
			if row.BoundaryField != "possible" || row.Risk != "authorization,high-signal" {
				t.Fatalf("billing row = %+v", row)
			}
		}
	}
	if !foundBilling {
		t.Fatal("billing export row not found")
	}
}
