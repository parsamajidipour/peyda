package jsrecon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractJSURLsResolvesRelativeURLs(t *testing.T) {
	got := ExtractJSURLs(
		[]string{`https://cdn.example.com/app.js`, `"/static/main.js"`},
		[]string{"https://app.example.com"},
	)
	want := strings.Join([]string{
		"https://app.example.com/static/main.js",
		"https://cdn.example.com/app.js",
	}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("js urls = %v", got)
	}
}

func TestBuildLeadsClassifiesRoutes(t *testing.T) {
	leads := BuildLeads([]string{"/api/v1/workspaces/{workspaceId}/billing/export"})
	if len(leads) != 1 {
		t.Fatalf("leads len = %d", len(leads))
	}
	if leads[0].ObjectOrAction != "export" {
		t.Fatalf("object = %q", leads[0].ObjectOrAction)
	}
	if !strings.Contains(leads[0].NextStep, "authorization-matrix") ||
		!strings.Contains(leads[0].NextStep, "high-signal") {
		t.Fatalf("next step = %q", leads[0].NextStep)
	}
}

func TestExtractFromRunRedactsSecretsAndFindsRoutes(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, "raw/js"), 0o755); err != nil {
		t.Fatal(err)
	}
	js := `fetch("/api/v1/users/me"); const key="AKIA1234567890ABCDEF"; //# sourceMappingURL=main.js.map`
	if err := os.WriteFile(filepath.Join(runDir, "raw/js/main.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}

	interesting, routes, maps := extractFromRun(runDir, nil, nil, "example.com")
	if len(routes) != 1 || routes[0] != "/api/v1/users/me" {
		t.Fatalf("routes = %v", routes)
	}
	if len(maps) != 1 || maps[0] != "main.js.map" {
		t.Fatalf("maps = %v", maps)
	}
	if len(interesting) != 1 || strings.Contains(interesting[0], "AKIA1234567890ABCDEF") {
		t.Fatalf("interesting line was not redacted: %v", interesting)
	}
}

func TestExtractFromRunExpandsConcatenatedAPIEndpoints(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, "raw/js"), 0o755); err != nil {
		t.Fatal(err)
	}
	js := `let o="https://app.example.com/api/v2",n={BASE:{REGIONS:o?"".concat(o,"/regions"):"",CONTACT_US:o?"".concat(o,"/contact-us"):""},CARS:{MAKES:o?"".concat(o,"/cars/makes"):"",MODELS:o+"/cars/models",SEARCH:o+"/cars/search"}};`
	if err := os.WriteFile(filepath.Join(runDir, "raw/js/app.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}

	_, routes, _ := extractFromRun(runDir, nil, nil, "example.com")
	got := strings.Join(routes, "\n")
	for _, want := range []string{
		"https://app.example.com/api/v2",
		"https://app.example.com/api/v2/regions",
		"https://app.example.com/api/v2/contact-us",
		"https://app.example.com/api/v2/cars/makes",
		"https://app.example.com/api/v2/cars/models",
		"https://app.example.com/api/v2/cars/search",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in routes:\n%s", want, got)
		}
	}
}

func TestExtractFromRunAddsNextAppRoutesFromJSURLs(t *testing.T) {
	runDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(runDir, "raw/js"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, routes, _ := extractFromRun(
		runDir,
		nil,
		[]string{"https://www.example.com/_next/static/chunks/app/%5Bcountry%5D/%5Blocale%5D/%5Bsection%5D/page-abc123.js"},
		"example.com",
	)
	if strings.Join(routes, "\n") != "/{country}/{locale}/{section}" {
		t.Fatalf("routes = %v", routes)
	}
}

func TestNormalizeRouteCandidateDropsAssetsAndEncodedNoise(t *testing.T) {
	for _, raw := range []string{
		"https://app.example.com/api/v2/landing/banner/banner-home.jpg",
		"/_next/image",
		"/%3E%3C/svg%3E",
		"/([^/]+?",
		"/a/b",
	} {
		if got := normalizeRouteCandidate(raw, "example.com"); got != "" {
			t.Fatalf("route %q should be dropped, got %q", raw, got)
		}
	}
}

func TestNormalizeRouteCandidateRepairsNextRouteSeparators(t *testing.T) {
	got := normalizeRouteCandidate("/:country/:localeauth/sign-in", "example.com")
	if got != "/:country/:locale/auth/sign-in" {
		t.Fatalf("route = %q", got)
	}
}

func TestFilterInScopeURLsDropsExternalAndEscapedNoise(t *testing.T) {
	got := filterInScopeURLs([]string{
		"https://app.example.com/_next/static/app.js",
		"https://example.com/api/v1/users",
		"https://static.example.com/image.png%5C",
		"https://www.facebook.com/example",
		"http://www.w3.org/2000/svg%5C",
		"not-a-url",
	}, "example.com")

	want := strings.Join([]string{
		"https://app.example.com/_next/static/app.js",
		"https://example.com/api/v1/users",
	}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("scoped urls = %v", got)
	}
}

func TestFilterRoutesInScopeKeepsRelativeAndTargetRoutes(t *testing.T) {
	got := filterRoutesInScope([]string{
		"/api/v1/users/me",
		"https://api.example.com/v2/accounts",
		"https://github.com/example/project/blob/v3/LICENSE",
		"https://nextjs.org/docs/app/api-reference/functions/use-search-params",
	}, "example.com")

	want := strings.Join([]string{
		"/api/v1/users/me",
		"https://api.example.com/v2/accounts",
	}, "\n")
	if strings.Join(got, "\n") != want {
		t.Fatalf("scoped routes = %v", got)
	}
}
