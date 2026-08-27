# JavaScript Recon Playbook

## Objective

Extract client-side routes, API paths, feature flags, source maps, build metadata, and accidental secrets from JavaScript assets, then convert them into scoped testing leads.

## Inputs

- Live web applications from subdomain enumeration.
- Browser-captured network traffic.
- JavaScript bundle URLs and source map URLs.
- Program rules for automated crawling and scraping.

## Workflow

1. Browse the application manually as each available role before crawling.
2. Collect initial HTML, script tags, lazy-loaded chunks, and service worker files.
3. Download JavaScript with timestamps and response headers.
4. Extract routes, API paths, GraphQL operation names, WebSocket URLs, feature flags, environment names, and build identifiers.
5. Check source maps only when allowed and avoid collecting unrelated source code beyond what is needed to identify attack surface.
6. Validate every discovered path through browser and direct protocol requests.
7. Send API routes to API discovery and authorization-focused checklists.

## Example Commands

Fast path from the repository root:

```bash
peyda run -t example.com --profile balanced
```

`peyda` runs `katana` as the crawl engine, then handles JavaScript URL extraction,
relative URL resolution, bundle downloads, route extraction, source-map candidates,
redaction of secret-looking strings, and `notes/js-leads.tsv` generation natively.

Manual path:

```bash
mkdir -p raw/js normalized notes

katana -u https://app.example.com -jc -silent -rl 20 -o raw/app-urls.txt

rg -o "https?://[^ ]+\\.js[^ ]*|/[^ ]+\\.js[^ ]*" raw/app-urls.txt \
  | sort -u > normalized/js-files.txt

while read -r url; do
  safe_name=$(printf "%s" "$url" | sed 's#[/:?&=]#_#g')
  curl -sL "$url" -o "raw/js/$safe_name"
done < normalized/js-files.txt

rg -n "(/api/|/v[0-9]+/|graphql|websocket|wss://|swagger|openapi|admin|internal|webhook)" raw/js \
  > normalized/js-interesting-lines.txt
```

Example `normalized/js-interesting-lines.txt`:

```text
raw/js/https___app.example.com_static_main.9c1.js:18:/api/v2/users/me
raw/js/https___app.example.com_static_main.9c1.js:19:/api/v2/orgs/{orgId}/members
raw/js/https___app.example.com_static_main.9c1.js:21:/api/v1/admin/audit/export
raw/js/https___app.example.com_static_main.9c1.js:44:wss://api.example.com/events
```

## Source Map Check

Only do this when source-map review is allowed by program policy.

```bash
rg -o "sourceMappingURL=[^ ]+" raw/js \
  | sed 's/.*sourceMappingURL=//' \
  | sort -u > normalized/source-map-candidates.txt
```

If a map is reachable, review only what is needed to identify attack surface:

```bash
curl -sL https://app.example.com/static/js/main.js.map -o raw/js/main.js.map
jq -r '.sources[]' raw/js/main.js.map | sort -u > normalized/source-map-files.txt
```

High-signal source-map paths:

```text
src/admin/routes.ts
src/api/billing.ts
src/features/invitations/mutations.ts
src/internal/debugPanel.tsx
```

## Route Triage

Build a small table in `notes/js-leads.tsv`:

```text
route | source | auth_guess | object_or_action | next_step
/api/v2/orgs/{orgId}/members | js bundle | user/org | org membership | authorization matrix
/api/v1/admin/audit/export | js bundle | admin? | audit export | function-level auth check
wss://api.example.com/events | js bundle | user | event stream | WebSocket authorization
```

## Validation

- A route inside JavaScript is a lead, not proof that the endpoint exists or is vulnerable.
- Confirm whether the endpoint is current, authenticated, role-gated, tenant-aware, and in scope.
- Treat public analytics and map keys differently from server-side credentials.
- Verify whether source maps expose sensitive comments, internal paths, or hidden operations before escalating.

## False Positives

- Dead routes from old bundles.
- Public client keys with domain restrictions.
- Example endpoints included in SDKs.
- Feature flags that are evaluated server-side and cannot be changed by the client.
- Static strings that look like secrets but are test placeholders.

## Output

| Field | Description |
| --- | --- |
| script_url | JavaScript or source map URL |
| discovered_item | Route, endpoint, operation, key, flag, or environment name |
| context | Bundle, function, source map, or UI flow |
| validation | live, dead, auth required, role gated, unknown |
| next_checklist | API, authorization, secrets, storage, WebSocket, or report handoff |

## Handoff

Send API routes to [API Discovery](api-discovery.md), possible secrets to [Cloud Asset Discovery](cloud-asset-discovery.md), and client-side security concerns to vulnerability-specific testing.

## References

- [OWASP WSTG Client-side Testing](https://owasp.org/www-project-web-security-testing-guide/)
- [ProjectDiscovery katana](https://docs.projectdiscovery.io/tools/katana/overview)
