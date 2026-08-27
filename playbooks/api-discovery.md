# API Discovery Playbook

## Objective

Turn browser traffic, JavaScript routes, API docs, schemas, and live hosts into an endpoint inventory that is ready for authorization, input validation, and business-logic testing.

Discovery is not the finding. A discovered endpoint becomes useful when you know the method, auth requirement, object type, tenant boundary, and next safe test.

## Inputs

```text
Live hosts: normalized/live-hosts.txt
Crawled URLs: raw/katana-urls.txt
JavaScript findings: normalized/js-routes.txt
Test accounts: user A, user B, optional second tenant
Output: normalized/api-inventory.tsv
```

## Step 1: Find API-Looking Hosts

Fast path from the repository root:

```bash
peyda run -t example.com --profile balanced
```

`peyda` builds API host candidates, probes common documentation/schema paths,
downloads reachable JSON schemas, extracts OpenAPI method/path pairs, and creates
`normalized/api-inventory.tsv`.

Manual path:

```bash
rg -i "(api|graphql|swagger|openapi|developer|docs|gateway)" normalized/live-hosts.txt \
  > notes/api-host-candidates.txt
```

Example:

```text
https://api.example.com [200] [API Gateway] [nginx] [417]
https://developer.example.com [200] [Developer Docs] [Next.js] [20841]
```

Manual check:

- Does the host belong to the target?
- Is it in scope?
- Is it production, sandbox, docs, or third-party?
- Does it require authentication?

## Step 2: Check Common API Documentation Paths

Run this only against confirmed in-scope hosts.

```bash
cat notes/api-host-candidates.txt \
  | awk '{print $1}' \
  | while read -r host; do
      for path in \
        /openapi.json \
        /swagger.json \
        /api-docs \
        /swagger-ui/ \
        /docs \
        /graphql \
        /graphiql; do
        printf "%s%s\n" "$host" "$path"
      done
    done > raw/api-doc-paths.txt

httpx -l raw/api-doc-paths.txt \
  -silent \
  -status-code \
  -title \
  -content-type \
  -content-length \
  -rl 20 \
  -o normalized/api-docs-probed.txt
```

High-signal examples:

```text
https://api.example.com/openapi.json [200] [application/json] [48213]
https://api.example.com/swagger-ui/ [200] [Swagger UI] [9281]
https://api.example.com/graphql [200] [application/json] [126]
```

## Step 3: Pull OpenAPI or Swagger Paths

```bash
curl -s https://api.example.com/openapi.json -o raw/openapi.json
jq -r '.paths | keys[]' raw/openapi.json | sort -u > normalized/openapi-paths.txt
```

Extract method and path:

```bash
jq -r '.paths | to_entries[] as $p | $p.value | keys[] as $m | [$m, $p.key] | @tsv' \
  raw/openapi.json > normalized/openapi-methods.tsv
```

Example:

```text
get     /v1/users/me
get     /v1/orgs/{orgId}/invoices
post    /v1/orgs/{orgId}/invoices/export
patch   /v1/users/{userId}
```

## Step 4: Extract API Routes from Crawled URLs

```bash
katana -list normalized/live-hosts.txt -jc -silent -rl 20 -o raw/katana-urls.txt

rg -o "https?://[^ ]+|/api/[A-Za-z0-9_./{}:-]+|/v[0-9]+/[A-Za-z0-9_./{}:-]+" raw/katana-urls.txt \
  | sort -u > normalized/crawled-api-routes.txt
```

If you downloaded JavaScript files:

```bash
rg -o "(/api/[A-Za-z0-9_./{}:-]+|/v[0-9]+/[A-Za-z0-9_./{}:-]+|graphql|webhook)" js/ \
  | sort -u > normalized/js-api-routes.txt
```

## Step 5: Check GraphQL Safely

First confirm the endpoint exists:

```bash
curl -s -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  --data '{"query":"query { __typename }"}'
```

If introspection is allowed by scope and policy:

```bash
curl -s -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  --data '{"query":"{__schema{queryType{name} mutationType{name} types{name}}}"}' \
  -o raw/graphql-introspection.json

jq -r '.data.__schema.types[].name' raw/graphql-introspection.json \
  | sort -u > normalized/graphql-types.txt
```

Do not report GraphQL introspection by itself unless the program accepts it or it exposes sensitive operations/data with real impact.

## Step 6: Build an Endpoint Inventory

Create a TSV with columns:

```bash
printf "method\thost\tpath\tauth\tobject\tboundary_field\trisk\tsource\tnext_test\n" \
  > normalized/api-inventory.tsv
```

Add rows manually after review:

```text
method  host             path                              auth  object   boundary_field  risk           source   next_test
GET     api.example.com  /v1/users/me                      user  user     none          data exposure  browser  response fields
POST    api.example.com  /v1/orgs/{orgId}/invoices/export  user  invoice  orgId         IDOR/export    openapi  cross-tenant matrix
PATCH   api.example.com  /v1/users/{userId}                user  user     userId        mass assign    openapi  property authorization
```

Useful risk tags:

- `idor`
- `function-auth`
- `mass-assignment`
- `excessive-data`
- `resource-consumption`
- `version-drift`
- `webhook`
- `file-export`
- `admin-action`

## Step 7: Prioritize Manual Tests

Start with endpoints that include:

- `{userId}`, `{accountId}`, `{orgId}`, `{tenantId}`, `{workspaceId}`, `{projectId}`.
- `export`, `download`, `bulk`, `invite`, `role`, `admin`, `billing`, `webhook`, `token`.
- Old versions like `/v1/` when the UI uses `/v3/`.
- Mutations or writes available to normal users.
- Search/list endpoints that may reveal excessive data.

## Step 8: Handoff Example

```text
Endpoint: POST https://api.example.com/v1/orgs/{orgId}/invoices/export
Source: OpenAPI schema
Auth: normal user
Object: invoice
Boundary field: orgId
Hypothesis: export worker may not enforce tenant membership
Safe test: create two owned orgs and attempt cross-org export with synthetic invoices
Stop condition: stop after first allowed/denied comparison
Next checklist: IDOR, REST API authorization, export security
```

## Common Mistakes

- Reporting API docs without proving sensitive exposure or weak authorization.
- Testing endpoints before confirming they are in scope.
- Treating JavaScript route strings as live endpoints.
- Testing only `GET` while missing `POST`, `PATCH`, `DELETE`, `bulk`, and `export`.
- Ignoring old API versions and mobile-only endpoints.
- Forgetting to compare User A, User B, and cross-tenant behavior.

## Troubleshooting

| Problem | What it means | What to do |
| --- | --- | --- |
| `/openapi.json` is 404 | Schema may live elsewhere or require auth | Check `/swagger.json`, `/api-docs`, `/docs`, developer portals, and browser traffic |
| GraphQL introspection is disabled | Common production hardening | Use observed operation names, JavaScript bundles, and normal UI traffic |
| `katana` only finds marketing URLs | API routes may require authentication | Capture authenticated browser traffic and inspect JS bundles |
| Endpoint returns 401 | Auth required | Use owned test accounts and record required role/scope |
| Endpoint returns 403 | Authorization may be working | Compare roles/tenants only after scope and test accounts are ready |
| Schema has hundreds of endpoints | Too much volume | Prioritize object IDs, exports, bulk actions, admin verbs, billing, invites, and old versions |

## Output Files

| File | Purpose |
| --- | --- |
| `notes/api-host-candidates.txt` | API-looking hosts from live probing |
| `raw/api-doc-paths.txt` | Candidate docs/schema URLs |
| `normalized/api-docs-probed.txt` | Probed docs/schema results |
| `raw/api/*.json` | Raw downloaded OpenAPI schema candidates |
| `normalized/openapi-methods.tsv` | Method/path pairs from schema |
| `normalized/crawled-api-routes.txt` | API routes found by crawler |
| `normalized/js-api-routes.txt` | API routes extracted from JavaScript |
| `normalized/api-inventory.tsv` | Reviewed endpoint inventory |

## References

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PortSwigger API Testing](https://portswigger.net/web-security/api-testing)
- [ProjectDiscovery katana](https://docs.projectdiscovery.io/tools/katana/overview)
- [ProjectDiscovery httpx](https://docs.projectdiscovery.io/tools/httpx/overview)
