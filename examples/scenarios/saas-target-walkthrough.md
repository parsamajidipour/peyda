# SaaS Target Walkthrough

This walkthrough shows how to move from scope to prioritized leads for a typical SaaS target. All domains are placeholders.

## Program Policy

```text
Allowed:
  *.example-saas.com
  api.example-saas.com

Excluded:
  support.example-saas.com
  status.example-saas.com
  third-party hosted help center

Automation:
  Passive recon allowed
  Low-rate HTTP probing allowed
  No brute force
  No denial-of-service testing
```

## Run Setup

```bash
bin/reconx run -t example-saas.com -e config/excluded.example.txt --profile balanced -p 30
```

Or run the first two stages manually:

```bash
bin/reconx run -t example-saas.com -e config/excluded.example.txt --profile balanced -p 30
```

## Sample Live Hosts

```text
https://www.example-saas.com [200] [Example SaaS] [Next.js,Cloudflare] [19284]
https://app.example-saas.com [200] [Sign in] [React,nginx] [15440]
https://api.example-saas.com [200] [API Gateway] [nginx] [512]
https://admin.example-saas.com [403] [Forbidden] [nginx] [146]
https://billing-staging.example-saas.com [401] [Staging Billing] [Basic,nginx] [181]
https://assets.example-saas.com [403] [] [AmazonS3,CloudFront] [263]
https://developer.example-saas.com [200] [Developer Docs] [Redoc] [32190]
```

## Manual Decisions

| Host | Decision | Reason |
| --- | --- | --- |
| `app.example-saas.com` | Investigate | Main authenticated app |
| `api.example-saas.com` | Investigate | Central API surface |
| `admin.example-saas.com` | Monitor/test auth safely | Admin-like surface, 403 is not a bug |
| `billing-staging.example-saas.com` | Ask/check policy | Staging name may be sensitive; confirm scope |
| `assets.example-saas.com` | Cloud check | S3/CloudFront clue, 403 alone is not exposure |
| `developer.example-saas.com` | API docs review | Redoc likely exposes schema |

## API Discovery

```bash
curl -s https://developer.example-saas.com/openapi.json -o runs/example-saas.com/$(date -u +%F)/raw/openapi.json
jq -r '.paths | to_entries[] as $p | $p.value | keys[] as $m | [$m, $p.key] | @tsv' \
  runs/example-saas.com/$(date -u +%F)/raw/openapi.json \
  > runs/example-saas.com/$(date -u +%F)/normalized/openapi-methods.tsv
```

Sample API paths:

```text
GET     /v1/users/me
GET     /v1/workspaces/{workspaceId}/members
POST    /v1/workspaces/{workspaceId}/invites
POST    /v1/workspaces/{workspaceId}/billing/export
PATCH   /v1/users/{userId}
```

## Lead Handoff

```text
Lead: POST /v1/workspaces/{workspaceId}/billing/export
Source: Developer OpenAPI schema
Scope status: confirmed under api.example-saas.com
Hypothesis: billing export may need workspace membership and role authorization checks
Safe test: create two owned workspaces with synthetic billing records and replay export across workspace IDs
Stop condition: stop after allowed/denied comparison with owned data
Next checklist: REST API authorization, IDOR, business logic export path
```

## What Not to Report Yet

- `admin.example-saas.com` returning `403`.
- `billing-staging.example-saas.com` existing.
- `developer.example-saas.com` exposing docs if docs are intended and do not expose sensitive operations.
- `assets.example-saas.com` returning an S3/CloudFront-looking `403`.

## Why This Run Is Useful

The run produced concrete next tests:

- Cross-workspace authorization on billing export.
- Role authorization on invitations.
- Property-level authorization on user updates.
- Cloud ownership check for asset storage.
- Monitoring item for admin/staging surfaces.
