# Screenshot Review Playbook

## Objective

Turn live-host output into a prioritized visual review queue. Screenshots help identify login panels, admin surfaces, debug pages, exposed files, unexpected brands, old apps, and duplicate hosts quickly.

## Inputs

- Live hosts from subdomain enumeration.
- Status codes, titles, redirect chains, and technology hints.
- Scope notes and excluded assets.
- Screenshot output directory.

## Workflow

1. Capture screenshots at conservative rates and keep the source URL for every image.
2. Cluster visually identical pages and shared hosting defaults.
3. Flag high-signal pages: admin/login panels, debug interfaces, directory listings, staging banners, stack traces, storage browsers, API docs, and unusual legacy UI.
4. Compare visual findings with status code, title, and technology metadata.
5. Manually open high-priority hosts before sending them to vulnerability testing.
6. Archive low-priority duplicates with enough metadata to avoid re-reviewing them.

## Example Commands

```bash
mkdir -p screenshots notes

awk '{print $1}' normalized/live-hosts.txt | sort -u > normalized/live-urls.txt

gowitness scan file \
  -f normalized/live-urls.txt \
  --screenshot-path screenshots \
  --threads 5 \
  --timeout 15
```

If `gowitness` creates a report/database, keep it inside the run folder and do not commit screenshots that contain private data.

## Manual Review Pass

Create `notes/screenshot-review.tsv`:

```text
url | cluster | signal | priority | next_action
https://app.example.com | unique-app | login/react | P2 | collect JS
https://api.example.com | unique-api | api gateway | P1 | api discovery
https://staging.example.com | staging | basic auth | P2 | confirm scope
https://assets.example.com | storage | 403 cloudfront | P2 | cloud ownership check
https://www.example.com | marketing | public site | P3 | monitor
```

Review order:

1. Open high-signal screenshots first: admin, API docs, staging, debug, storage, stack traces.
2. Cluster duplicates: same title, same screenshot, same content length, same redirect.
3. Mark out-of-scope or third-party assets clearly.
4. Send only scoped, interesting assets to the next playbook.

## High-Signal Visual Clues

| Clue | Why it matters | Next step |
| --- | --- | --- |
| Swagger, Redoc, GraphiQL | API schema or operation discovery | [API Discovery](api-discovery.md) |
| Basic auth on staging/dev | Potential non-production surface | Confirm scope, then manual review |
| Directory listing | Possible file exposure | Validate safely with minimal access |
| Stack trace/debug page | Framework, path, secret, or environment leakage | Information disclosure testing |
| Storage browser or XML bucket error | Cloud asset clue | [Cloud Asset Discovery](cloud-asset-discovery.md) |
| Admin/login panel | Role and session boundary | Auth and access-control testing |

## Validation

- A screenshot is a prioritization signal, not proof of a vulnerability.
- Confirm whether panels are intentionally public, protected, third-party, or out of scope.
- Use soft-404 and default-page baselines for repeated page templates.
- Do not brute force logins or perform credential attacks from screenshot leads.

## False Positives

- Shared CDN or hosting default pages.
- Login pages that are public by design.
- Staging-looking names that are still production marketing assets.
- Old screenshots from stale monitoring output.
- Visual duplicates across localized or vanity domains.

## Output

| Field | Description |
| --- | --- |
| url | Source URL captured |
| screenshot | Screenshot file path |
| cluster | Unique app, duplicate, default page, parked, error, unknown |
| signal | Login, admin, debug, docs, storage, legacy, stack trace |
| priority | high, medium, low, monitor, excluded |
| next_action | Manual review, API discovery, access-control test, monitor |

## Handoff

Send API docs to [API Discovery](api-discovery.md), debug/storage/cloud indicators to [Cloud Asset Discovery](cloud-asset-discovery.md), and role-sensitive apps to vulnerability-specific testing.

## References

- [gowitness](https://github.com/sensepost/gowitness)
- [OWASP WSTG Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
