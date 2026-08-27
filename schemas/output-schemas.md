# Output Schemas

These schemas keep recon output predictable across manual notes and scripts.

## `normalized/recon-events.jsonl`

Produced by `reconx run`.

Each line is one JSON object:

```json
{"type":"live_service","value":"https://app.example.com","source":"normalized/live-hosts.txt","timestamp":"2026-08-27T00:00:00Z","fields":{"status":"200","title":"Dashboard"}}
```

| Field | Meaning |
| --- | --- |
| type | Event category, such as `subdomain`, `live_service`, `api_endpoint`, `cloud_candidate` |
| value | Primary value for quick filtering |
| source | File that produced the event |
| timestamp | UTC generation time |
| fields | Optional structured metadata |

## `normalized/live-hosts.txt`

Produced by `reconx run` in `balanced` and `deep` profiles.

```text
https://app.example.com [200] [Sign in] [React,nginx] [14320]
```

| Field | Meaning |
| --- | --- |
| URL | Probed HTTP/S URL |
| status | HTTP status code |
| title | HTML title or detected label |
| technology | httpx technology hints |
| content_length | Response size hint |

## `notes/interesting-hosts.txt`

Produced by keyword filtering over live hosts. Treat as a review queue, not proof.

## `normalized/asset-scores.tsv`

Produced by `reconx run` in `balanced` and `deep` profiles.

| Column | Meaning |
| --- | --- |
| url | Live URL returned by ProjectDiscovery `httpx` |
| host | Hostname extracted from the URL |
| status | HTTP status code |
| title | HTML title |
| technology | Detected technology hints |
| score | Review priority score |
| reasons | Weighted signals that contributed to the score |

## `normalized/openapi-methods.tsv`

Produced by `reconx run` in `balanced` and `deep` profiles.

| Column | Meaning |
| --- | --- |
| method | HTTP method from OpenAPI |
| path | API path from OpenAPI |
| source | Schema URL where the path was found |

## `normalized/api-inventory.tsv`

Produced by `reconx run` in `balanced` and `deep` profiles, then edited manually.

| Column | Meaning |
| --- | --- |
| method | HTTP method, GraphQL operation, or RPC method |
| host | Hostname |
| path | Endpoint path or operation |
| auth | anonymous, user, admin, service, unknown |
| object | Primary object type, such as user, org, invoice, file, token |
| boundary_field | Tenant or ownership field, such as orgId or workspaceId |
| risk | Initial risk hint |
| source | Browser, JS, docs, schema, mobile, manual |
| next_test | Checklist or manual action |

## `notes/js-leads.tsv`

Produced by `scripts/js-recon-pass.sh`.

| Column | Meaning |
| --- | --- |
| route | Route, endpoint, operation, or WebSocket URL |
| source | JS, crawler, source map, browser, or manual |
| auth_guess | Expected authentication context |
| object_or_action | Inferred object or sensitive action |
| next_step | Suggested next test |

## `notes/cloud-candidates.tsv`

Produced by `scripts/cloud-candidate-pass.sh`.

| Column | Meaning |
| --- | --- |
| asset_or_string | Cloud asset clue or redacted secret pattern |
| source | File and line where it appeared |
| provider_or_type | AWS, GCP, Azure, PaaS, possible token type |
| ownership_confidence | confirmed, likely, unknown, third party |
| exposure_guess | provider hint, public read, possible secret, unknown |
| next_action | Validate ownership, monitor, discard, or ask permission |

## `notes/recon-summary.md`

Produced by `reconx run`. Use it as an internal run summary and handoff aid, not as a vulnerability report.
