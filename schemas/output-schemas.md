# Output Schemas

These schemas keep recon output predictable across manual notes and scripts.

## `results/<target>/`

This is the stable public dataset produced by `peyda example.com`.

```text
results/example.com/
├── recon.txt
├── subdomains.txt
├── resolved.txt
├── live.txt
├── ips.txt
├── ports.txt
├── urls.txt
├── parameters.txt
├── javascript.txt
├── endpoints.txt
├── dns.json
├── http.json
├── ports.json
├── technologies.json
└── summary.json
```

`recon.txt` is a comprehensive plain-text report intended for human review,
presentation, and private agent handoff. The focused text files contain one
deduplicated item per line and are sorted whenever practical.

| File | Schema |
| --- | --- |
| `recon.txt` | Full plain-text report with summary, WHOIS, DNS, HTTP, ports, URLs, parameters, JavaScript, endpoints, and handoff notes |
| `subdomains.txt` | In-scope hostnames |
| `resolved.txt` | In-scope hostnames that resolved |
| `live.txt` | Reachable HTTP/S URLs |
| `ips.txt` | Unique IPv4/IPv6 addresses observed from DNS records |
| `ports.txt` | Open TCP ports as `host:port service` |
| `urls.txt` | Normalized in-scope URLs |
| `parameters.txt` | Parameter names only |
| `javascript.txt` | In-scope JavaScript URLs |
| `endpoints.txt` | Relative endpoints or in-scope absolute HTTP/S/WebSocket URLs |

`recon.txt` uses a stable tagged plain-text format:

```text
PEYDA RECON REPORT
==============================================================================
Target             example.com

[WHOIS] [registrar] Example Registrar
[DNS] [A] example.com -> 1.2.3.4
[SUB] api.example.com
[HTTP] [200] [Go,nginx] https://api.example.com | API
[PORT] [443/https] api.example.com | source=naabu,nmap
[URL] https://api.example.com/users?id=1
[PARAM] [id] https://api.example.com/users?id= | source=url
[JS] https://example.com/assets/app.js
[JS-ENDPOINT] [api,relative] /api/v1/users
```

`dns.json` is an array of host records:

```json
[
  {
    "host": "example.com",
    "a": ["1.2.3.4"],
    "aaaa": [],
    "cname": [],
    "mx": ["mail.example.com"],
    "ns": [],
    "txt": [],
    "soa": [],
    "caa": [],
    "dnskey": [],
    "ds": []
  }
]
```

`http.json` is an array of HTTP assets:

```json
[
  {
    "url": "https://api.example.com",
    "host": "api.example.com",
    "status": 200,
    "title": "API",
    "content_type": "application/json",
    "content_length": 18420,
    "server": "",
    "ip": "",
    "redirect": "",
    "technologies": ["Go", "nginx"]
  }
]
```

`ports.json` is an array of open TCP ports:

```json
[
  {
    "host": "api.example.com",
    "port": 443,
    "service": "https",
    "source": "naabu,nmap"
  }
]
```

`technologies.json` groups best-effort technology hints by host:

```json
[
  {
    "host": "api.example.com",
    "technologies": ["Go", "nginx"]
  }
]
```

`summary.json` counts are derived from the final exported files:

```json
{
  "target": "example.com",
  "subdomains": 481,
  "resolved": 302,
  "live_hosts": 174,
  "ips": 18,
  "open_ports": 96,
  "urls": 18342,
  "javascript_files": 428,
  "parameters": 91,
  "endpoints": 637
}
```

## Internal Run Artifacts

The `runs/<target>/<date>/` tree is internal. It preserves raw tool output,
normalized intermediate files, JSONL events, and notes for debugging.

## `normalized/recon-events.jsonl`

Produced by `peyda run`.

Each line is one JSON object:

```json
{"type":"live_service","value":"https://app.example.com","source":"normalized/live-hosts.txt","timestamp":"2026-08-27T00:00:00Z","fields":{"status":"200","title":"Dashboard"}}
```

| Field | Meaning |
| --- | --- |
| type | Event category, such as `whois`, `dns`, `subdomain`, `live_service`, `port`, `url`, `parameter`, `javascript`, `js_endpoint`, `api_endpoint`, `cloud_candidate` |
| value | Primary value for quick filtering |
| source | File that produced the event |
| timestamp | UTC generation time |
| fields | Optional structured metadata |

## `normalized/live-hosts.txt`

Produced by `peyda run`.

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

## `normalized/whois.tsv`

Produced by `peyda run`.

| Column | Meaning |
| --- | --- |
| key | WHOIS field name, such as registrar or name_servers |
| value | Extracted field value |

## `normalized/dns-records.tsv`

Produced by `peyda run`.

| Column | Meaning |
| --- | --- |
| type | DNS record type, such as A, AAAA, MX, NS, or TXT |
| name | Queried domain name |
| value | Resolved record value |

## `normalized/open-ports.tsv`

Produced by `peyda run` when `naabu` is available.

| Column | Meaning |
| --- | --- |
| host | Hostname |
| port | Open TCP port |
| service | Service hint from common ports or `nmap` enrichment |
| source | Tool source, such as `naabu` or `naabu,nmap` |

## `normalized/urls.txt`

Produced by `peyda run` from `gau` and crawler output.

## `normalized/parameters.tsv`

Produced by `peyda run` from URL query strings and optional `Arjun` output.

| Column | Meaning |
| --- | --- |
| name | Parameter name |
| url | URL template containing the parameter |
| source | Discovery source, such as `url` or `arjun` |

## `normalized/js-endpoints.txt`

Produced by `peyda run` from native JavaScript route extraction and
`xnLinkFinder` enrichment. Native extraction understands API-like absolute
URLs, relative routes, WebSocket/GraphQL paths, Next.js app routes, and simple
JavaScript string construction such as `API + "/users"` and
`"".concat(API, "/auth/login")`.

## `notes/interesting-hosts.txt`

Produced by keyword filtering over live hosts. Treat as a review queue, not proof.

## `normalized/asset-scores.tsv`

Produced by `peyda run`.

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

Produced by `peyda run`.

| Column | Meaning |
| --- | --- |
| method | HTTP method from OpenAPI |
| path | API path from OpenAPI |
| source | Schema URL where the path was found |

## `normalized/api-inventory.tsv`

Produced by `peyda run`, then edited manually.

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

Produced by `peyda run`.

| Column | Meaning |
| --- | --- |
| route | Route, endpoint, operation, or WebSocket URL |
| source | JS, crawler, source map, browser, or manual |
| auth_guess | Expected authentication context |
| object_or_action | Inferred object or sensitive action |
| next_step | Suggested next test |

## `normalized/source-map-candidates.txt`

Produced by `peyda run`.
Treat source maps as review candidates and only inspect them where program policy allows it.

## `notes/cloud-candidates.tsv`

Produced by `peyda run`.

| Column | Meaning |
| --- | --- |
| asset_or_string | Cloud asset clue or redacted secret pattern |
| source | File and line where it appeared |
| provider_or_type | AWS, GCP, Azure, PaaS, possible token type |
| ownership_confidence | confirmed, likely, unknown, third party |
| exposure_guess | provider hint, public read, possible secret, unknown |
| next_action | Validate ownership, monitor, discard, or ask permission |

## `notes/recon-report.txt`

Produced by `peyda run`. This is an internal human-readable report for a run.
It includes run settings, counts, discovered subdomains, resolved hosts, live
HTTP/S services, JavaScript files, JavaScript route leads, API probes, API
inventory rows, cloud candidates, and next actions.

## `notes/recon-summary.md`

Produced by `peyda run`. Use it as an internal run summary and handoff aid, not as a vulnerability report.
