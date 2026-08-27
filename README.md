# reconx

> A scope-first reconnaissance CLI for authorized bug bounty and security assessment workflows.

[![CI](https://github.com/parsamajidipour/reconx/actions/workflows/ci.yml/badge.svg)](https://github.com/parsamajidipour/reconx/actions/workflows/ci.yml)
[![Markdown quality](https://github.com/parsamajidipour/reconx/actions/workflows/markdown.yml/badge.svg)](https://github.com/parsamajidipour/reconx/actions/workflows/markdown.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`reconx` turns messy reconnaissance into a repeatable command-line workflow:
scope setup, passive subdomain collection, DNS resolution, live HTTP probing,
JavaScript route extraction, API discovery, cloud hints, JSONL events, and
human-readable text/Markdown reports.

Recon output is a review queue, not a vulnerability report. The tool preserves
evidence, keeps output structured, and makes manual validation easier.

## Install

```bash
go build -o bin/reconx ./cmd/reconx
bin/reconx deps --check
```

Install or refresh dependencies:

```bash
bin/reconx deps
```

## Run

```bash
bin/reconx run -t example.com --profile balanced
```

Depth profiles:

| Profile | Behavior |
| --- | --- |
| `passive` | Passive subdomain collection and normalization only; no active dependency setup |
| `balanced` | Subdomains, DNS, HTTP probing, JS, API, cloud leads with a capped depth-1 crawl |
| `deep` | Balanced workflow with higher crawl and probe limits, depth-3 crawl, and larger page caps |

Example:

```bash
bin/reconx run -t sooq-cars.com --profile balanced -p 25
```

Outputs:

```text
runs/example.com/YYYY-MM-DD/
├── notes/recon-report.txt
├── notes/recon-summary.md
├── normalized/recon-events.jsonl
├── normalized/live-hosts.txt
├── normalized/asset-scores.tsv
├── normalized/js-route-leads.txt
├── normalized/api-inventory.tsv
├── raw/
└── screenshots/
```

## Config

Create an example config:

```bash
bin/reconx config init
```

Run with config:

```bash
bin/reconx run --config reconx.example.json
```

`reconx` has three configuration layers:

| Layer | Use it for |
| --- | --- |
| Profile | Pick a safe preset: `passive`, `balanced`, or `deep` |
| CLI flags | Change common run settings quickly, such as rate or crawl depth |
| JSON config | Tune underlying tools without turning the CLI into a long flag list |

Example:

```json
{
  "target": "example.com",
  "profile": "balanced",
  "probe_rate": 50,
  "crawl_rate": 10,
  "crawl_depth": 1,
  "crawl_duration": "45s",
  "max_domain_pages": 75,
  "tools": {
    "subfinder": {
      "all": true,
      "recursive": true
    },
    "dnsx": {
      "record_types": ["a"],
      "response": true
    },
    "httpx": {
      "follow_redirects": true,
      "title": true,
      "status_code": true,
      "content_length": true,
      "content_type": true,
      "tech_detect": true
    },
    "katana": {
      "js_crawl": true,
      "ignore_query_params": true,
      "filter_similar": true,
      "known_files": "",
      "field_scope": "rdn",
      "strategy": "depth-first",
      "headless": false,
      "xhr_extraction": false,
      "display_out_scope": false
    }
  }
}
```

Tool settings are optional. If you only override one field, the remaining safe
defaults stay enabled.

| Config path | Controls |
| --- | --- |
| `tools.subfinder.all` | Adds `subfinder -all` for broader passive sources |
| `tools.subfinder.recursive` | Adds `subfinder -recursive` for recursive enumeration |
| `tools.dnsx.record_types` | Adds DNS record flags such as `-a`, `-aaaa`, or `-cname` |
| `tools.dnsx.response` | Adds `dnsx -resp` to preserve DNS answers |
| `tools.httpx.*` | Controls live probing fields such as title, status, content type, tech detection, and redirects |
| `tools.katana.js_crawl` | Adds `katana -jc` to parse JavaScript-discovered endpoints |
| `tools.katana.known_files` | Adds `katana -kf`, for example `robotstxt,sitemapxml` |
| `tools.katana.field_scope` | Adds `katana -fs`, usually `rdn` for root-domain scope |
| `tools.katana.strategy` | Adds `katana -s`, such as `depth-first` or `breadth-first` |
| `tools.katana.headless` | Adds `katana -hl` for browser-based crawling |
| `tools.katana.xhr_extraction` | Adds `katana -xhr` when headless crawling should collect XHR URLs |

## Project Layout

```text
cmd/reconx/        CLI entry point
internal/config/   JSON config and profile defaults
internal/deps/     Dependency orchestration
internal/reconrun/ Native run setup and profile orchestration
internal/report/   Text, JSONL, and Markdown report generation
internal/subdomain/ Native subdomain collection, probing, and scoring
internal/apidiscovery/ Native API candidate discovery and OpenAPI parsing
internal/cloud/    Native cloud and secret-looking lead extraction
internal/jsrecon/  Native JavaScript crawling, extraction, and route triage
playbooks/         Manual review methodology
docs/              CLI design notes
config/            Keyword and path dictionaries
schemas/           Output format reference
examples/          Sample fixtures and walkthroughs
```

## Documentation

- [Quickstart](QUICKSTART.md)
- [CLI Design](docs/cli-design.md)
- [Output Schemas](schemas/output-schemas.md)
- [Tool Install](automation/tool-install.md)
- [Safe Automation](automation/safe-automation.md)
- [SaaS Target Walkthrough](examples/scenarios/saas-target-walkthrough.md)

## Playbooks

- [Passive Recon](playbooks/passive-recon.md)
- [Subdomain Enumeration](playbooks/subdomain-enumeration.md)
- [JavaScript Recon](playbooks/javascript-recon.md)
- [API Discovery](playbooks/api-discovery.md)
- [Screenshot Review](playbooks/screenshot-review.md)
- [Cloud Asset Discovery](playbooks/cloud-asset-discovery.md)
- [Monitoring Pipeline](playbooks/monitoring-pipeline.md)

## Responsible Use

Only perform recon where you have explicit authorization. Follow program policy,
automation limits, scope boundaries, data handling requirements, and stop conditions.

See [Security Policy](SECURITY.md) for repository safety expectations.

## License

MIT - see [LICENSE](LICENSE).
