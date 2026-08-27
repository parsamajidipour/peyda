# reconx

> A scope-first reconnaissance CLI for authorized bug bounty and security assessment workflows.

[![CI](https://github.com/parsamajidipour/reconx/actions/workflows/ci.yml/badge.svg)](https://github.com/parsamajidipour/reconx/actions/workflows/ci.yml)
[![Markdown quality](https://github.com/parsamajidipour/reconx/actions/workflows/markdown.yml/badge.svg)](https://github.com/parsamajidipour/reconx/actions/workflows/markdown.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`reconx` turns messy reconnaissance into a repeatable command-line workflow:
scope setup, passive subdomain collection, DNS resolution, live HTTP probing,
JavaScript route extraction, API discovery, cloud hints, JSONL events, and a
human-readable report.

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
| `balanced` | Subdomains, DNS, HTTP probing, JS, API, cloud leads |
| `deep` | Balanced workflow with higher crawl and probe limits |

Example:

```bash
bin/reconx run -t sooq-cars.com --profile balanced -p 25
```

Outputs:

```text
runs/example.com/YYYY-MM-DD/
├── notes/recon-summary.md
├── normalized/recon-events.jsonl
├── normalized/live-hosts.txt
├── normalized/asset-scores.tsv
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

## Project Layout

```text
cmd/reconx/        CLI entry point
internal/config/   JSON config and profile defaults
internal/deps/     Dependency orchestration
internal/reconrun/ Native run setup and profile orchestration
internal/report/   JSONL and Markdown report generation
internal/subdomain/ Native subdomain collection, probing, and scoring
internal/apidiscovery/ Native API candidate discovery and OpenAPI parsing
scripts/           External engine adapters
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
