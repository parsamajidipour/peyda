# peyda

> A scope-first reconnaissance CLI for authorized bug bounty and security assessment workflows.

[![CI](https://github.com/parsamajidipour/peyda/actions/workflows/ci.yml/badge.svg)](https://github.com/parsamajidipour/peyda/actions/workflows/ci.yml)
[![Markdown quality](https://github.com/parsamajidipour/peyda/actions/workflows/markdown.yml/badge.svg)](https://github.com/parsamajidipour/peyda/actions/workflows/markdown.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`peyda` turns messy reconnaissance into one repeatable workflow: subdomain discovery, DNS resolution, live HTTP probing, JavaScript crawling, route extraction, API discovery, cloud hints, JSONL events, and human-readable reports.

It is designed for authorized targets. The output is a review queue, not a vulnerability report.

## What It Does

```text
target domain
  -> passive subdomain discovery
  -> normalization and exclusions
  -> DNS resolution
  -> live HTTP/S probing
  -> asset scoring
  -> JavaScript crawling and route extraction
  -> API documentation/schema probing
  -> cloud and secret-looking lead extraction
  -> text report, Markdown summary, JSONL events
```

`peyda` uses proven recon tools where they are strongest, then normalizes and explains the output with native Go logic.

| Stage | Tooling | Output |
| --- | --- | --- |
| Subdomain discovery | `subfinder` + `crt.sh` | `normalized/subdomains.txt` |
| DNS resolution | `dnsx` | `normalized/resolved-hosts.txt` |
| HTTP probing | `httpx` | `normalized/live-hosts.txt` |
| Asset scoring | Native Go | `normalized/asset-scores.tsv` |
| JavaScript recon | `katana` + native Go parsing | `normalized/js-files.txt`, `notes/js-leads.tsv` |
| API discovery | `httpx` + native OpenAPI parsing | `normalized/api-docs-probed.txt`, `normalized/api-inventory.tsv` |
| Cloud hints | Native Go | `notes/cloud-candidates.tsv` |
| Reporting | Native Go | `notes/recon-report.txt`, `notes/recon-summary.md`, `normalized/recon-events.jsonl` |

## Banner

When a recon run starts, the CLI prints a small banner:

```text
 ____  _______   ______   _
|  _ \| ____\ \ / /  _ \ / \
| |_) |  _|  \ V /| | | / _ \
|  __/| |___  | | | |_| / ___ \
|_|   |_____| |_| |____/_/   \_\

        scope-first recon automation
        authorized targets only

[INF] Scope-first recon workflow initialized
[INF] Active probing is bounded by profile and config limits
```

No version is printed in the banner for now.

## Install

Install `peyda` from the repository:

```bash
git clone https://github.com/parsamajidipour/peyda.git
cd peyda
go install ./cmd/peyda
```

Make sure Go's binary directory is in your `PATH`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

If you use `zsh`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify the install:

```bash
which peyda
peyda help
```

You can also install directly from GitHub after the repository is public and pushed:

```bash
go install github.com/parsamajidipour/peyda/cmd/peyda@latest
```

Check dependencies:

```bash
peyda deps --check
```

Install or refresh missing ProjectDiscovery tools:

```bash
peyda deps
```

`peyda` prefers `$HOME/go/bin` first in `PATH`, so ProjectDiscovery `httpx` wins over the Python package named `httpx` when both exist.

## Quick Start

Run a normal balanced recon:

```bash
peyda run -t example.com --profile balanced
```

Run with a lower HTTP probe rate:

```bash
peyda run -t example.com --profile balanced -p 25
```

Write output to a specific directory:

```bash
peyda run -t example.com --profile balanced -o ~/recon-results
```

If `-o` is not provided, `peyda` writes to `./runs` under the directory where the command was executed.

Run a passive-only pass:

```bash
peyda run -t example.com --profile passive
```

Run a deeper pass:

```bash
peyda run -t example.com --profile deep
```

Open the final text report:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-report.txt"
```

## Example Run Output

At the end of a run, `peyda` prints the main artifacts:

```text
[INF] Recon complete
[INF] Output directory: /path/to/current/directory/runs/example.com/YYYY-MM-DD
[INF] Text report: /path/to/current/directory/runs/example.com/YYYY-MM-DD/notes/recon-report.txt
[INF] Markdown summary: /path/to/current/directory/runs/example.com/YYYY-MM-DD/notes/recon-summary.md
[INF] JSONL events: /path/to/current/directory/runs/example.com/YYYY-MM-DD/normalized/recon-events.jsonl
```

Start with `notes/recon-report.txt`. It is the main human-readable output.

## Output Layout

```text
runs/example.com/YYYY-MM-DD/
├── scope.txt
├── excluded.txt
├── notes/
│   ├── recon-report.txt
│   ├── recon-summary.md
│   ├── interesting-hosts.txt
│   ├── js-leads.tsv
│   └── cloud-candidates.tsv
├── normalized/
│   ├── recon-events.jsonl
│   ├── subdomains.txt
│   ├── resolved-hosts.txt
│   ├── live-hosts.txt
│   ├── asset-scores.tsv
│   ├── js-files.txt
│   ├── js-route-leads.txt
│   ├── source-map-candidates.txt
│   └── api-inventory.tsv
├── raw/
│   ├── subfinder.txt
│   ├── crtsh.txt
│   ├── katana-urls.txt
│   ├── katana-urls.all.txt
│   ├── js/
│   └── api/
└── screenshots/
```

This tree is created under `./runs` by default. If you pass `-o ~/recon-results`, the same tree is created under `~/recon-results`.

## Profiles

Profiles are safe presets. Use them when you do not want to tune every option manually.

| Profile | Best for | Behavior |
| --- | --- | --- |
| `passive` | First look, scope expansion, low-noise inventory | Passive subdomain discovery and normalization only |
| `balanced` | Normal bug bounty recon | DNS, HTTP, JS, API, cloud hints, depth-1 crawl, moderate caps |
| `deep` | Larger scopes or dedicated review windows | Higher probe/crawl rates, depth-3 crawl, larger page caps |

Balanced defaults:

```json
{
  "probe_rate": 50,
  "crawl_rate": 10,
  "crawl_depth": 1,
  "crawl_duration": "45s",
  "max_domain_pages": 75,
  "api_rate": 20
}
```

Deep defaults:

```json
{
  "probe_rate": 100,
  "crawl_rate": 50,
  "crawl_depth": 3,
  "crawl_duration": "5m",
  "max_domain_pages": 500,
  "api_rate": 50
}
```

## Configuration Model

`peyda` has three configuration layers:

| Layer | Use it for | Example |
| --- | --- | --- |
| Profile | Pick a safe preset | `--profile balanced` |
| CLI flags | Change common run settings quickly | `-p 25 --crawl-duration 30s` |
| JSON config | Tune the underlying tools | `tools.katana.strategy = "breadth-first"` |

Precedence:

```text
built-in defaults
  -> JSON config
  -> CLI flags for common top-level run options
  -> profile defaults fill missing values
```

Tool settings are optional. If you only override one tool field, the remaining defaults stay enabled.

## Step-by-Step Config

### 1. Create a config file

```bash
peyda config init -o peyda.json
```

This creates a runnable config file.

### 2. Set the target

Edit:

```json
{
  "target": "example.com"
}
```

Only use domains that are explicitly in scope.

### 3. Choose a profile

For normal recon:

```json
{
  "profile": "balanced"
}
```

For passive discovery only:

```json
{
  "profile": "passive"
}
```

For deeper authorized recon:

```json
{
  "profile": "deep"
}
```

### 4. Tune run limits

Example: keep the run polite and bounded.

```json
{
  "probe_rate": 25,
  "crawl_rate": 10,
  "crawl_depth": 1,
  "crawl_duration": "45s",
  "max_domain_pages": 75,
  "api_rate": 20
}
```

Meaning:

| Field | Meaning |
| --- | --- |
| `probe_rate` | Rate limit for live HTTP probing |
| `crawl_rate` | Rate limit for Katana crawling |
| `crawl_depth` | Maximum crawl depth |
| `crawl_duration` | Maximum crawl time, such as `30s`, `2m`, or `5m` |
| `max_domain_pages` | Maximum pages Katana should crawl per domain |
| `api_rate` | Rate limit for API docs/schema probing |

### 5. Tune tool behavior

The `tools` section controls how `peyda` calls `subfinder`, `dnsx`, `httpx`, and `katana`.

```json
{
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

### 6. Run with the config

```bash
peyda run --config peyda.json
```

You can still override common options from the CLI:

```bash
peyda run --config peyda.json -p 15 --crawl-duration 30s
```

## Tool Config Reference

### Subfinder

```json
{
  "tools": {
    "subfinder": {
      "all": true,
      "recursive": true
    }
  }
}
```

Maps to:

```bash
subfinder -d example.com -silent -all -recursive -o raw/subfinder.txt
```

| Field | Effect |
| --- | --- |
| `all` | Enables broader passive source collection with `-all` |
| `recursive` | Enables recursive enumeration with `-recursive` |

Disable recursive enumeration:

```json
{
  "tools": {
    "subfinder": {
      "recursive": false
    }
  }
}
```

### DNSX

```json
{
  "tools": {
    "dnsx": {
      "record_types": ["a", "aaaa", "cname"],
      "response": true
    }
  }
}
```

Maps to:

```bash
dnsx -l normalized/subdomains.txt -silent -nc -a -aaaa -cname -resp -o normalized/resolved.txt
```

| Field | Effect |
| --- | --- |
| `record_types` | DNS record flags to request |
| `response` | Preserves DNS answers with `-resp` |

The default is only `["a"]` because most recon workflows start with A records.

### HTTPX

```json
{
  "tools": {
    "httpx": {
      "follow_redirects": true,
      "title": true,
      "status_code": true,
      "content_length": true,
      "content_type": true,
      "tech_detect": true
    }
  }
}
```

Maps to live probing similar to:

```bash
httpx -l normalized/resolved-hosts.txt \
  -silent -nc \
  -title -status-code -content-length -content-type -tech-detect \
  -follow-redirects \
  -rl 50 \
  -o normalized/live-hosts.txt
```

| Field | Effect |
| --- | --- |
| `follow_redirects` | Follows redirects and keeps redirect status chains |
| `title` | Captures page titles |
| `status_code` | Captures HTTP status codes |
| `content_length` | Captures response size hints |
| `content_type` | Captures response content type |
| `tech_detect` | Enables technology detection |

Turn off technology detection:

```json
{
  "tools": {
    "httpx": {
      "tech_detect": false
    }
  }
}
```

### Katana

```json
{
  "tools": {
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

Maps to crawling similar to:

```bash
katana -list normalized/live-urls.txt \
  -silent -nc \
  -d 1 -ct 45s -mdp 75 -rl 10 \
  -jc -iqp -fsu \
  -fs rdn -s depth-first \
  -o raw/katana-urls.txt
```

| Field | Effect |
| --- | --- |
| `js_crawl` | Parses JavaScript-discovered endpoints with `-jc` |
| `ignore_query_params` | Reduces duplicate URLs with `-iqp` |
| `filter_similar` | Filters similar-looking URLs with `-fsu` |
| `known_files` | Crawls known files with `-kf`, such as `robotstxt,sitemapxml` |
| `field_scope` | Controls Katana scope with `-fs`; default is `rdn` |
| `strategy` | Crawl strategy: `depth-first` or `breadth-first` |
| `headless` | Enables browser-based crawling with `-hl` |
| `xhr_extraction` | Captures XHR URLs with `-xhr` when headless mode is enabled |
| `display_out_scope` | Displays out-of-scope endpoints with `-do`; normalized recon output still filters to target scope |

Use breadth-first crawling and known files:

```json
{
  "tools": {
    "katana": {
      "strategy": "breadth-first",
      "known_files": "robotstxt,sitemapxml"
    }
  }
}
```

Use headless crawling for modern apps:

```json
{
  "crawl_duration": "2m",
  "max_domain_pages": 150,
  "tools": {
    "katana": {
      "headless": true,
      "xhr_extraction": true
    }
  }
}
```

Headless crawling is heavier. Use it only when the target is in scope and the program allows browser automation.

## Minimal Config Examples

Only change the target:

```json
{
  "target": "example.com"
}
```

Polite balanced recon:

```json
{
  "target": "example.com",
  "profile": "balanced",
  "probe_rate": 25,
  "crawl_duration": "30s",
  "max_domain_pages": 50
}
```

API-focused recon:

```json
{
  "target": "example.com",
  "profile": "balanced",
  "api_rate": 10,
  "tools": {
    "httpx": {
      "content_type": true,
      "follow_redirects": true
    },
    "katana": {
      "js_crawl": true
    }
  }
}
```

Broader DNS recon:

```json
{
  "target": "example.com",
  "tools": {
    "dnsx": {
      "record_types": ["a", "aaaa", "cname"]
    }
  }
}
```

## Reviewing Results

Open the text report:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-report.txt"
```

Review priority-scored assets:

```bash
column -t -s $'\t' "$latest_run/normalized/asset-scores.tsv" | less -S
```

Extract live services from JSONL:

```bash
jq -r 'select(.type=="live_service") | [.value, .fields.status, .fields.title] | @tsv' \
  "$latest_run/normalized/recon-events.jsonl"
```

Extract JavaScript route leads:

```bash
jq -r 'select(.type=="js_route") | .value' "$latest_run/normalized/recon-events.jsonl"
```

## Troubleshooting

| Problem | Likely cause | Fix |
| --- | --- | --- |
| `httpx` looks like the Python CLI | PATH collision | Run `peyda deps`; `$HOME/go/bin` is preferred |
| `crt.sh` returns `429` or `502` | External rate limiting or service issue | `peyda` continues with other sources |
| Very few subdomains | No provider API keys or small public footprint | Add provider config for ProjectDiscovery tools and rerun |
| Too much crawl output | Crawl caps too high | Lower `crawl_duration`, `crawl_depth`, or `max_domain_pages` |
| JS recon is skipped | `katana` missing or failed | Run `peyda deps --update` |
| Report has many low-value assets | CDN or soft-404 behavior | Start with `notes/interesting-hosts.txt` and `asset-scores.tsv` |
| Lead looks sensitive | Scope or data risk unclear | Stop and confirm authorization before validation |

## Project Layout

```text
cmd/peyda/         CLI entry point
internal/config/    JSON config, profiles, and tool defaults
internal/deps/      Dependency orchestration
internal/reconrun/  Native run setup and profile orchestration
internal/report/    Text, JSONL, and Markdown report generation
internal/subdomain/ Subdomain collection, probing, and scoring
internal/apidiscovery/ API candidate discovery and OpenAPI parsing
internal/cloud/     Cloud and secret-looking lead extraction
internal/jsrecon/   JavaScript crawling, extraction, and route triage
playbooks/          Manual review methodology
docs/               CLI design notes
config/             Keyword and path dictionaries
schemas/            Output format reference
examples/           Sample fixtures and walkthroughs
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

Only perform recon where you have explicit authorization. Follow program policy, automation limits, scope boundaries, data handling requirements, and stop conditions.

See [Security Policy](SECURITY.md) for repository safety expectations.

## License

MIT - see [LICENSE](LICENSE).
