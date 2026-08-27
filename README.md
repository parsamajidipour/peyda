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
  -> WHOIS registration lookup
  -> DNS baseline records
  -> passive subdomain discovery
  -> subdomain resolution
  -> live HTTP/S probing
  -> port discovery and service enrichment
  -> historical URL collection
  -> crawling
  -> parameter discovery
  -> JavaScript endpoint extraction
  -> asset scoring
  -> API documentation/schema probing
  -> cloud and secret-looking lead extraction
  -> human output, JSON/JSONL, text report
```

`peyda` uses proven recon tools where they are strongest, then normalizes and explains the output with native Go logic.

| Stage | Tooling | Output |
| --- | --- | --- |
| WHOIS | `whois` | `normalized/whois.tsv` |
| DNS baseline | `dig` | `normalized/dns-records.tsv` |
| Subdomain discovery | `subfinder` + `crt.sh` | `normalized/subdomains.txt` |
| DNS resolution | `dnsx` | `normalized/resolved-hosts.txt` |
| HTTP probing | `httpx` | `normalized/live-hosts.txt` |
| Port discovery | `naabu` + `nmap` | `normalized/open-ports.tsv` |
| Historical URLs | `gau` | `normalized/urls.txt` |
| Asset scoring | Native Go | `normalized/asset-scores.tsv` |
| JavaScript recon | `katana` + `xnLinkFinder` + native Go parsing | `normalized/js-files.txt`, `normalized/js-endpoints.txt`, `notes/js-leads.tsv` |
| Parameter discovery | Native URL parsing + optional `Arjun` | `normalized/parameters.tsv` |
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
peyda run example.com --profile balanced
```

Run with a lower HTTP probe rate:

```bash
peyda run example.com --profile balanced -p 25
```

Write output to a specific directory:

```bash
peyda run example.com --profile balanced --output-dir ~/recon-results
```

If `--output-dir` is not provided, `peyda` writes artifacts to `./runs` under the directory where the command was executed.

Save the final CLI output to a file:

```bash
peyda example.com -o result.txt
```

Machine-readable output:

```bash
peyda example.com -json
peyda example.com -jsonl
peyda example.com -jsonl -o result.jsonl
```

Quiet result-only output:

```bash
peyda example.com -silent
```

For compatibility, `-t` still works:

```bash
peyda run -t example.com --profile balanced
```

Run a passive-only pass:

```bash
peyda run example.com --profile passive
```

Run a deeper pass:

```bash
peyda run example.com --profile deep
```

Open the final text report:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-report.txt"
```

## Example Run Output

By default, `peyda` prints human-readable result lines:

```text
[WHOIS] [registrar] NameCheap
[DNS] [A] example.com -> 1.2.3.4
[DNS] [MX] example.com -> mail.example.com

[SUB] api.example.com
[SUB] admin.example.com

[HTTP] [200] [nginx] https://api.example.com
[HTTP] [403] [cloudflare] https://admin.example.com

[PORT] [443/https] api.example.com
[PORT] [8080/http] api.example.com

[URL] https://example.com/login
[PARAM] [redirect] https://example.com/login?redirect=
[JS] https://example.com/assets/app.js
[JS-ENDPOINT] /api/v1/users

----------------------------------------
Scan completed in 47.2s

Subdomains       31
Live Hosts       18
IPs              7
Open Ports       24
URLs             683
Parameters       42
JavaScript       27
JS Endpoints     91
----------------------------------------
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
│   ├── open-ports.tsv
│   ├── urls.txt
│   ├── parameters.tsv
│   ├── asset-scores.tsv
│   ├── js-files.txt
│   ├── js-endpoints.txt
│   ├── js-route-leads.txt
│   ├── source-map-candidates.txt
│   └── api-inventory.tsv
├── raw/
│   ├── whois.txt
│   ├── dig-a.txt
│   ├── subfinder.txt
│   ├── crtsh.txt
│   ├── naabu.txt
│   ├── gau-urls.txt
│   ├── katana-urls.txt
│   ├── katana-urls.all.txt
│   ├── arjun.json
│   ├── xnlinkfinder.txt
│   ├── nmap/
│   ├── js/
│   └── api/
└── screenshots/
```

This tree is created under `./runs` by default. If you pass `--output-dir ~/recon-results`, the same tree is created under `~/recon-results`.

## Profiles

Profiles are safe presets. Use them when you do not want to tune every option manually.

| Profile | Best for | Behavior |
| --- | --- | --- |
| `passive` | First look, scope expansion, low-noise inventory | Passive subdomain discovery and normalization only |
| `balanced` | Normal bug bounty recon | DNS, HTTP, JS, API, cloud hints, depth-1 crawl, moderate caps |
| `deep` | Large scopes or dedicated review windows | Exhaustive crawl caps with slower, rate-limit-aware probing |

`balance` is also accepted as an alias for `balanced`.

Balanced defaults:

```json
{
  "probe_rate": 50,
  "crawl_rate": 10,
  "crawl_depth": 1,
  "crawl_duration": "45s",
  "max_domain_pages": 75,
  "api_rate": 20,
  "port_rate": 50
}
```

Deep defaults:

```json
{
  "probe_rate": 25,
  "crawl_rate": 5,
  "crawl_depth": 5,
  "crawl_duration": "30m",
  "max_domain_pages": 5000,
  "api_rate": 10,
  "port_rate": 25
}
```

Deep mode is intentionally slower. It favors broader coverage across live subdomains and deeper crawling over speed, which makes it better for long authorized recon windows.

### Profile Intensity

Profiles tune both workflow depth and the underlying tool flags.

| Tool | `passive` | `balanced` | `deep` |
| --- | --- | --- | --- |
| `whois` | Standard lookup | Standard lookup | Verbose lookup with `--verbose` |
| `dig` | Baseline DNS records | A, AAAA, MX, NS, TXT, SOA, CAA | Baseline records plus DNSSEC-oriented records, delegation trace, and NS search |
| `subfinder` | Passive sources | `-all -recursive`, normal timeout | `-all -recursive`, longer timeout and max-time |
| `dnsx` | Skipped | A records with responses | A, AAAA, CNAME, NS, MX, TXT, SOA, CAA with trace |
| `httpx` | Skipped | Parse-friendly live probing | Parse-friendly live probing plus rich JSONL fingerprinting |
| `naabu` | Skipped | Top 1000 ports with service hints | Full port range, all resolved IPs, verification, passive hints, service/version discovery |
| `nmap` | Skipped | Service enrichment for discovered ports | Service enrichment for discovered ports |
| `gau` | Skipped | All providers with moderate retry/timeout | All providers with higher retry/timeout and lower threading |
| `katana` | Skipped | Scoped JavaScript-aware crawl | Headless crawl, XHR extraction, JSLuice, forms, known files, path climb, knowledge base |
| `Arjun` | Skipped | Optional parameter probing | Optional parameter probing after URL normalization |
| `xnLinkFinder` | Skipped | Optional JavaScript endpoint extraction | Optional JavaScript endpoint extraction after JS download |

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
  "api_rate": 20,
  "port_rate": 50
}
```

Meaning:

| Field | Meaning |
| --- | --- |
| `probe_rate` | Rate limit for live HTTP probing |
| `crawl_rate` | Rate limit for Katana crawling |
| `crawl_depth` | Maximum crawl depth |
| `crawl_duration` | Maximum crawl time, such as `30s`, `2m`, `5m`, or `30m` |
| `max_domain_pages` | Maximum pages Katana should crawl per domain |
| `api_rate` | Rate limit for API docs/schema probing |
| `port_rate` | Rate limit for Naabu port probing |

### 5. Tune tool behavior

The `tools` section controls how `peyda` calls each recon stage. Helpers such as
`whois`, `dig`, `naabu`, `nmap`, `gau`, `Arjun`, and `xnLinkFinder` are detected
automatically and skipped gracefully if they are not installed.

```json
{
  "tools": {
    "whois": {
      "verbose": false
    },
    "dig": {
      "record_types": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"],
      "trace": false,
      "nssearch": false
    },
    "subfinder": {
      "all": true,
      "recursive": true,
      "timeout": 30,
      "max_time": 10
    },
    "dnsx": {
      "record_types": ["a"],
      "response": true,
      "recon": false,
      "trace": false
    },
    "httpx": {
      "follow_redirects": true,
      "title": true,
      "status_code": true,
      "content_length": true,
      "content_type": true,
      "tech_detect": true,
      "web_server": false,
      "ip": false,
      "cname": false,
      "asn": false,
      "cdn": true,
      "response_time": false,
      "http2": false,
      "pipeline": false,
      "tls_probe": false,
      "tls_grab": false,
      "probe_all_ips": false,
      "retries": 1,
      "timeout": 10
    },
    "naabu": {
      "top_ports": "1000",
      "scan_all_ips": false,
      "service_discovery": true,
      "service_version": false,
      "verify": false,
      "passive": false
    },
    "gau": {
      "subs": true,
      "providers": ["wayback", "commoncrawl", "otx", "urlscan"],
      "retries": 2,
      "timeout": 60,
      "threads": 2
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
      "display_out_scope": false,
      "jsluice": false,
      "form_extraction": false,
      "tech_detect": false,
      "path_climb": false,
      "knowledge_base": false,
      "store_field": "",
      "concurrency": 10,
      "parallelism": 10,
      "host_rate_limit": 0
    },
    "arjun": {
      "enabled": true
    },
    "xnlinkfinder": {
      "enabled": true
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

### WHOIS

```json
{
  "tools": {
    "whois": {
      "verbose": true
    }
  }
}
```

Maps to:

```bash
whois --verbose example.com
```

Deep profile enables verbose WHOIS automatically.

### Dig

```json
{
  "tools": {
    "dig": {
      "record_types": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"],
      "trace": true,
      "nssearch": true
    }
  }
}
```

Maps to:

```bash
dig +short example.com A
dig +short example.com MX
dig +trace example.com
dig +nssearch example.com
```

Deep profile adds DNSSEC-oriented records, delegation trace, and NS search.

### Subfinder

```json
{
  "tools": {
    "subfinder": {
      "all": true,
      "recursive": true,
      "timeout": 30,
      "max_time": 10
    }
  }
}
```

Maps to:

```bash
subfinder -d example.com -silent -all -recursive -timeout 30 -max-time 10 -o raw/subfinder.txt
```

| Field | Effect |
| --- | --- |
| `all` | Enables broader passive source collection with `-all` |
| `recursive` | Enables recursive enumeration with `-recursive` |
| `timeout` | Per-source timeout in seconds |
| `max_time` | Maximum enumeration time in minutes |

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
      "response": true,
      "recon": false,
      "trace": false
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
| `recon` | Uses `dnsx -recon` to query all supported DNS record types |
| `trace` | Enables DNS tracing with `-trace` |

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
      "tech_detect": true,
      "web_server": true,
      "ip": true,
      "cname": true,
      "asn": true,
      "cdn": true,
      "response_time": true,
      "http2": true,
      "pipeline": true,
      "tls_probe": true,
      "tls_grab": true,
      "probe_all_ips": true,
      "retries": 2,
      "timeout": 20
    }
  }
}
```

Maps to live probing similar to:

```bash
httpx -l normalized/resolved-hosts.txt \
  -silent -nc \
  -title -status-code -content-length -content-type -tech-detect \
  -web-server -ip -cname -asn -cdn -response-time \
  -http2 -pipeline -tls-probe -tls-grab -probe-all-ips \
  -follow-redirects \
  -retries 2 -timeout 20 -rl 25 \
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
| `web_server` | Captures server header hints with `-web-server` |
| `ip` | Captures resolved host IPs |
| `cname` | Captures CNAME data |
| `asn` | Captures ASN metadata |
| `cdn` | Captures CDN/WAF hints |
| `response_time` | Captures response time |
| `http2` | Probes HTTP/2 support |
| `pipeline` | Probes HTTP pipeline support |
| `tls_probe` | Probes TLS names |
| `tls_grab` | Captures TLS metadata |
| `probe_all_ips` | Probes all resolved IPs for a host |
| `retries` | Retry count |
| `timeout` | HTTP timeout in seconds |

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

### Naabu

```json
{
  "tools": {
    "naabu": {
      "top_ports": "full",
      "scan_all_ips": true,
      "service_discovery": true,
      "service_version": true,
      "verify": true,
      "passive": true
    }
  }
}
```

Maps to:

```bash
naabu -list normalized/resolved-hosts.txt \
  -silent -nc -rate 25 \
  -top-ports full -scan-all-ips \
  -service-discovery -service-version -verify -passive \
  -o raw/naabu.txt
```

Deep profile uses the full port set and lower rate by default.

### Gau

```json
{
  "tools": {
    "gau": {
      "subs": true,
      "providers": ["wayback", "commoncrawl", "otx", "urlscan"],
      "retries": 5,
      "timeout": 120,
      "threads": 1
    }
  }
}
```

Maps to:

```bash
gau --subs \
  --providers wayback,commoncrawl,otx,urlscan \
  --retries 5 --timeout 120 --threads 1 \
  example.com
```

Deep profile uses higher retry/timeout values and fewer threads to reduce noisy
provider failures.

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
      "headless": true,
      "xhr_extraction": true,
      "display_out_scope": false,
      "jsluice": true,
      "form_extraction": true,
      "tech_detect": true,
      "path_climb": true,
      "knowledge_base": true,
      "concurrency": 5,
      "parallelism": 5,
      "host_rate_limit": 2
    }
  }
}
```

Maps to crawling similar to:

```bash
katana -list normalized/live-urls.txt \
  -silent -nc \
  -d 5 -ct 30m -mdp 5000 -rl 5 -c 5 -p 5 -hrl 2 \
  -jc -jsl -iqp -fsu -hl -xhr -fx -td -pc -kb \
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
| `jsluice` | Enables memory-intensive JavaScript parsing with `-jsl` |
| `form_extraction` | Extracts forms and inputs with `-fx` |
| `tech_detect` | Enables Katana technology detection |
| `path_climb` | Crawls parent paths with `-pc` |
| `knowledge_base` | Enables knowledge-base classification |
| `concurrency` | Katana fetcher concurrency |
| `parallelism` | Number of inputs processed in parallel |
| `host_rate_limit` | Per-host crawl rate limit |

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

### Arjun

```json
{
  "tools": {
    "arjun": {
      "enabled": true
    }
  }
}
```

When enabled and installed, `peyda` runs Arjun after URL normalization and merges
parameter candidates into `normalized/parameters.tsv`.

### XNLinkFinder

```json
{
  "tools": {
    "xnlinkfinder": {
      "enabled": true
    }
  }
}
```

When enabled and installed, `peyda` runs `xnLinkFinder` against downloaded
JavaScript files and merges endpoints into `normalized/js-endpoints.txt`.

## Workflow Graph

```text
                 Target
                   |
          +--------+--------+
          v                 v
       whois               dig
                            |
                            v
                        subfinder
                            |
                            v
                          dnsx
                            |
                +-----------+-----------+
                v                       v
             httpx                   naabu
                |                       |
                v                       v
            web_hosts                 nmap
                |
      +---------+---------+
      v                   v
   katana                 gau
      |                   |
      +---------+---------+
                v
          URL Normalizer
                |
                v
             all_urls
           +----+----+
           v         v
         Arjun     JS Recon
```

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
