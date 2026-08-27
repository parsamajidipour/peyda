# peyda

> A scope-first reconnaissance CLI for authorized bug bounty and security assessment workflows.

[![CI](https://github.com/parsamajidipour/peyda/actions/workflows/ci.yml/badge.svg)](https://github.com/parsamajidipour/peyda/actions/workflows/ci.yml)
[![Markdown quality](https://github.com/parsamajidipour/peyda/actions/workflows/markdown.yml/badge.svg)](https://github.com/parsamajidipour/peyda/actions/workflows/markdown.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`peyda` is an opinionated reconnaissance CLI that turns one authorized domain into a clean, reusable recon dataset.

```bash
peyda example.com
```

Peyda collects useful reconnaissance data, normalizes it, deduplicates it, and writes the final dataset to:

```text
results/example.com/
```

It is designed for authorized targets. Peyda is not a vulnerability scanner, exploitation framework, or finding generator.

## What You Get

After a run, the stable public output contract is:

```text
results/example.com/
├── subdomains.txt
├── resolved.txt
├── live.txt
├── urls.txt
├── parameters.txt
├── javascript.txt
├── endpoints.txt
├── dns.json
├── http.json
├── technologies.json
└── summary.json
```

These files are meant to be piped into other tools, reviewed manually, or archived as a clean dataset.

| File | Contains |
| --- | --- |
| `subdomains.txt` | Unique in-scope hostnames discovered for the target |
| `resolved.txt` | In-scope hostnames that resolved through DNS |
| `live.txt` | Reachable HTTP/S URLs with the working scheme preserved |
| `urls.txt` | Normalized unique URLs from historical sources and crawling |
| `parameters.txt` | Unique parameter names only |
| `javascript.txt` | Unique in-scope JavaScript URLs |
| `endpoints.txt` | Interesting relative or in-scope absolute routes/endpoints |
| `dns.json` | Structured DNS records grouped by host |
| `http.json` | Asset-oriented HTTP metadata |
| `technologies.json` | Best-effort technology hints per host |
| `summary.json` | Counts derived from the final exported dataset |

Internal artifacts are still preserved under `runs/example.com/YYYY-MM-DD/` for debugging and reproducibility.

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
[INF] Active probing is bounded by built-in safety limits and config
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

Run the default recon pipeline:

```bash
peyda example.com
```

At the end, Peyda prints a concise summary:

```text
PEYDA

Target: example.com

Subdomains       481
Resolved         302
Live hosts       174
URLs             18342
Parameters       91
JavaScript       428
Endpoints        637

Output: results/example.com/
Duration: 2m41s
```

The main dataset is immediately available at:

```bash
ls results/example.com/
```

Compatibility with the explicit `run` command remains:

```bash
peyda run example.com
```

Run with a lower HTTP probe rate:

```bash
peyda example.com -p 25
```

Choose a base output directory:

```bash
peyda example.com --output-dir ~/recon-output
```

This creates:

```text
~/recon-output/results/example.com/
~/recon-output/runs/example.com/YYYY-MM-DD/
```

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
peyda run -t example.com
```

Review internal run notes when you need troubleshooting detail:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-report.txt"
```

## Example Run Output

By default, `peyda` prints progress and a final summary, not every collected result:

```text
PEYDA

Target: example.com

Subdomains       31
Resolved         24
Live hosts       18
URLs             683
Parameters       42
JavaScript       27
Endpoints        91

Output: results/example.com/
Duration: 47s
```

Open `results/example.com/` first. Use `runs/example.com/YYYY-MM-DD/` only when you need raw tool output or troubleshooting details.

## Output Layout

The final dataset:

```text
results/example.com/
├── subdomains.txt
├── resolved.txt
├── live.txt
├── urls.txt
├── parameters.txt
├── javascript.txt
├── endpoints.txt
├── dns.json
├── http.json
├── technologies.json
└── summary.json
```

Internal artifacts:

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

By default, `results/` and `runs/` are created under the directory where `peyda`
was executed. If you pass `--output-dir ~/recon-output`, Peyda writes to
`~/recon-output/results/` and `~/recon-output/runs/`.

## Default Recon Mode

Peyda has one default recon mode. It is intentionally thorough while still
applying conservative rate limits.

Default limits:

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

This mode favors broader coverage across live subdomains and extensive crawling
over speed, which makes it better for authorized recon windows where completeness
matters.

### Tool Intensity

The default mode tunes both workflow depth and the underlying tool flags.

| Tool | Default behavior |
| --- | --- |
| `whois` | Verbose lookup with `--verbose` |
| `dig` | Baseline records plus DNSSEC-oriented records, delegation trace, and NS search |
| `subfinder` | `-all -recursive`, longer timeout and max-time |
| `dnsx` | A, AAAA, CNAME, NS, MX, TXT, SOA, CAA with trace |
| `httpx` | Parse-friendly live probing plus rich JSONL fingerprinting |
| `naabu` | Full port range, all resolved IPs, verification, provider hints, service/version discovery |
| `nmap` | Service enrichment for discovered ports |
| `gau` | All providers with higher retry/timeout and lower threading |
| `katana` | Headless crawl, XHR extraction, JSLuice, forms, known files, path climb, knowledge base |
| `Arjun` | Optional parameter probing after URL normalization |
| `xnLinkFinder` | Optional JavaScript endpoint extraction after JS download |

## Configuration Model

`peyda` has two configuration layers:

| Layer | Use it for | Example |
| --- | --- | --- |
| CLI flags | Change common run settings quickly | `-p 25 --crawl-duration 30s` |
| JSON config | Tune the underlying tools | `tools.katana.strategy = "breadth-first"` |

Precedence:

```text
built-in defaults
  -> JSON config
  -> CLI flags for common top-level run options
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

### 3. Tune run limits

Example: keep the run polite and bounded.

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

### 4. Tune tool behavior

The `tools` section controls how `peyda` calls each recon stage. Helpers such as
`whois`, `dig`, `naabu`, `nmap`, `gau`, `Arjun`, and `xnLinkFinder` are detected
automatically and skipped gracefully if they are not installed.

```json
{
  "tools": {
    "whois": {
      "verbose": true
    },
    "dig": {
      "record_types": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DNSKEY", "DS"],
      "trace": true,
      "nssearch": true
    },
    "subfinder": {
      "all": true,
      "recursive": true,
      "timeout": 120,
      "max_time": 60
    },
    "dnsx": {
      "record_types": ["a", "aaaa", "cname", "ns", "mx", "txt", "soa", "caa"],
      "response": true,
      "recon": false,
      "trace": true
    },
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
    },
    "naabu": {
      "top_ports": "full",
      "scan_all_ips": true,
      "service_discovery": true,
      "service_version": true,
      "verify": true,
      "passive": true
    },
    "gau": {
      "subs": true,
      "providers": ["wayback", "commoncrawl", "otx", "urlscan"],
      "retries": 5,
      "timeout": 120,
      "threads": 1
    },
    "katana": {
      "js_crawl": true,
      "ignore_query_params": true,
      "filter_similar": true,
      "known_files": "all",
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
      "store_field": "",
      "concurrency": 5,
      "parallelism": 5,
      "host_rate_limit": 2
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

### 5. Run with the config

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

Verbose WHOIS is enabled by default.

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

DNSSEC-oriented records, delegation trace, and NS search are enabled by default.

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

The full port set and lower rate are enabled by default.

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

Higher retry/timeout values and fewer threads are enabled by default to reduce
noisy provider failures.

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

Polite custom run:

```json
{
  "target": "example.com",
  "probe_rate": 25,
  "crawl_duration": "30s",
  "max_domain_pages": 50
}
```

API-focused recon:

```json
{
  "target": "example.com",
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

Start with the final dataset:

```bash
cd results/example.com
wc -l subdomains.txt resolved.txt live.txt urls.txt parameters.txt javascript.txt endpoints.txt
jq . summary.json
```

Open the internal text report when you need run details:

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
internal/config/    JSON config and tool defaults
internal/deps/      Dependency orchestration
internal/reconrun/  Native run setup and pipeline orchestration
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
