# Quickstart

Replace `example.com` with a domain that is explicitly in scope.

## 1. Install

```bash
git clone https://github.com/parsamajidipour/peyda.git
cd peyda
go install ./cmd/peyda
```

Add Go's binary directory to your `PATH` if needed:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

For `zsh`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Verify:

```bash
which peyda
peyda help
```

## 2. Prepare Dependencies

Check only:

```bash
peyda deps --check
```

Install or update missing tools:

```bash
peyda deps
```

`peyda` prefers `$HOME/go/bin` first in `PATH` so ProjectDiscovery `httpx`
wins over the Python `httpx` CLI when both are installed.

## 3. Run Recon

Balanced profile:

```bash
peyda run -t example.com --profile balanced -p 50
```

Choose an output directory:

```bash
peyda run -t example.com --profile balanced -o ~/recon-results
```

Without `-o`, output is written to `./runs` under the directory where `peyda` was executed.

Passive profile:

```bash
peyda run -t example.com --profile passive
```

Deep profile:

```bash
peyda run -t example.com --profile deep
```

## 4. Use a Config File

```bash
peyda config init
peyda run --config peyda.example.json
```

Config fields:

```json
{
  "target": "example.com",
  "output_root": "runs",
  "profile": "balanced",
  "probe_rate": 50,
  "crawl_rate": 10,
  "crawl_depth": 1,
  "crawl_duration": "45s",
  "max_domain_pages": 75,
  "api_rate": 20,
  "excluded_file": "",
  "skip_deps": false,
  "write_jsonl": true,
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

You do not need to define every tool option. For example, this keeps all
defaults and only changes Katana's crawl strategy:

```json
{
  "target": "example.com",
  "tools": {
    "katana": {
      "strategy": "breadth-first"
    }
  }
}
```

Common customizations:

| Goal | Config change |
| --- | --- |
| Crawl `robots.txt` and sitemap URLs | Set `tools.katana.known_files` to `robotstxt,sitemapxml` |
| Try extra DNS record types | Set `tools.dnsx.record_types` to `["a", "aaaa", "cname"]` |
| Reduce noisy HTTP output files | Set unused `tools.httpx` fields to `false` |
| Crawl with a browser | Set `tools.katana.headless` to `true` |
| Capture XHR URLs in headless mode | Set `tools.katana.xhr_extraction` to `true` |

## 5. Review Output

```text
runs/example.com/YYYY-MM-DD/
├── notes/recon-report.txt
├── notes/recon-summary.md
├── normalized/recon-events.jsonl
├── normalized/subdomains.txt
├── normalized/resolved-hosts.txt
├── normalized/live-hosts.txt
├── normalized/asset-scores.tsv
├── normalized/js-route-leads.txt
├── normalized/source-map-candidates.txt
├── normalized/api-inventory.tsv
└── notes/cloud-candidates.tsv
```

Open the text report first:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-report.txt"
```

Use JSONL for automation:

```bash
jq -r 'select(.type=="live_service") | [.value, .fields.status, .fields.title] | @tsv' \
  "$latest_run/normalized/recon-events.jsonl"
```

Review priority-scored assets:

```bash
column -t -s $'\t' "$latest_run/normalized/asset-scores.tsv" | less -S
```

## Profiles

| Profile | Best for | Active probing |
| --- | --- | --- |
| `passive` | Safe first pass, scope expansion, asset inventory | No DNS or HTTP probing |
| `balanced` | Normal bug bounty recon | DNS, HTTP, JS, API, cloud hints; depth 1 crawl capped to 75 pages/domain |
| `deep` | Larger scopes or dedicated review windows | Higher probe and crawl limits; depth 3 crawl capped to 500 pages/domain |

## Troubleshooting

| Problem | Likely cause | Fix |
| --- | --- | --- |
| Python `httpx` runs instead of ProjectDiscovery `httpx` | PATH collision | Run `peyda deps` |
| Very few subdomains | No provider API keys | Add provider config and rerun |
| Many identical live pages | CDN, wildcard, or soft-404 | Review title, length, redirects, screenshots |
| JS recon is skipped | `katana` missing or failed | Run `peyda deps --update` |
| Lead looks sensitive | Scope or data risk unclear | Stop and confirm authorization |
