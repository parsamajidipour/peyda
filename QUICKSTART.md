# Quickstart

Replace `example.com` with a domain that is explicitly in scope.

## 1. Build

```bash
go build -o bin/reconx ./cmd/reconx
```

## 2. Prepare Dependencies

Check only:

```bash
bin/reconx deps --check
```

Install or update missing tools:

```bash
bin/reconx deps
```

`reconx` prefers `$HOME/go/bin` first in `PATH` so ProjectDiscovery `httpx`
wins over the Python `httpx` CLI when both are installed.

## 3. Run Recon

Balanced profile:

```bash
bin/reconx run -t example.com --profile balanced -p 50
```

Passive profile:

```bash
bin/reconx run -t example.com --profile passive
```

Deep profile:

```bash
bin/reconx run -t example.com --profile deep
```

## 4. Use a Config File

```bash
bin/reconx config init
bin/reconx run --config reconx.example.json
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
  "write_jsonl": true
}
```

## 5. Review Output

```text
runs/example.com/YYYY-MM-DD/
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

Open the summary first:

```bash
latest_run="$(ls -td runs/example.com/* | head -1)"
less "$latest_run/notes/recon-summary.md"
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
| Python `httpx` runs instead of ProjectDiscovery `httpx` | PATH collision | Run `bin/reconx deps` |
| Very few subdomains | No provider API keys | Add provider config and rerun |
| Many identical live pages | CDN, wildcard, or soft-404 | Review title, length, redirects, screenshots |
| JS recon is skipped | `katana` missing or failed | Run `bin/reconx deps --update` |
| Lead looks sensitive | Scope or data risk unclear | Stop and confirm authorization |
