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

Default recon:

```bash
peyda example.com
```

Open the final dataset:

```bash
ls results/example.com/
```

Choose a base output directory:

```bash
peyda example.com --output-dir ~/recon-output
```

This writes the final dataset to `~/recon-output/results/example.com/` and
internal run artifacts to `~/recon-output/runs/example.com/YYYY-MM-DD/`.

Save the CLI output:

```bash
peyda example.com -o result.txt
```

Machine-readable output:

```bash
peyda example.com -json
peyda example.com -jsonl
```

The legacy `-t` form still works, but the positional target is preferred.

## 4. Use a Config File

```bash
peyda config init
peyda run --config peyda.example.json
```

Minimal config:

```json
{
  "target": "example.com",
  "output_root": "runs",
  "results_root": "results"
}
```

`peyda config init` writes the full config schema with all supported tool
options. You do not need to define every option. For example, this keeps all
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

Check final counts:

```bash
jq . results/example.com/summary.json
```

Open the internal text report when you need troubleshooting details:

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

## Troubleshooting

| Problem | Likely cause | Fix |
| --- | --- | --- |
| Python `httpx` runs instead of ProjectDiscovery `httpx` | PATH collision | Run `peyda deps` |
| Very few subdomains | No provider API keys | Add provider config and rerun |
| Many identical live pages | CDN, wildcard, or soft-404 | Review title, length, redirects, screenshots |
| JS recon is skipped | `katana` missing or failed | Run `peyda deps --update` |
| Lead looks sensitive | Scope or data risk unclear | Stop and confirm authorization |
