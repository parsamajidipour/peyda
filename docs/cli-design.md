# CLI Design

`peyda` is an opinionated domain-to-recon-dataset CLI. The repository still
keeps the playbooks because they explain how to review and validate the data
produced by the tool.

## Current CLI

```bash
go install ./cmd/peyda
peyda example.com
peyda example.com -silent
peyda example.com -jsonl -o results.jsonl
```

Commands:

| Command | Purpose |
| --- | --- |
| `peyda example.com` | Runs the default recon pipeline and writes `results/example.com/` |
| `peyda run` | Compatibility command for the same pipeline |
| `peyda deps` | Checks, installs, or updates required recon dependencies |
| `peyda init` | Creates a structured run folder |
| `peyda config init` | Writes an example JSON config |
| `peyda version` | Prints the CLI version |

## Design Goals

- Produce `results/<target>/` as the stable researcher-facing dataset.
- Keep `runs/<target>/<date>/` as internal execution history.
- Produce JSONL events for automation and text/Markdown reports for internal run review.
- Keep terminal human mode focused on progress and final counts.
- Keep asset scoring as extended analysis, not the core product identity.
- Keep subdomain normalization, exclusion filtering, and asset scoring native.
- Keep API candidate selection, OpenAPI parsing, and inventory generation native.
- Keep cloud and secret-looking lead extraction native with conservative redaction.
- Keep JavaScript URL extraction, route triage, and source-map candidate generation native.
- Keep raw output separate from normalized output.
- Treat recon leads as candidates, not vulnerability findings.
- Detect common tool collisions, especially Python `httpx` versus ProjectDiscovery `httpx`.
- Keep every active probing step tied to explicit scope and rate limits.
- Keep common run controls as CLI flags and tool-specific behavior in JSON config.

## Stage Order

```text
whois -> dig -> subfinder -> dnsx -> httpx -> naabu -> nmap -> gau -> katana -> Arjun -> xnLinkFinder
```

Missing optional tools are skipped gracefully; normalized outputs are still created.

## Profiles

| Profile | Purpose |
| --- | --- |
| `passive` | Passive subdomain collection only; no DNS or HTTP probing or active dependency setup |
| `balanced` | Standard recon pipeline with moderate limits |
| `deep` | Exhaustive, slower, rate-limit-aware crawl and probe settings for large authorized scopes |

## Configuration Model

Profiles provide safe presets. CLI flags are for common one-off changes such as
`--profile`, `--crawl-depth`, `--crawl-duration`, and `-p`. The `tools` section
in JSON config controls the ProjectDiscovery command flags used internally.

This keeps the normal command short while still allowing advanced users to tune
`subfinder`, `dnsx`, `httpx`, `naabu`, `gau`, and `katana` behavior.

## Roadmap

1. Parse ProjectDiscovery `httpx` JSON output natively instead of text output.
2. Add screenshots as a first-class CLI stage.
3. Add profile presets for rate, crawl depth, and module selection.
4. Add HTML reports for presentation and GitHub artifacts.
5. Add installable release binaries for users who do not have Go installed.
