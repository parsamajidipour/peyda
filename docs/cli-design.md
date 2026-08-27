# CLI Design

`reconx` is moving from a playbook repository into a scope-first reconnaissance CLI.
The repository still keeps the playbooks because they explain how to review and validate
the data produced by the tool.

## Current CLI

```bash
go install ./cmd/reconx
reconx run -t example.com --profile balanced -p 50
```

Commands:

| Command | Purpose |
| --- | --- |
| `reconx run` | Runs the complete recon pipeline for one scoped root domain |
| `reconx deps` | Checks, installs, or updates required recon dependencies |
| `reconx init` | Creates a structured run folder |
| `reconx config init` | Writes an example JSON config |
| `reconx version` | Prints the CLI version |

## Design Goals

- Produce normalized files that can be reviewed, diffed, and handed off.
- Produce JSONL events for automation and text/Markdown reports for humans.
- Score live assets so the manual review queue is explainable.
- Keep subdomain normalization, exclusion filtering, and asset scoring native.
- Keep API candidate selection, OpenAPI parsing, and inventory generation native.
- Keep cloud and secret-looking lead extraction native with conservative redaction.
- Keep JavaScript URL extraction, route triage, and source-map candidate generation native.
- Keep raw output separate from normalized output.
- Treat recon leads as candidates, not vulnerability findings.
- Detect common tool collisions, especially Python `httpx` versus ProjectDiscovery `httpx`.
- Keep every active probing step tied to explicit scope and rate limits.
- Keep common run controls as CLI flags and tool-specific behavior in JSON config.

## Profiles

| Profile | Purpose |
| --- | --- |
| `passive` | Passive subdomain collection only; no DNS or HTTP probing or active dependency setup |
| `balanced` | Standard recon pipeline with moderate limits |
| `deep` | Higher probe and crawl rates for larger authorized scopes |

## Configuration Model

Profiles provide safe presets. CLI flags are for common one-off changes such as
`--profile`, `--crawl-depth`, `--crawl-duration`, and `-p`. The `tools` section
in JSON config controls the ProjectDiscovery command flags used internally.

This keeps the normal command short while still allowing advanced users to tune
`subfinder`, `dnsx`, `httpx`, and `katana` behavior.

## Roadmap

1. Parse ProjectDiscovery `httpx` JSON output natively instead of text output.
2. Add screenshots as a first-class CLI stage.
3. Add profile presets for rate, crawl depth, and module selection.
4. Add HTML reports for presentation and GitHub artifacts.
5. Add installable release binaries for users who do not have Go installed.
