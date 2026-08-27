# CLI Design

`reconx` is moving from a playbook repository into a scope-first reconnaissance CLI.
The repository still keeps the playbooks because they explain how to review and validate
the data produced by the tool.

## Current CLI

```bash
go build -o bin/reconx ./cmd/reconx
bin/reconx run -t example.com --profile balanced -p 50
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
- Produce JSONL events for automation and Markdown reports for humans.
- Score live assets so the manual review queue is explainable.
- Keep subdomain normalization, exclusion filtering, and asset scoring native.
- Keep API candidate selection, OpenAPI parsing, and inventory generation native.
- Keep raw output separate from normalized output.
- Treat recon leads as candidates, not vulnerability findings.
- Detect common tool collisions, especially Python `httpx` versus ProjectDiscovery `httpx`.
- Keep every active probing step tied to explicit scope and rate limits.

## Profiles

| Profile | Purpose |
| --- | --- |
| `passive` | Passive subdomain collection only; no DNS or HTTP probing or active dependency setup |
| `balanced` | Standard recon pipeline with moderate limits |
| `deep` | Higher probe and crawl rates for larger authorized scopes |

## Roadmap

1. Parse ProjectDiscovery `httpx` JSON output natively instead of text output.
2. Add screenshots as a first-class CLI stage.
3. Move cloud candidate extraction into native Go.
4. Add profile presets for rate, crawl depth, and module selection.
5. Add installable releases with `go install github.com/parsamajidipour/reconx/cmd/reconx@latest`.
