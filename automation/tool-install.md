# Tool Install

Install only what you need. These commands are examples for a Linux workstation with Go installed.

## One-Command Setup

From the repository root:

```bash
go build -o bin/reconx ./cmd/reconx
bin/reconx deps
```

This command:

- prefers `$HOME/go/bin` first in `PATH`
- installs missing system tools when `apt-get` is available
- installs or refreshes ProjectDiscovery tools with `go install @latest`
- detects the common Python `httpx` / ProjectDiscovery `httpx` name collision
- treats `rg` as optional because the recon scripts can fall back to `grep`

Force-update Go-based recon tools:

```bash
bin/reconx deps --update
```

Only check without installing:

```bash
bin/reconx deps --check
```

## ProjectDiscovery Tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Confirm:

```bash
subfinder -version
dnsx -version
httpx -version
katana -version
nuclei -version
```

## Screenshot Tool

```bash
go install github.com/sensepost/gowitness@latest
gowitness version
```

## Secret Scanning

```bash
go install github.com/gitleaks/gitleaks/v8@latest
gitleaks version
```

## Useful System Packages

```bash
sudo apt update
sudo apt install -y jq ripgrep curl git
```

## Path Setup

If Go tools are not found after installation:

```bash
export PATH="$HOME/go/bin:$PATH"
```

Add that line to your shell profile if needed.

## Notes

- Some providers require API keys for better passive recon results.
- Store API keys in your shell environment or a local secrets manager, not in this repository.
- Pin versions for repeatable team workflows.
- Use [Subfinder Provider Config Example](../config/subfinder-provider-config.example.yaml) as a placeholder-only reference.
