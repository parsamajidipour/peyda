# Tool Install

Install only what you need. These commands are examples for a Linux workstation with Go installed.

## Install Reconx

Install the CLI from the repository into Go's binary directory:

```bash
git clone https://github.com/parsamajidipour/reconx.git
cd reconx
go install ./cmd/reconx
```

Make sure Go's binary directory is in `PATH`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

For `zsh`:

```bash
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Then install or refresh recon dependencies:

```bash
reconx deps
```

This command:

- prefers `$HOME/go/bin` first in `PATH`
- installs or refreshes ProjectDiscovery tools with `go install @latest`
- detects the common Python `httpx` / ProjectDiscovery `httpx` name collision
- reports optional helper tools such as `rg` without blocking the recon run

Force-update Go-based recon tools:

```bash
reconx deps --update
```

Only check without installing:

```bash
reconx deps --check
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

## Optional Screenshot Tool

```bash
go install github.com/sensepost/gowitness@latest
gowitness version
```

## Optional Secret Scanning

```bash
go install github.com/gitleaks/gitleaks/v8@latest
gitleaks version
```

## Useful System Packages

These are optional for manual workflows and local development. `reconx` core
logic does not require them at runtime.

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

## Local Development Build

From a cloned repository:

```bash
go build -o bin/reconx ./cmd/reconx
bin/reconx deps --check
```

## Notes

- Some providers require API keys for better passive recon results.
- Store API keys in your shell environment or a local secrets manager, not in this repository.
- Pin versions for repeatable team workflows.
- Use [Subfinder Provider Config Example](../config/subfinder-provider-config.example.yaml) as a placeholder-only reference.
