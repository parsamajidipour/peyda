#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/subdomain-pass.sh -t example.com -r runs/example.com/YYYY-MM-DD [-p 50]

Runs a practical subdomain pass:
  1. subfinder passive collection
  2. crt.sh certificate transparency collection
  3. normalization and exclusion filtering
  4. wildcard DNS check
  5. dnsx resolution
  6. httpx live probing
  7. interesting host shortlist

Options:
  -t  Target root domain, required
  -r  Existing run directory, required
  -p  HTTP probe rate limit, default: 50
USAGE
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required tool '$1' is not installed or not in PATH." >&2
    echo "See automation/tool-install.md" >&2
    exit 3
  fi
}

target=""
run_dir=""
probe_rate="50"

while getopts ":t:r:p:h" opt; do
  case "$opt" in
    t) target="$OPTARG" ;;
    r) run_dir="$OPTARG" ;;
    p) probe_rate="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Missing value for -$OPTARG" >&2; usage; exit 2 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$target" || -z "$run_dir" ]]; then
  echo "Error: target and run directory are required." >&2
  usage
  exit 2
fi

require_tool subfinder
require_tool dnsx
require_tool httpx
require_tool jq
require_tool curl

mkdir -p "$run_dir"/{raw,normalized,notes}
touch "$run_dir/excluded.txt"

log="$run_dir/notes/subdomain-pass.log"
versions="$run_dir/notes/tool-versions.txt"

{
  echo "subdomain-pass started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "target=$target"
  echo "run_dir=$run_dir"
  echo "probe_rate=$probe_rate"
} > "$log"

{
  subfinder -version 2>&1 || true
  dnsx -version 2>&1 || true
  httpx -version 2>&1 || true
  jq --version 2>&1 || true
  if command -v rg >/dev/null 2>&1; then
    rg --version 2>&1 | head -n 1 || true
  else
    grep --version 2>&1 | head -n 1 || true
  fi
  curl --version 2>&1 | head -n 1 || true
} > "$versions"

echo "[1/7] Running subfinder..."
subfinder -d "$target" -all -recursive -silent -o "$run_dir/raw/subfinder.txt"

echo "[2/7] Querying crt.sh..."
if curl -s "https://crt.sh/?q=%25.$target&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' \
  | sort -u > "$run_dir/raw/crtsh.txt"; then
  :
else
  echo "crt.sh returned invalid data; continuing with subfinder output." | tee -a "$log"
  : > "$run_dir/raw/crtsh.txt"
fi

echo "[3/7] Normalizing and applying exclusions..."
cat "$run_dir/raw/subfinder.txt" "$run_dir/raw/crtsh.txt" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\.$//' \
  | sed '/^$/d' \
  | sort -u > "$run_dir/normalized/subdomains.all.txt"

grep -vxFf "$run_dir/excluded.txt" "$run_dir/normalized/subdomains.all.txt" \
  > "$run_dir/normalized/subdomains.txt" || true

echo "[4/7] Checking wildcard DNS behavior..."
wildcard_file="$run_dir/notes/wildcard-dns-check.txt"
for _ in 1 2 3; do
  printf "does-not-exist-%s.%s\n" "$(date +%s%N)" "$target"
done | dnsx -silent -a -resp > "$wildcard_file" || true

if [[ -s "$wildcard_file" ]]; then
  echo "Warning: wildcard-like DNS responses observed. Review $wildcard_file" | tee -a "$log"
fi

echo "[5/7] Resolving candidates..."
dnsx -l "$run_dir/normalized/subdomains.txt" -silent -a -resp -o "$run_dir/normalized/resolved.txt"
cut -d' ' -f1 "$run_dir/normalized/resolved.txt" | sort -u > "$run_dir/normalized/resolved-hosts.txt"

echo "[6/7] Probing HTTP/S services..."
httpx -l "$run_dir/normalized/resolved-hosts.txt" \
  -silent \
  -title \
  -status-code \
  -content-length \
  -tech-detect \
  -follow-redirects \
  -rl "$probe_rate" \
  -o "$run_dir/normalized/live-hosts.txt"

echo "[7/7] Creating interesting host shortlist..."
keywords_file="config/high-signal-keywords.txt"
if [[ -f "$keywords_file" ]]; then
  pattern="$(grep -vE '^[[:space:]]*(#|$)' "$keywords_file" | paste -sd '|' -)"
else
  pattern="admin|login|sign in|api|swagger|graphql|staging|dev|debug|jenkins|grafana|kibana|s3|bucket|blob|cloudfront|401|403|500"
fi

if command -v rg >/dev/null 2>&1; then
  rg -i "($pattern)" "$run_dir/normalized/live-hosts.txt" > "$run_dir/notes/interesting-hosts.txt" || true
else
  grep -Ei "($pattern)" "$run_dir/normalized/live-hosts.txt" > "$run_dir/notes/interesting-hosts.txt" || true
fi

{
  echo
  echo "Counts:"
  wc -l "$run_dir/normalized/subdomains.all.txt" \
    "$run_dir/normalized/subdomains.txt" \
    "$run_dir/normalized/resolved-hosts.txt" \
    "$run_dir/normalized/live-hosts.txt" \
    "$run_dir/notes/interesting-hosts.txt"
} | tee -a "$log"

cat <<EOF

Done.
Review:
  $run_dir/normalized/live-hosts.txt
  $run_dir/notes/interesting-hosts.txt
  $run_dir/notes/subdomain-pass.log
EOF
