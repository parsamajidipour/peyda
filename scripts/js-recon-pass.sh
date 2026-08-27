#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/js-recon-pass.sh -r runs/example.com/YYYY-MM-DD [-p 20]

Collects JavaScript and route leads:
  1. crawls live URLs with katana
  2. extracts JavaScript URLs
  3. downloads same-host JavaScript files when possible
  4. extracts API, GraphQL, WebSocket, admin, webhook, and source-map leads

Options:
  -r  Existing run directory, required
  -p  Crawl rate limit, default: 20
USAGE
}

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: required tool '$1' is not installed or not in PATH." >&2
    echo "See automation/tool-install.md" >&2
    exit 3
  fi
}

run_dir=""
rate="20"

while getopts ":r:p:h" opt; do
  case "$opt" in
    r) run_dir="$OPTARG" ;;
    p) rate="$OPTARG" ;;
    h) usage; exit 0 ;;
    :) echo "Missing value for -$OPTARG" >&2; usage; exit 2 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$run_dir" ]]; then
  echo "Error: run directory is required." >&2
  usage
  exit 2
fi

live_hosts="$run_dir/normalized/live-hosts.txt"
if [[ ! -f "$live_hosts" ]]; then
  echo "Error: missing $live_hosts. Run scripts/subdomain-pass.sh first." >&2
  exit 4
fi

require_tool katana
require_tool curl

mkdir -p "$run_dir"/{raw/js,normalized,notes}
awk '{print $1}' "$live_hosts" | sort -u > "$run_dir/normalized/live-urls.txt"

echo "[1/4] Crawling live URLs with katana..."
katana -list "$run_dir/normalized/live-urls.txt" -jc -silent -rl "$rate" -o "$run_dir/raw/katana-urls.txt"

echo "[2/4] Extracting JavaScript URLs..."
if command -v rg >/dev/null 2>&1; then
  rg -o "https?://[^ ]+\\.js[^ ]*|/[^ ]+\\.js[^ ]*" "$run_dir/raw/katana-urls.txt" \
    | sed 's/[\"'\'')]$//' \
    | sort -u > "$run_dir/normalized/js-files.txt" || true
else
  grep -Eo "https?://[^ ]+\\.js[^ ]*|/[^ ]+\\.js[^ ]*" "$run_dir/raw/katana-urls.txt" \
    | sed 's/[\"'\'')]$//' \
    | sort -u > "$run_dir/normalized/js-files.txt" || true
fi

echo "[3/4] Downloading absolute JavaScript URLs..."
while read -r url; do
  [[ "$url" != http* ]] && continue
  safe_name="$(printf "%s" "$url" | sed 's#[/:?&=]#_#g')"
  curl -sL --max-time 20 "$url" -o "$run_dir/raw/js/$safe_name"
done < "$run_dir/normalized/js-files.txt"

echo "[4/4] Extracting interesting JS lines..."
if command -v rg >/dev/null 2>&1; then
  rg -n "(/api/|/v[0-9]+/|graphql|websocket|wss://|swagger|openapi|admin|internal|webhook|sourceMappingURL|AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-)" \
    "$run_dir/raw/js" > "$run_dir/normalized/js-interesting-lines.txt" || true

  rg -o "(/api/[A-Za-z0-9_./{}:-]+|/v[0-9]+/[A-Za-z0-9_./{}:-]+|https?://[^\"'<> ]+/(api|graphql|v[0-9])[^\"'<> ]*|wss://[^\"'<> ]+)" \
    "$run_dir/raw/js" "$run_dir/raw/katana-urls.txt" \
    | sort -u > "$run_dir/normalized/js-route-leads.txt" || true
else
  grep -RInE "(/api/|/v[0-9]+/|graphql|websocket|wss://|swagger|openapi|admin|internal|webhook|sourceMappingURL|AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-)" \
    "$run_dir/raw/js" > "$run_dir/normalized/js-interesting-lines.txt" || true

  grep -REoh "(/api/[A-Za-z0-9_./{}:-]+|/v[0-9]+/[A-Za-z0-9_./{}:-]+|https?://[^\"'<> ]+/(api|graphql|v[0-9])[^\"'<> ]*|wss://[^\"'<> ]+)" \
    "$run_dir/raw/js" "$run_dir/raw/katana-urls.txt" \
    | sort -u > "$run_dir/normalized/js-route-leads.txt" || true
fi

cat > "$run_dir/notes/js-leads.tsv" <<'EOF'
route	source	auth_guess	object_or_action	next_step
EOF

while read -r route; do
  [[ -z "$route" ]] && continue
  risk="manual-review"
  if [[ "$route" =~ (org|tenant|workspace|account|project|user) ]]; then
    risk="authorization-matrix"
  fi
  if [[ "$route" =~ (admin|billing|export|invite|webhook|token) ]]; then
    risk="$risk high-signal"
  fi
  printf "%s\tjs/katana\tunknown\tunknown\t%s\n" "$route" "$risk" >> "$run_dir/notes/js-leads.tsv"
done < "$run_dir/normalized/js-route-leads.txt"

cat <<EOF

Done.
Review:
  $run_dir/normalized/js-files.txt
  $run_dir/normalized/js-interesting-lines.txt
  $run_dir/normalized/js-route-leads.txt
  $run_dir/notes/js-leads.tsv
EOF
