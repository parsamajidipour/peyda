#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/api-discovery-pass.sh -r runs/example.com/YYYY-MM-DD [-p 20]

Builds API discovery artifacts from a run folder:
  1. extracts API-looking hosts from normalized/live-hosts.txt
  2. probes common API documentation and schema paths
  3. downloads reachable OpenAPI/Swagger JSON candidates
  4. extracts method/path pairs when schemas are valid JSON
  5. creates a reviewed inventory starter file

Options:
  -r  Existing run directory, required
  -p  HTTP probe rate limit, default: 20
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
probe_rate="20"

while getopts ":r:p:h" opt; do
  case "$opt" in
    r) run_dir="$OPTARG" ;;
    p) probe_rate="$OPTARG" ;;
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
  echo "Error: missing $live_hosts. Run reconx with the balanced or deep profile first." >&2
  exit 4
fi

require_tool httpx
require_tool jq
require_tool curl

mkdir -p "$run_dir"/{raw/api,normalized,notes}
log="$run_dir/notes/api-discovery-pass.log"

{
  echo "api-discovery-pass started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "run_dir=$run_dir"
  echo "probe_rate=$probe_rate"
} > "$log"

echo "[1/5] Extracting API-looking hosts..."
if command -v rg >/dev/null 2>&1; then
  rg -i "(api|graphql|swagger|openapi|developer|docs|gateway|redoc)" "$live_hosts" \
    | awk '{print $1}' \
    | sort -u > "$run_dir/notes/api-host-candidates.txt" || true
else
  grep -Ei "(api|graphql|swagger|openapi|developer|docs|gateway|redoc)" "$live_hosts" \
    | awk '{print $1}' \
    | sort -u > "$run_dir/notes/api-host-candidates.txt" || true
fi

if [[ ! -s "$run_dir/notes/api-host-candidates.txt" ]]; then
  awk '{print $1}' "$live_hosts" | sort -u > "$run_dir/notes/api-host-candidates.txt"
  echo "No API-looking hosts matched keywords; using all live hosts as low-confidence candidates." | tee -a "$log"
fi

echo "[2/5] Building common docs/schema path list..."
doc_paths_file="config/api-doc-paths.txt"
if [[ ! -f "$doc_paths_file" ]]; then
  doc_paths_file=""
fi

while read -r host; do
  if [[ -n "$doc_paths_file" ]]; then
    grep -vE '^[[:space:]]*(#|$)' "$doc_paths_file" | while read -r path; do
      printf "%s%s\n" "$host" "$path"
    done
  else
    for path in /openapi.json /swagger.json /api-docs /docs /swagger-ui/ /graphql /graphiql; do
      printf "%s%s\n" "$host" "$path"
    done
  fi
done < "$run_dir/notes/api-host-candidates.txt" > "$run_dir/raw/api-doc-paths.txt"

echo "[3/5] Probing docs/schema paths..."
httpx -l "$run_dir/raw/api-doc-paths.txt" \
  -silent \
  -status-code \
  -title \
  -content-type \
  -content-length \
  -follow-redirects \
  -rl "$probe_rate" \
  -o "$run_dir/normalized/api-docs-probed.txt"
touch "$run_dir/normalized/api-docs-probed.txt"

echo "[4/5] Downloading JSON schema candidates..."
if command -v rg >/dev/null 2>&1; then
  rg "\\[200\\].*(json|openapi|swagger|api-docs)" "$run_dir/normalized/api-docs-probed.txt" \
    | awk '{print $1}' \
    | sort -u > "$run_dir/normalized/schema-json-candidates.txt" || true
else
  grep -E "\\[200\\].*(json|openapi|swagger|api-docs)" "$run_dir/normalized/api-docs-probed.txt" \
    | awk '{print $1}' \
    | sort -u > "$run_dir/normalized/schema-json-candidates.txt" || true
fi

: > "$run_dir/normalized/openapi-methods.tsv"
while read -r url; do
  [[ -z "$url" ]] && continue
  safe_name="$(printf "%s" "$url" | sed 's#[/:?&=]#_#g')"
  output="$run_dir/raw/api/$safe_name.json"
  curl -sL "$url" -o "$output"
  if jq -e '.paths' "$output" >/dev/null 2>&1; then
    jq -r --arg source "$url" '
      .paths
      | to_entries[]
      | . as $p
      | $p.value
      | keys[]
      | select(test("^(get|post|put|patch|delete|head|options)$"))
      | [. , $p.key, $source]
      | @tsv
    ' "$output" >> "$run_dir/normalized/openapi-methods.tsv"
  else
    echo "Downloaded candidate is not a JSON OpenAPI schema: $url" >> "$log"
  fi
done < "$run_dir/normalized/schema-json-candidates.txt"

sort -u "$run_dir/normalized/openapi-methods.tsv" -o "$run_dir/normalized/openapi-methods.tsv"

echo "[5/5] Creating endpoint inventory starter..."
inventory="$run_dir/normalized/api-inventory.tsv"
printf "method\thost\tpath\tauth\tobject\tboundary_field\trisk\tsource\tnext_test\n" > "$inventory"

awk -F'\t' '
  NF >= 3 {
    method=toupper($1)
    path=$2
    source=$3
    host=source
    sub(/^https?:\/\//, "", host)
    sub(/\/.*/, "", host)
    risk="review"
    object="unknown"
    tenant="unknown"
    if (path ~ /\{[^}]*((org|tenant|workspace|account|project|user)[Ii]?[Dd]?)\}/) {
      risk="authorization"
      tenant="possible"
    }
    if (path ~ /(export|download|bulk|invite|role|admin|billing|webhook|token)/) {
      risk=risk ",high-signal"
    }
    print method "\t" host "\t" path "\tunknown\t" object "\t" tenant "\t" risk "\t" source "\tmanual-review"
  }
' "$run_dir/normalized/openapi-methods.tsv" >> "$inventory"

{
  echo
  echo "Counts:"
  wc -l "$run_dir/notes/api-host-candidates.txt" \
    "$run_dir/raw/api-doc-paths.txt" \
    "$run_dir/normalized/api-docs-probed.txt" \
    "$run_dir/normalized/schema-json-candidates.txt" \
    "$run_dir/normalized/openapi-methods.tsv" \
    "$inventory"
} | tee -a "$log"

cat <<EOF

Done.
Review:
  $run_dir/normalized/api-docs-probed.txt
  $run_dir/normalized/openapi-methods.tsv
  $run_dir/normalized/api-inventory.tsv
  $run_dir/notes/api-discovery-pass.log
EOF
