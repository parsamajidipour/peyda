#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/cloud-candidate-pass.sh -r runs/example.com/YYYY-MM-DD

Extracts cloud and secret-looking leads from normalized recon output.
This script does not validate credentials or access private data.
USAGE
}

run_dir=""

while getopts ":r:h" opt; do
  case "$opt" in
    r) run_dir="$OPTARG" ;;
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

mkdir -p "$run_dir"/{normalized,notes}

cloud_regex="(amazonaws\\.com|s3[.-]|cloudfront\\.net|storage\\.googleapis\\.com|googleusercontent\\.com|blob\\.core\\.windows\\.net|azurewebsites\\.net|digitaloceanspaces\\.com|firebaseio\\.com|supabase\\.co|vercel\\.app|netlify\\.app|herokuapp\\.com)"
secret_regex="(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})"

echo "[1/3] Extracting cloud provider hints..."
if command -v rg >/dev/null 2>&1; then
  rg -n -i "$cloud_regex" "$run_dir" \
    --glob '!screenshots/**' \
    --glob '!notes/cloud-candidates.tsv' \
    > "$run_dir/normalized/cloud-provider-hints.txt" || true
else
  grep -RInEi --exclude='cloud-candidates.tsv' "$cloud_regex" "$run_dir" \
    | grep -v '/screenshots/' \
    > "$run_dir/normalized/cloud-provider-hints.txt" || true
fi

echo "[2/3] Extracting secret-looking strings..."
if command -v rg >/dev/null 2>&1; then
  rg -n "$secret_regex" "$run_dir" \
    --glob '!screenshots/**' \
    --glob '!normalized/secret-looking-strings.txt' \
    > "$run_dir/normalized/secret-looking-strings.txt" || true
else
  grep -RInE --exclude='secret-looking-strings.txt' "$secret_regex" "$run_dir" \
    | grep -v '/screenshots/' \
    > "$run_dir/normalized/secret-looking-strings.txt" || true
fi

echo "[3/3] Creating candidate table..."
cat > "$run_dir/notes/cloud-candidates.tsv" <<'EOF'
asset_or_string	source	provider_or_type	ownership_confidence	exposure_guess	next_action
EOF

awk -F: '
  NF >= 3 {
    line=$0
    provider="cloud"
    if (line ~ /amazonaws|s3|cloudfront/) provider="aws"
    else if (line ~ /googleapis|googleusercontent|firebase/) provider="gcp"
    else if (line ~ /blob.core.windows|azurewebsites/) provider="azure"
    else if (line ~ /vercel|netlify|heroku|supabase/) provider="paas"
    print $3 "\t" $1 ":" $2 "\t" provider "\tunknown\tprovider-hint\tmanual ownership validation"
  }
' "$run_dir/normalized/cloud-provider-hints.txt" >> "$run_dir/notes/cloud-candidates.tsv"

awk -F: '
  NF >= 3 {
    kind="possible-secret"
    if ($0 ~ /AKIA|ASIA/) kind="possible-aws-key"
    else if ($0 ~ /BEGIN PRIVATE KEY/) kind="possible-private-key"
    else if ($0 ~ /xox/) kind="possible-slack-token"
    else if ($0 ~ /ghp_/) kind="possible-github-token"
    else if ($0 ~ /AIza/) kind="possible-google-api-key"
    print "<redacted-pattern>\t" $1 ":" $2 "\t" kind "\tunknown\tsecret-looking-string\tvalidate only with explicit permission"
  }
' "$run_dir/normalized/secret-looking-strings.txt" >> "$run_dir/notes/cloud-candidates.tsv"

cat <<EOF

Done.
Review:
  $run_dir/normalized/cloud-provider-hints.txt
  $run_dir/normalized/secret-looking-strings.txt
  $run_dir/notes/cloud-candidates.tsv
EOF
