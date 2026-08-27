# Subdomain Enumeration Playbook

## Objective

Turn an in-scope root domain into a deduplicated, resolved, live-host list that is ready for screenshot review, JavaScript recon, API discovery, and cloud checks.

Use this playbook when you have explicit permission to perform passive collection and low-rate DNS/HTTP probing.

## Inputs

```text
Target root domain: example.com
Allowed scope: *.example.com
Excluded assets: support.example.com, status.example.com
Max HTTP probe rate: 50 requests/second
Run directory: runs/example.com/YYYY-MM-DD/
```

## Folder Setup

Fast path from the repository root:

```bash
bin/reconx run -t example.com --profile balanced -p 50
```

`reconx` handles normalization, exclusion filtering, DNS/HTTP orchestration, and
asset scoring natively. ProjectDiscovery tools are used as engines, while the
review queue is produced by `normalized/asset-scores.tsv`.

Manual setup:

```bash
export TARGET=example.com
export RUN_DATE=$(date -u +%F)
mkdir -p runs/$TARGET/$RUN_DATE/{raw,normalized,screenshots,notes}
cd runs/$TARGET/$RUN_DATE

printf "%s\n" "$TARGET" > scope.txt
touch excluded.txt
```

Put excluded hosts in `excluded.txt`, one per line:

```text
support.example.com
status.example.com
```

## Step 1: Passive Collection with subfinder

```bash
subfinder -d "$TARGET" -all -recursive -silent -o raw/subfinder.txt
```

What this does:

- `-d "$TARGET"` sets the root domain.
- `-all` uses all configured passive sources.
- `-recursive` includes recursive subdomain discovery.
- `-silent` keeps output clean for pipelines.
- `-o raw/subfinder.txt` preserves raw output.

Example output:

```text
www.example.com
app.example.com
api.example.com
dev-api.example.com
staging.example.com
assets.example.com
```

## Step 2: Add Certificate Transparency

```bash
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | sed 's/\*\.//g' \
  | sort -u > raw/crtsh.txt
```

If `crt.sh` is rate-limited or returns invalid JSON, keep going with the sources you already have.

## Step 3: Normalize and Deduplicate

```bash
cat raw/subfinder.txt raw/crtsh.txt \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/\.$//' \
  | sort -u > normalized/subdomains.all.txt
```

Remove excluded hosts:

```bash
grep -vxFf excluded.txt normalized/subdomains.all.txt > normalized/subdomains.txt
```

Count results:

```bash
wc -l normalized/subdomains.all.txt normalized/subdomains.txt
```

## Step 4: Check for Wildcard DNS

```bash
for i in 1 2 3; do
  printf "does-not-exist-%s.%s\n" "$(date +%s%N)" "$TARGET"
done | dnsx -silent -a -resp
```

If random names resolve, the domain may use wildcard DNS. In that case, do not trust DNS resolution alone; prioritize HTTP response differences, titles, screenshots, and manual review.

## Step 5: Resolve Hosts

```bash
dnsx -l normalized/subdomains.txt -silent -a -resp -o normalized/resolved.txt
cut -d' ' -f1 normalized/resolved.txt | sort -u > normalized/resolved-hosts.txt
```

Example `normalized/resolved.txt`:

```text
app.example.com [104.18.10.10]
api.example.com [104.18.11.10]
staging.example.com [203.0.113.24]
```

## Step 6: Probe HTTP and HTTPS

```bash
httpx -l normalized/resolved-hosts.txt \
  -silent \
  -title \
  -status-code \
  -content-length \
  -tech-detect \
  -follow-redirects \
  -rl 50 \
  -o normalized/live-hosts.txt
```

Example `normalized/live-hosts.txt`:

```text
https://www.example.com [200] [Example] [Cloudflare] [8152]
https://app.example.com [200] [Sign in] [React,nginx] [14320]
https://api.example.com [200] [API Gateway] [nginx] [417]
https://staging.example.com [401] [Staging] [Basic,nginx] [183]
https://assets.example.com [403] [] [AmazonS3,CloudFront] [263]
```

## Step 7: Prioritize

Create an interesting-hosts file:

```bash
rg -i "(admin|login|sign in|api|swagger|graphql|staging|dev|debug|jenkins|grafana|kibana|s3|bucket)" \
  normalized/live-hosts.txt > notes/interesting-hosts.txt
```

Manual priority guide:

| Signal | Why it matters | Next playbook |
| --- | --- | --- |
| `api`, `swagger`, `graphql` | API surface may expose object/tenant operations | [API Discovery](api-discovery.md) |
| `staging`, `dev`, `test` | Non-production controls may differ | Screenshot and manual scope validation |
| `admin`, `login`, `sso` | Role and session boundaries | Screenshot review, auth testing |
| `s3`, `blob`, `storage`, `cloudfront` | Storage or CDN exposure | [Cloud Asset Discovery](cloud-asset-discovery.md) |
| old framework or unusual tech | Known weak configuration or forgotten app | Screenshot review |

## Step 8: Handoff

Use this format in `notes/handoff.md`:

```text
Host: https://api.example.com
Source: subfinder + httpx
Scope: confirmed under *.example.com
Signal: API gateway title
Why interesting: likely central API surface
Next step: API Discovery
Stop condition: do not test auth/tenant behavior until test accounts are ready
```

## Common Mistakes

- Reporting a subdomain just because it exists.
- Trusting wildcard DNS as real assets.
- Treating a `403` or login page as a vulnerability.
- Probing excluded third-party services.
- Running high-rate HTTP probing without checking program policy.
- Deleting excluded assets without recording why they were excluded.

## Troubleshooting

| Problem | What it means | What to do |
| --- | --- | --- |
| `subfinder` finds almost nothing | Passive sources are limited or provider keys are missing | Configure provider keys and add CT/search sources |
| `crt.sh` command creates an empty file | CT service returned invalid JSON or no data | Keep the empty raw file and continue |
| DNS count is huge | Wildcard DNS or broad passive noise | Run wildcard check and rely on HTTP/screenshot validation |
| `httpx` misses known hosts | HTTPS/TLS, redirects, WAF, or uncommon ports | Manually check the host and consider scoped port/service discovery |
| Many hosts have same title/length | Shared default page or CDN | Cluster and deprioritize duplicates |
| `interesting-hosts.txt` is empty | No keyword matches | Manually review `live-hosts.txt`; regex is only a helper |

## Output Files

| File | Purpose |
| --- | --- |
| `raw/subfinder.txt` | Raw passive subfinder output |
| `raw/crtsh.txt` | Raw certificate transparency output |
| `normalized/subdomains.all.txt` | Combined normalized candidates |
| `normalized/subdomains.txt` | In-scope candidates after exclusions |
| `normalized/resolved.txt` | DNS results with IPs |
| `normalized/resolved-hosts.txt` | Resolved hostnames only |
| `normalized/live-hosts.txt` | HTTP-probed live services |
| `notes/interesting-hosts.txt` | Manual review shortlist |

## References

- [ProjectDiscovery subfinder](https://docs.projectdiscovery.io/tools/subfinder/overview)
- [ProjectDiscovery dnsx](https://docs.projectdiscovery.io/tools/dnsx/overview)
- [ProjectDiscovery httpx](https://docs.projectdiscovery.io/tools/httpx/overview)
- [OWASP WSTG Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
