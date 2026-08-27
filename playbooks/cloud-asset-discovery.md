# Cloud Asset Discovery Playbook

## Objective

Find cloud-hosted assets, storage clues, repository leaks, CI/CD metadata, and secret-looking strings, then separate harmless public infrastructure from reportable exposure.

This playbook is intentionally conservative. It creates cloud candidates and validation notes; it does not encourage broad bucket listing, credential use, destructive testing, or private-data collection.

## Inputs

```text
Run folder: runs/example.com/YYYY-MM-DD/
Live hosts: normalized/live-hosts.txt
JS lines: normalized/js-interesting-lines.txt
Known names: company, product, root domain, old brand names
Policy: cloud testing and secrets validation rules
```

## Fast Path

From the repository root:

```bash
peyda example.com
```

`peyda` extracts cloud provider hints and secret-looking strings natively from
the run folder, redacts secret-looking values in generated notes, and writes the
candidate table without validating credentials or accessing private data.

Review:

```text
normalized/cloud-provider-hints.txt
normalized/secret-looking-strings.txt
notes/cloud-candidates.tsv
```

## Step 1: Extract Provider Hints

Manual search:

```bash
rg -n -i "(amazonaws\\.com|s3[.-]|cloudfront\\.net|storage\\.googleapis\\.com|blob\\.core\\.windows\\.net|azurewebsites\\.net|firebaseio\\.com|supabase\\.co|vercel\\.app|netlify\\.app|herokuapp\\.com)" \
  normalized raw notes > normalized/cloud-provider-hints.txt
```

High-signal hints:

| Hint | Possible meaning | Next action |
| --- | --- | --- |
| `s3.amazonaws.com`, `s3-website` | AWS S3 bucket or static website | Confirm ownership and access level |
| `cloudfront.net` | CDN distribution | Identify origin clues, do not assume exposure |
| `storage.googleapis.com` | GCS bucket/object URL | Confirm ownership and public-read behavior |
| `blob.core.windows.net` | Azure Blob container | Confirm container/object exposure safely |
| `firebaseio.com` | Firebase database/app | Check rules only where authorized |
| `vercel.app`, `netlify.app`, `herokuapp.com` | PaaS deployment | Confirm whether it belongs to target |

## Step 2: Generate Candidate Names

Use product and environment words to build a small, explainable list:

```text
example
example-saas
example-prod
example-staging
example-assets
example-uploads
example-backups
example-invoices
```

Do not brute force massive bucket wordlists unless the program explicitly allows it.

## Step 3: Read-Only Storage Checks

AWS S3 candidate:

```bash
aws s3 ls s3://example-assets --no-sign-request
```

GCS candidate:

```bash
curl -I https://storage.googleapis.com/example-assets/
```

Azure Blob candidate:

```bash
curl -I "https://example.blob.core.windows.net/assets?restype=container&comp=list"
```

Interpretation:

- `AccessDenied`, `403`, or auth errors are usually not findings.
- Public static assets may be intended.
- Listing sensitive object names can be enough; do not download unrelated files.
- If one canary object proves exposure, stop.

## Step 4: Secret-Looking Strings

Search local recon output and downloaded JavaScript:

```bash
rg -n "(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|BEGIN PRIVATE KEY|xox[baprs]-|ghp_[A-Za-z0-9_]{30,}|AIza[0-9A-Za-z_-]{20,})" \
  raw normalized notes > normalized/secret-looking-strings.txt
```

Validation rules:

- Treat matches as sensitive immediately and redact in notes.
- Confirm whether the string is a placeholder, public client key, expired token, or live secret.
- Validate live credentials only with explicit permission and the minimum safe request.
- Never browse broadly, change resources, or exfiltrate data with a found credential.

## Step 5: Candidate Table

Use `notes/cloud-candidates.tsv`:

```text
asset_or_string | source | provider_or_type | ownership_confidence | exposure_guess | next_action
assets.example.com | live-hosts.txt:5 | aws/cloudfront | likely | provider-hint | check ownership
<redacted-pattern> | js-interesting-lines.txt:44 | possible-google-api-key | unknown | secret-looking-string | classify public vs secret
example-assets | manual naming | s3 | unknown | possible bucket | ask/safe read-only check
```

## Step 6: Handoff Examples

Storage exposure:

```text
Asset: s3://example-invoices
Scope: likely target-owned from app URL and bucket naming
Observed: anonymous list exposes invoice-like object names
Safe proof: object names only, no downloads
Next action: report if program accepts storage exposure
Stop condition: do not access real invoice contents
```

Secret lead:

```text
String: <redacted AWS key pattern>
Source: public JS bundle
Classification: possible AWS access key
Safe proof: not validated yet
Next action: ask program or validate only with minimal allowed identity call
Stop condition: no resource enumeration
```

## Common Mistakes

- Reporting a `403` cloud URL as public exposure.
- Assuming every CloudFront, Vercel, or Netlify URL belongs to the target.
- Downloading private-looking files to prove impact.
- Treating public client-side analytics keys as secrets.
- Validating credentials without explicit permission.
- Using huge bucket brute-force lists against a program that only allows passive recon.

## Output Files

| File | Purpose |
| --- | --- |
| `normalized/cloud-provider-hints.txt` | Provider-looking URLs and strings from recon output |
| `normalized/secret-looking-strings.txt` | Secret-pattern matches that require redaction and classification |
| `notes/cloud-candidates.tsv` | Reviewed cloud candidate table |

## References

- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Google Cloud Storage Access Control](https://cloud.google.com/storage/docs/access-control)
- [Azure Blob Storage Authorization](https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
