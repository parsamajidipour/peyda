# Monitoring Pipeline Playbook

## Objective

Track meaningful changes in the target's attack surface over time without generating noisy alerts or violating program rules.

## Inputs

- Scoped root domains and exclusions.
- Previous recon snapshots.
- Approved tool list, rate limits, and schedule.
- Storage location for raw and normalized outputs.

## Workflow

1. Run passive collection, DNS resolution, HTTP probing, screenshot capture, JavaScript discovery, and API discovery on a fixed schedule.
2. Store raw output and normalized output separately with timestamps and tool versions.
3. Diff structural changes: new host, new status, changed title, new technology, new route, new schema, new storage exposure.
4. Filter expected noise: rotating timestamps, analytics parameters, cache busters, marketing content, localization, and redirects.
5. Review high-signal changes manually before starting vulnerability testing.
6. Archive dismissed alerts with the reason so they do not reappear every run.

## Example Commands

```bash
export TARGET=example.com
export TODAY=$(date -u +%F)
export PREVIOUS=2026-08-20

mkdir -p snapshots/$TARGET/$TODAY/{raw,normalized,notes}

subfinder -d "$TARGET" -all -recursive -silent \
  -o snapshots/$TARGET/$TODAY/raw/subfinder.txt

dnsx -l snapshots/$TARGET/$TODAY/raw/subfinder.txt -silent -a -resp \
  -o snapshots/$TARGET/$TODAY/normalized/resolved.txt

cut -d' ' -f1 snapshots/$TARGET/$TODAY/normalized/resolved.txt \
  | sort -u > snapshots/$TARGET/$TODAY/normalized/resolved-hosts.txt

httpx -l snapshots/$TARGET/$TODAY/normalized/resolved-hosts.txt \
  -silent -title -status-code -content-length -tech-detect -follow-redirects -rl 50 \
  -o snapshots/$TARGET/$TODAY/normalized/live-hosts.txt
```

Find new live hosts:

```bash
comm -13 \
  <(awk '{print $1}' snapshots/$TARGET/$PREVIOUS/normalized/live-hosts.txt | sort -u) \
  <(awk '{print $1}' snapshots/$TARGET/$TODAY/normalized/live-hosts.txt | sort -u) \
  > snapshots/$TARGET/$TODAY/notes/new-live-hosts.txt
```

Find changed titles/status/tech:

```bash
diff -u \
  snapshots/$TARGET/$PREVIOUS/normalized/live-hosts.txt \
  snapshots/$TARGET/$TODAY/normalized/live-hosts.txt \
  > snapshots/$TARGET/$TODAY/notes/live-hosts.diff || true
```

Filter high-signal changes:

```bash
rg -i "(admin|login|api|swagger|graphql|staging|dev|debug|jenkins|grafana|kibana|s3|bucket|403|401|500)" \
  snapshots/$TARGET/$TODAY/notes/live-hosts.diff \
  > snapshots/$TARGET/$TODAY/notes/high-signal-changes.txt || true
```

Example `notes/new-live-hosts.txt`:

```text
https://new-api.example.com
https://staging-billing.example.com
```

Example decision:

```text
Asset: https://staging-billing.example.com
Change: new live host, Basic auth, staging name
Scope: under *.example.com, needs program policy check for staging
Priority: P2
Next action: screenshot review, then API discovery if confirmed in scope
```

## Validation

- Alerts should represent meaningful attack-surface change, not raw byte differences.
- Confirm that newly discovered assets are in scope before active probing.
- Tune frequency and request rates to program rules.
- Prefer manual review for risky techniques and high-impact surfaces.

## False Positives

- Rotating banners, timestamps, release hashes, cache-busting parameters, and A/B tests.
- DNS flaps and transient CDN errors.
- Title changes from localization or marketing copy.
- Previously known hosts that appeared because a data source changed.
- Out-of-scope assets reintroduced by broad data sources.

## Output

| Field | Description |
| --- | --- |
| change_type | New host, new route, new tech, new screenshot cluster, new cloud asset |
| asset | Host, endpoint, script, schema, bucket, repository, or service |
| first_seen | Timestamp of first observation |
| source | Tool, data source, or playbook stage |
| priority | high, medium, low, noise, excluded |
| decision | Investigate, monitor, discard, hand off |

## Handoff

Send high-priority changes to the matching playbook or vulnerability checklist. Keep monitoring alerts out of reports until impact is validated.

## References

- [ProjectDiscovery notify](https://github.com/projectdiscovery/notify)
- [ProjectDiscovery httpx](https://docs.projectdiscovery.io/tools/httpx/overview)
- [OWASP WSTG Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
