# Passive Recon Playbook

## Objective

Build the target's public footprint without sending traffic to target-controlled systems. Passive recon should produce a scoped asset hypothesis, not a vulnerability report.

## Inputs

- Program scope and exclusions.
- Primary domains, brand names, product names, subsidiaries, and acquisition history.
- Allowed data sources and automation rules.
- Output directory for timestamped notes.

## Workflow

1. Read the program policy before collecting assets.
2. Record root domains, wildcard rules, excluded domains, and third-party service boundaries.
3. Search certificate transparency, public DNS, company documentation, status pages, developer portals, app stores, package registries, and public code.
4. Group assets by confidence: confirmed in scope, likely related, third party, excluded, unknown.
5. Hand unknown or ambiguous assets to manual ownership validation before active probing.

## Example Commands

```bash
curl -s "https://crt.sh/?q=%.example.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u
```

## Validation

- Confirm that each asset maps to the program scope or documented target ownership.
- Mark old brands, acquired products, parked domains, and CDN-hosted services separately.
- Do not treat a search result, certificate entry, or public repository mention as proof of ownership.

## False Positives

- Historical domains no longer owned by the target.
- Third-party SaaS domains using the target's name.
- Parked or expired assets.
- Documentation examples that look like real environments.

## Output

| Field | Description |
| --- | --- |
| asset | Domain, organization, repository, package, or public service |
| source | CT log, search engine, docs, app store, package registry, public code |
| confidence | confirmed, likely, unknown, excluded |
| notes | Ownership clues, scope notes, and next action |

## Handoff

Send confirmed domains to [Subdomain Enumeration](subdomain-enumeration.md). Send repositories and exposed code leads to [Cloud Asset Discovery](cloud-asset-discovery.md) or JavaScript review when relevant.

## References

- [OWASP WSTG Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [crt.sh Certificate Search](https://crt.sh/)
