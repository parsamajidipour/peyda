# Contributing

Contributions are welcome when they make recon safer, cleaner, more repeatable, or easier to hand off into focused testing.

## Acceptance Criteria

A contribution should:

1. State the recon objective and authorized scope assumptions.
2. Distinguish discovery leads from reportable vulnerabilities.
3. Include deduplication, validation, and false-positive handling.
4. Preserve timestamps, tool versions, commands, and output provenance where useful.
5. Include safe stop conditions for automation, scanning, secrets, cloud exposure, and third-party services.
6. Cite primary documentation for tool behavior, platform behavior, or standards claims.
7. Avoid live target names, secrets, private data, and unauthorized exploit evidence.

## Pull Requests

- Keep one playbook, template, or coherent improvement per pull request.
- Explain what problem the change solves and how it improves signal quality.
- Run Markdown lint and local link checks.
- Keep filenames lowercase and stable unless a migration is included.
