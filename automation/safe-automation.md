# Safe Automation

## Objective

Use tools repeatably without creating noisy traffic, out-of-scope scans, or low-quality reports.

## Checklist

- [ ] Confirm automation is allowed by the program.
- [ ] Pin scope to explicit domains, hosts, or files.
- [ ] Set rate limits and concurrency limits in commands.
- [ ] Store raw outputs, normalized outputs, commands, tool versions, and timestamps.
- [ ] Review tool hits manually before treating them as leads.
- [ ] Avoid destructive, intrusive, brute-force, or denial-of-service templates unless explicitly permitted.
- [ ] Keep credentials, tokens, and cookies out of logs.

## Command Hygiene

```bash
tool --input scoped-assets.txt --rate-limit 20 --output runs/2026-08-27/output.txt
tool --version > runs/2026-08-27/tool-version.txt
```

## Stop Conditions

- Unexpected authentication prompts or private data exposure.
- Rate-limit responses, instability, or service degradation.
- Assets outside the approved scope.
- Tool behavior you cannot explain or manually reproduce.

## References

- [ProjectDiscovery Documentation](https://docs.projectdiscovery.io/)
- [HackerOne Responsible Disclosure Guidelines](https://docs.hackerone.com/en/articles/8494846-responsible-disclosure)
