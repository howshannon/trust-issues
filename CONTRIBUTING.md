# Contributing to Trust Issues

The most valuable contributions here are **new ways to catch bad code** and **new
examples of bad code to catch**. Attackers iterate monthly, so this project is never
"done."

## Great first contributions

- **A new evasion fixture.** Drop an inert malicious sample into
  `benchmark/fixtures/malicious/` (exfil targets must be non-resolving
  `*.example.com`, payloads are strings not working attacks). Re-run
  `bash benchmark/run_benchmark.sh`. If the scanner misses a *realistic* pattern,
  that is a real gap.
- **A scanner rule** in `scripts/triage_scan.sh` that closes a miss. Add or extend a
  section, keep it read-only, and prove it with a fixture.
- **A threat-catalog entry** in `references/threat-catalog.md` for a technique the
  five-persona read should hunt.
- **A benign fixture** that a naive rule would wrongly panic about, to keep us honest
  about the review workload.

## Post-release evasions & versioned results

Evasions that beat the scanner *after* release go in `benchmark/fixtures/community/` (same
inert rules as the core corpus). The benchmark reports them separately under "Community
evasions," so the corpus keeps growing with real-world attempts.

The benchmark also reports **false positives and precision**, not just recall, and snapshots
them to `benchmark/RESULTS.md`. Regenerate that file whenever you change a scanner rule:

```bash
bash benchmark/run_benchmark.sh --results
```

Commit the updated `RESULTS.md` alongside your ruleset change so the numbers stay traceable
to a specific version.

## Ground rules

1. **Read-only forever.** Nothing in this repo may execute the target under review.
   The scanner greps, it does not run. This invariant is non-negotiable.
2. **No working malware.** Fixtures are inert by construction. If a sample could do
   real harm when run, it does not belong here.
3. **Dogfood.** Before you open a PR, run the scanner on your own change
   (`bash scripts/triage_scan.sh .`) and the benchmark. CI does this too.
4. **One change per branch/PR.** Small, focused changes are easier to review and to
   revert. Use a short-lived branch (`feat/…`, `fix/…`, `docs/…`) and Conventional
   Commit messages.

## Workflow

```bash
git checkout -b feat/catch-dns-tunneling
# ...make the change + add a fixture...
bash benchmark/run_benchmark.sh
git commit -m "feat(scanner): flag DNS-tunneling exfil shapes"
git push -u origin feat/catch-dns-tunneling
# open a PR; CI must pass; we squash-merge
```

## Commit style

Conventional Commits (`type(scope): summary`). It keeps the history readable and lets
the changelog write itself. Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`,
`sec`.

## Reporting a real vulnerability

If you find a genuine security issue in this repo (not in code it reviews), open a
private GitHub Security Advisory rather than a public issue.
