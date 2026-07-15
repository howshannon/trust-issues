# Community evasions

Post-release samples submitted by the community to test the scanner against
real-world evasion attempts. Drop an **inert** malicious fixture here via PR and the
benchmark will report it under "Community evasions caught."

Rules (same as the core corpus):

- **Inert only.** No working malware. Payloads are strings, not functioning attacks.
- **Non-resolving exfil targets** — use `*.example.com` / reserved addresses.
- Name the file after the technique (e.g. `dns_tunnel_exfil.py`) and, if it targets a
  specific scanner category, note it in the PR description.

The point is to keep the corpus honest and growing: if your sample slips past the
grep layer, that's a documented gap that argues for the five-persona read — and a
candidate for a new scanner rule.
