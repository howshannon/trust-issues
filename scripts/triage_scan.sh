#!/usr/bin/env bash
# triage_scan.sh — READ-ONLY static triage for an untrusted repo or skill.
#
# This script NEVER executes code from the target. It only reads files with
# grep / find / file / wc. It does not follow symlinks (grep -r, find -P), skips
# common vendor and generated directories, and skips very large files in the
# binary pass. It is a fast first pass whose job is to surface things a human (or
# the reviewing agent) must then read manually. A clean run is NOT proof of
# safety — it is the floor, not the ceiling.
#
# It does NO online research. The "research current threats" step in SKILL.md is
# performed by the agent or human running the full workflow, not by this script.
#
# For a hostile or very large target, bound the wall-clock time yourself, e.g.:
#     timeout 120 bash triage_scan.sh <path>
#
# Usage:  bash triage_scan.sh <path-to-repo>
# Exit:   0 = ran (triage is informational, not a gate); 2 = bad arguments.

set -uo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "usage: bash triage_scan.sh <path-to-repo>"; exit 0
fi
if [[ -z "${1:-}" ]]; then
  echo "usage: bash triage_scan.sh <path-to-repo>" >&2; exit 2
fi
TARGET="$1"
if [[ ! -d "$TARGET" ]]; then
  echo "error: not a directory: $TARGET" >&2; exit 2
fi
# Canonicalize early: an absolute, symlink-resolved path can't be misread as an
# option (leading '-') or escape the tree via a symlinked target.
if ! TARGET="$(cd -- "$TARGET" 2>/dev/null && pwd -P)"; then
  echo "error: cannot access target" >&2; exit 2
fi

MAX_BYTES=$((5 * 1024 * 1024))   # skip files larger than 5 MB in the binary pass
PRUNE=( -path '*/.git/*' -o -path '*/node_modules/*' -o -path '*/vendor/*'
        -o -path '*/dist/*' -o -path '*/build/*' -o -path '*/.venv/*'
        -o -path '*/venv/*' -o -path '*/.next/*' -o -path '*/target/*' )
EXCLUDES=( --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor
           --exclude-dir=dist --exclude-dir=build --exclude-dir=.venv
           --exclude-dir=venv --exclude-dir=.next --exclude-dir=target )

SRC_INC=( --include=*.py --include=*.js --include=*.mjs --include=*.cjs --include=*.ts
          --include=*.tsx --include=*.jsx --include=*.sh --include=*.bash --include=*.zsh
          --include=*.rb --include=*.go --include=*.rs --include=*.php --include=*.pl
          --include=*.ps1 --include=*.psm1 )
TXT_INC=( --include=*.md --include=*.mdx --include=*.markdown --include=*.txt
          --include=*.json --include=*.yml --include=*.yaml --include=*.toml --include=*.env* )

hr(){ printf '\n== %s ==\n' "$1"; }

# g(): recursive content grep. -r (not -R) does not follow symlinks while
# recursing; -I skips binary files; vendor/generated dirs are excluded; the '--'
# guards a target whose name might begin with '-'.
g(){ grep -rInI "${EXCLUDES[@]}" "$@" -- "$TARGET" 2>/dev/null; }
# go(): value-only extraction (-o, no path prefix) for de-duplication by callers.
go(){ grep -rhoIE "${EXCLUDES[@]}" "$@" -- "$TARGET" 2>/dev/null; }

# cap N: print up to N matching lines from stdin; if more exist, report the total.
cap(){
  local n="${1:-10}" buf total
  buf="$(cat)"
  if [[ -z "$buf" ]]; then echo "  (none)"; return 0; fi
  total="$(printf '%s\n' "$buf" | grep -c .)"
  printf '%s\n' "$buf" | head -n "$n"
  if (( total > n )); then echo "  … showing $n of $total matches"; fi
  return 0
}

# tfind: null-delimited find over the target, no symlink following, pruning the
# vendor/generated dirs. Extra predicates are passed as arguments.
tfind(){ find -P "$TARGET" '(' "${PRUNE[@]}" ')' -prune -o "$@" -print0 2>/dev/null; }

HAVE_P=0; printf 'x\n' | grep -qP 'x' 2>/dev/null && HAVE_P=1

echo "######## TRIAGE: $TARGET ########"
echo "(read-only signature scan — manual review still required; this script does no online research)"

hr "1. INVENTORY"
echo "File types present:"
tfind -type f | tr '\0' '\n' | sed 's/.*\.//; s#.*/##' | sort | uniq -c | sort -rn | head -30
echo; echo "Largest files (watch for vendored blobs / minified bundles):"
find -P "$TARGET" '(' "${PRUNE[@]}" ')' -prune -o -type f -exec wc -c {} + 2>/dev/null \
  | grep -vE '[[:space:]]total$' | sort -rn | head -10 \
  | awk '{n=$1; $1=""; sub(/^[[:space:]]+/,""); printf "  %12d  %s\n", n, $0}'

hr "2. NON-TEXT / BINARY / HIGH-ENTROPY BLOBS (unexplained binaries are a red flag)"
bin_hits=""
while IFS= read -r -d '' f; do
  case "$f" in *.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.webp|*.woff*|*.ttf|*.otf|*.pdf) continue;; esac
  sz="$(wc -c < "$f" 2>/dev/null || echo 0)"
  if (( sz > MAX_BYTES )); then continue; fi
  if file "$f" 2>/dev/null | grep -qiE 'executable|ELF|Mach-O|PE32|shared object|archive data|compiled'; then
    bin_hits+="  BINARY: $f -> $(file -b "$f" 2>/dev/null)"$'\n'
  fi
done < <(tfind -type f)
printf '%s' "$bin_hits" | cap 20
echo "  minified / bundled JS (can hide payloads):"
tfind -type f '(' -name '*.min.js' -o -name '*bundle*.js' ')' | tr '\0' '\n' | sed 's/^/    /' | cap 10

hr "3. NPM INSTALL HOOKS (the #1 npm supply-chain vector — runs on 'npm install')"
g --include=package.json -E '"(pre|post)?install"|"prepare"|"preprepare"|"postprepare"' | cap 15

hr "4. REMOTE-CODE-INTO-SHELL (curl|wget|iwr piped to an interpreter)"
g -E '(curl|wget|fetch|iwr|Invoke-WebRequest)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|d)?sh|python[0-9]?|node|perl|ruby' | cap 15

hr "5. DYNAMIC CODE EXECUTION / DESERIALIZATION"
echo "-- Python --"
g "${SRC_INC[@]}" -E '\b(eval|exec|compile)\s*\(|__import__\s*\(|os\.system\s*\(|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True|pickle\.loads|yaml\.load\s*\((?!.*Loader)|marshal\.loads|ctypes|getattr\([^,]+,\s*[^)]*\)\s*\(' | cap 25
echo "-- JS/TS --"
g "${SRC_INC[@]}" -E '\beval\s*\(|new\s+Function\s*\(|child_process|execSync|spawnSync|vm\.runIn|require\(\s*[`"'"'"']child_process|process\.binding' | cap 25

hr "6. BASE64 / HEX / OBFUSCATED BLOBS DECODED THEN RUN"
g "${SRC_INC[@]}" -E '(base64|b64decode|atob|fromCharCode|unhexlify|bytes\.fromhex|Buffer\.from\([^)]*base64)' | cap 20
echo "  long inline base64-looking strings (>120 chars):"
go "${SRC_INC[@]}" -E '[A-Za-z0-9+/]{120,}={0,2}' | sort -u | cap 10

hr "7. CREDENTIAL / SECRET HARVESTING (reads of local secret stores)"
g -E '\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.aws/config|\.npmrc|\.netrc|\.docker/config|keychain|security[[:space:]]+find-generic|/etc/passwd|/etc/shadow|LocalStorage|Cookies?/|login\.keychain|gnome-keyring|libsecret|browser.*[Pp]assword' | cap 20
echo "  dumps / exfil of environment variables (bulk access or env shipped to a call):"
g "${SRC_INC[@]}" -E 'dict\(os\.environ|os\.environ\.(copy|items|keys)\(|os\.environ\)|(json|data|params|body)\s*=\s*[^\n]*os\.environ|requests\.(post|get|put|patch)\([^\n]*environ|process\.env\b[^.]*(JSON|Object\.(keys|entries|values)|for\b|\.\.\.)|Object\.(keys|entries)\(process\.env|printenv|env\s*\|' | cap 12

hr "8. NETWORK EGRESS — every endpoint (compare against the repo's STATED purpose)"
echo "-- URLs in source --"
go "${SRC_INC[@]}" -E 'https?://[a-zA-Z0-9._~:/?#@!$&*+,;=%-]+' | sort -u | cap 40
echo "-- raw IP addresses (hardcoded IPs / possible C2) --"
go "${SRC_INC[@]}" -E '([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?' | sort -u | grep -vE '127\.0\.0\.1|0\.0\.0\.0' | cap 20
echo "-- inbound listeners / reverse-shell shapes --"
g "${SRC_INC[@]}" -E '\.listen\(|createServer|bind\(\(|socket\.(bind|listen)|/dev/tcp/|nc\s+-e|ncat|bash\s+-i' | cap 12

hr "9. SECRETS LEAKED INSIDE THE REPO (someone committed a live key)"
g -E '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|AIza[0-9A-Za-z_-]{35})' | cap 15

hr "10. CI/CD WORKFLOW RISK (.github/workflows, etc.)"
if find -P "$TARGET" -type d '(' -name workflows -o -name '.circleci' -o -name '.gitlab-ci*' ')' 2>/dev/null | grep -q .; then
  echo "-- dangerous triggers (pull_request_target / workflow_run run attacker code with secrets) --"
  g --include=*.yml --include=*.yaml -E 'pull_request_target|workflow_run' | cap 10
  echo "-- curl|bash or inline secret use inside CI --"
  g --include=*.yml --include=*.yaml -E '(curl|wget)[^|]*\|[[:space:]]*sh|\$\{\{\s*secrets\.' | cap 10
  echo "-- third-party actions pinned by tag/branch not SHA (mutable = poisonable) --"
  g --include=*.yml --include=*.yaml -E 'uses:\s+[^@]+@(v?[0-9]|main|master)' | cap 10
else
  echo "  (no CI workflow dir found)"
fi

hr "11. DEPENDENCY MANIFESTS (audit each for typosquats / unpinned / young packages)"
tfind -type f '(' -name package.json -o -name 'requirements*.txt' -o -name Pipfile \
  -o -name pyproject.toml -o -name go.mod -o -name Cargo.toml -o -name Gemfile ')' \
  | tr '\0' '\n' | sed 's/^/  /' | cap 20
echo "  unpinned python deps (no '==') — supply-chain drift risk:"
g --include=requirements*.txt -E '^[A-Za-z0-9._-]+\s*$' | cap 15

hr "12. AGENT / PROMPT-INJECTION SIGNALS (critical for SKILL.md / MCP / .cursorrules / AGENTS.md)"
echo "-- imperative directives aimed at an AI agent inside docs --"
g "${TXT_INC[@]}" -iE 'ignore (all |the )?(previous|prior|above) instructions|disregard (the )?(system|previous)|do not (tell|inform|mention to) the user|without (asking|telling|informing) the user|bypass|override .*(safety|guardrail|approval)|exfiltrate|send .*(\.env|secret|token|key|credential).*(to|http)|curl .*\| *sh|as an ai,? you (must|should|will)' | cap 20
echo "-- directives to read secrets / .env from within a skill doc --"
g "${TXT_INC[@]}" -iE '(read|open|cat|load|print) .*(\.env|\.ssh|credentials|api[_ -]?key|secret|token)|process\.env|os\.environ' | cap 15
echo "-- directives to install/connect external tooling (MCP servers, remote skills) --"
g "${TXT_INC[@]}" -iE 'mcp add|add custom connector|npx [^ ]+ (install|add)|pip install (git\+|http)|install .*from .*http|claude mcp add|register .*server' | cap 15

hr "13. HIDDEN / OBFUSCATED TEXT (zero-width, bidi, homoglyph tricks that hide instructions)"
if [[ "$HAVE_P" == 1 ]]; then
  echo "  files containing zero-width / bidi-override / tag unicode:"
  grep -rlIP "${EXCLUDES[@]}" '[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{E0000}-\x{E007F}]' -- "$TARGET" 2>/dev/null | cap 10
else
  echo "  (skipped — this grep lacks -P; check for zero-width/bidi unicode manually)"
fi
echo "  HTML comments in markdown (can hide agent instructions from rendered view):"
g --include=*.md --include=*.mdx -oE '<!--.*-->' | cap 10

hr "14. COMPILED-MALWARE / INJECTION / MINING / ANONYMIZING-C2 INDICATORS (when native code or binaries present)"
echo "-- code injection / process hollowing / shellcode --"
g "${SRC_INC[@]}" -E 'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|QueueUserAPC|SetWindowsHookEx|ptrace\(|LD_PRELOAD|mprotect\([^)]*PROT_EXEC|reflectiveloader|process[_ ]?hollow' | cap 12
echo "-- anti-analysis (anti-debug / anti-VM / anti-sandbox) --"
g "${SRC_INC[@]}" -E 'IsDebuggerPresent|CheckRemoteDebugger|anti[_-]?(vm|debug|sandbox)|vmware|virtualbox|qemu|sbiedll|sandboxie' | cap 10
echo "-- anonymizing / covert C2 / mining --"
g "${SRC_INC[@]}" -E '\.onion\b|stratum\+tcp|xmrig|minerd|coinhive|i2p\b|torify|dga_|domain_?generation' | cap 10
echo "-- keylogging / clipboard / wallet targeting --"
g "${SRC_INC[@]}" -E 'GetAsyncKeyState|pynput|keylog|pyperclip|clipboard.*(get|paste)|wallet\.dat|metamask|electrum' | cap 10
echo "-- destructive wipes --"
g "${SRC_INC[@]}" -E 'rm\s+-rf\s+/(\s|$|\*)|shred\s+-|cipher\s+/w|mkfs\.|dd\s+if=/dev/(zero|urandom)\s+of=/dev/' | cap 8

hr "SUMMARY"
echo "Triage complete across 14 categories. This scan flags candidates only. Now do the"
echo "manual adversarial read (SKILL.md steps 3-5): open every executable entrypoint, every"
echo "SKILL.md / agent doc, every CI workflow, and every network call, and reason about"
echo "intent. A clean triage does not clear the repo."
