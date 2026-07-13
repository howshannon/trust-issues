#!/usr/bin/env bash
# run_benchmark.sh — measure what the triage scanner actually catches, and whether
# it catches it in the RIGHT category.
#
# Each malicious fixture declares the scanner category (section number) that should
# flag it. A fixture counts as caught only if it is flagged in one of its expected
# categories — not merely because the scan emitted "some output". That means a
# scanner that still prints noise but silently loses the rule that mattered will
# fail here. 'MISS' marks a fixture engineered to evade pattern matching; it is
# expected to slip through, and reporting that is the point.
#
# We also report how many BENIGN fixtures surface a flag (the manual-review
# workload — the scanner is tuned for recall; the reasoning pass clears these).
#
# Nothing here executes a fixture. Each sample is copied into a temp dir and
# scanned read-only.
#
# Usage:  bash benchmark/run_benchmark.sh [--check]
#   --check  CI mode: exit 1 if any non-evasive fixture is missed or mis-categorized.

set -uo pipefail
CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/../scripts/triage_scan.sh"
MAL="$HERE/fixtures/malicious"
BEN="$HERE/fixtures/benign"

# fixture -> expected scanner category numbers (any one is sufficient).
declare -A EXPECT=(
  [base64_exec.py]="5 6"
  [curl_pipe_sh.sh]="4"
  [dynamic_eval.js]="5"
  [env_exfil.py]="7"
  [hidden_unicode_SKILL.md]="12 13"
  [miner_tor_c2.py]="14"
  [npm_postinstall]="3"
  [prompt_injection_SKILL.md]="12"
  [reverse_shell.sh]="8"
  [ssh_key_theft.py]="7"
  [evasive_obfuscated.py]="MISS"
)

# sections_for SAMPLE: echo the space-separated category numbers whose section
# references the sample. Section 1 (inventory) is ignored because it lists paths.
sections_for(){
  local sample="$1" name tmp out
  name="$(basename "$sample")"
  tmp="$(mktemp -d)"
  cp -R "$sample" "$tmp/"
  out="$(bash "$SCAN" "$tmp" 2>/dev/null)"
  rm -rf "$tmp"
  printf '%s\n' "$out" | awk -v n="$name" '
    /^== [0-9]+\./ { if (match($0, /[0-9]+/)) sec = substr($0, RSTART, RLENGTH) }
    /^== 1\./      { sec = "" }
    sec != "" && index($0, n) { print sec }
  ' | sort -un | tr "\n" " "
}

echo "############################################"
echo "#         Trust Issues — benchmark         #"
echo "############################################"
echo
printf "MALICIOUS FIXTURES (must be flagged in an expected category)\n"

mal_total=0 mal_ok=0 missed="" wrongcat=""
for s in "$MAL"/*; do
  name="$(basename "$s")"
  expect="${EXPECT[$name]:-}"
  hits="$(sections_for "$s")"
  if [[ "$expect" == "MISS" ]]; then
    if [[ -n "${hits// /}" ]]; then
      printf "  %-28s evasive — unexpectedly caught in %s\n" "$name" "$hits"
    else
      printf "  %-28s MISS (by design)\n" "$name"
    fi
    continue
  fi
  mal_total=$((mal_total + 1))
  ok=0
  read -ra exp_arr <<< "$expect"
  for e in "${exp_arr[@]}"; do
    case " $hits " in *" $e "*) ok=1 ;; esac
  done
  if (( ok )); then
    mal_ok=$((mal_ok + 1)); printf "  %-28s OK (category %s)\n" "$name" "$expect"
  elif [[ -n "${hits// /}" ]]; then
    wrongcat="$wrongcat $name"; printf "  %-28s WRONG CATEGORY (hit %s, expected %s)\n" "$name" "$hits" "$expect"
  else
    missed="$missed $name"; printf "  %-28s MISSED entirely\n" "$name"
  fi
done

echo
printf "BENIGN FIXTURES (a flag = surfaced for manual review, not a failure)\n"
ben_total=0 ben_flag=0 noisy=""
for s in "$BEN"/*; do
  name="$(basename "$s")"
  ben_total=$((ben_total + 1))
  if [[ -n "$(sections_for "$s" | tr -d ' ')" ]]; then
    ben_flag=$((ben_flag + 1)); noisy="$noisy $name"; printf "  %-28s surfaced\n" "$name"
  else
    printf "  %-28s quiet\n" "$name"
  fi
done

echo
echo "--------------------------------------------"
echo "RESULTS"
echo "  Correct-category recall: $mal_ok / $mal_total"
echo "  Missed entirely:        ${missed:- none}"
echo "  Wrong category:         ${wrongcat:- none}"
echo "  Benign surfaced:         $ben_flag / $ben_total for review:${noisy:- none}"
echo "--------------------------------------------"
cat <<'NOTE'
How to read this:
- "Correct-category recall" is stronger than "emitted some output": a fixture only
  counts if flagged in the category matching its technique.
- "Wrong category" means the scanner noticed something but lost the specific rule —
  treat that as a regression to fix, not a pass.
- The evasive fixture is expected to be missed; that is the argument for the manual
  five-persona read and for sandboxing. A clean scan never clears the code.
NOTE

if [[ "$CHECK" == "1" ]]; then
  if [[ -n "${missed// /}" || -n "${wrongcat// /}" ]]; then
    echo; echo "CI FAIL: missed:${missed:- none} | wrong-category:${wrongcat:- none}" >&2
    exit 1
  fi
  echo; echo "CI OK: every non-evasive fixture flagged in its expected category."
fi
