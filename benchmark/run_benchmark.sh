#!/usr/bin/env bash
# run_benchmark.sh — measure what the triage scanner catches, in the RIGHT category,
# AND how many benign samples it wrongly surfaces. Recall alone is a misleading number
# for a scanner you have to live with, so we report false positives and precision too.
#
# Each malicious fixture declares the scanner category (section number) that should
# flag it. A fixture counts as caught only if flagged in one of its expected
# categories. 'MISS' marks a fixture engineered to evade pattern matching; it is
# expected to slip through, and reporting that is the point.
#
# Benign fixtures that get flagged are FALSE POSITIVES — the manual-review workload.
# A scanner tuned purely for recall is unusable if it blocks common benign install
# hooks, so we surface that number openly instead of hiding it behind recall.
#
# Post-release evasions submitted by the community live in fixtures/community/ and are
# reported separately, so the corpus grows with real-world attempts after launch.
#
# Nothing here executes a fixture. Each sample is copied into a temp dir, scanned
# read-only, then deleted.
#
# Usage:  bash benchmark/run_benchmark.sh [--check] [--results]
#   --check    CI mode: exit 1 if any non-evasive fixture is missed or mis-categorized.
#   --results  Write a dated, versioned benchmark/RESULTS.md snapshot.

set -uo pipefail
CHECK=0
WRITE_RESULTS=0
for a in "$@"; do
  case "$a" in
    --check)   CHECK=1 ;;
    --results) WRITE_RESULTS=1 ;;
  esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
SCAN="$HERE/../scripts/triage_scan.sh"
MAL="$HERE/fixtures/malicious"
BEN="$HERE/fixtures/benign"
COMM="$HERE/fixtures/community"

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

mal_total=0 mal_ok=0 evasive_total=0 evasive_caught=0 missed="" wrongcat=""
for s in "$MAL"/*; do
  name="$(basename "$s")"
  expect="${EXPECT[$name]:-}"
  hits="$(sections_for "$s")"
  if [[ "$expect" == "MISS" ]]; then
    evasive_total=$((evasive_total + 1))
    if [[ -n "${hits// /}" ]]; then
      evasive_caught=$((evasive_caught + 1))
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
printf "BENIGN FIXTURES (a flag = false positive surfaced for manual review)\n"
ben_total=0 ben_flag=0 noisy=""
for s in "$BEN"/*; do
  name="$(basename "$s")"
  ben_total=$((ben_total + 1))
  if [[ -n "$(sections_for "$s" | tr -d ' ')" ]]; then
    ben_flag=$((ben_flag + 1)); noisy="$noisy $name"; printf "  %-28s FALSE POSITIVE\n" "$name"
  else
    printf "  %-28s quiet\n" "$name"
  fi
done

# Post-release community-submitted evasions (reported separately from the core corpus).
comm_total=0 comm_caught=0 comm_missed=""
if [[ -d "$COMM" ]]; then
  shopt -s nullglob
  for s in "$COMM"/*; do
    name="$(basename "$s")"
    [[ "$name" == "README.md" || "$name" == ".gitkeep" ]] && continue
    comm_total=$((comm_total + 1))
    if [[ -n "$(sections_for "$s" | tr -d ' ')" ]]; then
      comm_caught=$((comm_caught + 1))
    else
      comm_missed="$comm_missed $name"
    fi
  done
  shopt -u nullglob
fi

# Precision + false-positive rate. tp = malicious caught, fp = benign flagged.
tp=$mal_ok; fp=$ben_flag
fp_pct="n/a"; precision="n/a"
(( ben_total > 0 ))   && fp_pct="$(awk "BEGIN{printf \"%.0f%%\", 100*$fp/$ben_total}")"
(( tp + fp > 0 ))     && precision="$(awk "BEGIN{printf \"%.1f%%\", 100*$tp/($tp+$fp)}")"
mal_all=$((mal_total + evasive_total))
mal_all_caught=$((mal_ok + evasive_caught))

echo
echo "--------------------------------------------"
echo "RESULTS"
echo "  Malicious recall (all):      $mal_all_caught / $mal_all  (correct-category $mal_ok / $mal_total; $evasive_total evasive by design)"
echo "  Missed entirely:             ${missed:- none}"
echo "  Wrong category:              ${wrongcat:- none}"
echo "  False positives (benign):    $ben_flag / $ben_total  ($fp_pct)"
echo "  Precision (flags truly bad): $precision"
echo "  Community evasions caught:   $comm_caught / $comm_total"
echo "--------------------------------------------"
cat <<'NOTE'
How to read this:
- Recall AND false positives are both reported on purpose. A scanner that catches
  malware but flags every benign install hook is unusable, so precision matters as
  much as recall.
- "False positive" here means a benign sample was surfaced for manual review, which
  the five-persona reasoning pass is meant to clear — not a hard block.
- The evasive fixture is expected to be missed; that is the argument for the manual
  read and for sandboxing. A clean scan never proves the code is safe.
- Community evasions are post-release samples submitted via PR; the count grows as
  people try to beat the scanner.
NOTE

if (( WRITE_RESULTS )); then
  results="$HERE/RESULTS.md"
  sha="$(git -C "$HERE/.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
  when="$(date -u +%Y-%m-%d)"
  {
    echo "# Benchmark results"
    echo
    echo "Generated ${when} from commit \`${sha}\`. Regenerate after any ruleset change with \`bash benchmark/run_benchmark.sh --results\`."
    echo
    echo "| Metric | Value |"
    echo "| --- | --- |"
    echo "| Malicious recall (all) | ${mal_all_caught} / ${mal_all} |"
    echo "| — correct category | ${mal_ok} / ${mal_total} |"
    echo "| — evasive, missed by design | ${evasive_total} |"
    echo "| Missed entirely | ${missed:- none} |"
    echo "| Wrong category | ${wrongcat:- none} |"
    echo "| False positives (benign flagged) | ${ben_flag} / ${ben_total} (${fp_pct}) |"
    echo "| Precision (flags that are truly malicious) | ${precision} |"
    echo "| Community evasions caught | ${comm_caught} / ${comm_total} |"
    echo
    echo "**Recall** is how many known-malicious techniques are flagged in the *right* category. **Precision** and the **false-positive** count measure how often benign code gets surfaced for review — a scanner tuned only for recall is unusable if it blocks common benign install hooks, so both are reported. **Community evasions** are post-release samples submitted via PR into \`benchmark/fixtures/community/\`. A clean scan is never proof of safety."
  } > "$results"
  echo; echo "Wrote $results"
fi

if [[ "$CHECK" == "1" ]]; then
  if [[ -n "${missed// /}" || -n "${wrongcat// /}" ]]; then
    echo; echo "CI FAIL: missed:${missed:- none} | wrong-category:${wrongcat:- none}" >&2
    exit 1
  fi
  echo; echo "CI OK: every non-evasive fixture flagged in its expected category."
fi
