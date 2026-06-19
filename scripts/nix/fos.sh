#!/usr/bin/env bash
# First-On-Scene orchestrator (Linux/macOS). collect -> triage -> report -> seal -> act.
# Exit codes: 0 ALL_CLEAR | 10 MONITOR | 20 PROBLEM(Incident) | 21 PROBLEM(Breach) | 1 error
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/fos-common.sh"

MODE="full"; CASEDIR=""; BUNDLE=""; BRAND="First-On-Scene"
ENABLE_AI=0; OLLAMA_MODEL="llama3.1:8b"; OLLAMA_ENDPOINT="http://127.0.0.1:11434"
CUSTOM_PROBLEM=""; CUSTOM_CLEAR=""; NOACTION=0

while [ "$#" -gt 0 ]; do case "$1" in
  --mode) MODE="$2"; shift 2;;
  --case-dir) CASEDIR="$2"; shift 2;;
  --bundle) BUNDLE="$2"; shift 2;;
  --brand) BRAND="$2"; shift 2;;
  --enable-local-ai) ENABLE_AI=1; shift;;
  --ollama-model) OLLAMA_MODEL="$2"; shift 2;;
  --ollama-endpoint) OLLAMA_ENDPOINT="$2"; shift 2;;
  --custom-problem) CUSTOM_PROBLEM="$2"; shift 2;;
  --custom-all-clear) CUSTOM_CLEAR="$2"; shift 2;;
  --no-action) NOACTION=1; shift;;
  *) echo "Unknown option: $1" >&2; exit 1;;
esac; done

command -v "$JQ" >/dev/null 2>&1 || { echo "FATAL: jq is required."; exit 1; }

# 1. COLLECT
if [ "$MODE" != "analyze" ]; then
  BUNDLE="$(bash "$HERE/collect-artifacts.sh" "$CASEDIR" | tail -n1)"
  [ -z "$CASEDIR" ] && CASEDIR="$(dirname "$BUNDLE")"
else
  [ -z "$BUNDLE" ] && { echo "analyze mode requires --bundle"; exit 1; }
  [ -z "$CASEDIR" ] && CASEDIR="$(dirname "$BUNDLE")"
fi
if [ "$MODE" = "collect" ]; then
  fos_manifest_new "$CASEDIR" "$("$JQ" -r '.metadata.caseId' "$BUNDLE")" >/dev/null
  fos_log OK "Collection complete (collect mode): $BUNDLE" "$CASEDIR"; echo "$CASEDIR"; exit 0
fi

# 2. TRIAGE
set +e
bash "$HERE/invoke-triage.sh" "$BUNDLE" "$CASEDIR" "$ROOT/rules/detections.json" "$BRAND"
set -e
FINDINGS="$CASEDIR/findings.json"
VERDICT="$("$JQ" -r '.verdict' "$FINDINGS")"
CLASS="$("$JQ" -r '.classification' "$FINDINGS")"
REASON="$("$JQ" -r '.reasonCode' "$FINDINGS")"
EXITCODE="$("$JQ" -r '.exitCode' "$FINDINGS")"

# 3. OPTIONAL LOCAL AI
if [ "$ENABLE_AI" -eq 1 ]; then
  bash "$HERE/invoke-local-ai.sh" "$FINDINGS" "$CASEDIR" "$OLLAMA_ENDPOINT" "$OLLAMA_MODEL" || true
fi

# 4. REPORT
bash "$HERE/write-report.sh" "$FINDINGS" "$CASEDIR" "$BRAND" >/dev/null

# 5. SEAL
fos_manifest_new "$CASEDIR" "$("$JQ" -r '.caseId' "$FINDINGS")" >/dev/null

# 6. ACTION
if [ "$NOACTION" -eq 0 ]; then
  if [ "$VERDICT" = "PROBLEM_DETECTED" ]; then
    bash "$HERE/action-problem-detected.sh" "$REASON" "$CASEDIR" "$CUSTOM_PROBLEM" "$BRAND" || true
  else
    bash "$HERE/action-all-clear.sh" "$CASEDIR" "$CUSTOM_CLEAR" "$BRAND" || true
  fi
fi

fos_log STEP "DONE. Verdict=$VERDICT Class=$CLASS Case=$CASEDIR" "$CASEDIR"
echo "$CASEDIR"
exit "$EXITCODE"
