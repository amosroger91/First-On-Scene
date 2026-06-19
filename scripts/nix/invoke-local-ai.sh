#!/usr/bin/env bash
# OPTIONAL local-only AI narrative (Linux/macOS). Loopback-only; advisory; never changes the verdict.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/fos-common.sh"
FINDINGS="${1:?findings.json required}"; CASEDIR="${2:?case dir required}"
ENDPOINT="${3:-http://127.0.0.1:11434}"; MODEL="${4:-llama3.1:8b}"

# CJIS guard: loopback only
if ! echo "$ENDPOINT" | grep -qE '^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$)'; then
  echo "Refusing non-loopback AI endpoint '$ENDPOINT'. Local AI must be localhost-only (CJIS)." >&2
  exit 1
fi
command -v curl >/dev/null 2>&1 || { fos_log WARN "curl not found; skipping AI narrative." "$CASEDIR"; exit 0; }

LINES="$("$JQ" -r '.findings[] | "- [\(.ruleId)] \(.name) | sev=\(.severity) | hits=\(.evidenceCount) | ATTACK=\(.mitre.technique // "-")"' "$FINDINGS")"
PROMPT="You are a SOC analyst writing a concise incident-triage narrative for an MSP client. A deterministic engine ALREADY decided the verdict; do not change it. Write 2-3 short plain-English paragraphs: what was found, why it matters, immediate next steps.
VERDICT: $("$JQ" -r '.verdict' "$FINDINGS")
CLASSIFICATION: $("$JQ" -r '.classification' "$FINDINGS")
SEVERITY: $("$JQ" -r '.severity' "$FINDINGS")
SCORE: $("$JQ" -r '.score' "$FINDINGS")
HOST: $("$JQ" -r '.targetHostname' "$FINDINGS")
DETECTIONS:
$LINES"

BODY="$("$JQ" -n --arg m "$MODEL" --arg p "$PROMPT" '{model:$m, prompt:$p, stream:false}')"
fos_log STEP "Requesting local AI narrative ($MODEL @ $ENDPOINT)" "$CASEDIR"
RESP="$(curl -s --max-time 120 -X POST "${ENDPOINT%/}/api/generate" -H 'Content-Type: application/json' -d "$BODY" 2>/dev/null || true)"
TEXT="$(echo "$RESP" | "$JQ" -r '.response // empty' 2>/dev/null || true)"
if [ -z "$TEXT" ]; then fos_log WARN "Local AI unavailable; skipping narrative." "$CASEDIR"; exit 0; fi

tmp="$(mktemp)"
"$JQ" --arg m "$MODEL" --arg e "$ENDPOINT" --arg t "$TEXT" \
  '.aiNarrative = {enabled:true, model:$m, endpoint:$e, text:$t}' "$FINDINGS" > "$tmp" && mv "$tmp" "$FINDINGS"
fos_coc_add "$CASEDIR" "AI_NARRATIVE_ADDED" "model=$MODEL (advisory only)" >/dev/null
fos_log OK "Local AI narrative attached (advisory)." "$CASEDIR"
