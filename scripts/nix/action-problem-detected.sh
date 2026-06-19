#!/usr/bin/env bash
# Escalation action for a confirmed incident/breach (Linux/macOS). No destructive action.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/fos-common.sh"
REASON="${1:?reason code required}"; CASEDIR="${2:?case dir required}"; CUSTOM="${3:-}"; BRAND="${4:-First-On-Scene}"
echo ""
echo "=================================================================="
echo "  $BRAND :: PROBLEM DETECTED"
echo "  REASON CODE: $REASON"
echo "  CASE DIR   : $CASEDIR"
echo "=================================================================="
fos_log ERROR "FINAL CALL: PROBLEM_DETECTED ($REASON)" "$CASEDIR"
fos_coc_add "$CASEDIR" "FINAL_PROBLEM_DETECTED" "$REASON" >/dev/null
if [ -n "$CUSTOM" ] && [ -x "$CUSTOM" ]; then
  fos_log STEP "Invoking custom action: $CUSTOM" "$CASEDIR"
  "$CUSTOM" "$REASON" "$CASEDIR" || fos_log WARN "Custom action failed" "$CASEDIR"
  fos_coc_add "$CASEDIR" "CUSTOM_ACTION_RAN" "$CUSTOM" >/dev/null
fi
exit 20
