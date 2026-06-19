#!/usr/bin/env bash
# Clearance action for a false positive / contained event (Linux/macOS).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/fos-common.sh"
CASEDIR="${1:?case dir required}"; CUSTOM="${2:-}"; BRAND="${3:-First-On-Scene}"
echo ""
echo "=================================================================="
echo "  $BRAND :: ALL CLEAR"
echo "  CASE DIR: $CASEDIR"
echo "=================================================================="
fos_log OK "FINAL CALL: ALL_CLEAR" "$CASEDIR"
fos_coc_add "$CASEDIR" "FINAL_ALL_CLEAR" "No actionable threat confirmed." >/dev/null
if [ -n "$CUSTOM" ] && [ -x "$CUSTOM" ]; then
  fos_log STEP "Invoking custom action: $CUSTOM" "$CASEDIR"
  "$CUSTOM" "$CASEDIR" || fos_log WARN "Custom action failed" "$CASEDIR"
  fos_coc_add "$CASEDIR" "CUSTOM_ACTION_RAN" "$CUSTOM" >/dev/null
fi
exit 0
