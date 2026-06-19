#!/usr/bin/env bash
# First-On-Scene runner for NinjaOne (Linux/macOS). Add to Script Library, run as root.
# Publishes verdict to NinjaOne custom fields via ninjarmm-cli and returns a verdict exit code.
# CJIS: no data leaves the device; stage the toolkit from an INTERNAL source for regulated clients.
# Exit codes: 0 ALL_CLEAR | 10 MONITOR | 20 PROBLEM(Incident) | 21 PROBLEM(Breach) | 1 error
set -uo pipefail

INSTALL_PATH="${INSTALL_PATH:-/opt/first-on-scene}"
BRAND="${BRAND:-First-On-Scene}"

# NinjaOne provides ninjarmm-cli for custom fields on managed Linux/macOS endpoints.
ninja_set() {
  local name="$1" value="$2"
  if command -v ninjarmm-cli >/dev/null 2>&1; then
    ninjarmm-cli set "$name" "$value" >/dev/null 2>&1 || echo "WARN: could not set $name"
  else
    echo "[no-ninja] $name = $value"
  fi
}

FOS="$(find "$INSTALL_PATH" -name fos.sh -type f 2>/dev/null | head -n1)"
if [ -z "$FOS" ]; then echo "fos.sh not found under $INSTALL_PATH"; ninja_set fosVerdict ERROR; exit 1; fi

CASE_ROOT="/var/lib/first-on-scene/cases"
mkdir -p "$CASE_ROOT"
CASE_DIR="$CASE_ROOT/case-$(date +%Y%m%d-%H%M%S)"

set +e
bash "$FOS" --mode full --case-dir "$CASE_DIR" --brand "$BRAND" --no-action
EXITCODE=$?
set -e 2>/dev/null || true

F="$CASE_DIR/findings.json"
if [ ! -f "$F" ]; then echo "findings.json not produced"; ninja_set fosVerdict ERROR; exit 1; fi

JQ="${JQ:-jq}"
ninja_set fosVerdict        "$("$JQ" -r '.verdict' "$F")"
ninja_set fosScore          "$("$JQ" -r '.score' "$F")"
ninja_set fosClassification "$("$JQ" -r '.classification' "$F")"
ninja_set fosReasonCode     "$("$JQ" -r '.reasonCode' "$F")"
ninja_set fosCasePath       "$CASE_DIR"
ninja_set fosFindings       "$("$JQ" -r '.findings | sort_by(-.weight)[0:8][] | "[\(.severity)] \(.ruleId) \(.name) (x\(.evidenceCount))"' "$F")"

echo "First-On-Scene: $("$JQ" -r '.verdict' "$F") (score $("$JQ" -r '.score' "$F")). Case: $CASE_DIR"
exit "$EXITCODE"
