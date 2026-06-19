#!/usr/bin/env bash
# First-On-Scene shared library (Linux/macOS).
# Sourced by the collector and analyzer. Pure bash + jq + coreutils. No network calls.

# Allow overriding the jq binary (e.g. for testing): JQ=/path/to/jq
JQ="${JQ:-jq}"
FOS_ENGINE_VERSION="3.0.0"

fos_utc_now() { date -u +"%Y-%m-%dT%H:%M:%S.000Z"; }

fos_sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
fos_sha256_string() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}';
  else printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; fi
}

fos_case_id() {
  local host="${1:-$(hostname)}"
  local stamp rand
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  rand="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom 2>/dev/null | head -c6)"
  [ -z "$rand" ] && rand="$(date +%s | tail -c6)"
  echo "FOS-${stamp}-$(echo "$host" | tr '[:lower:]' '[:upper:]')-${rand}"
}

fos_operator_json() {
  "$JQ" -n --arg u "$(id -un 2>/dev/null)@$(hostname)" --arg h "$(hostname)" --arg t "First-On-Scene/${FOS_ENGINE_VERSION}" \
    '{user:$u, host:$h, tool:$t}'
}

fos_log() {
  # fos_log LEVEL MESSAGE [CASEDIR]
  local level="$1" msg="$2" casedir="$3"
  local line="[$(fos_utc_now)] [$level] $msg"
  echo "$line" >&2
  [ -n "$casedir" ] && echo "$line" >> "$casedir/Steps_Taken.txt"
}

# --- Chain of custody: hash-chained JSON lines (tamper-evident) ---
fos_coc_add() {
  # fos_coc_add CASEDIR ACTION DETAIL [FILE...]
  local casedir="$1" action="$2" detail="$3"; shift 3
  local coc="$casedir/chain_of_custody.log"
  local prev="GENESIS" seq=0
  if [ -s "$coc" ]; then
    prev="$(tail -n1 "$coc" | "$JQ" -r '.entryHash')"
    seq=$(( $(tail -n1 "$coc" | "$JQ" -r '.seq') + 1 ))
  fi
  # Build file hash array
  local files_json="[]"
  if [ "$#" -gt 0 ]; then
    files_json="$("$JQ" -n '[]')"
    for f in "$@"; do
      if [ -f "$f" ]; then
        files_json="$(echo "$files_json" | "$JQ" --arg p "$(basename "$f")" --arg s "$(fos_sha256_file "$f")" '. + [{path:$p, sha256:$s}]')"
      fi
    done
  fi
  local payload
  payload="$("$JQ" -cn --argjson seq "$seq" --arg ts "$(fos_utc_now)" \
    --arg op "$(id -un 2>/dev/null)@$(hostname)" --arg host "$(hostname)" \
    --arg action "$action" --arg detail "$detail" --argjson files "$files_json" --arg prev "$prev" \
    '{seq:$seq, timestampUtc:$ts, operator:$op, host:$host, action:$action, detail:$detail, files:$files, prevHash:$prev}')"
  local entryHash
  entryHash="$(fos_sha256_string "${prev}|${payload}")"
  echo "$payload" | "$JQ" -c --arg eh "$entryHash" '. + {entryHash:$eh}' >> "$coc"
  echo "$entryHash"
}

fos_coc_verify() {
  local casedir="$1"; local coc="$casedir/chain_of_custody.log"
  [ -f "$coc" ] || { echo "INVALID: no chain_of_custody.log"; return 1; }
  local prev="GENESIS" n=0 line payload expected got
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    payload="$(echo "$line" | "$JQ" -c '{seq,timestampUtc,operator,host,action,detail,files,prevHash}')"
    expected="$(fos_sha256_string "${prev}|${payload}")"
    got="$(echo "$line" | "$JQ" -r '.entryHash')"
    [ "$(echo "$line" | "$JQ" -r '.prevHash')" = "$prev" ] || { echo "INVALID: broken chain at seq $n"; return 1; }
    [ "$got" = "$expected" ] || { echo "INVALID: tamper at seq $n"; return 1; }
    prev="$got"; n=$((n+1))
  done < "$coc"
  echo "VALID: $n entries"; return 0
}

# --- Evidence manifest (excludes append-only audit logs) ---
fos_manifest_new() {
  local casedir="$1" caseid="$2"; local manifest="$casedir/manifest.json"
  local arr; arr="$("$JQ" -n '[]')"
  for f in "$casedir"/*; do
    local b; b="$(basename "$f")"
    case "$b" in manifest.json|chain_of_custody.log|Steps_Taken.txt) continue;; esac
    [ -f "$f" ] || continue
    arr="$(echo "$arr" | "$JQ" --arg file "$b" --argjson size "$(wc -c <"$f")" --arg sha "$(fos_sha256_file "$f")" \
      '. + [{file:$file, sizeBytes:$size, sha256:$sha}]')"
  done
  "$JQ" -n --arg caseId "$caseid" --arg createdUtc "$(fos_utc_now)" --argjson operator "$(fos_operator_json)" \
    --arg ev "$FOS_ENGINE_VERSION" --argjson files "$arr" \
    '{caseId:$caseId, createdUtc:$createdUtc, operator:$operator, engineVersion:$ev, algorithm:"SHA-256", files:$files}' > "$manifest"
  echo "$manifest"
}

fos_manifest_verify() {
  local casedir="$1"; local manifest="$casedir/manifest.json"
  [ -f "$manifest" ] || { echo "INVALID: no manifest.json"; return 1; }
  local bad=0 n=0 file sha actual
  while IFS=$'\t' read -r file sha; do
    n=$((n+1))
    if [ ! -f "$casedir/$file" ]; then echo "MISSING: $file"; bad=1; continue; fi
    actual="$(fos_sha256_file "$casedir/$file")"
    [ "$actual" = "$sha" ] || { echo "MISMATCH: $file"; bad=1; }
  done < <("$JQ" -r '.files[] | "\(.file)\t\(.sha256)"' "$manifest" | tr -d '\r')
  if [ "$bad" -eq 0 ]; then echo "VALID: $n files"; return 0; else return 1; fi
}
