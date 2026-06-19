#!/usr/bin/env bash
# First-On-Scene READ-ONLY forensic collector (Linux/macOS).
#
# Design guarantees (mirror of the Windows collector):
#   * READ-ONLY : never kills a process, never runs an AV scan, never modifies the host.
#   * ZERO EGRESS : makes no outbound network connection.
#   * MINIMAL DEPS : pure bash + jq + coreutils (plus optional ss/systemctl/dpkg/rpm).
#   * NEVER ABORTS : a single failed artifact is logged to metadata.errors and skipped.
#
# Emits a schema-conformant bundle.json + a tamper-evident chain of custody.
# Output is consumed by invoke-triage.sh (which performs ALL analysis).
#
# Usage:
#   collect-artifacts.sh [--case-dir DIR] [--expected-remote-tools "a,b"] [--deep] [--max-events N]
#   collect-artifacts.sh DIR            # positional case dir (back-compat)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/fos-common.sh"

command -v "$JQ" >/dev/null 2>&1 || { echo "FATAL: jq is required (install: apt install jq / brew install jq)"; exit 1; }

# --- Arguments ---
CASEDIR=""; EXPECTED_RAW=""; DEEP=0; MAX_EVENTS=1000
while [ "$#" -gt 0 ]; do case "$1" in
  --case-dir)             CASEDIR="$2"; shift 2;;
  --expected-remote-tools) EXPECTED_RAW="$2"; shift 2;;
  --deep)                 DEEP=1; shift;;
  --max-events)           MAX_EVENTS="$2"; shift 2;;
  --*)                    echo "Unknown option: $1" >&2; shift;;
  *)                      [ -z "$CASEDIR" ] && CASEDIR="$1"; shift;;   # back-compat positional
esac; done

CASEID="$(fos_case_id)"
[ -z "$CASEDIR" ] && CASEDIR="$ROOT/results/$CASEID"
mkdir -p "$CASEDIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

case "$(uname -s 2>/dev/null)" in Darwin) PLATFORM="darwin";; *) PLATFORM="linux";; esac
emptyarr='[]'

# --- Non-fatal error capture -> metadata.errors ---
ERRJSON="$TMP/errors.json"; echo "$emptyarr" > "$ERRJSON"
add_err() { # component message
  local t; t="$(mktemp)"
  "$JQ" --arg c "$1" --arg m "$2" --arg t "$(fos_utc_now)" \
    '. + [{component:$c, message:$m, timestampUtc:$t}]' "$ERRJSON" > "$t" 2>/dev/null && mv "$t" "$ERRJSON"
  fos_log WARN "[$1] $2" "$CASEDIR"
}

[ "$(id -u)" -ne 0 ] && add_err "privilege" "Not root; auth logs, some processes and shadow metadata may be incomplete."
fos_log STEP "First-On-Scene collector $FOS_ENGINE_VERSION | case $CASEID | platform $PLATFORM | deep=$DEEP" "$CASEDIR"
fos_coc_add "$CASEDIR" "COLLECT_START" "host=$(hostname) uid=$(id -u) platform=$PLATFORM" >/dev/null

# --- Operator-declared sanctioned remote tools (allow-list) ---
echo "$emptyarr" > "$TMP/expected.json"
if [ -n "$EXPECTED_RAW" ]; then
  printf '%s' "$EXPECTED_RAW" | tr ',;' '\n\n' \
    | "$JQ" -R -s 'split("\n")|map(ascii_downcase|gsub("^\\s+|\\s+$";""))|map(select(length>0))' \
    > "$TMP/expected.json" 2>/dev/null || echo "$emptyarr" > "$TMP/expected.json"
fi

# --- cron jobs (no matches is normal, not an error) ---
{ cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* ; do cat "$f" 2>/dev/null; done; } \
  | { grep -vE '^\s*#|^\s*$' || true; } | head -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map(. as $l|($l|split(" ")|map(select(length>0))) as $p|{schedule:($p[0:5]|join(" ")), user:($p[5]//"root"), command:($p[6:]|join(" "))})' \
  > "$TMP/cron.json" 2>/dev/null
[ -s "$TMP/cron.json" ] || echo "$emptyarr" > "$TMP/cron.json"

# --- systemd services ---
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -n "$MAX_EVENTS" \
    | while read -r u; do
        [ -z "$u" ] && continue
        es="$(systemctl show -p FragmentPath -p ExecStart -p UnitFileState -p ActiveState "$u" 2>/dev/null)"
        exec_start="$(echo "$es" | sed -n 's/^ExecStart=.*argv\[\]=\([^;]*\).*/\1/p' | head -n1)"
        [ -z "$exec_start" ] && exec_start="$(echo "$es" | sed -n 's/^ExecStart=\(.*\)/\1/p' | head -n1)"
        state="$(echo "$es" | sed -n 's/^ActiveState=\(.*\)/\1/p')"
        enabled="$(echo "$es" | sed -n 's/^UnitFileState=\(.*\)/\1/p')"
        "$JQ" -cn --arg u "$u" --arg s "$state" --arg en "$enabled" --arg ex "$exec_start" \
          '{unit:$u, state:$s, enabled:($en=="enabled"), execStart:$ex}'
      done | "$JQ" -s '.' > "$TMP/systemd.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/systemd.json"; add_err "systemdServices" "enumeration failed"; }
else echo "$emptyarr" > "$TMP/systemd.json"; fi

# --- processes (base fields) ---
ps -axwwo pid=,ppid=,user=,comm=,args= 2>/dev/null | head -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|gsub("^\\s+";"")|split(" ")|map(select(length>0))) as $p|{processId:($p[0]|tonumber? // 0), parentProcessId:($p[1]|tonumber? // 0), user:($p[2]//""), name:($p[3]//""), executablePath:"", commandLine:($p[4:]|join(" "))})' \
  > "$TMP/procbase.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/procbase.json"; add_err "processes" "ps enumeration failed"; }

# --- /proc enrichment: real executable path, deleted-image flag, (deep) sha256 ---
echo '{}' > "$TMP/exemap.json"
if [ -d /proc ]; then
  : > "$TMP/exemap.jsonl"
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    target="$(readlink "$d/exe" 2>/dev/null)" || continue
    [ -z "$target" ] && continue
    deleted=false
    case "$target" in *" (deleted)") deleted=true; target="${target% (deleted)}";; esac
    sha=""
    if [ "$DEEP" -eq 1 ] && [ "$deleted" = "false" ] && [ -f "$target" ]; then
      sha="$(fos_sha256_file "$target" 2>/dev/null || true)"
    fi
    "$JQ" -cn --arg pid "$pid" --arg exe "$target" --argjson del "$deleted" --arg sha "$sha" \
      '{key:$pid, value:{executablePath:$exe, imageDeleted:$del, sha256:$sha}}'
  done >> "$TMP/exemap.jsonl" 2>/dev/null
  "$JQ" -s 'from_entries' "$TMP/exemap.jsonl" > "$TMP/exemap.json" 2>/dev/null || echo '{}' > "$TMP/exemap.json"
fi
"$JQ" --slurpfile base "$TMP/procbase.json" --slurpfile em "$TMP/exemap.json" -n '
  ($base[0]) as $p | ($em[0]) as $e |
  $p | map(. as $row | ($e[($row.processId|tostring)] // {}) as $x |
    { processId:$row.processId, name:$row.name, executablePath:($x.executablePath // $row.executablePath // ""),
      commandLine:$row.commandLine, parentProcessId:$row.parentProcessId, user:$row.user,
      signatureStatus:"", signer:"", sha256:($x.sha256 // ""), imageDeleted:($x.imageDeleted // false) })' \
  > "$TMP/proc.json" 2>/dev/null || cp "$TMP/procbase.json" "$TMP/proc.json"

# --- network connections ---
if command -v ss >/dev/null 2>&1; then
  ss -tunap 2>/dev/null | tail -n +2 | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:($p[0]//""), state:($p[1]//""), localAddress:($p[4]|split(":")[0:-1]|join(":")), localPort:($p[4]|split(":")[-1]|tonumber? // 0), remoteAddress:($p[5]|split(":")[0:-1]|join(":")), remotePort:($p[5]|split(":")[-1]|tonumber? // 0), processId:0, processName:($p[6:]|join(" "))})' \
    > "$TMP/net.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/net.json"; add_err "connections" "ss parse failed"; }
elif command -v netstat >/dev/null 2>&1; then
  netstat -tunap 2>/dev/null | grep -E '^(tcp|udp)' | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:($p[0]//""), localAddress:($p[3]|split(":")[0:-1]|join(":")), localPort:($p[3]|split(":")[-1]|tonumber? // 0), remoteAddress:($p[4]|split(":")[0:-1]|join(":")), remotePort:($p[4]|split(":")[-1]|tonumber? // 0), state:($p[5]//""), processId:0, processName:($p[6:]|join(" "))})' \
    > "$TMP/net.json" 2>/dev/null || echo "$emptyarr" > "$TMP/net.json"
else echo "$emptyarr" > "$TMP/net.json"; add_err "connections" "neither ss nor netstat present"; fi

# --- auth / logon events (and account-creation events split out) ---
AUTHRAW="$TMP/auth.raw"
( cat /var/log/auth.log 2>/dev/null; cat /var/log/secure 2>/dev/null; journalctl -q _SYSTEMD_UNIT=sshd.service --since "7 days ago" 2>/dev/null ) > "$AUTHRAW" 2>/dev/null || : > "$AUTHRAW"

grep -E -i "(sshd.*(accept|fail|disconnect))|(pam_unix.*(session opened|closed))|(sudo.*(granted|denied|COMMAND))" "$AUTHRAW" 2>/dev/null \
  | tail -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({eventId:0, timestamp:"", logonType:0, account:"", sourceAddress:"", message:.})' \
  > "$TMP/logon.json" 2>/dev/null || echo "$emptyarr" > "$TMP/logon.json"

# Synthesize 4720 (account created) events so FOS-CRD-002 fires cross-platform.
grep -E -i "(useradd.*new user|new user:|adduser.*new user)" "$AUTHRAW" 2>/dev/null \
  | tail -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({eventId:4720, timestamp:"", message:.})' \
  > "$TMP/usercreate.json" 2>/dev/null || echo "$emptyarr" > "$TMP/usercreate.json"

# --- autostart entries (.desktop, rc.local, init.d) ---
( for d in /etc/xdg/autostart "$HOME/.config/autostart" /etc/init.d /etc/rc.local; do
    [ -e "$d" ] && find "$d" -maxdepth 2 -type f 2>/dev/null
  done ) | head -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({path:., command:""})' > "$TMP/autostart.json" 2>/dev/null || echo "$emptyarr" > "$TMP/autostart.json"

# --- file metadata (ISO8601 times so timestomping/ransom-note rules work) ---
file_meta_emit() { # args: explicit files
  local f size perm uid gid mt at bt miso aiso biso
  for f in "$@"; do
    [ -e "$f" ] || continue
    size="$(stat -c %s "$f" 2>/dev/null)"; [ -z "$size" ] && continue
    perm="$(stat -c %A "$f" 2>/dev/null)"
    uid="$(stat -c %u "$f" 2>/dev/null)"; gid="$(stat -c %g "$f" 2>/dev/null)"
    mt="$(stat -c %Y "$f" 2>/dev/null)"; at="$(stat -c %X "$f" 2>/dev/null)"; bt="$(stat -c %W "$f" 2>/dev/null)"
    miso="$(date -u -d "@${mt:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
    aiso="$(date -u -d "@${at:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
    biso=""; { [ -n "$bt" ] && [ "$bt" != "0" ] && [ "$bt" != "-" ]; } && biso="$(date -u -d "@$bt" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
    "$JQ" -cn --arg n "$f" --argjson s "${size:-0}" --arg p "${perm:-}" \
      --argjson u "${uid:-0}" --argjson g "${gid:-0}" --arg m "${miso:-}" --arg a "${aiso:-}" --arg c "${biso:-}" \
      '{fileName:$n, size:$s, permissions:$p, uid:$u, gid:$g, modified:$m, accessed:$a, created:$c}'
  done
}
{
  file_meta_emit /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ld.so.preload
  # Suspicious / staging directories: surfaces ransom notes (FOS-RAN-001) and timestomping (FOS-AF-001).
  scan_cap=200
  for dir in /tmp /var/tmp /dev/shm "$HOME/Desktop" "$HOME/Downloads"; do
    [ -d "$dir" ] || continue
    while IFS= read -r ff; do [ -n "$ff" ] && file_meta_emit "$ff"; done \
      < <(find "$dir" -maxdepth 2 -type f 2>/dev/null | head -n "$scan_cap")
  done
} | "$JQ" -s '.' > "$TMP/files.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/files.json"; add_err "fileMetadata" "stat collection failed"; }

# --- remote-access / RMM tool inventory (read-only) ---
PROC_TEXT="$("$JQ" -r '.[]|"\(.name) \(.commandLine) \(.executablePath)"' "$TMP/proc.json" 2>/dev/null | tr 'A-Z' 'a-z')"
SVC_TEXT="$("$JQ" -r '.[]|"\(.unit) \(.execStart)"' "$TMP/systemd.json" 2>/dev/null | tr 'A-Z' 'a-z')"
PKG_TEXT="$( { dpkg -l 2>/dev/null | awk '{print $2}'; rpm -qa 2>/dev/null; } | tr 'A-Z' 'a-z')"
: > "$TMP/remote.jsonl"
# tool|regex (lowercase). Tuned for Linux/macOS remote-access and RMM agents.
RTOOLS='AnyDesk|anydesk
TeamViewer|teamviewer
RustDesk|rustdesk
ScreenConnect / ConnectWise Control|screenconnect|connectwise.?control
ConnectWise Automate (LabTech)|ltsvc|labtech
NinjaOne (NinjaRMM)|ninjarmm|ninjaone|ninja-?agent
Atera|ateraagent|\batera\b
Splashtop|splashtop|srservice
VNC (x11/tiger/tight/real)|x11vnc|tigervnc|vncserver|tightvnc|realvnc|\bvino\b
LogMeIn|logmein
GoTo / GoToAssist|gotoassist|gotoresolve|logmeinrescue
Datto RMM|cagservice|centrastage|datto.?rmm
Kaseya|kaseya|agentmon
Action1|action1
Syncro|syncro|kabuto
MeshCentral / MeshAgent|meshagent|meshcentral
Tactical RMM|tacticalrmm|tacticalagent
Chrome Remote Desktop|chrome-remote-desktop|chromoting|remoting_host
DWAgent|dwagent
Remote Utilities|rutserv|rfusclient
Supremo|supremo
ToDesk|todesk
Parsec|\bparsec\b
NoMachine|nxserver|nomachine'
EXPECTED_TOKENS="$("$JQ" -r '.[]' "$TMP/expected.json" 2>/dev/null)"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  tool="${line%%|*}"; rx="${line#*|}"
  ev=""
  echo "$PROC_TEXT" | grep -qE "$rx" && ev="${ev}process,"
  echo "$SVC_TEXT"  | grep -qE "$rx" && ev="${ev}service,"
  echo "$PKG_TEXT"  | grep -qE "$rx" && ev="${ev}installed,"
  [ -z "$ev" ] && continue
  ev="${ev%,}"
  tl="$(printf '%s' "$tool" | tr 'A-Z' 'a-z')"
  auth=false
  for tok in $EXPECTED_TOKENS; do case "$tl" in *"$tok"*) auth=true; break;; esac; done
  "$JQ" -cn --arg t "$tool" --arg e "$ev" --arg d "$tool" --argjson a "$auth" \
    '{tool:$t, evidence:$e, detail:$d, authorized:$a}' >> "$TMP/remote.jsonl"
done <<< "$RTOOLS"
"$JQ" -s '.' "$TMP/remote.jsonl" > "$TMP/remote.json" 2>/dev/null || echo "$emptyarr" > "$TMP/remote.json"

# --- access-control posture (context) ---
ADMINS="$( { getent group sudo wheel admin root 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n';
             awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null; } | sort -u | grep -v '^$' )"
ADMINS_JSON="$(printf '%s\n' "$ADMINS" | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo "$emptyarr")"
RDP=false
if command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-active xrdp 2>/dev/null)" = "active" ]; then RDP=true; fi
echo "$SVC_TEXT" | grep -qE 'xrdp' && RDP=true
SHARES="$( { command -v testparm >/dev/null 2>&1 && testparm -s 2>/dev/null | grep -E '^\[' | grep -viE '^\[global\]|^\[printers\]|^\[print\$\]';
             grep -vE '^\s*#|^\s*$' /etc/exports 2>/dev/null | awk '{print "NFS "$1}'; } )"
SHARES_JSON="$(printf '%s\n' "$SHARES" | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null || echo "$emptyarr")"
ACCESS_JSON="$("$JQ" -n --argjson a "$ADMINS_JSON" --argjson r "$RDP" --argjson s "$SHARES_JSON" \
  '{localAdmins:$a, rdpEnabled:$r, shares:$s}')"

# --- security posture: no Microsoft Defender on *nix; declared unavailable so DEF rules never fire ---
DEFENDER_JSON='{"available":false,"realTimeEnabled":null,"antivirusEnabled":null,"tamperProtectionEnabled":null,"exclusionPaths":[],"exclusionExtensions":[],"exclusionProcesses":[]}'

# --- ClamAV: READ existing logs only (does NOT run a scan) ---
CLAM_HITS="$( for lg in /var/log/clamav/*.log /var/log/clamav.log /var/log/clamd.scan /var/log/clamd.log; do
                [ -f "$lg" ] && grep -aE ' FOUND$' "$lg" 2>/dev/null
              done | tail -n "$MAX_EVENTS" )"
CLAM_PRESENT=false
{ [ -d /var/log/clamav ] || [ -f /var/log/clamav.log ] || [ -f /var/log/clamd.scan ]; } && CLAM_PRESENT=true
CLAM_THREATS="$(printf '%s\n' "$CLAM_HITS" | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((capture("^(?<file>.*): (?<name>.*) FOUND$")? // {file:., name:""}))' 2>/dev/null || echo "$emptyarr")"
CLAMAV_JSON="$("$JQ" -n --argjson present "$CLAM_PRESENT" --argjson threats "$CLAM_THREATS" \
  '{executed:$present, threatsFound:($threats|length), threats:$threats}' 2>/dev/null || echo '{"executed":false,"threatsFound":0,"threats":[]}')"

# --- Assemble bundle ---
OSVER="$(uname -srm 2>/dev/null)"
"$JQ" -n \
  --arg schemaVersion "3.0.0" --arg caseId "$CASEID" --arg ts "$(fos_utc_now)" \
  --arg host "$(hostname)" --arg osver "$OSVER" --arg ver "$FOS_ENGINE_VERSION" --arg platform "$PLATFORM" \
  --argjson operator "$(fos_operator_json)" \
  --slurpfile cron "$TMP/cron.json" --slurpfile systemd "$TMP/systemd.json" \
  --slurpfile proc "$TMP/proc.json" --slurpfile net "$TMP/net.json" \
  --slurpfile logon "$TMP/logon.json" --slurpfile usercreate "$TMP/usercreate.json" \
  --slurpfile autostart "$TMP/autostart.json" --slurpfile files "$TMP/files.json" \
  --slurpfile remote "$TMP/remote.json" --slurpfile expected "$TMP/expected.json" \
  --slurpfile errors "$ERRJSON" \
  --argjson access "$ACCESS_JSON" --argjson defender "$DEFENDER_JSON" --argjson clamav "$CLAMAV_JSON" \
  '{
    schemaVersion:$schemaVersion,
    metadata:{caseId:$caseId, collectionTimestampUtc:$ts, targetHostname:$host, platform:$platform,
              osVersion:$osver, collectorVersion:$ver, executionMode:"local", evidenceIntegrityMode:true,
              expectedRemoteTools:$expected[0], operator:$operator, errors:$errors[0]},
    artifacts:{
      remoteAccess:{tools:$remote[0]},
      securityPosture:{defender:$defender},
      accessControl:$access,
      defenseEvasion:{logClearEvents:[]},
      persistence:{cronJobs:$cron[0], systemdServices:$systemd[0], autostartFiles:$autostart[0],
                   registryRunKeys:[], scheduledTasks:[], services:[], asep:[],
                   wmiEventSubscriptions:{eventFilters:[],eventConsumers:[],filterBindings:[]}},
      execution:{processes:$proc[0], processCreationEvents:[], prefetch:[], injectedModules:[]},
      network:{connections:$net[0]},
      credentialAccess:{logonEvents:$logon[0], privilegeEscalationEvents:[],
                        userCreationEvents:$usercreate[0], serviceInstallEvents:[]},
      fileSystem:{fileMetadata:$files[0], browserArtifacts:[]},
      powerShellActivity:{scriptBlockLogs:[]},
      antivirusScans:{defenderScan:{executed:false,threatsFound:0,threats:[]}, clamavScan:$clamav}
    }
  }' > "$CASEDIR/bundle.json" 2>"$TMP/assemble.err" \
  || { add_err "assemble" "bundle assembly failed: $(tr -d '\n' < "$TMP/assemble.err")"; echo '{}' > "$CASEDIR/bundle.json"; }

NPROC="$("$JQ" '.artifacts.execution.processes|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
NREMOTE="$("$JQ" '.artifacts.remoteAccess.tools|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
NERR="$("$JQ" '.metadata.errors|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
fos_coc_add "$CASEDIR" "COLLECT_DONE" "cron=$("$JQ" '.|length' "$TMP/cron.json") systemd=$("$JQ" '.|length' "$TMP/systemd.json") proc=$NPROC remoteTools=$NREMOTE errors=$NERR" "$CASEDIR/bundle.json" >/dev/null
fos_log OK "Bundle written: $CASEDIR/bundle.json (proc=$NPROC remoteTools=$NREMOTE errors=$NERR)" "$CASEDIR"
echo "$CASEDIR/bundle.json"
