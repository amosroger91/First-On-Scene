#!/usr/bin/env bash
# First-On-Scene READ-ONLY forensic collector (Linux/macOS).
# Pure bash + jq + coreutils. No network egress. Never aborts on a single failed artifact.
# Emits a schema-conformant bundle.json + tamper-evident chain of custody.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/fos-common.sh"

command -v "$JQ" >/dev/null 2>&1 || { echo "FATAL: jq is required (install: apt install jq / brew install jq)"; exit 1; }

CASEDIR="${1:-}"
CASEID="$(fos_case_id)"
[ -z "$CASEDIR" ] && CASEDIR="$ROOT/results/$CASEID"
mkdir -p "$CASEDIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

[ "$(id -u)" -ne 0 ] && fos_log WARN "Not root; some artifacts (auth.log, all processes) may be incomplete." "$CASEDIR"
fos_log STEP "First-On-Scene collector $FOS_ENGINE_VERSION | case $CASEID" "$CASEDIR"
fos_coc_add "$CASEDIR" "COLLECT_START" "host=$(hostname) uid=$(id -u)" >/dev/null

emptyarr='[]'

# --- cron ---
( cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* ; do cat "$f" 2>/dev/null; done ) \
  | grep -vE '^\s*#|^\s*$' \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map(. as $l|($l|split(" ")|map(select(length>0))) as $p|{schedule:($p[0:5]|join(" ")), user:($p[5]//"root"), command:($p[6:]|join(" "))})' \
  > "$TMP/cron.json" 2>/dev/null || echo "$emptyarr" > "$TMP/cron.json"

# --- systemd services ---
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | awk '{print $1}' \
    | while read -r u; do
        es="$(systemctl show -p FragmentPath -p ExecStart -p UnitFileState -p ActiveState "$u" 2>/dev/null)"
        exec_start="$(echo "$es" | sed -n 's/^ExecStart=.*argv\[\]=\([^;]*\).*/\1/p' | head -n1)"
        [ -z "$exec_start" ] && exec_start="$(echo "$es" | sed -n 's/^ExecStart=\(.*\)/\1/p' | head -n1)"
        state="$(echo "$es" | sed -n 's/^ActiveState=\(.*\)/\1/p')"
        enabled="$(echo "$es" | sed -n 's/^UnitFileState=\(.*\)/\1/p')"
        "$JQ" -cn --arg u "$u" --arg s "$state" --arg en "$enabled" --arg ex "$exec_start" \
          '{unit:$u, state:$s, enabled:($en=="enabled"), execStart:$ex}'
      done | "$JQ" -s '.' > "$TMP/systemd.json" 2>/dev/null || echo "$emptyarr" > "$TMP/systemd.json"
else echo "$emptyarr" > "$TMP/systemd.json"; fi

# --- processes ---
ps -axwwo pid=,ppid=,user=,comm=,args= 2>/dev/null \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|gsub("^\\s+";"")|split(" ")|map(select(length>0))) as $p|{processId:($p[0]|tonumber? // 0), parentProcessId:($p[1]|tonumber? // 0), user:$p[2], name:$p[3], executablePath:"", commandLine:($p[4:]|join(" "))})' \
  > "$TMP/proc.json" 2>/dev/null || echo "$emptyarr" > "$TMP/proc.json"

# --- network connections ---
if command -v ss >/dev/null 2>&1; then
  ss -tunap 2>/dev/null | tail -n +2 \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:$p[0], state:$p[1], localAddress:($p[4]|split(":")[0:-1]|join(":")), localPort:($p[4]|split(":")[-1]|tonumber? // 0), remoteAddress:($p[5]|split(":")[0:-1]|join(":")), remotePort:($p[5]|split(":")[-1]|tonumber? // 0), processName:($p[6:]|join(" "))})' \
    > "$TMP/net.json" 2>/dev/null || echo "$emptyarr" > "$TMP/net.json"
else echo "$emptyarr" > "$TMP/net.json"; fi

# --- logon events ---
( cat /var/log/auth.log 2>/dev/null; cat /var/log/secure 2>/dev/null; journalctl -q _SYSTEMD_UNIT=sshd.service --since "7 days ago" 2>/dev/null ) \
  | grep -E -i "(sshd.*(accept|fail|disconnect))|(pam_unix.*(session opened|closed))|(sudo.*(granted|denied|COMMAND))|(useradd|new user)" \
  | tail -n 500 \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({eventId:0, timestamp:"", message:.})' \
  > "$TMP/logon.json" 2>/dev/null || echo "$emptyarr" > "$TMP/logon.json"

# --- autostart files (.desktop, rc.local, profile.d) ---
( for d in /etc/xdg/autostart "$HOME/.config/autostart" /etc/init.d /etc/rc.local; do
    [ -e "$d" ] && find "$d" -maxdepth 2 -type f 2>/dev/null
  done ) | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({path:., command:""})' > "$TMP/autostart.json" 2>/dev/null || echo "$emptyarr" > "$TMP/autostart.json"

# --- file metadata (key system files) ---
( for f in /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ld.so.preload; do
    [ -e "$f" ] && stat -c '{"fileName":"%n","size":%s,"permissions":"%A","uid":%u,"gid":%g,"modified":"%y","accessed":"%x","created":"%w"}' "$f" 2>/dev/null
  done ) | "$JQ" -s '.' > "$TMP/files.json" 2>/dev/null || echo "$emptyarr" > "$TMP/files.json"

# --- clamav (read existing log only; does NOT run a scan) ---
clamav='{"executed":false,"threatsFound":0,"threats":[]}'

OSVER="$(uname -srm 2>/dev/null)"
"$JQ" -n \
  --arg schemaVersion "3.0.0" --arg caseId "$CASEID" --arg ts "$(fos_utc_now)" \
  --arg host "$(hostname)" --arg osver "$OSVER" --arg ver "$FOS_ENGINE_VERSION" \
  --argjson operator "$(fos_operator_json)" \
  --slurpfile cron "$TMP/cron.json" --slurpfile systemd "$TMP/systemd.json" \
  --slurpfile proc "$TMP/proc.json" --slurpfile net "$TMP/net.json" \
  --slurpfile logon "$TMP/logon.json" --slurpfile autostart "$TMP/autostart.json" \
  --slurpfile files "$TMP/files.json" --argjson clamav "$clamav" \
  '{
    schemaVersion:$schemaVersion,
    metadata:{caseId:$caseId, collectionTimestampUtc:$ts, targetHostname:$host, platform:"linux",
              osVersion:$osver, collectorVersion:$ver, executionMode:"local", evidenceIntegrityMode:true,
              operator:$operator, errors:[]},
    artifacts:{
      persistence:{cronJobs:$cron[0], systemdServices:$systemd[0], autostartFiles:$autostart[0],
                   registryRunKeys:[], scheduledTasks:[], services:[], wmiEventSubscriptions:{eventFilters:[],eventConsumers:[],filterBindings:[]}},
      execution:{processes:$proc[0], processCreationEvents:[]},
      network:{connections:$net[0]},
      credentialAccess:{logonEvents:$logon[0], privilegeEscalationEvents:[], userCreationEvents:[], serviceInstallEvents:[]},
      fileSystem:{fileMetadata:$files[0], browserArtifacts:[]},
      powerShellActivity:{scriptBlockLogs:[]},
      antivirusScans:{defenderScan:{executed:false,threatsFound:0,threats:[]}, clamavScan:$clamav}
    }
  }' > "$CASEDIR/bundle.json"

fos_coc_add "$CASEDIR" "COLLECT_DONE" "cron=$("$JQ" '.|length' "$TMP/cron.json") systemd=$("$JQ" '.|length' "$TMP/systemd.json") proc=$("$JQ" '.|length' "$TMP/proc.json")" "$CASEDIR/bundle.json" >/dev/null
fos_log OK "Bundle written: $CASEDIR/bundle.json" "$CASEDIR"
echo "$CASEDIR/bundle.json"
