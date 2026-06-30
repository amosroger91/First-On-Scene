#!/usr/bin/env bash
# First-On-Scene READ-ONLY forensic collector (Linux/macOS).
#
# Design guarantees (mirror of the Windows collector):
#   * READ-ONLY : never kills a process, never runs an AV scan, never modifies the host.
#   * ZERO EGRESS : makes no outbound network connection.
#   * MINIMAL DEPS : pure bash + jq + coreutils (plus optional ss/systemctl/dpkg/rpm on Linux,
#                    and the always-present lsof/codesign/dscl/csrutil/sw_vers on macOS).
#   * NEVER ABORTS : a single failed artifact is logged to metadata.errors and skipped.
#   * bash 3.2 safe : macOS ships /bin/bash 3.2, so NO associative arrays / bash-4 features.
#
# Both Linux and macOS (darwin) are first-class. The collector detects the OS and gathers the
# native artifact for each, normalising into the shared schema the analyzer reads:
#   persistence : systemd + cron + .desktop (linux)   vs  launchd plists + cron (macOS)
#   processes   : ps + /proc/<pid>/exe (linux)         vs  ps + codesign + shasum (macOS)
#   network     : ss / netstat (linux)                 vs  lsof -i (macOS)        [+ hosts/listeners both]
#   logons      : auth.log / journalctl (linux)        vs  last (macOS)
#   admins      : sudo/wheel groups (linux)            vs  dscl . admin group (macOS)
#   posture     : -- (linux)                           vs  SIP / Gatekeeper / FileVault (macOS)
#   file MACE   : GNU stat -c (linux)                  vs  BSD stat -f (macOS)
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

# --- cron jobs (no matches is normal, not an error). macOS user crontabs live under /usr/lib/cron/tabs. ---
{ cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* /usr/lib/cron/tabs/* ; do cat "$f" 2>/dev/null; done; } \
  | { grep -vE '^\s*#|^\s*$' || true; } | head -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(select(length>0))|map(. as $l|($l|split(" ")|map(select(length>0))) as $p|{schedule:($p[0:5]|join(" ")), user:($p[5]//"root"), command:($p[6:]|join(" "))})' \
  > "$TMP/cron.json" 2>/dev/null
[ -s "$TMP/cron.json" ] || echo "$emptyarr" > "$TMP/cron.json"

# --- persistence: systemd services (linux) ---
if [ "$PLATFORM" != "darwin" ] && command -v systemctl >/dev/null 2>&1; then
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

# --- persistence: autostart entries. linux: .desktop/rc.local/init.d. macOS: launchd plists. ---
: > "$TMP/autostart.jsonl"
if [ "$PLATFORM" = "darwin" ]; then
  # LaunchDaemons/LaunchAgents are THE macOS persistence surface. command = Program or ProgramArguments.
  for d in /Library/LaunchDaemons /Library/LaunchAgents /Users/*/Library/LaunchAgents; do
    [ -d "$d" ] || continue
    for p in "$d"/*.plist; do
      [ -f "$p" ] || continue
      cmd="$(plutil -convert json -o - "$p" 2>/dev/null | "$JQ" -r 'if type=="object" then ((.Program) // ((.ProgramArguments//[])|join(" ")) // "") else "" end' 2>/dev/null)"
      [ -z "$cmd" ] && cmd="$(sed -n 's/.*<string>\(.*\)<\/string>.*/\1/p' "$p" 2>/dev/null | head -n1)"
      "$JQ" -cn --arg path "$p" --arg cmd "$cmd" '{path:$path, command:$cmd}' >> "$TMP/autostart.jsonl" 2>/dev/null
    done
  done
else
  for d in /etc/xdg/autostart "$HOME/.config/autostart" /etc/init.d /etc/rc.local; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 2 -type f 2>/dev/null | while read -r f; do
      cmd="$(sed -n 's/^Exec=//p' "$f" 2>/dev/null | head -n1)"
      "$JQ" -cn --arg path "$f" --arg cmd "$cmd" '{path:$path, command:$cmd}' >> "$TMP/autostart.jsonl" 2>/dev/null
    done
  done
fi
head -n "$MAX_EVENTS" "$TMP/autostart.jsonl" | "$JQ" -s '.' > "$TMP/autostart.json" 2>/dev/null || echo "$emptyarr" > "$TMP/autostart.json"

# --- processes ---
if [ "$PLATFORM" = "darwin" ]; then
  # macOS `comm` is the full executable path and can contain spaces, so pull comm and args
  # separately (pid is the stable join key) and merge. No /proc on macOS.
  ps -axww -o pid=,args= 2>/dev/null > "$TMP/psargs.txt" || true
  ps -axww -o pid=,ppid=,user=,comm= 2>/dev/null > "$TMP/pscomm.txt" || true
  awk 'FNR==NR{pid=$1;$1="";sub(/^ +/,"");a[pid]=$0;next}
       {pid=$1;ppid=$2;user=$3;$1=$2=$3="";sub(/^ +/,"");printf "%s\t%s\t%s\t%s\t%s\n",pid,ppid,user,$0,a[pid]}' \
       "$TMP/psargs.txt" "$TMP/pscomm.txt" 2>/dev/null | head -n "$MAX_EVENTS" > "$TMP/procmerged.tsv" || : > "$TMP/procmerged.tsv"

  # Signature/sha map keyed by exe path (computed once per unique binary; no assoc arrays).
  : > "$TMP/sigmap.jsonl"
  cut -f4 "$TMP/procmerged.tsv" 2>/dev/null | sort -u | while IFS= read -r exe; do
    [ -z "$exe" ] && continue
    sig=""; signer=""; sha=""; del=false
    if [ -f "$exe" ]; then
      if codesign -v "$exe" >/dev/null 2>&1; then sig="Valid"
      else cse="$(codesign -v "$exe" 2>&1)"; case "$cse" in *"not signed"*) sig="NotSigned";; *) sig="Invalid";; esac; fi
      signer="$(codesign -dvvv "$exe" 2>&1 | sed -n 's/^Authority=//p' | head -n1)"
      [ "$DEEP" -eq 1 ] && sha="$(fos_sha256_file "$exe" 2>/dev/null || true)"
    else
      del=true   # process running but its on-disk image is gone (FOS-EXE-004)
    fi
    "$JQ" -cn --arg k "$exe" --arg sig "$sig" --arg signer "$signer" --arg sha "$sha" --argjson del "$del" \
      '{key:$k, value:{signatureStatus:$sig, signer:$signer, sha256:$sha, imageDeleted:$del}}' >> "$TMP/sigmap.jsonl" 2>/dev/null
  done
  "$JQ" -s 'from_entries' "$TMP/sigmap.jsonl" > "$TMP/sigmap.json" 2>/dev/null || echo '{}' > "$TMP/sigmap.json"

  "$JQ" -R -s 'split("\n")|map(select(length>0))|map(split("\t") as $p|{processId:($p[0]|tonumber? // 0), parentProcessId:($p[1]|tonumber? // 0), user:($p[2]//""), name:(($p[3]//"")|split("/")|last), executablePath:($p[3]//""), commandLine:($p[4]//"")})' \
    "$TMP/procmerged.tsv" > "$TMP/procbase.json" 2>/dev/null || echo "$emptyarr" > "$TMP/procbase.json"
  "$JQ" --slurpfile base "$TMP/procbase.json" --slurpfile sm "$TMP/sigmap.json" -n '
    ($base[0]) as $p | ($sm[0]) as $s |
    $p | map(. as $r | ($s[$r.executablePath] // {}) as $x |
      { processId:$r.processId, name:$r.name, executablePath:$r.executablePath, commandLine:$r.commandLine,
        parentProcessId:$r.parentProcessId, user:$r.user,
        signatureStatus:($x.signatureStatus // ""), signer:($x.signer // ""), sha256:($x.sha256 // ""), imageDeleted:($x.imageDeleted // false) })' \
    > "$TMP/proc.json" 2>/dev/null || cp "$TMP/procbase.json" "$TMP/proc.json"
else
  ps -axwwo pid=,ppid=,user=,comm=,args= 2>/dev/null | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|gsub("^\\s+";"")|split(" ")|map(select(length>0))) as $p|{processId:($p[0]|tonumber? // 0), parentProcessId:($p[1]|tonumber? // 0), user:($p[2]//""), name:($p[3]//""), executablePath:"", commandLine:($p[4:]|join(" "))})' \
    > "$TMP/procbase.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/procbase.json"; add_err "processes" "ps enumeration failed"; }

  # /proc enrichment: real executable path, deleted-image flag, (deep) sha256.
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
fi

# --- network connections + listeners. macOS: lsof. linux: ss / netstat. ---
echo "$emptyarr" > "$TMP/net.json"; echo "$emptyarr" > "$TMP/listeners.json"
if [ "$PLATFORM" = "darwin" ]; then
  # One lsof pass -> typed objects; jq splits into established connections vs listeners.
  lsof -nP -iTCP -iUDP 2>/dev/null | awk '
    NR==1 {next}
    {
      pidIdx=0
      for(i=1;i<=NF;i++){ if($i ~ /^[0-9]+$/){ pidIdx=i; break } }
      if(pidIdx<2) next
      pid=$(pidIdx); proto=""; name=""; state=""; cmd=""
      for(i=1;i<pidIdx;i++){ cmd = cmd (i>1?" ":"") $i }
      for(i=pidIdx+1;i<=NF;i++){
        if($i=="TCP"||$i=="UDP") proto=$i
        else if($i ~ /^\(.*\)$/){ s=$i; gsub(/[()]/,"",s); state=s }
        else if($i ~ /->/ || $i ~ /:[0-9*]+$/) name=$i
      }
      laddr=""; lport="0"; raddr=""; rport="0"; loc=name; rem=""
      ri=index(name,"->")
      if(ri>0){ loc=substr(name,1,ri-1); rem=substr(name,ri+2) }
      c=0; for(k=length(loc);k>=1;k--){ if(substr(loc,k,1)==":"){c=k;break} }
      if(c>0){ laddr=substr(loc,1,c-1); lport=substr(loc,c+1) } else { laddr=loc }
      if(rem!=""){ c=0; for(k=length(rem);k>=1;k--){ if(substr(rem,k,1)==":"){c=k;break} }
                   if(c>0){ raddr=substr(rem,1,c-1); rport=substr(rem,c+1) } else { raddr=rem } }
      gsub(/"/,"",cmd); gsub(/"/,"",laddr); gsub(/"/,"",raddr); gsub(/"/,"",state)
      printf "{\"protocol\":\"%s\",\"state\":\"%s\",\"localAddress\":\"%s\",\"localPort\":%d,\"remoteAddress\":\"%s\",\"remotePort\":%d,\"processName\":\"%s\",\"processId\":%d}\n", proto,state,laddr,(lport+0),raddr,(rport+0),cmd,(pid+0)
    }' | head -n "$MAX_EVENTS" | "$JQ" -s '.' > "$TMP/net_all.json" 2>/dev/null || echo "$emptyarr" > "$TMP/net_all.json"
  "$JQ" '[ .[] | select(.remoteAddress != "" and .remotePort != 0) ]' "$TMP/net_all.json" > "$TMP/net.json" 2>/dev/null || echo "$emptyarr" > "$TMP/net.json"
  "$JQ" '[ .[] | select(.state=="LISTEN" or (.remoteAddress=="" and .protocol=="UDP")) | {protocol, localAddress, localPort, processId, processName} ]' "$TMP/net_all.json" > "$TMP/listeners.json" 2>/dev/null || echo "$emptyarr" > "$TMP/listeners.json"
elif command -v ss >/dev/null 2>&1; then
  ss -tunap 2>/dev/null | tail -n +2 | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:($p[0]//""), state:($p[1]//""), localAddress:($p[4]|split(":")[0:-1]|join(":")), localPort:($p[4]|split(":")[-1]|tonumber? // 0), remoteAddress:($p[5]|split(":")[0:-1]|join(":")), remotePort:($p[5]|split(":")[-1]|tonumber? // 0), processId:0, processName:($p[6:]|join(" "))})' \
    > "$TMP/net.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/net.json"; add_err "connections" "ss parse failed"; }
  ss -ltunp 2>/dev/null | tail -n +2 | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:($p[0]//""), localAddress:($p[4]|split(":")[0:-1]|join(":")), localPort:($p[4]|split(":")[-1]|tonumber? // 0), processId:0, processName:($p[6:]|join(" "))})' \
    > "$TMP/listeners.json" 2>/dev/null || echo "$emptyarr" > "$TMP/listeners.json"
elif command -v netstat >/dev/null 2>&1; then
  netstat -tunap 2>/dev/null | grep -E '^(tcp|udp)' | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((.|split(" ")|map(select(length>0))) as $p|{protocol:($p[0]//""), localAddress:($p[3]|split(":")[0:-1]|join(":")), localPort:($p[3]|split(":")[-1]|tonumber? // 0), remoteAddress:($p[4]|split(":")[0:-1]|join(":")), remotePort:($p[4]|split(":")[-1]|tonumber? // 0), state:($p[5]//""), processId:0, processName:($p[6:]|join(" "))})' \
    > "$TMP/net.json" 2>/dev/null || echo "$emptyarr" > "$TMP/net.json"
else add_err "connections" "neither lsof, ss nor netstat present"; fi

# --- hosts-file entries (both platforms) -> FOS-NET-003 ---
{ grep -vE '^\s*#|^\s*$' /etc/hosts 2>/dev/null || true; } | head -n "$MAX_EVENTS" \
  | "$JQ" -R -s 'split("\n")|map(gsub("^\\s+|\\s+$";""))|map(select(length>0))|map((split("\\s+";"")) as $p|{ipAddress:($p[0]//""), hostnames:($p[1:]|join(" ")), raw:.})' \
  > "$TMP/hosts.json" 2>/dev/null || echo "$emptyarr" > "$TMP/hosts.json"

# --- auth / logon events (and account-creation events split out) ---
if [ "$PLATFORM" = "darwin" ]; then
  # macOS has no /var/log/auth.log; `last` is the read-only login record. Account creation does
  # not appear in `last`, so userCreationEvents stays empty on macOS.
  last -100 2>/dev/null | { grep -vE '^$|^wtmp begins|^reboot|^shutdown' || true; } | head -n "$MAX_EVENTS" \
    | "$JQ" -R -s 'split("\n")|map(select(length>0))|map({eventId:0, timestamp:"", logonType:0, account:"", sourceAddress:"", message:.})' \
    > "$TMP/logon.json" 2>/dev/null || echo "$emptyarr" > "$TMP/logon.json"
  echo "$emptyarr" > "$TMP/usercreate.json"
else
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
fi

# --- file metadata (ISO8601 times so timestomping/ransom-note rules work) ---
file_meta_emit() { # args: explicit files
  local f size perm uid gid mt at bt miso aiso biso
  for f in "$@"; do
    [ -e "$f" ] || continue
    if [ "$PLATFORM" = "darwin" ]; then
      size="$(stat -f %z "$f" 2>/dev/null)"; [ -z "$size" ] && continue
      perm="$(stat -f %Sp "$f" 2>/dev/null)"; uid="$(stat -f %u "$f" 2>/dev/null)"; gid="$(stat -f %g "$f" 2>/dev/null)"
      mt="$(stat -f %m "$f" 2>/dev/null)"; at="$(stat -f %a "$f" 2>/dev/null)"; bt="$(stat -f %B "$f" 2>/dev/null)"
      miso="$(date -u -r "${mt:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
      aiso="$(date -u -r "${at:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
      biso=""; { [ -n "$bt" ] && [ "$bt" != "0" ] && [ "$bt" != "-" ]; } && biso="$(date -u -r "$bt" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
    else
      size="$(stat -c %s "$f" 2>/dev/null)"; [ -z "$size" ] && continue
      perm="$(stat -c %A "$f" 2>/dev/null)"; uid="$(stat -c %u "$f" 2>/dev/null)"; gid="$(stat -c %g "$f" 2>/dev/null)"
      mt="$(stat -c %Y "$f" 2>/dev/null)"; at="$(stat -c %X "$f" 2>/dev/null)"; bt="$(stat -c %W "$f" 2>/dev/null)"
      miso="$(date -u -d "@${mt:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
      aiso="$(date -u -d "@${at:-0}" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
      biso=""; { [ -n "$bt" ] && [ "$bt" != "0" ] && [ "$bt" != "-" ]; } && biso="$(date -u -d "@$bt" +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
    fi
    "$JQ" -cn --arg n "$f" --argjson s "${size:-0}" --arg p "${perm:-}" \
      --argjson u "${uid:-0}" --argjson g "${gid:-0}" --arg m "${miso:-}" --arg a "${aiso:-}" --arg c "${biso:-}" \
      '{fileName:$n, size:$s, permissions:$p, uid:$u, gid:$g, modified:$m, accessed:$a, created:$c}'
  done
}
{
  if [ "$PLATFORM" = "darwin" ]; then
    file_meta_emit /etc/passwd /etc/sudoers /private/etc/sudoers /etc/hosts /etc/crontab /etc/ssh/sshd_config
    scan_dirs="/tmp /private/tmp /var/tmp /Users/Shared $HOME/Desktop $HOME/Downloads"
  else
    file_meta_emit /etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/hosts /etc/ld.so.preload
    scan_dirs="/tmp /var/tmp /dev/shm $HOME/Desktop $HOME/Downloads"
  fi
  # Suspicious / staging directories: surfaces ransom notes (FOS-RAN-001) and timestomping (FOS-AF-001).
  scan_cap=200; [ "$DEEP" -eq 1 ] && scan_cap=1000
  for dir in $scan_dirs; do
    [ -d "$dir" ] || continue
    while IFS= read -r ff; do [ -n "$ff" ] && file_meta_emit "$ff"; done \
      < <(find "$dir" -maxdepth 3 -type f 2>/dev/null | head -n "$scan_cap")
  done
} | "$JQ" -s '.' > "$TMP/files.json" 2>/dev/null || { echo "$emptyarr" > "$TMP/files.json"; add_err "fileMetadata" "stat collection failed"; }

# --- remote-access / RMM tool inventory (read-only) ---
PROC_TEXT="$("$JQ" -r '.[]|"\(.name) \(.commandLine) \(.executablePath)"' "$TMP/proc.json" 2>/dev/null | tr 'A-Z' 'a-z')"
SVC_TEXT="$( { "$JQ" -r '.[]|"\(.unit) \(.execStart)"' "$TMP/systemd.json" 2>/dev/null;
               "$JQ" -r '.[]|"\(.path) \(.command)"' "$TMP/autostart.json" 2>/dev/null; } | tr 'A-Z' 'a-z')"
if [ "$PLATFORM" = "darwin" ]; then
  PKG_TEXT="$(ls /Applications /Applications/Utilities "$HOME/Applications" 2>/dev/null | tr 'A-Z' 'a-z')"
else
  PKG_TEXT="$( { dpkg -l 2>/dev/null | awk '{print $2}'; rpm -qa 2>/dev/null; } | tr 'A-Z' 'a-z')"
fi
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
Apple Remote Desktop|ardagent|remotedesktopagent
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
if [ "$PLATFORM" = "darwin" ]; then
  ADMINS_JSON="$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: //' | tr ' ' '\n' | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null)"
  RDP=false
  systemsetup -getremotelogin 2>/dev/null | grep -qi "On" && RDP=true            # SSH remote login
  echo "$PROC_TEXT" | grep -qE 'screensharingd|ardagent|remotedesktop' && RDP=true # ARD / Screen Sharing
  SHARES_JSON="$(sharing -l 2>/dev/null | sed -n 's/^name:[[:space:]]*//p' | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null)"
else
  ADMINS="$( { getent group sudo wheel admin root 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n';
               awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null; } | sort -u | grep -v '^$' )"
  ADMINS_JSON="$(printf '%s\n' "$ADMINS" | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null)"
  RDP=false
  if command -v systemctl >/dev/null 2>&1 && [ "$(systemctl is-active xrdp 2>/dev/null)" = "active" ]; then RDP=true; fi
  echo "$SVC_TEXT" | grep -qE 'xrdp' && RDP=true
  SHARES="$( { command -v testparm >/dev/null 2>&1 && testparm -s 2>/dev/null | grep -E '^\[' | grep -viE '^\[global\]|^\[printers\]|^\[print\$\]';
               grep -vE '^\s*#|^\s*$' /etc/exports 2>/dev/null | awk '{print "NFS "$1}'; } )"
  SHARES_JSON="$(printf '%s\n' "$SHARES" | "$JQ" -R -s 'split("\n")|map(select(length>0))' 2>/dev/null)"
fi
[ -z "$ADMINS_JSON" ] && ADMINS_JSON="$emptyarr"
[ -z "$SHARES_JSON" ] && SHARES_JSON="$emptyarr"
ACCESS_JSON="$("$JQ" -n --argjson a "$ADMINS_JSON" --argjson r "$RDP" --argjson s "$SHARES_JSON" \
  '{localAdmins:$a, rdpEnabled:$r, shares:$s}')"

# --- security posture ---
# No Microsoft Defender on *nix; declared unavailable so DEF/firewall rules never fire.
DEFENDER_JSON='{"available":false,"realTimeEnabled":null,"antivirusEnabled":null,"tamperProtectionEnabled":null,"exclusionPaths":[],"exclusionExtensions":[],"exclusionProcesses":[]}'
MACOS_JSON='null'; MACCTRL="$emptyarr"
if [ "$PLATFORM" = "darwin" ]; then
  sip="unknown"; s="$(csrutil status 2>/dev/null)"; echo "$s" | grep -qi "enabled" && sip="enabled"; echo "$s" | grep -qi "disabled" && sip="disabled"
  gk="unknown"; g="$(spctl --status 2>/dev/null)"; echo "$g" | grep -qi "assessments enabled" && gk="enabled"; echo "$g" | grep -qi "assessments disabled" && gk="disabled"
  fv="unknown"; f="$(fdesetup status 2>/dev/null)"; echo "$f" | grep -qi "On" && fv="on"; echo "$f" | grep -qi "Off" && fv="off"
  MACOS_JSON="$("$JQ" -cn --arg sip "$sip" --arg gk "$gk" --arg fv "$fv" '{sip:$sip, gatekeeper:$gk, fileVault:$fv}')"
  # macControls holds ONLY disabled high-value controls (anomaly-only) -> FOS-MAC-001.
  : > "$TMP/ctrl.jsonl"
  [ "$sip" = "disabled" ] && "$JQ" -cn '{control:"SIP", state:"disabled"}' >> "$TMP/ctrl.jsonl"
  [ "$gk"  = "disabled" ] && "$JQ" -cn '{control:"Gatekeeper", state:"disabled"}' >> "$TMP/ctrl.jsonl"
  MACCTRL="$("$JQ" -s '.' "$TMP/ctrl.jsonl" 2>/dev/null)"; [ -z "$MACCTRL" ] && MACCTRL="$emptyarr"
fi

# --- ClamAV: READ existing logs only (does NOT run a scan) ---
CLAM_HITS="$( for lg in /var/log/clamav/*.log /var/log/clamav.log /var/log/clamd.scan /var/log/clamd.log; do
                [ -f "$lg" ] && grep -aE ' FOUND$' "$lg" 2>/dev/null
              done | tail -n "$MAX_EVENTS" )"
CLAM_PRESENT=false
{ [ -d /var/log/clamav ] || [ -f /var/log/clamav.log ] || [ -f /var/log/clamd.scan ]; } && CLAM_PRESENT=true
CLAM_THREATS="$(printf '%s\n' "$CLAM_HITS" | "$JQ" -R -s 'split("\n")|map(select(length>0))|map((capture("^(?<file>.*): (?<name>.*) FOUND$")? // {file:., name:""}))' 2>/dev/null || echo "$emptyarr")"
CLAMAV_JSON="$("$JQ" -n --argjson present "$CLAM_PRESENT" --argjson threats "$CLAM_THREATS" \
  '{executed:$present, threatsFound:($threats|length), threats:$threats}' 2>/dev/null || echo '{"executed":false,"threatsFound":0,"threats":[]}')"

# --- Exfiltration / data-theft signals (read-only; mirror of the Windows collector) ---
# Shared user-writable landing/staging zones across all home directories.
DIRS_FILE="$TMP/userdirs.txt"; : > "$DIRS_FILE"
for base in /home /Users; do
  [ -d "$base" ] || continue
  for u in "$base"/*; do
    [ -d "$u" ] || continue
    for sub in Downloads Desktop Documents .cache; do
      [ -d "$u/$sub" ] && printf '%s\n' "$u/$sub" >> "$DIRS_FILE"
    done
  done
done
[ -d /root/Downloads ] && printf '%s\n' /root/Downloads >> "$DIRS_FILE"
printf '%s\n%s\n' /tmp /var/tmp >> "$DIRS_FILE"

# Download provenance: Linux records a downloaded file's origin in the user.xdg.origin.url xattr.
: > "$TMP/dlprov.jsonl"
if command -v getfattr >/dev/null 2>&1; then
  while IFS= read -r d; do
    [ -n "$d" ] && [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f 2>/dev/null | head -n 500 | while IFS= read -r f; do
      url="$(getfattr -n user.xdg.origin.url --only-values "$f" 2>/dev/null)"
      [ -n "$url" ] || continue
      hostpart="$(printf '%s' "$url" | sed -n 's#^[a-zA-Z][a-zA-Z0-9+.-]*://\([^/:?#]*\).*#\1#p')"
      sz="$(wc -c <"$f" 2>/dev/null | tr -d ' ')"
      "$JQ" -cn --arg fn "$f" --arg url "$url" --arg host "$hostpart" --argjson sz "${sz:-0}" \
        '{fileName:$fn, sourceUrl:$url, referrerUrl:"", sourceHost:$host, zoneId:"", sizeBytes:$sz, modifiedUtc:""}' >> "$TMP/dlprov.jsonl" 2>/dev/null
    done
  done < "$DIRS_FILE"
fi
"$JQ" -s '.' "$TMP/dlprov.jsonl" > "$TMP/dlprov.json" 2>/dev/null || echo "$emptyarr" > "$TMP/dlprov.json"

# Archive staging: recently-modified archives in user/temp paths (last 14 days).
: > "$TMP/archives.jsonl"
while IFS= read -r d; do
  [ -n "$d" ] && [ -d "$d" ] || continue
  find "$d" -maxdepth 1 -type f \( -iname '*.zip' -o -iname '*.rar' -o -iname '*.7z' -o -iname '*.tar' \
       -o -iname '*.gz' -o -iname '*.tgz' -o -iname '*.cab' -o -iname '*.iso' \) -mtime -14 2>/dev/null | head -n 200 | while IFS= read -r f; do
    sz="$(wc -c <"$f" 2>/dev/null | tr -d ' ')"
    "$JQ" -cn --arg fn "$f" --argjson sz "${sz:-0}" \
      '{fileName:$fn, sizeBytes:$sz, createdUtc:"", modifiedUtc:"", ageMinutes:0}' >> "$TMP/archives.jsonl" 2>/dev/null
  done
done < "$DIRS_FILE"
"$JQ" -s '.' "$TMP/archives.jsonl" > "$TMP/archives.json" 2>/dev/null || echo "$emptyarr" > "$TMP/archives.json"

# Transfer-tool inventory: bulk data-egress utilities that are not default OS components.
: > "$TMP/xfer.jsonl"
for pair in "Rclone:rclone" "MEGAcmd:mega-cmd" "MEGAcmd:megacmd" "FileZilla:filezilla" "WinSCP:winscp" \
            "Croc:croc" "Magic-Wormhole:wormhole" "ffsend:ffsend" "NcFTP:ncftp"; do
  name="${pair%%:*}"; bin="${pair##*:}"
  if command -v "$bin" >/dev/null 2>&1; then
    "$JQ" -cn --arg t "$name" --arg d "$(command -v "$bin")" '{tool:$t, evidence:"installed", detail:$d}' >> "$TMP/xfer.jsonl" 2>/dev/null
  fi
done
"$JQ" -s '.' "$TMP/xfer.jsonl" > "$TMP/xfer.json" 2>/dev/null || echo "$emptyarr" > "$TMP/xfer.json"

# BITS is Windows-only; RMM transfer-log scanning is left empty on *nix (best-effort only).
echo "$emptyarr" > "$TMP/bits.json"
echo "$emptyarr" > "$TMP/rmmlogs.json"

# Browser history: SEAL ONLY. Copy History/places.sqlite into the case as hashed evidence;
# never parsed on the endpoint. find (not glob) keeps space-bearing macOS paths safe.
: > "$TMP/browser.jsonl"
for base in /home /Users; do
  [ -d "$base" ] || continue
  for u in "$base"/*; do
    [ -d "$u" ] || continue
    uname_="$(basename "$u")"
    find "$u/.config" "$u/.mozilla" "$u/Library/Application Support" -maxdepth 4 \
         \( -name 'History' -o -name 'places.sqlite' \) -type f 2>/dev/null | head -n 20 | while IFS= read -r src; do
      case "$src" in
        *Brave*|*brave*)        br="Brave";;
        *hromium*)              br="Chromium";;
        *dge*)                  br="Edge";;
        *hrome*|*Chrome*)       br="Chrome";;
        *mozilla*|*Firefox*)    br="Firefox";;
        *)                      br="Browser";;
      esac
      prof="$(basename "$(dirname "$src")")"; art="$(basename "$src")"
      safe="$(printf 'browser_%s_%s_%s_%s' "$br" "$uname_" "$prof" "$art" | tr -c 'A-Za-z0-9_.-' '_')"
      if cp -p "$src" "$CASEDIR/$safe" 2>/dev/null; then
        sha="$(fos_sha256_file "$CASEDIR/$safe" 2>/dev/null)"
        sz="$(wc -c <"$CASEDIR/$safe" 2>/dev/null | tr -d ' ')"
        "$JQ" -cn --arg b "$br" --arg u "$uname_" --arg p "$prof" --arg a "$art" --arg src "$src" \
          --arg sf "$safe" --arg sha "$sha" --argjson sz "${sz:-0}" \
          '{browser:$b, user:$u, profile:$p, artifact:$a, sourcePath:$src, sealedFile:$sf, sha256:$sha, sizeBytes:$sz, modifiedUtc:""}' >> "$TMP/browser.jsonl" 2>/dev/null
      fi
    done
  done
done
"$JQ" -s '.' "$TMP/browser.jsonl" > "$TMP/browser.json" 2>/dev/null || echo "$emptyarr" > "$TMP/browser.json"

# --- Assemble bundle ---
if [ "$PLATFORM" = "darwin" ]; then OSVER="$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(uname -m 2>/dev/null))"
else OSVER="$(uname -srm 2>/dev/null)"; fi

"$JQ" -n \
  --arg schemaVersion "3.0.0" --arg caseId "$CASEID" --arg ts "$(fos_utc_now)" \
  --arg host "$(hostname)" --arg osver "$OSVER" --arg ver "$FOS_ENGINE_VERSION" --arg platform "$PLATFORM" \
  --argjson operator "$(fos_operator_json)" \
  --slurpfile cron "$TMP/cron.json" --slurpfile systemd "$TMP/systemd.json" \
  --slurpfile proc "$TMP/proc.json" --slurpfile net "$TMP/net.json" \
  --slurpfile listeners "$TMP/listeners.json" --slurpfile hosts "$TMP/hosts.json" \
  --slurpfile logon "$TMP/logon.json" --slurpfile usercreate "$TMP/usercreate.json" \
  --slurpfile autostart "$TMP/autostart.json" --slurpfile files "$TMP/files.json" \
  --slurpfile remote "$TMP/remote.json" --slurpfile expected "$TMP/expected.json" \
  --slurpfile dlprov "$TMP/dlprov.json" --slurpfile archives "$TMP/archives.json" \
  --slurpfile bits "$TMP/bits.json" --slurpfile xfer "$TMP/xfer.json" \
  --slurpfile rmmlogs "$TMP/rmmlogs.json" --slurpfile browser "$TMP/browser.json" \
  --slurpfile errors "$ERRJSON" \
  --argjson access "$ACCESS_JSON" --argjson defender "$DEFENDER_JSON" --argjson clamav "$CLAMAV_JSON" \
  --argjson macos "$MACOS_JSON" --argjson macctrl "$MACCTRL" \
  '{
    schemaVersion:$schemaVersion,
    metadata:{caseId:$caseId, collectionTimestampUtc:$ts, targetHostname:$host, platform:$platform,
              osVersion:$osver, collectorVersion:$ver, executionMode:"local", evidenceIntegrityMode:true,
              expectedRemoteTools:$expected[0], operator:$operator, errors:$errors[0]},
    artifacts:{
      remoteAccess:{tools:$remote[0]},
      securityPosture:{defender:$defender, macos:$macos, macControls:$macctrl},
      accessControl:$access,
      defenseEvasion:{logClearEvents:[]},
      persistence:{cronJobs:$cron[0], systemdServices:$systemd[0], autostartFiles:$autostart[0],
                   registryRunKeys:[], scheduledTasks:[], services:[], asep:[],
                   wmiEventSubscriptions:{eventFilters:[],eventConsumers:[],filterBindings:[]}},
      execution:{processes:$proc[0], processCreationEvents:[], prefetch:[], injectedModules:[], drivers:[]},
      network:{connections:$net[0], listeners:$listeners[0], dnsCache:[], hostsFileEntries:$hosts[0]},
      credentialAccess:{logonEvents:$logon[0], privilegeEscalationEvents:[],
                        userCreationEvents:$usercreate[0], serviceInstallEvents:[]},
      fileSystem:{fileMetadata:$files[0], browserArtifacts:$browser[0]},
      exfiltration:{downloadProvenance:$dlprov[0], archiveStaging:$archives[0], bitsJobs:$bits[0],
                    transferTools:$xfer[0], remoteToolTransferLogs:$rmmlogs[0]},
      powerShellActivity:{scriptBlockLogs:[]},
      antivirusScans:{defenderScan:{executed:false,threatsFound:0,threats:[]}, clamavScan:$clamav}
    }
  }' > "$CASEDIR/bundle.json" 2>"$TMP/assemble.err" \
  || { add_err "assemble" "bundle assembly failed: $(tr -d '\n' < "$TMP/assemble.err")"; echo '{}' > "$CASEDIR/bundle.json"; }

NPROC="$("$JQ" '.artifacts.execution.processes|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
NREMOTE="$("$JQ" '.artifacts.remoteAccess.tools|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
NERR="$("$JQ" '.metadata.errors|length' "$CASEDIR/bundle.json" 2>/dev/null || echo 0)"
fos_coc_add "$CASEDIR" "COLLECT_DONE" "platform=$PLATFORM proc=$NPROC remoteTools=$NREMOTE errors=$NERR" "$CASEDIR/bundle.json" >/dev/null
fos_log OK "Bundle written: $CASEDIR/bundle.json (platform=$PLATFORM proc=$NPROC remoteTools=$NREMOTE errors=$NERR)" "$CASEDIR"
echo "$CASEDIR/bundle.json"
