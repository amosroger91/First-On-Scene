#!/bin/bash

# gather_info.sh
# Collects forensic artifacts on Linux systems and outputs them as a single JSON object.

# Ensure jq is installed
if ! command -v jq &> /dev/null
then
    echo "{"error": "jq is not installed. Please install jq to continue."}"
    exit 1
fi

# --- METADATA ---
METADATA=$(jq -n \
  --arg timestamp "$(date --iso-8601=seconds)" \
  --arg hostname "$(hostname)" \
  --arg version "$(cat package.json | jq -r .version)" \
  '{collectionTimestamp: $timestamp, targetHostname: $hostname, platform: "linux", collectorVersion: $version}')

# --- ARTIFACT COLLECTION ---

# Persistence: cron jobs
CRON_JOBS=$( (cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do cat "$f" 2>/dev/null; done; for f in /var/spool/cron/crontabs/*; do cat "$f" 2>/dev/null; done) | grep -v "^#" | grep -v "^$" | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {schedule: .[0:5] | join(" "), user: (if .[5] then .[5] else "root" end), command: .[6:] | join(" ")}' | jq -s '.' 2>/dev/null)

# Persistence: systemd services
SYSTEMD_SERVICES=$(systemctl list-units --type=service --all --no-pager --no-legend | awk '{print $1}' | xargs -I {} systemctl show -p Id,ActiveState,LoadState,ExecStart {} 2>/dev/null | jq -s -R 'split("\n\n") | .[] | select(length > 0) | split("\n") | .[] | select(length > 0) | split("=") | {(.[0]): .[1]}' | jq -s '.' 2>/dev/null)

# Execution: processes
PROCESSES=$(ps -axwwo pid,ppid,user,comm,cmd --no-headers | cat -v | sed 's/\^.//g' | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {processId: .[0] | tonumber, parentProcessId: .[1] | tonumber, user: .[2], name: .[3], commandLine: .[4:] | join(" ")}' | jq -s '.' 2>/dev/null)

# Network: connections
CONNECTIONS=$(ss -tunanlpo | tail -n +2 | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {protocol: .[0], state: .[1], localAddress: (.[4] | split(":") | .[0]), localPort: (.[4] | split(":") | .[1] | tonumber), remoteAddress: (.[5] | split(":") | .[0]), remotePort: (.[5] | split(":") | .[1] | tonumber), process: .[6]}' | jq -s '.' 2>/dev/null)

# Credential Access: logon events (from auth.log)
LOGON_EVENTS=$(cat /var/log/auth.log 2>/dev/null | tr -dc '[:print:]\n' | grep -ie "sshd" -e "Accepted" | jq -R -s 'split("\n") | .[] | select(length > 0) | {timestamp: .[0:15], user: .[8], sourceAddress: .[10]}' | jq -s '.' 2>/dev/null)

# --- JSON OUTPUT ---
jq -n \
  --argjson metadata "$METADATA" \
  --argjson persistence "{\"cronJobs\":${CRON_JOBS:-\[\]},\"systemdServices\":${SYSTEMD_SERVICES:-\[\]}}" \
  --argjson execution "{\"processes\":${PROCESSES:-\[\]}}" \
  --argjson network "{\"connections\":${CONNECTIONS:-\[\]}}" \
  --argjson credentialAccess "{\"logonEvents\":${LOGON_EVENTS:-\[\]}}" \
'{ 
    "metadata": $metadata,
    "artifacts": {
      "persistence": $persistence,
      "execution": $execution,
      "network": $network,
      "credentialAccess": $credentialAccess
    }
  }'
