#!/bin/bash

# gather_info.sh
# Collects forensic artifacts on Linux systems and outputs them as a single JSON object.

# Ensure jq is installed
if ! command -v jq &> /dev/null
then
    echo "{"error": "jq is not installed. Please install jq to continue."}"
    exit 1
fi

# Create a temporary directory
TMP_DIR=$(mktemp -d)

# --- METADATA ---
jq -n \
  --arg timestamp "$(date --iso-8601=seconds)" \
  --arg hostname "$(hostname)" \
  --arg version "$(cat package.json | jq -r .version)" \
  '{collectionTimestamp: $timestamp, targetHostname: $hostname, platform: "linux", collectorVersion: $version}' > "$TMP_DIR/metadata.json"

# --- ARTIFACTS ---
(cat /etc/crontab 2>/dev/null; for f in /etc/cron.d/*; do cat "$f" 2>/dev/null; done; for f in /var/spool/cron/crontabs/*; do cat "$f" 2>/dev/null; done) | grep -v "^#" | grep -v "^$" | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {schedule: .[0:5] | join(" "), user: (if .[5] then .[5] else "root" end), command: .[6:] | join(" ")} ' | jq -s '.' > "$TMP_DIR/cron_jobs.json"
systemctl list-units --type=service --all --no-pager --no-legend | awk '{print $1}' | xargs -I {} systemctl show -p Id,ActiveState,LoadState,ExecStart {} 2>/dev/null | jq -s -R 'split("\n\n") | .[] | select(length > 0) | split("\n") | .[] | select(length > 0) | split("=") | {(.[0]): .[1]}' | jq -s '.' > "$TMP_DIR/systemd_services.json"
ps -axwwo pid,ppid,user,comm,cmd --no-headers | cat -v | sed 's/\^.//g' | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {processId: .[0] | tonumber, parentProcessId: .[1] | tonumber, user: .[2], name: .[3], commandLine: .[4:] | join(" ")} ' | jq -s '.' > "$TMP_DIR/processes.json"
ss -tunanlpo | tail -n +2 | jq -R -s 'split("\n") | .[] | select(length > 0) | [split(" ") | .[] | select(length > 0)] | {protocol: .[0], state: .[1], localAddress: (.[4] | split(":") | .[0]), localPort: (.[4] | split(":") | .[1] | tonumber), remoteAddress: (.[5] | split(":") | .[0]), remotePort: (.[5] | split(":") | .[1] | tonumber), process: .[6]} ' | jq -s '.' > "$TMP_DIR/connections.json"
(cat /var/log/auth.log 2>/dev/null; journalctl -q _SYSTEMD_UNIT=sshd.service --since "1 week ago" 2>/dev/null) | tr -dc '[:print:]\n' | grep -E -i "(sshd.*(accept|fail|disconnect))|(pam_unix.*(session opened|session closed))|(sudo.*(granted|denied))" | jq -R -s 'split("\n") | .[] | select(length > 0) | {logEntry: .}' | jq -s '.' > "$TMP_DIR/logon_events.json"
find /etc/passwd /etc/shadow /etc/sudoers /var/log/auth.log /var/log/syslog /etc/hosts /etc/resolv.conf -type f -exec stat -c '{"fileName": "%n", "size": %s, "permissions": "%A", "uid": %u, "gid": %g, "modified": "%y", "accessed": "%x", "created": "%w"}' {} + 2>/dev/null | jq -s '.' > "$TMP_DIR/file_metadata.json"
find /home /root -name "History" -o -name "places.sqlite" 2>/dev/null | jq -R -s 'split("\n") | .[] | select(length > 0) | {"path": .}' | jq -s '.' > "$TMP_DIR/browser_artifacts.json"

# --- JSON OUTPUT ---
jq -n \
  --slurpfile metadata "$TMP_DIR/metadata.json" \
  --slurpfile cron_jobs "$TMP_DIR/cron_jobs.json" \
  --slurpfile systemd_services "$TMP_DIR/systemd_services.json" \
  --slurpfile processes "$TMP_DIR/processes.json" \
  --slurpfile connections "$TMP_DIR/connections.json" \
  --slurpfile logon_events "$TMP_DIR/logon_events.json" \
  --slurpfile file_metadata "$TMP_DIR/file_metadata.json" \
  --slurpfile browser_artifacts "$TMP_DIR/browser_artifacts.json" \
'{ 
    "metadata": $metadata[0],
    "artifacts": {
      "persistence": {
        "cronJobs": $cron_jobs[0],
        "systemdServices": $systemd_services[0]
      },
      "execution": {
        "processes": $processes[0]
      },
      "network": {
        "connections": $connections[0]
      },
      "credentialAccess": {
        "logonEvents": $logon_events[0]
      },
      "fileSystem": {
        "fileMetadata": $file_metadata[0],
        "browserArtifacts": $browser_artifacts[0]
      }
    }
  }'

# Clean up the temporary directory
rm -rf "$TMP_DIR"