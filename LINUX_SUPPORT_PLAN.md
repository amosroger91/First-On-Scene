# Plan for Adding Linux Support to First-On-Scene

## 1. Create Linux Script Directory

- **Action:** Create a new directory `scripts/nix/`.
- **Purpose:** This directory will contain all the Bash scripts for Linux and macOS, keeping them separate from the Windows PowerShell scripts.

## 2. Create `gather_info.sh`

- **Action:** Create a new file `scripts/nix/gather_info.sh`.
- **Purpose:** This will be the main data collection script for Linux, equivalent to `scripts/win/Gather_Info.ps1`. It will be a Bash script responsible for collecting all forensic artifacts.

## 3. Implement Artifact Collection in `gather_info.sh`

The script must collect the following artifacts and format them into a single JSON object that conforms to `schemas/artifact_schema.json`. The `jq` utility will be used for JSON manipulation.

- **Metadata:**
  - `collectionTimestamp`: `date --iso-8601=seconds`
  - `targetHostname`: `hostname`
  - `platform`: "linux"
  - `collectorVersion`: Get from `package.json`.

- **Persistence:**
  - `cronJobs`: Parse `/etc/crontab`, `/etc/cron.d/*`, and user crontabs from `/var/spool/cron/crontabs/*`.
  - `systemdServices`: Use `systemctl list-units --type=service` to get service status and `systemctl list-unit-files` to check if they are enabled to run on startup.

- **Execution:**
  - `processes`: Use `ps -eo pid,ppid,user,cmd --no-headers` to get a list of all running processes.

- **Network:**
  - `connections`: Use `ss -tuna` to get all TCP and UDP connections, including listening ports.

- **Credential Access:**
  - `logonEvents`: Parse `/var/log/auth.log` (or equivalent from `journalctl`) for successful and failed SSH logins, `su`, and `sudo` commands.

- **File System:**
  - `fileMetadata`: Use the `stat` command to get MACE (Modified, Accessed, Created, Entry) timestamps for key system files and executables identified during the collection.
  - `browserArtifacts`: Locate and copy browser history files for Chrome (`~/.config/google-chrome/Default/History`) and Firefox (`~/.mozilla/firefox/*.default/places.sqlite`).

- **Output:** The script's final action will be to print the complete JSON object to standard output.

## 4. Update TypeScript Core Logic

- **`src/modules/platform.ts`:** The existing logic correctly identifies Linux and points to the `scripts/nix/` directory. I will verify the script name is correct.
- **`src/cli.ts`:** The `collect` command currently has a hardcoded check that exits if the platform is not Windows. This check will be removed to allow execution on Linux.

## 5. Create Linux-Specific Action Scripts

- **Action:** Create `scripts/nix/problem_detected.sh` and `scripts/nix/all_clear.sh`.
- **Purpose:** These will be the Linux equivalents of the PowerShell action scripts, allowing for custom actions based on the triage result. They will be simple, customizable Bash scripts.

## 6. Update Documentation

- **`README.md`:** Add a section for Linux support, including prerequisites (e.g., `jq`, `ps`, `ss`) and execution instructions.
- **`ONE_LINERS.md`:** Add one-liner commands for downloading and running the toolkit on Linux systems.

## 7. Testing

- **Action:** Create a `test.sh` script in the `scripts/nix/` directory.
- **Purpose:** This script will:
  1. Execute `gather_info.sh`.
  2. Pipe the output to a JSON validator (like `ajv-cli`) to ensure it conforms to `artifact_schema.json`.
  3. Print a success or failure message based on the validation result.
