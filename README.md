<div align="center">
  <img src="assets/logo.png" alt="First-On-Scene Logo" width="300"/>
  <h1>First-On-Scene</h1>
  <p><strong>AI-Powered Incident Response Triage for Windows & Linux</strong></p>

  <p>
    <strong>🎯 What it does:</strong> Automatically collects forensic data from Windows and Linux computers, analyzes it using AI, and makes a decisive call: <strong>Problem Detected</strong> or <strong>All Clear</strong>.
  </p>

  <p>
    <strong>💡 Why it exists:</strong> When antivirus or monitoring tools trigger alerts, this toolkit acts like a "First Responding Officer"—quickly determining if a real threat exists or if it's a false positive.
  </p>

  <p>
    <strong>🏆 Best for:</strong> MSPs, IT professionals, and security teams who need rapid, AI-assisted incident triage across multiple platforms.
  </p>
</div>

---

## 🚀 Quick Start

**Run one command. Get instant AI-powered triage.**

### Prerequisites

1. **Supported OS:**
    - **Windows:** PowerShell 5.1+
    - **Linux:** A modern distribution with Bash, `jq`, `systemctl`, `ps`, and `ss`.
2. **Administrator/Root Privileges** - Required for forensic data collection.
3. **OpenRouter API Key** (FREE) - Get yours at [openrouter.ai/keys](https://openrouter.ai/keys).
   - No credit card required
   - Takes 2 minutes to set up
   - You'll be prompted on first run
   - Securely stored in Windows Credential Manager or as an environment variable on Linux.

### Run It

#### Windows (PowerShell One-Liner)
**Download and run from GitHub (PowerShell as Administrator):**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1"
```

#### Linux (Bash One-Liner)
**Download and run from GitHub:**
```bash
cd /tmp && curl -L https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.tar.gz | tar -xz && cd First-On-Scene-main && chmod +x scripts/nix/gather_info.sh && ./scripts/nix/gather_info.sh
```

**🆕 Time-ranged collection (last 24 hours):**
```powershell
$start = (Get-Date).AddHours(-24); $d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -StartTime $start
```

**💡 Tip**: See [ONE_LINERS.md](ONE_LINERS.md) for platform-specific commands, time range examples, branding options, and advanced usage.

**What happens automatically:**
1. ✅ Collects volatile and persistent forensic artifacts.
2. ✅ Parses and structures the data into a standard JSON format.
3. ✅ Launches AI triage using OpenRouter's free tier.
4. ✅ Generates detailed findings report (`results/findings.txt`).
5. ✅ Makes final decision: **Problem Detected** or **All Clear**.
6. ✅ Executes custom action scripts for automation (optional).

---

## 🛡️ Platform Support

**Current Status: Windows & Linux**

First-On-Scene is designed for both **Windows** and **Linux** systems.

### Windows
- **Shell:** PowerShell 5.1+
- **Remote Execution:** WinRM
- **Artifacts:** Registry, WMI, Event Logs, etc.
- **Secure Storage:** Windows Credential Manager

### Linux
- **Shell:** Bash
- **Dependencies:** `jq`, `systemctl`, `ps`, `ss`
- **Remote Execution:** SSH (planned for future)
- **Artifacts:** `systemd`, `cron`, `auth.log`, etc.
- **Secure Storage:** Environment variables (future: Linux Keyring)

---

## 🌐 Remote vs. Local Execution

### Windows Remote Execution (Recommended)
Run from a **clean computer on the same network** to analyze a remote target:
```powershell
.\scripts\Gather_Info.ps1 -ComputerName "SuspectPC" -Credential (Get-Credential)
```
**Requirements:**
- PowerShell Remoting (WinRM) must be enabled on the target computer.

**Why remote execution is better:**
- ✅ **Avoids contamination**: Malware on the target can't interfere with your analysis tools
- ✅ **Safer**: Your analysis machine remains clean
- ✅ **Better evidence integrity**: Collection happens from a trusted source
- ✅ **Stealth**: Some advanced malware can detect and evade local forensic tools

**Requirements for remote execution:**
- PowerShell Remoting (WinRM) must be enabled on the target computer
- Network connectivity between your analysis machine and the target
- Administrative credentials for the target computer

**Enable WinRM on target computer (run as Administrator):**
```powershell
Enable-PSRemoting -Force
```

**Ports:**
- WinRM uses port 5985 (HTTP) or 5986 (HTTPS)
- Ensure these ports are open on the target's firewall

WinRM Auto-Fix:
First-On-Scene includes automatic WinRM corruption detection and repair. If WinRM is corrupted, the script will attempt to restore it remotely before falling back to local execution. **Note: If WinRM repair fails, the script will proceed with local data collection on the machine where it is executed, rather than the specified remote target.**

---

## 🤖 Custom Actions & Automation

After the AI makes its final determination, it executes one of two scripts that you can customize for your environment:

- **Windows:** `scripts/win/Problem_Detected.ps1` or `scripts/win/All_Clear.ps1`
- **Linux:** `scripts/nix/problem_detected.sh` or `scripts/nix/all_clear.sh`

These scripts can be customized to send alerts, create tickets, isolate systems, or trigger any other workflow.

---

## 🔍 How It Works: The Triage Process

**First-On-Scene** parallels how a responding officer handles a crime scene, collecting and analyzing forensic data across multiple categories.

### Forensic Artifacts Collected

**Currently Implemented:**
- ✅ **Memory Capture** (Optional - use `-CaptureMemory` flag):
  - Full RAM image via WinPmem - **MOST VOLATILE**
  - WARNING: Creates very large file (size of installed RAM)
- ✅ Network TCP Connections (with owning processes) - **Volatile**
- ✅ Running Processes (with paths, command lines, parent-child relationships) - **Volatile**
- ✅ Open Files and Handles (open files, SMB sessions, mapped drives) - **Volatile**
- ✅ Registry Run/RunOnce keys (HKCU/HKLM) - **Persistent**
- ✅ Scheduled Tasks (all tasks with paths, authors, states, arguments) - **Persistent**
- ✅ Windows Services (configuration, start modes, executable paths) - **Persistent**
- ✅ WMI Event Subscriptions (Event Filters, Consumers, Bindings) - **Persistent**
- ✅ Security Event Logs (Logon, Admin, Process Creation, Service Install, User Creation, Object Access) - **Persistent**
- ✅ PowerShell Operational Logs (Script Block Logging) - **Persistent**
- ✅ Browser History Databases (Chrome, Edge, Firefox) - **Persistent**
- ✅ Prefetch Files (program execution history) - **Persistent**
- ✅ Jump Lists (recent items accessed per user) - **Persistent**
- ✅ LNK Files (shortcuts from Recent and Desktop folders) - **Persistent**
- ✅ MACE Timestamps (Modified, Accessed, Created, Entry metadata) - **Persistent**
- ✅ Antivirus Scans (Optional - use `-RunRkill` and `-EnableDefender` flags):
  - ClamAV full system scan (if available, **SKIPPED by default** - use `-RunClamAV` flag to enable)
  - Windows Defender full scan (only if running OR if `-EnableDefender` flag used)
  - Rkill execution (ONLY if `-RunRkill` flag used - modifies system state!)

**Linux:**
- Network Connections
- Running Processes
- Cron Jobs
- Systemd Services
- Logon Events (`auth.log`, `journalctl`)
- File Metadata (key system files)
- Browser Artifact Paths

---

## ⚙️ Output & Reports

All analysis results are saved to the `results/` directory:

### Generated Files

- **`findings.txt`** - MANDATORY: Structured Markdown report with AI's complete analysis and findings
- **`Incident_Report_YYYYMMDD_HHMMSS.html`** - Professional, human-readable HTML report
- **Note on AI-generated summaries:** Executive summaries and recommendations within reports are filtered to remove any tool call syntax generated by the LLM, ensuring clean, readable text.

- **`Info_Results.txt`** - Structured JSON with parsed triage indicators (output from `Parse_Results.ps1`)
- **`Steps_Taken.txt`** - MANDATORY: Append-only audit log of all actions taken
- **`config.json`** - Configuration file (target computer, branding, custom script paths)
- **Raw forensic data** (various JSON files):
  - `registry_run_keys.json`
  - `scheduled_tasks.json`
  - `services_config.json`
  - `wmi_persistence.json`
  - `processes_snapshot.json`
  - `netstat_snapshot.json`
  - `security_events.json`
  - `powershell_logs.json`
  - `file_metadata.json`
  - `browser_artifacts.json`
  - `defender_scan_results.txt`
  - `clamav_scan_results.txt`
  - `rkill_execution.log`

### Final Action Decision

The AI must make a decisive call:

- **`scripts/Problem_Detected.ps1 [REASON_CODE]`** - Called if classification is a **Breach** or uncontained **Incident**
  - Argument must be capitalized, concise (e.g., "MALWARE_DETECTED", "RANSOMWARE_ENCRYPTED_FILES", "UNAUTHORIZED_ACCESS")
  - Displays a critical alert and logs to `results/Steps_Taken.txt`

- **`scripts/All_Clear.ps1`** - Called if classification is a contained **Event** or **False Positive**
  - Logs the clearance action to `results/Steps_Taken.txt`

---

## 🗺️ Automated Workflow

When you run `.\scripts\Gather_Info.ps1`, here's the complete workflow:

1. **Parameter Validation** - Processes command-line arguments (target computer, credentials, custom scripts, branding)
2. **WinRM Check & Auto-Fix** (Remote only) - Tests PSRemoting and attempts self-healing if WinRM corruption is detected
3. **Software Dependency Check** (Local only) - Uses Winget to ensure Git, Node.js, and ClamAV are installed
4. **Pre-Scan Remediation** - Downloads and executes `rkill.exe` to neutralize active malware
5. **Data Collection** - `Gather_Info.ps1` collects comprehensive forensic artifacts (local or remote)
6. **Parsing** - `Parse_Results.ps1` automatically structures data into `results/Info_Results.txt`
7. **API Token Validation** - Retrieves or prompts for OpenRouter API key (stored in Windows Credential Manager)
8. **AI Analysis** - The LLM (via OpenRouter/qwen CLI) analyzes `Info_Results.txt` and raw forensic data
9. **LLM Error Diagnostics** - If script errors occur, the LLM provides diagnostic assistance
10. **Report Generation** - AI writes `findings.txt`, and `Generate_Report.ps1` creates HTML reports
11. **Final Decision & Action** - AI executes either `Problem_Detected.ps1` or `All_Clear.ps1`

**Everything is logged to `results/Steps_Taken.txt` for a complete audit trail.**

---

## 🤖 Why OpenRouter? Free AI Analysis

**First-On-Scene** uses [OpenRouter](https://openrouter.ai) to provide **completely free** AI-powered incident triage. This requires a one-time, 2-minute setup to get a free API key. This is the best engineering decision to keep the tool free and accessible.

---

## 🔧 Advanced Options

### Command-Line Parameters

**`Gather_Info.ps1` accepts the following parameters:**

```powershell
.\scripts\Gather_Info.ps1 `
    -ComputerName "RemotePC" `
    -Credential (Get-Credential) `
    -StartTime "2025-01-15 08:00:00" `
    -EndTime "2025-01-15 17:00:00" `
    -CustomProblemScript "C:\MyScripts\SendAlert.ps1" `
    -CustomAllClearScript "C:\MyScripts\ClearAlert.ps1" `
    -BrandName "Acme Security" `
    -LogoPath "C:\MyLogo.png" `
    -RunRkill `
    -EnableDefender `
    -CaptureMemory
```

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `-ComputerName` | Target computer name for analysis | `"localhost"` (local execution) |
| `-Credential` | Credentials for remote execution | Current user credentials |
| `-StartTime` | **🆕 Start time for time-ranged collection** (e.g., `"2025-01-15 08:00:00"` or `(Get-Date).AddHours(-24)`) | None (collects all available data) |
| `-EndTime` | **🆕 End time for time-ranged collection** (e.g., `"2025-01-15 17:00:00"`) | None (collects up to current time) |
| `-CustomProblemScript` | Path to custom PowerShell script for problem detection | Uses default `Problem_Detected.ps1` |
| `-CustomAllClearScript` | Path to custom PowerShell script for all clear | Uses default `All_Clear.ps1` |
| `-BrandName` | Custom brand name for reports | `"First-On-Scene"` |
| `-LogoPath` | Path to custom logo image for reports | None |
| `-RunRkill` | **⚠️ Execute rkill.exe to terminate malware processes (MODIFIES SYSTEM STATE)** | `$false` (SKIPPED for evidence integrity) |
| `-EnableDefender` | **⚠️ Auto-enable Windows Defender if stopped (MAY ALERT MALWARE)** | `$false` (SKIPPED for stealth) |
| `-RunClamAV` | **⚠️ Execute ClamAV full system scan (can be very time-consuming and prone to permission issues)** | `$false` (SKIPPED by default) |
| `-CaptureMemory` | **⚠️ Capture full RAM image via WinPmem (VERY LARGE FILE - size of installed RAM)** | `$false` (SKIPPED to save time/disk space) |

**Example with custom branding:**
```powershell
.\scripts\Gather_Info.ps1 -BrandName "YourCompany Security Response" -LogoPath "C:\logo.png"
```

**🆕 Example with time-ranged collection (targeted investigation):**
```powershell
# Investigate last 24 hours
.\scripts\Gather_Info.ps1 -StartTime (Get-Date).AddHours(-24)

# Investigate specific date/time range
.\scripts\Gather_Info.ps1 -StartTime "2025-01-15 08:00:00" -EndTime "2025-01-15 17:00:00"

# Combine with remote computer
.\scripts\Gather_Info.ps1 -ComputerName "KS-BENCH01" -StartTime (Get-Date).AddDays(-7)
```

**Why use time ranges?**
- 🎯 **Targeted investigation**: Focus on known incident timeframes without noise from unrelated events
- 📊 **Reduce data volume**: Collect only relevant event logs for faster analysis
- 🕒 **Scope compliance**: Comply with investigation scope requirements for specific time windows
- 🔍 **Correlate events**: Analyze all activity within specific operational windows (e.g., business hours)

---

## 📄 License

This project is open source. See the LICENSE file for details.

---

## 🔗 Links

- **OpenRouter**: https://openrouter.ai
- **Get API Key**: https://openrouter.ai/keys (free, no credit card)
- **GitHub Issues**: https://github.com/amosroger91/First-On-Scene/issues