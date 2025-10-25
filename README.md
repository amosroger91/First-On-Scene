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

### Linux Remote Execution (Future)
Remote execution for Linux via SSH is planned for a future release.

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

**Windows:**
- Memory Capture (Optional)
- Network Connections
- Running Processes
- Registry Run Keys
- Scheduled Tasks
- Windows Services
- WMI Event Subscriptions
- Event Logs (Security, PowerShell)
- Browser History
- Prefetch Files, Jump Lists, LNK Files
- MACE Timestamps

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

All analysis results are saved to the `results/` directory, including:
- `findings.txt`: Structured Markdown report with AI's analysis.
- `Incident_Report_YYYYMMDD_HHMMSS.html`: Professional HTML report.
- Raw forensic data (JSON files).

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