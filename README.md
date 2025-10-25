<div align="center">
  <img src="assets/logo.png" alt="First-On-Scene Logo" width="300"/>
  <h1>First-On-Scene</h1>
  <p><strong>AI-Powered Incident Response Triage for Windows Systems</strong></p>

  <p>
    <strong>🎯 What it does:</strong> Automatically collects forensic data from Windows computers, analyzes it using AI, and makes a decisive call: <strong>Problem Detected</strong> or <strong>All Clear</strong>.
  </p>

  <p>
    <strong>💡 Why it exists:</strong> When antivirus or monitoring tools trigger alerts, this toolkit acts like a "First Responding Officer"—quickly determining if a real threat exists or if it's a false positive.
  </p>

  <p>
    <strong>🏆 Best for:</strong> MSPs, IT professionals, and security teams who need rapid, AI-assisted incident triage.
  </p>
</div>

---

## 🚀 Quick Start

**Run one PowerShell command. Get instant AI-powered triage.**

### Prerequisites

1. **Windows with PowerShell** - This toolkit is currently **Windows-only** (PowerShell). Linux/Bash support is planned for future releases.
2. **Administrator Privileges** - Required for forensic data collection.
3. **OpenRouter API Key** (FREE) - Get yours at [openrouter.ai/keys](https://openrouter.ai/keys).
   - No credit card required
   - Takes 2 minutes to set up
   - You'll be prompted on first run
   - Securely stored in Windows Credential Manager
4. **Winget (Optional)** - Recommended for automatic installation of Git, Node.js, and ClamAV.

### Run It (PowerShell One-Liner)

**Download and run from GitHub (PowerShell as Administrator):**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\Gather_Info.ps1"
```

**Or clone and run locally:**
```powershell
git clone https://github.com/amosroger91/First-On-Scene.git
cd First-On-Scene
.\scripts\Gather_Info.ps1
```

**What happens automatically:**
1. ✅ Collects volatile forensic artifacts (network connections, processes, open files)
2. ✅ Collects persistent forensic artifacts (registry, scheduled tasks, services, event logs)
3. ✅ Parses and structures the data
4. ✅ Launches AI triage using OpenRouter's free tier
5. ✅ Generates detailed findings report (`results/findings.txt`)
6. ✅ Makes final decision: **Problem Detected** or **All Clear**
7. ✅ Executes custom action scripts for automation (optional)

**⚠️ Evidence Integrity Mode (Default):**
- Rkill execution **SKIPPED** (preserves volatile evidence)
- Defender auto-enable **SKIPPED** (preserves stealth)
- Use `-RunRkill` and `-EnableDefender` flags to enable these (modifies system state)

---

## 🌐 Remote vs. Local Execution

**First-On-Scene can analyze both local and remote Windows systems.**

### Local Execution
Run on the **suspected compromised computer itself**:
```powershell
.\scripts\Gather_Info.ps1
```

**⚠️ Risk:** If the system is compromised, malware could interfere with data collection or tamper with results.

### Remote Execution (Recommended)
Run from a **clean computer on the same network** to analyze a remote target:
```powershell
.\scripts\Gather_Info.ps1 -ComputerName "SuspectPC" -Credential (Get-Credential)
```

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

**WinRM Auto-Fix:**
First-On-Scene includes automatic WinRM corruption detection and repair. If WinRM is corrupted, the script will attempt to restore it remotely before falling back to local execution.

---

## 🤖 Custom Actions & Automation

**First-On-Scene doesn't just analyze—it acts.**

After the AI makes its final determination, it executes one of two PowerShell scripts that you can customize for your environment:

1. **`scripts/Problem_Detected.ps1`** - Executed when a threat is confirmed
   - Receives a `REASON_CODE` argument (e.g., "MALWARE_DETECTED", "RANSOMWARE_ENCRYPTED_FILES")
   - **Default:** Shows a critical alert message box
   - **Customize:** Send alerts, create tickets, isolate systems, trigger workflows

2. **`scripts/All_Clear.ps1`** - Executed when no threat is found
   - **Default:** Shows an "all clear" message box
   - **Customize:** Close tickets, update dashboards, send notifications

### Customization Examples

Both scripts are **templates** with extensive inline documentation. Here are some integration examples:

**Trigger an n8n Workflow:**
```powershell
# Add to Problem_Detected.ps1
$webhookUrl = "https://your-n8n-instance.com/webhook/incident-alert"
$body = @{
    incident = "First-On-Scene Detection"
    reason = $REASON_CODE
    hostname = $env:COMPUTERNAME
} | ConvertTo-Json
Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
```

**Create a ServiceNow Ticket:**
```powershell
$ticketData = @{
    summary = "Security Alert: $REASON_CODE"
    description = "First-On-Scene detected a security incident on $($env:COMPUTERNAME)"
    priority = 1
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://your-instance.service-now.com/api/now/table/incident" `
    -Method Post -Body $ticketData -Headers @{Authorization="Basic YOUR_API_KEY"}
```

**Send Slack Alert:**
```powershell
$slackWebhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
$slackMessage = @{
    text = ":rotating_light: *CRITICAL INCIDENT DETECTED* :rotating_light:"
    attachments = @(@{
        color = "danger"
        fields = @(
            @{ title = "Reason"; value = $REASON_CODE; short = $true }
            @{ title = "Hostname"; value = $env:COMPUTERNAME; short = $true }
        )
    })
} | ConvertTo-Json -Depth 3
Invoke-RestMethod -Uri $slackWebhook -Method Post -Body $slackMessage -ContentType "application/json"
```

### Advanced: Custom Action Script Paths

You can specify custom scripts via command-line parameters:

```powershell
.\scripts\Gather_Info.ps1 `
    -CustomProblemScript "C:\MyScripts\SendAlert.ps1" `
    -CustomAllClearScript "C:\MyScripts\ClearAlert.ps1" `
    -BrandName "Acme Security" `
    -LogoPath "C:\MyLogo.png"
```

**Security Note:** These scripts run with the same permissions as the user executing `Gather_Info.ps1`. Be cautious when adding commands, especially with administrative privileges.

---

## 🔍 How It Works: The Triage Process

**First-On-Scene** parallels how a responding officer handles a crime scene:

| Responding Officer | First-On-Scene |
| :--- | :--- |
| **Determine if a crime occurred** | **Determine if a malicious event occurred** by separating threats from false positives |
| **Check if crime is ongoing** | **Determine if attack is active/uncontained** by checking processes, network, persistence |
| **Document without tampering** | **Log every action** to `results/Steps_Taken.txt` (append-only audit trail) |
| **Interview witnesses** | **Gather info from the user** about observed behaviors |
| **Check cameras and logs** | **Execute data collection** to review logs and forensic data |
| **Determine escalation** | **Make final decisive call** based on classification (Event, Incident, or Breach) |

### Forensic Analysis Categories

The AI analyzes data across multiple categories:

| Category | What It Checks | What It Looks For |
| :--- | :--- | :--- |
| **Persistence** | Registry Run keys, Scheduled Tasks, Windows Services, WMI Event Subscriptions | Non-standard startup entries, hidden tasks, suspicious services, WMI-based persistence |
| **Execution** | Running processes, Process Creation Events (Event ID 4688) | Processes from user profiles/temp dirs, suspicious parent-child relationships, obfuscated commands |
| **Network** | Active TCP connections | Unusual external connections on high-risk ports (80, 443, 8080, 4444, 5555, 8443, 3389) |
| **Credential Access** | Security event logs (Logons, Service Installs, User Creations, Object Access) | Suspicious logon patterns, service installations, user account creations (Event IDs 4624, 4672, 4697, 4720, 4663) |
| **PowerShell Activity** | PowerShell Operational Logs | Obfuscated commands, base64 encoding, suspicious cmdlets (`Invoke-Expression`, `DownloadString`, etc.) |
| **File System** | MACE Timestamps | Timestomping indicators (creation time after modification time) |
| **Antivirus Scans** | Windows Defender, ClamAV, Rkill | Malware detections, terminated malicious processes |
| **Browser Activity** | Browser history databases (Chrome, Edge, Firefox) | Collected for manual analysis (requires SQLite parsing) |

### Forensic Artifacts Collected

**Currently Implemented:**
- ✅ Network TCP Connections (with owning processes) - **Volatile**
- ✅ Running Processes (with paths, command lines, parent-child relationships) - **Volatile**
- ✅ Open Files and Handles (open files, SMB sessions, mapped drives) - **Volatile** ⭐ NEW
- ✅ Registry Run/RunOnce keys (HKCU/HKLM) - **Volatile**
- ✅ Scheduled Tasks (all tasks with paths, authors, states, arguments) - **Persistent**
- ✅ Windows Services (configuration, start modes, executable paths) - **Persistent**
- ✅ WMI Event Subscriptions (Event Filters, Consumers, Bindings) - **Persistent**
- ✅ Security Event Logs (Logon, Admin, Process Creation, Service Install, User Creation, Object Access) - **Persistent**
- ✅ PowerShell Operational Logs (Script Block Logging) - **Persistent**
- ✅ Browser History Databases (Chrome, Edge, Firefox) - **Persistent**
- ✅ MACE Timestamps (Modified, Accessed, Created, Entry metadata) - **Persistent**
- ✅ Antivirus Scans (Optional - use `-RunRkill` and `-EnableDefender` flags):
  - ClamAV full system scan (if available)
  - Windows Defender full scan (only if running OR if `-EnableDefender` flag used)
  - Rkill execution (ONLY if `-RunRkill` flag used - modifies system state!)

**Planned for Future:**
- Full memory (RAM) image
- Full disk image
- Prefetch files, Jump Lists, LNK files
- USB device history
- Credential Manager data
- Group Policy snapshots

---

## ⚙️ Output & Reports

All analysis results are saved to the `results/` directory:

### Generated Files

- **`findings.txt`** - MANDATORY: Structured Markdown report with AI's complete analysis and findings
- **`Incident_Report_YYYYMMDD_HHMMSS.html`** - Professional, human-readable HTML report
- **`Incident_Report_YYYYMMDD_HHMMSS.docx`** - Professional DOCX report (if Word conversion succeeds)
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
10. **Report Generation** - AI writes `findings.txt`, and `Generate_Report.ps1` creates HTML/DOCX reports
11. **Final Decision & Action** - AI executes either `Problem_Detected.ps1` or `All_Clear.ps1`

**Everything is logged to `results/Steps_Taken.txt` for a complete audit trail.**

---

## 🤖 Why OpenRouter? Free AI Analysis

**First-On-Scene** uses [OpenRouter](https://openrouter.ai) to provide **completely free** AI-powered incident triage.

### The Engineering Decision: Cost vs. Performance

We understand that requiring an OpenRouter account is an extra step. However, this is the **best engineering decision** for keeping this tool truly free:

| Provider | Model Quality | Cost | Verdict |
| :--- | :--- | :--- | :--- |
| **OpenRouter (Our Choice)** | ✅ Cutting-edge (Qwen3 Coder 480B A35B) | ✅ **100% FREE** | ✅ **Best Option** |
| Google Gemini | ✅ Good | ❌ **Paid API** (after trial) | ❌ Not viable |
| OpenAI GPT | ✅ Excellent | ❌ **Expensive** | ❌ Not viable |
| Claude API | ✅ Excellent | ❌ **Paid** | ❌ Not viable |

### What is OpenRouter?

[OpenRouter](https://openrouter.ai) is an API gateway providing **unified access to dozens of AI models**. Their free tier includes state-of-the-art models specialized for technical analysis and code generation.

**Current Model:** Qwen3 Coder 480B A35B (free tier)
- Alternative free models: `qwen/qwen-2.5-72b-instruct:free`, `qwen/qwen-2.5-coder-32b-instruct:free`

### Setup (One-Time, 2 Minutes)

1. **Create free account**: Visit [openrouter.ai/keys](https://openrouter.ai/keys)
2. **Generate API key**: Click "Create Key" (no credit card required)
3. **Run First-On-Scene**: You'll be prompted for the key on first run
4. **Done**: Key is securely stored in Windows Credential Manager for future runs

**Manual Token Management:**
```powershell
# Store a new token
.\scripts\Manage_API_Token.ps1 -Action Set

# Retrieve stored token
.\scripts\Manage_API_Token.ps1 -Action Get
```

**Yes, it's an extra step.** But it means:
- ✅ State-of-the-art AI analysis for $0
- ✅ No monthly subscriptions or usage limits (within free tier)
- ✅ A tool that works long-term without asking for payment

We chose this path to ensure **First-On-Scene remains truly free and accessible** to MSPs, IT professionals, and security teams of all sizes.

---

## 📊 Cybersecurity Classification Framework

The AI uses these definitions to classify findings:

- **Breach of Confidentiality** - Unauthorized acquisition, access, use, or disclosure of confidential information
- **Brute Force Attack** - Attempting multiple password combinations to gain access
- **Business Email Compromise** - Sophisticated scam targeting legitimate fund transfers
- **Fraudulent Transaction** - Unauthorized use of accounts/payment info resulting in loss
- **Loss or Theft of Equipment** - Removal of physical assets without consent
- **Malware** - Intentionally harmful software, firmware, or hardware
- **Phishing** - Fraudulent solicitation masquerading as legitimate to acquire sensitive data
- **Ransomware** - Malicious attack encrypting data and demanding payment
- **Spam** - Unsolicited bulk messages via electronic messaging
- **Spyware** - Software secretly gathering information without knowledge
- **Unauthorized Access** - Gaining logical/physical access without permission
- **Virus** - Self-replicating program that corrupts/deletes data without permission
- **Vulnerability** - Weakness in systems/procedures that could be exploited

(See `system_prompt.txt` for complete classification definitions with citations)

---

## 🛡️ Platform Support & Future Plans

**Current Status: Windows Only (PowerShell)**

First-On-Scene is currently designed for **Windows systems** and requires **PowerShell 5.1+**.

**Why Windows-only right now?**
- Native PowerShell Remoting (WinRM) support
- Windows-specific forensic artifacts (Registry, Windows services, Event Logs, etc.)
- Windows Defender and ClamAV integration
- Windows Credential Manager for secure token storage

**Future Plans:**
We are **considering expanding to Linux (Bash)** in future releases. Linux support would include:
- Bash equivalents of the action scripts (`problem_found.sh`, `no_problem.sh`)
- Linux-specific forensic artifact collection (systemd services, cron jobs, auth logs, etc.)
- SSH-based remote execution instead of WinRM
- Secure token storage via Linux keyring

**Stay tuned** - We'll update this README when Linux support is added.

---

## 🔧 Advanced Options

### Command-Line Parameters

**`Gather_Info.ps1` accepts the following parameters:**

```powershell
.\scripts\Gather_Info.ps1 `
    -ComputerName "RemotePC" `
    -Credential (Get-Credential) `
    -CustomProblemScript "C:\MyScripts\SendAlert.ps1" `
    -CustomAllClearScript "C:\MyScripts\ClearAlert.ps1" `
    -BrandName "Acme Security" `
    -LogoPath "C:\MyLogo.png" `
    -RunRkill `
    -EnableDefender
```

| Parameter | Description | Default |
| :--- | :--- | :--- |
| `-ComputerName` | Target computer name for analysis | `"localhost"` (local execution) |
| `-Credential` | Credentials for remote execution | Current user credentials |
| `-CustomProblemScript` | Path to custom PowerShell script for problem detection | Uses default `Problem_Detected.ps1` |
| `-CustomAllClearScript` | Path to custom PowerShell script for all clear | Uses default `All_Clear.ps1` |
| `-BrandName` | Custom brand name for reports | `"First-On-Scene"` |
| `-LogoPath` | Path to custom logo image for reports | None |
| `-RunRkill` | **⚠️ Execute rkill.exe to terminate malware processes (MODIFIES SYSTEM STATE)** | `$false` (SKIPPED for evidence integrity) |
| `-EnableDefender` | **⚠️ Auto-enable Windows Defender if stopped (MAY ALERT MALWARE)** | `$false` (SKIPPED for stealth) |

**Example with custom branding:**
```powershell
.\scripts\Gather_Info.ps1 -BrandName "YourCompany Security Response" -LogoPath "C:\logo.png"
```

---

## 📄 License

This project is open source. See the LICENSE file for details.

---

## 🔗 Links

- **OpenRouter**: https://openrouter.ai
- **Get API Key**: https://openrouter.ai/keys (free, no credit card)
- **GitHub Issues**: https://github.com/amosroger91/First-On-Scene/issues

---

<div align="center">
  <p><strong>Built for MSPs, IT Professionals, and Security Teams</strong></p>
  <p>Powered by AI • Completely Free • Evidence-Preserving</p>
</div>
