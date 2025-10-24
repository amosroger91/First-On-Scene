<div align="center">
  <img src="assets/logo.png" alt="First-On-Scene Logo" width="300"/>
  <h1 style="margin-top: 5px; margin-bottom: 0px;">First-On-Scene</h1>
  <p style="margin-top: 0px; margin-bottom: 20px;">**Agentic Cyber Incident Response Triage Toolkit**</p>
</div>

## 🚨 The Triage Agent's Mission

**First-On-Scene** acts as a **First Responding Officer** to cybersecurity incidents. When your antivirus, EDR, or network monitors trigger an alert, this toolkit performs automated forensic triage to determine if a real threat exists—separating actual incidents from false positives with AI-powered analysis.

---

## 🚀 Quick Start

**Run one command. Get instant AI-powered triage.**

### Prerequisites
1. **Administrator PowerShell** - Required for forensic data collection.
2. **OpenRouter API Key** (FREE) - Get yours at [openrouter.ai/keys](https://openrouter.ai/keys).
   - No credit card required.
   - Takes 2 minutes to set up.
   - You'll be prompted on first run.
3. **Winget (Windows Package Manager)** - Recommended for automatic installation of Git, Node.js, and ClamAV. If not installed, these dependencies may need to be installed manually.

### Local Execution (Windows Only)

**One-liner (download and run in PowerShell):**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\Gather_Info.ps1"
```

**From cloned repository:**
```powershell
.\scripts\Gather_Info.ps1
```

**What happens automatically:**
1. ✅ **Pre-Scan Remediation**: Downloads and executes `rkill.exe` to terminate known malware processes and services, ensuring a cleaner forensic collection.
2. ✅ **Software Dependency Check**: Uses Winget to check for and install Git, Node.js (for AI execution), and ClamAV (for antivirus scanning).
3. ✅ **Collects Forensic Artifacts**: Gathers volatile and persistent data (processes, network connections, registry run keys, scheduled tasks, Windows services, WMI persistence, event logs, browser history, MACE timestamps).
4. ✅ **Parses and Analyzes Data**: Deterministically processes raw data to identify suspicious activities across multiple categories.
5. ✅ **Launches AI Triage**: Uses a powerful LLM (via OpenRouter) to analyze findings and generate a detailed report.
6. ✅ **LLM-Based Error Diagnostics**: If script errors occur, the LLM can be invoked to provide real-time diagnosis and potential fixes.
7. ✅ **Generates Detailed Reports**: Creates `findings.txt` (AI analysis), `Incident_Report_*.html` (professional HTML report), and attempts to generate `Incident_Report_*.docx` (professional DOCX report).
8. ✅ **Makes Final Binary Decision**: Determines if a problem is detected or if it's an all-clear scenario.
9. ✅ **Executes Custom Action Script**: Triggers either `Problem_Detected.ps1` or `All_Clear.ps1` for automated responses.

### Remote Execution

Analyze a remote machine (requires WinRM enabled):

```powershell
.\scripts\Gather_Info.ps1 -ComputerName "RemotePC" -Credential (Get-Credential)
```

**Enable WinRM on target machine:**
```powershell
Enable-PSRemoting -Force
```

**WinRM Corruption Detection and Fix**: The toolkit includes a mechanism to detect and attempt to automatically fix common WinRM configuration issues on remote machines, enhancing reliability for remote collections.

---

## 🤖 LLM-Triggered Custom Actions & Automation

**First-On-Scene** doesn't just stop at analysis. It makes a binary decision (problem vs. no problem) and executes one of two corresponding PowerShell scripts to trigger your custom workflows.

This allows you to automate critical next steps, such as:
- Isolating a machine from the network.
- Creating a ticket in your PSA/ticketing system.
- Sending an alert to a Slack or Teams channel.
- Triggering a workflow in an automation platform like n8n or Zapier.

### How It Works

The LLM's final decision triggers one of two scripts:

1.  **`scripts/Problem_Detected.ps1`**: Executed when a credible threat is found. Requires a single capitalized argument (e.g., "MALWARE_DETECTED").
2.  **`scripts/All_Clear.ps1`**: Executed when the alert is a false positive or a contained, low-impact event. No arguments required.

### Customization: Integrating Your Systems

We provide simple, ready-to-edit template scripts. **You are expected to replace the contents of these files** to integrate with your own systems.

**Example:** Need to integrate with an n8n workflow? Just drop your custom cURL command or script logic into `Problem_Detected.ps1`.

```powershell
# Example: Triggering a webhook in Problem_Detected.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$REASON_CODE
)

# Your custom logic here
$webhookUrl = "https://your-n8n-instance.com/webhook/123"
$body = @{
    "incident" = "First-On-Scene Detection"
    "reason" = $REASON_CODE
    "hostname" = $env:COMPUTERNAME
} | ConvertTo-Json

Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
```

### Security Note

These scripts run with the user's local permissions. Be mindful of the commands you add, especially when running with administrative privileges.

**Platform Support:** Currently, these scripts are for **Windows (PowerShell) only**. We are considering expanding to support Linux (Bash) in the future.

---

## 🔑 Secure API Token Management

First-On-Scene securely manages your OpenRouter API key using **Windows Credential Manager**. This ensures your sensitive token is not stored in plain text on disk.

-   **Automatic Prompting**: On the first run, you will be prompted for your OpenRouter API key. It will then be stored securely.
-   **Manual Management**: You can manually manage your API token using the `Manage_API_Token.ps1` script:
    ```powershell
    # Store a new token
    .\scripts\Manage_API_Token.ps1 -Action Set

    # Retrieve stored token (for verification or debugging)
    .\scripts\Manage_API_Token.ps1 -Action Get
    ```

---

## 🔍 The Triage Agent's Approach

A Responding Officer arriving at a crime scene must secure the area and, without contaminating evidence, quickly determine what happened. Our approach directly parallels this:

| Responding Officer Duty | Triage Agent Duty |
| :--- | :--- |
| **Determine if a "crime" occurred** | **Determine if a malicious event definitively occurred** by separating threats from false positives. |
| **Determine if "crime" is ongoing** | **Determine if attack is ongoing/uncontained**, checking active processes, network connections, and persistence. |
| **Document without tampering** | **Document every action** to preserve integrity. All commands are logged to `results/Steps_Taken.txt`. |
| **Interview witnesses** | **Gather info from the client** about what they observed or actions taken. |
| **Check cameras and logs** | **Execute data collection and parsing** to systematically review logs and forensic data. |
| **Determine escalation** | **Make a final decisive call** based on the classification (Event, Incident, or Breach). |

---

## 🛠️ How It Works: The Agentic Triage Strategy

**First-On-Scene** operates on a **Structured LLM Triage** strategy, treating the AI as a scoring engine for pre-defined forensic indicators.

### Forensic Analysis Categories

The AI analyzes various categories for suspicious indicators:

| Category | What It Checks | AI Task |
| :--- | :--- | :--- |
| **Persistence** | Registry Run keys, Scheduled Tasks, Windows Services, WMI Event Subscriptions | Identify non-standard startup entries, hidden tasks, suspicious services, and WMI-based persistence. |
| **Execution** | Running processes, Process Creation Events | Flag processes from user profiles/temp dirs, and suspicious command-line activity (e.g., PowerShell obfuscation). |
| **Network** | Active connections | Find unusual external connections, especially on high-risk ports, excluding known local/private IPs. |
| **Credential Access** | Security event logs (Logons, Service Installs, User Creations) | Detect suspicious logon patterns, service installations, user account creations, and object access attempts. |
| **PowerShell Activity** | PowerShell Operational Logs | Identify obfuscated commands, base64 encoding, and suspicious cmdlets (e.g., `Invoke-Expression`, `DownloadString`). |
| **File System** | MACE Timestamps | Look for timestomping indicators (e.g., creation time after last write time) on executables. |

### Forensic Artifacts Collected

**Currently Implemented:**
- ✅ **Running Processes** - All active processes with paths and command lines.
- ✅ **Network Connections** - TCP connections with owning processes.
- ✅ **Registry Run Keys** - Persistence mechanisms (HKCU/HKLM).
- ✅ **Scheduled Tasks** - Comprehensive details of all scheduled tasks.
- ✅ **Windows Services** - Configuration and state of all installed services.
- ✅ **WMI Event Subscriptions** - Details of WMI event filters, consumers, and bindings.
- ✅ **Security Event Logs** - Logon events (4624), Admin privileges (4672), Process Creation (4688), Service Install (4697), User Creation (4720), Object Access (4663).
- ✅ **PowerShell Operational Logs** - Script Block Logging and other PowerShell activity.
- ✅ **Browser History & Downloads** - Database files from Chrome, Edge, and Firefox.
- ✅ **MACE Timestamps** - Creation, Access, Write, and Entry Modified timestamps for executables referenced in persistence mechanisms and running processes.
- ✅ **Antivirus Scans** - ClamAV and Windows Defender results.

**Planned for Future:**
- Full memory (RAM) image
- Full disk image
- Prefetch files, Jump Lists, LNK files, ShellBags
- Credential Manager data
- Group Policy snapshots

---

## ⚙️ Output & Decision Making

### Final Action

The AI must make a decisive call:

- **`scripts/Problem_Detected.ps1 [REASON_CODE]`** - Called if classification is a **Breach** or uncontained **Incident**.
  - Argument must be capitalized, concise (e.g., "MALWARE_DETECTED").
  - Displays a critical alert and logs to `results/Steps_Taken.txt`.

- **`scripts/All_Clear.ps1`** - Called if classification is a contained **Event** or False Positive.
  - Logs the clearance action.

### Output Files

All analysis results are saved to the `results/` directory:

- **`findings.txt`** - MANDATORY: Structured Markdown report explaining analysis and findings.
- **`Info_Results.txt`** - Structured JSON with parsed triage indicators (detailed findings from `Parse_Results.ps1`).
- **`Steps_Taken.txt`** - MANDATORY: Append-only audit log of all actions.
- **`Incident_Report_YYYYMMDD_HHMMSS.html`** - A professional, human-readable HTML report summarizing the findings.
- **`Incident_Report_YYYYMMDD_HHMMSS.docx`** - An attempt to generate a professional DOCX report (requires Word conversion to succeed).
- Raw forensic data (various JSON files).

---

## 🗺️ Automated Workflow

When you run `.\scripts\Gather_Info.ps1`, here's what happens:

1. **WinRM Check & Fix**: For remote targets, checks WinRM configuration and attempts to self-heal if corruption is detected.
2. **Pre-Scan Remediation**: `rkill.exe` is executed to stop malicious processes.
3. **Software Dependency Installation**: Winget is used to ensure Git, Node.js, and ClamAV are installed.
4. **Data Collection** - `Gather_Info.ps1` collects comprehensive forensic artifacts.
5. **Parsing** - `Parse_Results.ps1` runs automatically, structuring data into `results/Info_Results.txt`.
6. **AI Analysis** - The LLM analyzes the findings from `Info_Results.txt`.
7. **LLM Error Diagnostics**: If any script errors occur, the LLM can be invoked to provide diagnostic assistance.
8. **Report Generation** - The AI writes a detailed analysis to `findings.txt`, and `Generate_Report.ps1` creates HTML and DOCX reports.
9. **Final Decision & Action** - The AI executes either `Problem_Detected.ps1` or `All_Clear.ps1`.

**Everything is logged to `results/Steps_Taken.txt` for a complete audit trail.**

---

## 🤖 Why OpenRouter? Free Access to Cutting-Edge AI

**First-On-Scene** uses OpenRouter with powerful LLMs to provide **completely free** AI-powered incident triage.

### The Engineering Decision: Cost vs. Performance

We understand that requiring an OpenRouter account is an extra step. However, this is the **best engineering decision** for keeping this tool truly free:

| Provider | Model Quality | Cost | Verdict |
| :--- | :--- | :--- |
| **OpenRouter (Our Choice)** | ✅ Cutting-edge (various models available) | ✅ **100% FREE** | ✅ **Best Option** |
| Google Gemini | ✅ Good | ❌ **Paid API** (after trial) | ❌ Not viable |
| OpenAI GPT | ✅ Excellent | ❌ **Expensive** | ❌ Not viable |
| Claude API | ✅ Excellent | ❌ **Paid** | ❌ Not viable |

### What is OpenRouter?

[OpenRouter](https://openrouter.ai) is an API gateway providing **unified access to dozens of AI models**. Their free tier includes a variety of powerful models specialized for technical analysis.

### Setup (One-Time, 2 Minutes)

1. **Create free account**: Visit [openrouter.ai/keys](https://openrouter.ai/keys)
2. **Generate API key**: Click "Create Key" (no credit card)
3. **Run First-On-Scene**: You'll be prompted for the key on first run
4. **Done**: Key is securely stored in Windows Credential Manager for future runs

**Yes, it's an extra step.** But it means:
- ✅ State-of-the-art AI analysis for $0
- ✅ No monthly subscriptions or usage limits (within free tier)
- ✅ A tool that works long-term without asking for payment

We chose this path to ensure **First-On-Scene remains truly free and accessible** to MSPs, IT professionals, and security teams of all sizes.

---

## 🔒 PowerShell Remoting Prerequisites

For remote execution, PowerShell Remoting must be enabled on the target machine(s).

**On the target machine** (run as Administrator):
```powershell
Enable-PSRemoting -Force
```

**Firewall requirements:**
- Allow WinRM traffic (port 5985 for HTTP, 5986 for HTTPS).

---

## 📊 Cybersecurity Classification Framework

The AI uses these definitions to classify findings:

- **Breach of Confidentiality** - Unauthorized access/disclosure of confidential information.
- **Brute Force Attack** - A method of accessing an obstructed device by attempting multiple combinations of numeric/alphanumeric passwords.
- **Business Email Compromise** - A sophisticated scam that targets both businesses and individuals who perform legitimate transfer-of-funds requests.
- **Fraudulent Transaction** - The unauthorized use of accounts or payment information; can result in the loss of funds, property, or information.
- **Loss or Theft of Equipment** - Inadvertent loss or removal by a third party of physical assets without consent.
- **Malware** - Hardware, firmware, or software that is intentionally included or inserted in a system for a harmful purpose.
- **Phishing** - A technique for attempting to acquire sensitive data, such as bank account numbers, through a fraudulent solicitation in email or on a web site, in which the perpetrator masquerades as a legitimate business or reputable person.
- **Ransomware** - A type of malicious attack where attackers encrypt an organization's data and demand payment to restore access.
- **Spam** - Electronic junk mail or the abuse of electronic messaging systems to indiscriminately send unsolicited bulk messages.
- **Spyware** - Software that is secretly or surreptitiously installed into an information system to gather information on individuals or organizations without their knowledge; a type of malicious code.
- **Unauthorized Access** - A person gains logical or physical access without permission to a network, system, application, data, or other resource.
- **Virus** - A computer program that can copy itself and infect a computer without permission or knowledge of the user; may corrupt or delete data on a computer, use e-mail programs to spread itself to other computers, or even erase everything on a hard disk.
- **Vulnerability** - Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source.

(See `system_prompt.txt` for complete classification definitions)

---

## 🤝 Contributing

First-On-Scene is designed for MSPs and incident responders. Contributions are welcome:

- **Forensic Artifacts**: Add new data sources to `Gather_Info.ps1`.
- **Triage Logic**: Improve scoring in `Parse_Results.ps1`.
- **Documentation**: Help improve setup guides and usage docs.

---

## 📝 License

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

### Local Execution (Windows Only)

**One-liner (download and run in PowerShell):**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\Gather_Info.ps1"
```

**From cloned repository:**
```powershell
.\scripts\Gather_Info.ps1
```

**What happens automatically:**
1. ✅ Collects forensic artifacts (processes, registry, network, event logs).
2. ✅ Parses and analyzes the data.
3. ✅ Launches AI triage using a powerful LLM (via OpenRouter).
4. ✅ Generates a detailed findings report.
5. ✅ Makes a final binary decision: **Problem Detected** or **All Clear**.
6. ✅ **Executes a corresponding custom script (`Problem_Detected.ps1` or `All_Clear.ps1`) to trigger external actions.**

### Remote Execution

Analyze a remote machine (requires WinRM enabled):

```powershell
.\scripts\Gather_Info.ps1 -ComputerName "RemotePC" -Credential (Get-Credential)
```

**Enable WinRM on target machine:**
```powershell
Enable-PSRemoting -Force
```

---

## 🤖 LLM-Triggered Custom Actions & Automation

**First-On-Scene** doesn't just stop at analysis. It makes a binary decision (problem vs. no problem) and executes one of two corresponding PowerShell scripts to trigger your custom workflows.

This allows you to automate critical next steps, such as:
- Isolating a machine from the network.
- Creating a ticket in your PSA/ticketing system.
- Sending an alert to a Slack or Teams channel.
- Triggering a workflow in an automation platform like n8n or Zapier.

### How It Works

The LLM's final decision triggers one of two scripts:

1.  **`scripts/Problem_Detected.ps1`**: Executed when a credible threat is found.
2.  **`scripts/All_Clear.ps1`**: Executed when the alert is a false positive or a contained, low-impact event.

### Customization: Integrating Your Systems

We provide simple, ready-to-edit template scripts. **You are expected to replace the contents of these files** to integrate with your own systems.

**Example:** Need to integrate with an n8n workflow? Just drop your custom cURL command or script logic into `Problem_Detected.ps1`.

```powershell
# Example: Triggering a webhook in Problem_Detected.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$REASON_CODE
)

# Your custom logic here
$webhookUrl = "https://your-n8n-instance.com/webhook/123"
$body = @{
    "incident" = "First-On-Scene Detection"
    "reason" = $REASON_CODE
    "hostname" = $env:COMPUTERNAME
} | ConvertTo-Json

Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
```

### Security Note

These scripts run with the user's local permissions. Be mindful of the commands you add, especially when running with administrative privileges.

**Platform Support:** Currently, these scripts are for **Windows (PowerShell) only**. We are considering expanding to support Linux (Bash) in the future.

---

## 🔍 The Triage Agent's Approach

A Responding Officer arriving at a crime scene must secure the area and, without contaminating evidence, quickly determine what happened. Our approach directly parallels this:

| Responding Officer Duty | Triage Agent Duty |
| :--- | :--- |
| **Determine if a "crime" occurred** | **Determine if a malicious event definitively occurred** by separating threats from false positives. |
| **Determine if "crime" is ongoing** | **Determine if attack is ongoing/uncontained**, checking active processes, network connections, and persistence. |
| **Document without tampering** | **Document every action** to preserve integrity. All commands are logged to `Steps_Taken.txt`. |
| **Interview witnesses** | **Gather info from the client** about what they observed or actions taken. |
| **Check cameras and logs** | **Execute data collection and parsing** to systematically review logs and forensic data. |
| **Determine escalation** | **Make a final decisive call** based on the classification (Event, Incident, or Breach). |

---

## 🛠️ How It Works: The Agentic Triage Strategy

**First-On-Scene** operates on a **Structured LLM Triage** strategy, treating the AI as a scoring engine for pre-defined forensic indicators.

### Forensic Analysis Categories

The AI analyzes four key categories:

| Category | What It Checks | AI Task |
| :--- | :--- | :--- |
| **Persistence** | Registry Run keys | Identify non-standard startup entries. |
| **Execution** | Running processes | Flag processes from user profiles/temp dirs. |
| **Network** | Active connections | Find unusual external connections. |
| **Credential Access** | Security event logs | Detect suspicious logon patterns (Event IDs 4624/4672). |

### Forensic Artifacts Collected

**Currently Implemented:**
- ✅ **Running Processes** - All active processes with paths and command lines.
- ✅ **Network Connections** - TCP connections with owning processes.
- ✅ **Registry Run Keys** - Persistence mechanisms (HKCU/HKLM).
- ✅ **Security Event Logs** - Logon events (4624/4672).
- ✅ **Antivirus Scans** - ClamAV and Windows Defender results.

**Planned for Future:**
- Full memory (RAM) image
- Full disk image
- Prefetch files, Jump Lists, LNK files
- Browser history and downloads
- USB device history
- Credential Manager data

---

## ⚙️ Output & Decision Making

### Final Action

The AI must make a decisive call:

- **`scripts/Problem_Detected.ps1 [REASON_CODE]`** - Called if classification is a **Breach** or uncontained **Incident**.
  - Argument must be capitalized, concise (e.g., "MALWARE_DETECTED").
  - Displays a critical alert and logs to `results/Steps_Taken.txt`.

- **`scripts/All_Clear.ps1`** - Called if classification is a contained **Event** or False Positive.
  - Logs the clearance action.

### Output Files

All analysis results are saved to the `results/` directory:

- **`findings.txt`** - MANDATORY: Structured Markdown report explaining analysis and findings.
- **`Steps_Taken.txt`** - MANDATORY: Append-only audit log of all actions.
- **`Info_Results.txt`** - Structured JSON with parsed triage indicators.
- Raw forensic data (JSON files).

---

## 🗺️ Automated Workflow

When you run `.\scripts\Gather_Info.ps1`, here's what happens:

1. **Data Collection** - `Gather_Info.ps1` collects forensic artifacts.
2. **Parsing** - `Parse_Results.ps1` runs automatically, structuring data into `Info_Results.txt`.
3. **AI Analysis** - The LLM analyzes the findings.
4. **Report Generation** - The AI writes a detailed analysis to `findings.txt`.
5. **Final Decision & Action** - The AI executes either `Problem_Detected.ps1` or `All_Clear.ps1`.

**Everything is logged to `results/Steps_Taken.txt` for a complete audit trail.**

---

## 🔒 PowerShell Remoting Prerequisites

For remote execution, PowerShell Remoting must be enabled on the target machine(s).

**On the target machine** (run as Administrator):
```powershell
Enable-PSRemoting -Force
```

**Firewall requirements:**
- Allow WinRM traffic (port 5985 for HTTP, 5986 for HTTPS).

---

## 📊 Cybersecurity Classification Framework

The AI uses these definitions to classify findings:

- **Breach of Confidentiality** - Unauthorized access/disclosure of confidential information.
- **Malware** - Intentionally harmful software inserted in a system.
- **Ransomware** - Malicious attack encrypting organization data, demanding payment.
- **Unauthorized Access** - Logical/physical access without permission.
- **Phishing** - Fraudulent attempt to acquire sensitive data.
- **Spyware** - Software secretly gathering information.
- **Virus** - Self-replicating program infecting a system.

(See `system_prompt.txt` for complete classification definitions)

---

## 🤝 Contributing

First-On-Scene is designed for MSPs and incident responders. Contributions are welcome:

- **Forensic Artifacts**: Add new data sources to `Gather_Info.ps1`.
- **Triage Logic**: Improve scoring in `Parse_Results.ps1`.
- **Documentation**: Help improve setup guides and usage docs.

---

## 📝 License

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
