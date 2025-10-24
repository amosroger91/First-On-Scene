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
1. **Administrator PowerShell** - Required for forensic data collection
2. **OpenRouter API Key** (FREE) - Get yours at [openrouter.ai/keys](https://openrouter.ai/keys)
   - No credit card required
   - Takes 2 minutes to set up
   - You'll be prompted on first run

### Local Execution

**One-liner (download and run):**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\Gather_Info.ps1"
```

**From cloned repository:**
```powershell
.\scripts\Gather_Info.ps1
```

**What happens automatically:**
1. ✅ Collects forensic artifacts (processes, registry, network, event logs)
2. ✅ Parses and analyzes the data
3. ✅ Launches AI triage using Qwen3 Coder 480B (via OpenRouter)
4. ✅ Generates detailed findings report
5. ✅ Makes final call: **Problem Detected** or **All Clear**

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

## 🤖 Why OpenRouter? Free Access to Cutting-Edge AI

**First-On-Scene uses OpenRouter with the Qwen3 Coder 480B A35B model** to provide **completely free** AI-powered incident triage.

### The Engineering Decision: Cost vs. Performance

We understand that requiring an OpenRouter account is an extra step. However, this is the **best engineering decision** for keeping this tool truly free:

| Provider | Model Quality | Cost | Verdict |
| :--- | :--- | :--- | :--- |
| **OpenRouter (Our Choice)** | ✅ Cutting-edge (Qwen3 Coder 480B) | ✅ **100% FREE** | ✅ **Best Option** |
| Google Gemini | ✅ Good | ❌ **Paid API** (after trial) | ❌ Not viable |
| OpenAI GPT | ✅ Excellent | ❌ **Expensive** | ❌ Not viable |
| Claude API | ✅ Excellent | ❌ **Paid** | ❌ Not viable |

### What is OpenRouter?

[OpenRouter](https://openrouter.ai) is an API gateway providing **unified access to dozens of AI models**. Their free tier includes:
- **Qwen3 Coder 480B A35B** (what we use) - Massive model specialized for code and technical analysis
- Qwen 2.5 72B Instruct - Larger general-purpose model
- Qwen 2.5 Coder 32B Instruct - Alternative coder model

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

## 🔍 The Triage Agent's Approach

A Responding Officer arriving at a crime scene must secure the area and, without contaminating evidence, quickly determine what happened. Our approach directly parallels this:

| Responding Officer Duty | Triage Agent Duty |
| :--- | :--- |
| **Determine if a "crime" occurred** | **Determine if a malicious event definitively occurred** by separating threats from false positives |
| **Determine if "crime" is ongoing** | **Determine if attack is ongoing/uncontained**, checking active processes, network connections, persistence |
| **Document without tampering** | **Document every action** to preserve integrity. All commands logged to `Steps_Taken.txt` |
| **Interview witnesses** | **Gather info from client** about what they observed or actions taken |
| **Check cameras and logs** | **Execute data collection and parsing** to systematically review logs and forensic data |
| **Determine escalation** | **Make final decisive call** based on classification (Event, Incident, or Breach) |

---

## 🛠️ How It Works: The Agentic Triage Strategy

**First-On-Scene** operates on a **Structured LLM Triage** strategy, treating the AI as a scoring engine for pre-defined forensic indicators.

### Forensic Analysis Categories

The AI analyzes four key categories:

| Category | What It Checks | AI Task |
| :--- | :--- | :--- |
| **Persistence** | Registry Run keys | Identify non-standard startup entries |
| **Execution** | Running processes | Flag processes from user profiles/temp dirs |
| **Network** | Active connections | Find unusual external connections |
| **Credential Access** | Security event logs | Detect suspicious logon patterns (Event IDs 4624/4672) |

### Forensic Artifacts Collected

**Currently Implemented:**
- ✅ **Running Processes** - All active processes with paths and command lines
- ✅ **Network Connections** - TCP connections with owning processes
- ✅ **Registry Run Keys** - Persistence mechanisms (HKCU/HKLM)
- ✅ **Security Event Logs** - Logon events (4624/4672)
- ✅ **Antivirus Scans** - ClamAV and Windows Defender results

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

- **`scripts/Problem_Detected.ps1 [REASON_CODE]`** - Called if classification is a **Breach** or uncontained **Incident**
  - Argument must be capitalized, concise (e.g., "MALWARE_DETECTED")
  - Displays critical alert and logs to `results/Steps_Taken.txt`

- **`scripts/All_Clear.ps1`** - Called if classification is a contained **Event** or False Positive
  - Logs clearance action

### Output Files

All analysis results are saved to the `results/` directory:

- **`findings.txt`** - MANDATORY: Structured Markdown report explaining analysis and findings
- **`Steps_Taken.txt`** - MANDATORY: Append-only audit log of all actions
- **`Info_Results.txt`** - Structured JSON with parsed triage indicators
- Raw forensic data (JSON files)

---

## 🗺️ Automated Workflow

When you run `.\scripts\Gather_Info.ps1`, here's what happens:

1. **Data Collection** - `Gather_Info.ps1` collects forensic artifacts
2. **Parsing** - `Parse_Results.ps1` runs automatically, structures data into `Info_Results.txt`
3. **AI Analysis** - Qwen CLI launches with OpenRouter, analyzes findings
4. **Report Generation** - AI writes detailed analysis to `findings.txt`
5. **Final Decision** - AI executes either `Problem_Detected.ps1` or `All_Clear.ps1`

**Everything is logged to `results/Steps_Taken.txt` for audit trail.**

---

## 🔒 PowerShell Remoting Prerequisites

For remote execution, PowerShell Remoting must be enabled on target machine(s).

**On the target machine** (run as Administrator):
```powershell
Enable-PSRemoting -Force
```

**Firewall requirements:**
- Allow WinRM traffic (port 5985 for HTTP, 5986 for HTTPS)

---

## 📊 Cybersecurity Classification Framework

The AI uses these definitions to classify findings:

- **Breach of Confidentiality** - Unauthorized access/disclosure of confidential information
- **Malware** - Intentionally harmful software inserted in system
- **Ransomware** - Malicious attack encrypting organization data, demanding payment
- **Unauthorized Access** - Logical/physical access without permission
- **Phishing** - Fraudulent attempt to acquire sensitive data
- **Spyware** - Software secretly gathering information
- **Virus** - Self-replicating program infecting system

(See `system_prompt.txt` for complete classification definitions)

---

## 🤝 Contributing

First-On-Scene is designed for MSPs and incident responders. Contributions are welcome:

- **Forensic Artifacts**: Add new data sources to `Gather_Info.ps1`
- **Triage Logic**: Improve scoring in `Parse_Results.ps1`
- **Documentation**: Help improve setup guides and usage docs

---

## 📝 License

This project is open source. See LICENSE file for details.

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
