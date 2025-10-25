# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**First-On-Scene** is an Agentic Cyber Incident Response Triage Toolkit designed to act as a "First Responding Officer" for cybersecurity incidents. The system operates as a Triage Agent that collects forensic artifacts from potentially compromised systems (Windows/Linux/macOS), analyzes the data deterministically, and makes a decisive call on whether a security incident has occurred.

**Core Philosophy**: Maintain high skepticism and seek deterministic proof. Separate actual threats from false positives while preserving evidence integrity. The goal is comprehensive triage—find *everything*, not just the first thing.

## Architecture

### **⚠️ MIGRATION IN PROGRESS: Hybrid Node.js + TypeScript Architecture**

**Current Status**: Phase 0 (Architecture Setup) - COMPLETE ✅
- Node.js/TypeScript orchestrator established
- Cross-platform foundation implemented
- Legacy PowerShell scripts moved to `scripts/win/`
- JSON schema defined for data contracts

**Next Steps**: See `dev/task.txt` for Phase 1-4 implementation plan

### New Hybrid Architecture (v2.0+)

The system is transitioning to a **hybrid architecture** with:
- **Node.js/TypeScript Core** (`src/`) - Cross-platform orchestrator, CLI, API integration
- **Native Scripts** - OS-specific data collection:
  - `scripts/win/` - PowerShell scripts for Windows
  - `scripts/nix/` - Bash scripts for Linux/macOS (planned)

**Key Components**:
- `src/cli.ts` - Main CLI entry point (`fos-triage` command)
- `src/modules/platform.ts` - OS detection and script routing
- `src/modules/executor.ts` - Native script execution with timeout/capture
- `src/modules/schema-validator.ts` - JSON schema validation (Ajv)
- `src/types/index.ts` - TypeScript type definitions
- `schemas/artifact_schema.json` - **Data contract** for native scripts

**Data Flow**:
1. CLI detects OS and routes to appropriate native script
2. Native script collects artifacts, outputs JSON to stdout (conforming to schema)
3. Node.js executor captures stdout, validates against schema
4. Typed artifact data passed to AI triage logic
5. Final decision triggers action scripts

**Building & Running**:
```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript to dist/
npm run dev          # Run with ts-node (development)
node dist/cli.js     # Run compiled CLI

# Commands
fos-triage info      # Platform detection and status
fos-triage collect   # Collect artifacts (Phase 1+)
fos-triage analyze   # AI triage (Phase 3+)
```

### Legacy PowerShell Workflow (Current Production)

The original PowerShell-based system follows a strict sequential workflow orchestrated by the Triage Agent (LLM):

1. **`scripts/win/Gather_Info.ps1`** - Data Collection
   - Collects volatile and persistent forensic artifacts from the target system
   - Supports both local execution (`localhost`) and remote execution via PSRemoting
   - Parameters: `-ComputerName` (default: "localhost"), `-Credential` (optional)
   - Stores raw data as JSON files in `results/` directory
   - Executes antivirus scans (ClamAV, Windows Defender)
   - Requires Administrator privileges for full artifact collection

2. **`scripts/win/Parse_Results.ps1`** - Data Analysis
   - Reads raw JSON artifacts from `results/` directory
   - Applies deterministic triage logic across four categories:
     - **Persistence**: Non-standard registry Run keys
     - **Execution**: Processes launched from user profiles or temp directories
     - **Network**: Suspicious external connections on high-risk ports
     - **Credential Access**: Admin/Service logon event correlations
   - Outputs structured findings to `results/Info_Results.txt`

3. **Final Decision Scripts**:
   - **`scripts/win/Problem_Detected.ps1 [REASON_CODE]`** - Escalation for confirmed incidents
     - Requires a single capitalized argument (e.g., "MALWARE_DETECTED", "RANSOMWARE_ENCRYPTED_FILES")
     - Displays critical incident alert and logs to `results/Steps_Taken.txt`
   - **`scripts/win/All_Clear.ps1`** - Clears the incident (false positive or contained event)
     - No arguments required
     - Logs clearance to `results/Steps_Taken.txt`

### File Structure

```
results/
├── registry_run_keys.json       # Registry persistence mechanisms
├── processes_snapshot.json      # Running processes with paths/commands
├── netstat_snapshot.json        # Network connections state
├── security_logons.json         # Security event logs (4624, 4672)
├── Info_Results.txt             # Structured triage findings (JSON)
├── Steps_Taken.txt              # MANDATORY action log (append-only)
└── findings.txt                 # MANDATORY final analysis report (Markdown)

scripts/
├── Gather_Info.ps1              # Artifact collection
├── Parse_Results.ps1            # Deterministic parsing/scoring
├── Problem_Detected.ps1         # Incident escalation
└── All_Clear.ps1                # Incident clearance

system_prompt.txt                # Triage Agent operational instructions
```

## Development Commands

### Running the Triage Workflow

**Important:** The workflow is now fully automated. Running `Gather_Info.ps1` will:
1. Collect all forensic artifacts
2. Automatically run `Parse_Results.ps1`
3. Launch qwen CLI with OpenRouter for AI analysis
4. AI automatically reads data, writes findings, and makes final determination

**Prerequisites:**
- OpenRouter API key (free tier: https://openrouter.ai/keys)
- First run will prompt for API key (stored securely in Windows Credential Manager)

**Local execution:**
```powershell
# This single command does everything
.\scripts\Gather_Info.ps1
```

**Remote execution:**
```powershell
.\scripts\Gather_Info.ps1 -ComputerName "RemotePC" -Credential (Get-Credential)
```

**Manual API token management:**
```powershell
# Store a new token
.\scripts\Manage_API_Token.ps1 -Action Set

# Retrieve stored token
.\scripts\Manage_API_Token.ps1 -Action Get
```

### Testing & Development

- **Git operations**: Standard git workflow on `main` branch
- **PowerShell version**: Requires PowerShell 5.1+ (uses `Invoke-Command`, `Get-NetTCPConnection`, `Get-WinEvent`)
- **Remote execution prerequisites**: Target machine must have PSRemoting enabled (`Enable-PSRemoting -Force`)

### Quick Run (One-liner deployment)

The toolkit includes a one-liner that downloads and executes from GitHub:

```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\Gather_Info.ps1"
```

## Key Operational Constraints

### Triage Agent Behavior (from system_prompt.txt)

When acting as the Triage Agent, you MUST:

1. **Follow the strict order of operations**:
   - Execute `scripts/Gather_Info.ps1` → Log to `results/Steps_Taken.txt`
   - Execute `scripts/Parse_Results.ps1` → Log to `results/Steps_Taken.txt`
   - Review `results/Info_Results.txt`
   - Review raw JSON files ONLY if validation needed
   - Determine classification (Event/Incident/Breach)
   - Write final analysis to `results/findings.txt` (Markdown)
   - Make final call: `Problem_Detected.ps1 [REASON_CODE]` or `All_Clear.ps1`

2. **Mandatory logging**: ALL actions must be appended to `results/Steps_Taken.txt` (never erase)

3. **Forbidden actions**: ONLY execute commands explicitly listed in the Tools section of `system_prompt.txt`. No arbitrary PowerShell commands.

4. **Classification criteria**:
   - **Breach**: Confirmed unauthorized access/confidentiality breach → `Problem_Detected.ps1`
   - **Uncontained Incident**: Active attack in progress → `Problem_Detected.ps1`
   - **Contained Event**: Security event contained or resolved → `All_Clear.ps1`
   - **False Positive**: No actual threat detected → `All_Clear.ps1`

5. **Comprehensive triage**: Find ALL issues, not just the first one. Complete full analysis before making final call.

### Cybersecurity Classification Definitions

The Triage Agent uses these definitions (from `system_prompt.txt`) to classify findings:
- Breach of Confidentiality
- Brute Force Attack
- Business Email Compromise
- Fraudulent Transaction
- Loss or Theft of Equipment
- Malware
- Phishing
- Ransomware
- Spam
- Spyware
- Unauthorized Access
- Virus
- Vulnerability

## Forensic Artifacts Collected

**Currently implemented** (via `Gather_Info.ps1`):
- Registry Run/RunOnce keys (HKCU/HKLM)
- Running processes with executable paths and command lines
- Network TCP connections (netstat equivalent)
- Security Event Logs: Logon events (4624), Admin privileges (4672)
- ClamAV antivirus scan results
- Windows Defender scan results

**Planned for future implementation** (documented in README):
- Full memory (RAM) image
- Full disk image
- Prefetch files, Jump Lists, LNK files, ShellBags
- Browser history and download logs
- USB device history
- Credential Manager data
- Group Policy snapshots

## Remote Execution Architecture

`Gather_Info.ps1` uses PowerShell Remoting (`New-PSSession`, `Invoke-Command`) to execute artifact collection on remote machines. Key points:

- Establishes PSSession to target computer
- Executes collection scriptblock remotely
- Copies results back to local `results/` directory
- Disconnects session when complete
- WinRM must be enabled on target (ports 5985/5986)

## AI Model Configuration

**Current Setup (as of latest update):**
- **AI Provider:** OpenRouter (https://openrouter.ai)
- **Model:** Qwen3 Coder 480B A35B (Free tier: `qwen/qwen3-coder:free`)
- **CLI Tool:** qwen CLI (`@qwen-code/qwen-code` via npx)
- **Execution Mode:** `--yolo` (auto-approve all tool executions for full automation)
- **Auto-Configuration:** Script automatically creates/updates `~/.qwen/settings.json` with OpenRouter configuration

**Alternative Free Models (can be configured in Gather_Info.ps1):**
- `qwen/qwen-2.5-72b-instruct:free` - Larger general model
- `qwen/qwen-2.5-coder-32b-instruct:free` - Smaller coder model

**API Token Management:**
- Tokens are stored securely in Windows Credential Manager
- Token prompt on first run
- Manual management via `Manage_API_Token.ps1`

## Software Dependencies

The toolkit attempts to auto-install required software via Winget (if available):
- Git (Git.Git)
- Node.js (OpenJS.NodeJS) - **Required** for qwen CLI execution
- ClamAV (ClamAV.ClamAV)

Malwarebytes is noted as requiring business version for CLI scanning.

## Important Notes for Development

1. **Fully automated workflow**: `Gather_Info.ps1` now orchestrates the entire triage process end-to-end
   - User runs ONE command only
   - Data collection → Parsing → AI analysis → Final decision all happen automatically
   - No manual intervention required (except first-run API token prompt)

2. **Evidence integrity**: All scripts are designed to collect without modifying the target system state

3. **Administrator privileges**: Required for full artifact collection (Security Event Logs, Registry, etc.)

4. **Append-only logging**: `results/Steps_Taken.txt` must NEVER be truncated or erased

5. **Structured output**: `Parse_Results.ps1` outputs JSON, `findings.txt` must be Markdown

6. **Error handling**: Scripts should continue on individual collection failures (e.g., ClamAV not found) but log warnings

7. **AI automation**: qwen CLI runs in `--yolo` mode to auto-approve tool usage, allowing the AI to autonomously:
   - Read forensic data files
   - Write analysis reports
   - Execute final determination scripts

8. **Recent changes**:
   - Switched from Gemini CLI to qwen CLI with OpenRouter
   - Implemented secure API token management via Windows Credential Manager
   - Automated `Parse_Results.ps1` execution
   - Added `--yolo` mode for full AI autonomy
   - Enhanced Windows Defender scanning robustness
   - Improved ClamAV path detection
