# First-On-Scene - Platform-Specific One-Liners

## Windows (PowerShell)

### Download and Run from GitHub (Recommended)
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; Invoke-WebRequest "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1"
```

### Local Execution (Already Cloned)
```powershell
cd First-On-Scene; .\scripts\win\Gather_Info.ps1
```

### Remote Computer Scan
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; Invoke-WebRequest "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -ComputerName "TARGET-PC" -Credential (Get-Credential)
```

### With Branding
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; Invoke-WebRequest "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -BrandName "Your Company Name"
```

### Enable Defender and Run Rkill (Evidence Modification Mode)
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; Invoke-WebRequest "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -EnableDefender -RunRkill
```

---

## Linux (Bash)

### Download and Run from GitHub
```bash
cd /tmp && curl -L https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.tar.gz | tar -xz && cd First-On-Scene-main && chmod +x scripts/nix/gather_info.sh && ./scripts/nix/gather_info.sh
```

### Local Execution (Already Cloned)
```bash
cd First-On-Scene && ./scripts/nix/gather_info.sh
```

### Remote Computer Scan via SSH (Future)
```bash
# Remote scanning for Linux is planned for a future release.
```

---

## macOS (Bash/Zsh) - Coming in Phase 2

### Download and Run from GitHub (Future)
```bash
cd /tmp && curl -L https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.tar.gz | tar -xz && cd First-On-Scene-main && chmod +x scripts/nix/gather_info.sh && ./scripts/nix/gather_info.sh
```

### Local Execution (Future)
```bash
cd First-On-Scene && ./scripts/nix/gather_info.sh
```

---

## Node.js CLI (Cross-Platform) - Phase 1+

### After Phase 1 Implementation
```bash
# Install globally
npm install -g first-on-scene

# Run collection
fos-triage collect

# Remote collection
fos-triage collect --computer-name TARGET-HOST

# With branding
fos-triage collect --brand-name "Your Company"
```

---

## Quick Copy-Paste Examples

### Windows: Analyze Local Machine
**Run in elevated PowerShell:**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1"
```

### Windows: Analyze Remote Machine (e.g., KS-BENCH01)
**Run in elevated PowerShell:**
```powershell
$d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -ComputerName "KS-BENCH01"
```

**If credentials are needed:**
```powershell
$cred = Get-Credential; $d=(Join-Path $env:TEMP "FOS_Run"); New-Item -ItemType Directory -Path $d -Force | Out-Null; iwr "https://github.com/amosroger91/First-On-Scene/archive/refs/heads/main.zip" -OutFile "$d\m.zip" -UseBasicParsing; Expand-Archive -Path "$d\m.zip" -DestinationPath $d -Force; & "$d\First-On-Scene-main\scripts\win\Gather_Info.ps1" -ComputerName "KS-BENCH01" -Credential $cred
```

---

## Notes

- **Windows one-liners require elevated (Administrator) PowerShell**
- All one-liners download the latest version from GitHub main branch
- Downloaded files are stored in `%TEMP%\FOS_Run` (Windows) or `/tmp` (Linux/macOS)
- Results are saved to the `results/` directory
- Linux/macOS support is under development (see `dev/task.txt` for roadmap)
