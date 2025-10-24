<#
.SYNOPSIS
    Gathers essential volatile and persistent system artifacts for Triage Agent analysis.
.DESCRIPTION
    Collects live processes, network state, basic persistence mechanisms, and event logs 
    using only native PowerShell and stores raw output in the 'results' directory.
#>
param()

# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges to collect all artifacts. Please run as an administrator."
}

$RawDataPath = Join-Path -Path $PSScriptRoot -ChildPath "results"

# --- 1. Setup ---
Write-Host "--- Gather_Info.ps1: Starting constrained data collection ---"
if (-not (Test-Path $RawDataPath)) {
    New-Item -Path $RawDataPath -ItemType Directory | Out-Null
    Write-Host "Created results directory: $RawDataPath"
}

# --- 2. Collection Commands (Volatile & Persistent Artifacts) ---

# II. Persistent System Artifacts: Registry (Persistence & Execution Evidence)
Write-Host "Collecting Registry Run Keys (Persistence)..."
$RunKeyPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
$RunKeyData = foreach ($key in $RunKeyPaths) {
    if (Test-Path $key) {
        Get-ItemProperty -Path $key | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
    }
}
$RunKeyData | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "registry_run_keys.json") -Encoding UTF8

# I. Volatile Data: Running Processes (Execution Evidence)
Write-Host "Collecting Processes Snapshot (Execution)..."
# Captures Name, Path, Command Line, and Parent Process ID
Get-CimInstance -ClassName Win32_Process | 
    Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate | 
    ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "processes_snapshot.json") -Encoding UTF8

# I. Volatile Data: Network Connections (Network Evidence)
Write-Host "Collecting Network Connection State (Network)..."
# Captures active connections and their owning process
Get-NetTCPConnection | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | 
    ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "netstat_snapshot.json") -Encoding UTF8

# III. Credential and User Activity: Security Event Logs (Credential Access Evidence)
Write-Host "Collecting Security Event Logs (Logons)..."
# Focusing on Event ID 4624 (Successful Logon) and 4672 (Admin Logon)
# A full log dump is too large; constraining to recent, high-priority events.
try {
    Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4672)]]" -MaxEvents 500 | 
        Select-Object TimeCreated, Id, Message | 
        ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "security_logons.json") -Encoding UTF8
}
catch {
    Write-Warning "Could not collect security event logs. Error: $_"
    #Create empty security_logons.json file
    New-Item -Path (Join-Path $RawDataPath "security_logons.json") -ItemType File -Force | Out-Null
}

Write-Host "--- Gather_Info.ps1: Collection Complete ---"
