<#
.SYNOPSIS
    Parses raw data into the structured Info_Results.txt file for the Triage Agent.
.DESCRIPTION
    Reads JSON files from results, applies LLM-defined Triage logic/filters (Persistence, 
    Execution, Network, Credential Access), and writes the final JSON structure.
.OUTPUTS
    results/Info_Results.txt (Structured JSON).
#>
param()

$RawDataPath = Join-Path -Path $PSScriptRoot -ChildPath "results"
$OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "results\Info_Results.txt"

Write-Host "--- Parse_Results.ps1: Starting deterministic parsing ---"

# --- 1. Load Raw Data ---
$RunKeys = Get-Content (Join-Path $RawDataPath "registry_run_keys.json") | ConvertFrom-Json
$Processes = Get-Content (Join-Path $RawDataPath "processes_snapshot.json") | ConvertFrom-Json
$Netstat = Get-Content (Join-Path $RawDataPath "netstat_snapshot.json") | ConvertFrom-Json
$SecurityLogons = Get-Content (Join-Path $RawDataPath "security_logons.json") | ConvertFrom-Json

# --- 2. Triage Logic (The LLM Scoring Input/Task Mapping) ---

# Persistence Task: "Are there any non-standard entries in these keys?"
$PersistenceFindings = $RunKeys | 
    Where-Object {
        # Filter for non-standard paths (i.e., not System32, Program Files, or common system paths)
        $_.PSObject.Properties | 
        Where-Object {$_.Name -ne 'PSParentPath' -and $_.Value -notmatch "C:\\(?:Windows|Program Files|Program Files \(x86\))" }
    } | 
    Select-Object Path, Name, Value

# Execution Task: "Identify all processes executed from $user_profiles or C:\Temp."
$ExecutionFindings = $Processes | 
    Where-Object { 
        $_.ExecutablePath -like "*\Users\*\*" -or $_.ExecutablePath -like "*\AppData\Local\Temp\*" 
    } | 
    Select-Object Name, ExecutablePath, CommandLine

# Network Task: "Are there connections to any IPs with ports 80/443 that are NOT common services?"
$SuspiciousPorts = @(80, 443, 8080, 4444)
$SuspiciousConnections = $Netstat |
    Where-Object {
        # Filter: Established connections on suspicious ports, excluding common internal/loopback
        $SuspiciousPorts -contains $_.RemotePort -and 
        $_.State -eq "Established" -and
        $_.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))"
    } |
    Select-Object RemoteAddress, RemotePort, OwningProcess

# Credential Access Task: "Was a logon event for the temporary admin account immediately followed by a Service logon (type 5)?"
# This requires a more complex chronological check. For initial Triage, we look for *any* Type 5 logons near Type 4672 events.
$AdminEvents = $SecurityLogons | Where-Object {$_.Id -eq 4672} # Admin logon
$ServiceLogons = $SecurityLogons | Where-Object {$_.Message -like "*Logon Type: 5*"} # Service logon

$CredentialAccessFinding = $False
if ($AdminEvents.Count -gt 0 -and $ServiceLogons.Count -gt 0) {
    # If both exist, a YES/NO finding can be triggered for the LLM. 
    # A true check for "immediately followed" is deferred to a human/next stage, but the indicator is flagged.
    $CredentialAccessFinding = $True
}

# --- 3. Output Structured JSON (`Info_Results.txt`) ---
$InfoResults = @{
    "analysis_timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "Triage_Indicators" = @{
        "Persistence" = @{
            "non_standard_run_keys_found" = $PersistenceFindings.Count -gt 0
            "details" = $PersistenceFindings
        }
        "Execution" = @{
            "user_or_temp_process_found" = $ExecutionFindings.Count -gt 0
            "details" = $ExecutionFindings
        }
        "Network" = @{
            "suspicious_external_connections_found" = $SuspiciousConnections.Count -gt 0
            "details" = $SuspiciousConnections
        }
        "Credential_Access" = @{
            "admin_logon_near_service_logon" = $CredentialAccessFinding
            "details" = $CredentialAccessFinding
        }
    }
}

$InfoResults | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8

Write-Host "--- Parse_Results.ps1: Structured output written to results/Info_Results.txt ---"
