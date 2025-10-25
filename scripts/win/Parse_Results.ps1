<#
.SYNOPSIS
    Parses raw data into the structured Info_Results.txt file for the Triage Agent.
.DESCRIPTION
    Reads JSON files from results, applies comprehensive Triage logic/filters (Persistence,
    Execution, Network, Credential Access, PowerShell Activity, Browser Activity), and
    writes the final JSON structure.
.OUTPUTS
    results/Info_Results.txt (Structured JSON).
#>
param()

$RootDirectory = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$RawDataPath = Join-Path -Path $RootDirectory -ChildPath "results"
$OutputPath = Join-Path -Path $RootDirectory -ChildPath "results\Info_Results.txt"

Write-Host "--- Parse_Results.ps1: Starting deterministic parsing ---"

# --- 1. Load Raw Data ---
Write-Host "Loading artifact files..."

# Core artifacts
$RunKeys = Get-Content (Join-Path $RawDataPath "registry_run_keys.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$Processes = Get-Content (Join-Path $RawDataPath "processes_snapshot.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$Netstat = Get-Content (Join-Path $RawDataPath "netstat_snapshot.json") -ErrorAction SilentlyContinue | ConvertFrom-Json

# Extended persistence artifacts
$ScheduledTasks = Get-Content (Join-Path $RawDataPath "scheduled_tasks.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$Services = Get-Content (Join-Path $RawDataPath "services_config.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$WMIPersistence = Get-Content (Join-Path $RawDataPath "wmi_persistence.json") -ErrorAction SilentlyContinue | ConvertFrom-Json

# Event logs
$SecurityEvents = Get-Content (Join-Path $RawDataPath "security_events.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$PowerShellLogs = Get-Content (Join-Path $RawDataPath "powershell_logs.json") -ErrorAction SilentlyContinue | ConvertFrom-Json

# File system artifacts
$FileMetadata = Get-Content (Join-Path $RawDataPath "file_metadata.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
$BrowserArtifacts = Get-Content (Join-Path $RawDataPath "browser_artifacts.json") -ErrorAction SilentlyContinue | ConvertFrom-Json

# Antivirus scan results
$DefenderScan = Get-Content (Join-Path $RawDataPath "defender_scan_results.txt") -Raw -ErrorAction SilentlyContinue
$ClamAVScan = Get-Content (Join-Path $RawDataPath "clamav_scan_results.txt") -Raw -ErrorAction SilentlyContinue
$RkillLog = Get-Content (Join-Path $RawDataPath "rkill_execution.log") -Raw -ErrorAction SilentlyContinue

# --- 2. Triage Logic (Comprehensive Threat Detection) ---
Write-Host "Applying triage logic..."

## PERSISTENCE MECHANISMS ##

# Registry Run Keys: Non-standard paths
$RunKeyFindings = $RunKeys |
    Where-Object {
        $_.PSObject.Properties |
        Where-Object {$_.Name -notmatch '^PS' -and $_.Value -notmatch "C:\\(?:Windows|Program Files|Program Files \(x86\))" }
    } |
    Select-Object -First 50 # Limit output

# Scheduled Tasks: Non-system paths or suspicious names
$SuspiciousTasks = $ScheduledTasks |
    Where-Object {
        ($_.Actions -like "*\Users\*" -or $_.Actions -like "*\Temp\*" -or
         $_.Actions -like "*\AppData\*" -or $_.TaskName -match "(update|install|check)" -and
         $_.Author -notmatch "Microsoft")
    } |
    Select-Object TaskName, Actions, Author, State, Enabled -First 50

# Services: Auto-start from non-standard paths
$SuspiciousServices = $Services |
    Where-Object {
        $_.StartMode -eq "Auto" -and
        $_.PathName -notmatch "C:\\(?:Windows|Program Files)" -and
        $_.PathName -match "\\.exe"
    } |
    Select-Object Name, PathName, StartMode, State -First 50

# WMI Event Subscriptions: Any non-standard subscriptions are suspicious
$WMIEventCount = 0
if ($WMIPersistence) {
    $WMIEventCount = ($WMIPersistence.EventFilters.Count +
                      $WMIPersistence.EventConsumers.Count +
                      $WMIPersistence.FilterBindings.Count)
}

## EXECUTION EVIDENCE ##

# Processes: Executed from user profiles or temp directories
$SuspiciousProcesses = $Processes |
    Where-Object {
        $_.ExecutablePath -like "*\Users\*" -or
        $_.ExecutablePath -like "*\AppData\Local\Temp\*" -or
        $_.ExecutablePath -like "*\Temp\*"
    } |
    Select-Object Name, ExecutablePath, CommandLine, ProcessId -First 50

# Process Creation Events (4688): Look for suspicious parent-child relationships
$ProcessCreationEvents = $SecurityEvents |
    Where-Object {
        $_.Id -eq 4688 -and
        ($_.Message -like "*powershell*" -or $_.Message -like "*cmd.exe*" -or
         $_.Message -like "*wscript*" -or $_.Message -like "*cscript*")
    } |
    Select-Object TimeCreated, ProcessName, ProcessCommandLine -First 50

## NETWORK ACTIVITY ##

# Suspicious external connections
$SuspiciousPorts = @(80, 443, 8080, 4444, 5555, 8443, 3389)
$SuspiciousConnections = $Netstat |
    Where-Object {
        $SuspiciousPorts -contains $_.RemotePort -and
        $_.State -eq "Established" -and
        $_.RemoteAddress -notmatch "^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))"
    } |
    Select-Object RemoteAddress, RemotePort, OwningProcess, State -First 50

## CREDENTIAL ACCESS & USER ACTIVITY ##

# Service/User Creation Events
$ServiceInstalls = $SecurityEvents | Where-Object {$_.Id -eq 4697} | Select-Object TimeCreated, Message -First 20
$UserCreations = $SecurityEvents | Where-Object {$_.Id -eq 4720} | Select-Object TimeCreated, Message -First 20
$ObjectAccess = $SecurityEvents | Where-Object {$_.Id -eq 4663} | Select-Object TimeCreated, Message -First 20

# Admin/Service Logon Correlation
$AdminEvents = $SecurityEvents | Where-Object {$_.Id -eq 4672}
$ServiceLogons = $SecurityEvents | Where-Object {$_.Id -eq 4624 -and $_.Message -like "*Logon Type: 5*"}
$CredentialAccessFinding = ($AdminEvents.Count -gt 0 -and $ServiceLogons.Count -gt 0)

## POWERSHELL ACTIVITY ##

# PowerShell Logs: Detect obfuscation, base64, suspicious commands
$SuspiciousPowerShell = $PowerShellLogs |
    Where-Object {
        $_.Message -match "(base64|encodedcommand|invoke-expression|iex|downloadstring|" +
                          "webclient|invoke-webrequest|invoke-restmethod|bitstransfer|" +
                          "reflection\.assembly|system\.net|hidden|bypass|noprofile)"
    } |
    Select-Object TimeCreated, Id, Message -First 50

## FILE SYSTEM ARTIFACTS ##

# MACE Timestamp Analysis: Look for timestomping indicators
$SuspiciousTimestamps = $FileMetadata |
    Where-Object {
        # Files where creation time is AFTER last write time (timestomping indicator)
        try {
            $created = [DateTime]::Parse($_.CreationTime)
            $modified = [DateTime]::Parse($_.LastWriteTime)
            $created -gt $modified
        } catch { $false }
    } |
    Select-Object FilePath, CreationTime, LastWriteTime, Length -First 30

## ANTIVIRUS SCAN RESULTS ##

# Windows Defender: Parse for threats
$DefenderThreats = @()
if ($DefenderScan) {
    if ($DefenderScan -match "(?ms)ThreatStatusID\s*:\s*(\d+)" -or
        $DefenderScan -match "(?ms)Threat\s+detected" -or
        $DefenderScan -match "(?ms)(\d+)\s+threat[s]?\s+detected") {
        $DefenderThreats += @{
            Scanner = "Windows Defender"
            Status = "Threats Detected"
            Details = $DefenderScan.Substring(0, [Math]::Min(500, $DefenderScan.Length))
        }
    }
}

# ClamAV: Parse for infected files
$ClamAVThreats = @()
if ($ClamAVScan) {
    # ClamAV reports infected files as "file: FOUND"
    $infectedMatches = [regex]::Matches($ClamAVScan, "(?m)^(.+?):\s+(.+?)\s+FOUND\s*$")
    foreach ($match in $infectedMatches) {
        $ClamAVThreats += @{
            FilePath = $match.Groups[1].Value.Trim()
            ThreatName = $match.Groups[2].Value.Trim()
        }
    }

    # Also check summary line
    if ($ClamAVScan -match "Infected files:\s+(\d+)") {
        $infectedCount = [int]$matches[1]
        if ($infectedCount -gt 0 -and $ClamAVThreats.Count -eq 0) {
            # Summary indicates threats but we didn't parse them - include raw excerpt
            $ClamAVThreats += @{
                Scanner = "ClamAV"
                Status = "Threats Detected ($infectedCount)"
                Details = $ClamAVScan.Substring([Math]::Max(0, $ClamAVScan.Length - 500))
            }
        }
    }
}

# Rkill: Parse for terminated processes
$RkillTerminations = @()
if ($RkillLog) {
    $terminationMatches = [regex]::Matches($RkillLog, "(?m)^Terminated process:\s+(.+)$")
    foreach ($match in $terminationMatches) {
        $RkillTerminations += $match.Groups[1].Value.Trim()
    }
}

## BROWSER ACTIVITY ANALYSIS ##

# Browser artifacts collected but full analysis requires SQLite parsing
# For now, just flag that browser history was collected
$BrowserHistoryCollected = if ($BrowserArtifacts -and $BrowserArtifacts.Count -gt 0) { $true } else { $false }

# --- 3. Output Structured JSON (`Info_Results.txt`) ---
Write-Host "Generating structured output..."

# Calculate counts (PowerShell hashtables can't have if statements as direct values)
$RunKeyCount = if ($RunKeyFindings) { @($RunKeyFindings).Count } else { 0 }
$TasksCount = if ($SuspiciousTasks) { @($SuspiciousTasks).Count } else { 0 }
$ServicesCount = if ($SuspiciousServices) { @($SuspiciousServices).Count } else { 0 }
$ProcessesCount = if ($SuspiciousProcesses) { @($SuspiciousProcesses).Count } else { 0 }
$ConnectionsCount = if ($SuspiciousConnections) { @($SuspiciousConnections).Count } else { 0 }
$PowerShellCount = if ($SuspiciousPowerShell) { @($SuspiciousPowerShell).Count } else { 0 }
$ServiceInstallsCount = if ($ServiceInstalls) { @($ServiceInstalls).Count } else { 0 }
$UserCreationsCount = if ($UserCreations) { @($UserCreations).Count } else { 0 }
$TimestampsCount = if ($SuspiciousTimestamps) { @($SuspiciousTimestamps).Count } else { 0 }
$ProcessCreationCount = if ($ProcessCreationEvents) { @($ProcessCreationEvents).Count } else { 0 }
$DefenderThreatsCount = if ($DefenderThreats) { @($DefenderThreats).Count } else { 0 }
$ClamAVThreatsCount = if ($ClamAVThreats) { @($ClamAVThreats).Count } else { 0 }
$RkillTerminationsCount = if ($RkillTerminations) { @($RkillTerminations).Count } else { 0 }

$InfoResults = @{
    "analysis_timestamp" = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "summary_counts" = @{
        "suspicious_run_keys" = $RunKeyCount
        "suspicious_scheduled_tasks" = $TasksCount
        "suspicious_services" = $ServicesCount
        "wmi_persistence_artifacts" = $WMIEventCount
        "suspicious_processes" = $ProcessesCount
        "suspicious_connections" = $ConnectionsCount
        "suspicious_powershell_events" = $PowerShellCount
        "service_installs" = $ServiceInstallsCount
        "user_creations" = $UserCreationsCount
        "suspicious_timestamps" = $TimestampsCount
        "defender_threats" = $DefenderThreatsCount
        "clamav_threats" = $ClamAVThreatsCount
        "rkill_terminations" = $RkillTerminationsCount
    }
    "Triage_Indicators" = @{
        "Persistence" = @{
            "registry_run_keys" = @{
                "found" = $RunKeyCount -gt 0
                "details" = $RunKeyFindings
            }
            "scheduled_tasks" = @{
                "found" = $TasksCount -gt 0
                "details" = $SuspiciousTasks
            }
            "services" = @{
                "found" = $ServicesCount -gt 0
                "details" = $SuspiciousServices
            }
            "wmi_subscriptions" = @{
                "found" = $WMIEventCount -gt 0
                "count" = $WMIEventCount
                "details" = $WMIPersistence
            }
        }
        "Execution" = @{
            "suspicious_processes" = @{
                "found" = $ProcessesCount -gt 0
                "details" = $SuspiciousProcesses
            }
            "process_creation_events" = @{
                "found" = $ProcessCreationCount -gt 0
                "details" = $ProcessCreationEvents
            }
        }
        "Network" = @{
            "suspicious_connections" = @{
                "found" = $ConnectionsCount -gt 0
                "details" = $SuspiciousConnections
            }
        }
        "Credential_Access" = @{
            "admin_service_logon_correlation" = $CredentialAccessFinding
            "service_installs" = @{
                "found" = $ServiceInstallsCount -gt 0
                "details" = $ServiceInstalls
            }
            "user_creations" = @{
                "found" = $UserCreationsCount -gt 0
                "details" = $UserCreations
            }
        }
        "PowerShell_Activity" = @{
            "suspicious_commands" = @{
                "found" = $PowerShellCount -gt 0
                "details" = $SuspiciousPowerShell
            }
        }
        "File_System" = @{
            "suspicious_timestamps" = @{
                "found" = $TimestampsCount -gt 0
                "details" = $SuspiciousTimestamps
            }
        }
        "Antivirus_Scans" = @{
            "windows_defender" = @{
                "threats_found" = $DefenderThreatsCount -gt 0
                "threat_count" = $DefenderThreatsCount
                "details" = $DefenderThreats
            }
            "clamav" = @{
                "threats_found" = $ClamAVThreatsCount -gt 0
                "threat_count" = $ClamAVThreatsCount
                "details" = $ClamAVThreats
            }
            "rkill" = @{
                "processes_terminated" = $RkillTerminationsCount -gt 0
                "termination_count" = $RkillTerminationsCount
                "terminated_processes" = $RkillTerminations
            }
        }
        "Browser_Activity" = @{
            "history_collected" = $BrowserHistoryCollected
            "artifact_count" = if ($BrowserArtifacts) { @($BrowserArtifacts).Count } else { 0 }
            "note" = "Browser history databases collected for manual analysis (requires SQLite parsing)"
        }
    }
}

$InfoResults | ConvertTo-Json -Depth 6 | Out-File $OutputPath -Encoding UTF8

Write-Host "--- Parse_Results.ps1: Structured output written to results/Info_Results.txt ---"
Write-Host "Summary:"
Write-Host "  - Suspicious Run Keys: $RunKeyCount"
Write-Host "  - Suspicious Scheduled Tasks: $TasksCount"
Write-Host "  - Suspicious Services: $ServicesCount"
Write-Host "  - WMI Persistence Artifacts: $WMIEventCount"
Write-Host "  - Suspicious Processes: $ProcessesCount"
Write-Host "  - Suspicious Network Connections: $ConnectionsCount"
Write-Host "  - Suspicious PowerShell Events: $PowerShellCount"
Write-Host "  - Windows Defender Threats: $DefenderThreatsCount" -ForegroundColor $(if ($DefenderThreatsCount -gt 0) { "Red" } else { "Green" })
Write-Host "  - ClamAV Threats: $ClamAVThreatsCount" -ForegroundColor $(if ($ClamAVThreatsCount -gt 0) { "Red" } else { "Green" })
Write-Host "  - Rkill Terminations: $RkillTerminationsCount" -ForegroundColor $(if ($RkillTerminationsCount -gt 0) { "Yellow" } else { "Green" })
