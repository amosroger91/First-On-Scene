<#
.SYNOPSIS
    Gathers essential volatile and persistent system artifacts for Triage Agent analysis.
.DESCRIPTION
    Collects live processes, network state, basic persistence mechanisms, and event logs
    using only native PowerShell and stores raw output in the 'results' directory.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges to collect all artifacts. Please run as an administrator."
}

# --- Remote Session Setup ---
$session = $null
if ($ComputerName -ne "localhost") {
    Write-Host "Attempting to establish remote session to ${ComputerName}..."
    try {
        if ($Credential) {
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
        } else {
            $session = New-PSSession -ComputerName $ComputerName
        }
        Write-Host "Remote session established successfully."
    } catch {
        Write-Error "Failed to establish remote session to ${ComputerName}: ${PSItem}"
        exit 1
    }
}

# --- Winget and Software Installation Check (Always run locally) ---
function Test-WingetInstallation {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "Winget is not installed or not in PATH. Please install Winget from the Microsoft Store or https://github.com/microsoft/winget-cli/releases"
        return $false
    }
    return $true
}

function Install-Software {
    param(
        [Parameter(Mandatory=$true)]
        [string]$PackageId,
        [Parameter(Mandatory=$true)]
        [string]$FriendlyName
    )

    Write-Host "Checking for ${FriendlyName}..."
    try {
        $installed = winget list --id $PackageId --exact -q
        if ($installed) {
            Write-Host "${FriendlyName} is already installed."
        } else {
            Write-Host "Installing ${FriendlyName}..."
            winget install --id $PackageId --exact --accept-package-agreements --accept-source-agreements -q
            if ($LASTEXITCODE -eq 0) {
                Write-Host "${FriendlyName} installed successfully."
            } else {
                Write-Warning "Failed to install ${FriendlyName}. Winget exit code: ${LASTEXITCODE}"
            }
        }
    } catch {
        Write-Warning "Error checking/installing ${FriendlyName}: ${PSItem}"
    }
}

if (Test-WingetInstallation) {
    Write-Host "Winget is installed. Checking for required software..."
    Install-Software -PackageId "Git.Git" -FriendlyName "Git"
    Install-Software -PackageId "OpenJS.NodeJS" -FriendlyName "Node.js" # This should include npm
    Install-Software -PackageId "ClamAV.ClamAV" -FriendlyName "ClamAV" # Assuming a winget package ID
    # Malwarebytes is skipped as it requires a business version for command-line scanning
} else {
    Write-Warning "Skipping software installation as Winget is not available."
}

$RawDataPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results"

# --- 1. Setup ---
if (-not (Test-Path $RawDataPath)) {
    New-Item -Path $RawDataPath -ItemType Directory | Out-Null
    Write-Host "Created results directory: $RawDataPath"
}

if ($session) {
    # Remote Execution
    Write-Host "--- Gather_Info.ps1: Starting remote data collection on ${ComputerName} ---"
    Invoke-Command -Session $session -ScriptBlock {
        param($RemoteRawDataPath)

        # Ensure results directory exists on remote machine
        if (-not (Test-Path $RemoteRawDataPath)) {
            New-Item -Path $RemoteRawDataPath -ItemType Directory | Out-Null
            Write-Host "Created remote results directory: ${RemoteRawDataPath}"
        }

        # II. Persistent System Artifacts: Registry (Persistence & Execution Evidence)
        Write-Host "Collecting Registry Run Keys (Persistence) on remote machine..."
        $RunKeyPaths = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        $RunKeyData = foreach ($key in $RunKeyPaths) {
            if (Test-Path $key) {
                Get-ItemProperty -Path $key | Select-Object -Property * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider
            }
        }
        $RunKeyData | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "registry_run_keys.json") -Encoding UTF8

        # I. Volatile Data: Running Processes (Execution Evidence)
        Write-Host "Collecting Processes Snapshot (Execution) on remote machine..."
        Get-CimInstance -ClassName Win32_Process |
            Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "processes_snapshot.json") -Encoding UTF8

        # I. Volatile Data: Network Connections (Network Evidence)
        Write-Host "Collecting Network Connection State (Network)..."
        Get-NetTCPConnection |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "netstat_snapshot.json") -Encoding UTF8

        # III. Credential and User Activity: Security Event Logs (Credential Access Evidence)
        Write-Host "Collecting Security Event Logs (Logons) on remote machine..."
        try {
            Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4672)]]" -MaxEvents 500 |
                Select-Object TimeCreated, Id, Message |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "security_logons.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect security event logs on remote machine. Error: ${PSItem}"
            New-Item -Path (Join-Path $RemoteRawDataPath "security_logons.json") -ItemType File -Force | Out-Null
        }

        # --- 3. Antivirus Scans ---

        # ClamAV Scan
        Write-Host "Starting ClamAV scan on remote machine..."
        $ClamAVPath = (Get-Command clamscan.exe -ErrorAction SilentlyContinue).Path
        if (-not $ClamAVPath) {
            # Try common installation paths if not found in PATH
            $ClamAVCommonPaths = @(
                "C:\Program Files\ClamAV\clamscan.exe",
                "C:\Program Files (x86)\ClamAV\clamscan.exe"
            )
            foreach ($path in $ClamAVCommonPaths) {
                if (Test-Path $path) {
                    $ClamAVPath = $path
                    break
                }
            }
        }
        if ($ClamAVPath) {
            $ClamAVLogPath = Join-Path -Path $RemoteRawDataPath -ChildPath "clamav_scan_results.txt"
            try {
                & "${ClamAVPath}" -r "C:\" | Out-File $ClamAVLogPath -Encoding UTF8
                Write-Host "ClamAV scan complete on remote machine. Results saved to ${ClamAVLogPath}"
            } catch {
                Write-Warning "ClamAV scan failed on remote machine: ${PSItem}"
            }
        } else {
            Write-Warning "ClamAV (clamscan.exe) not found on remote machine. Skipping scan."
        }

        # Windows Defender Scan
        Write-Host "Starting Windows Defender Full Scan on remote machine..."
        $DefenderLogPath = Join-Path -Path $RemoteRawDataPath -ChildPath "defender_scan_results.txt"
        try {
            # Explicitly import the Defender module
            Import-Module -Name Defender -ErrorAction SilentlyContinue

            if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
                # Check if Windows Defender Service is running
                $DefenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                if ($DefenderService -and $DefenderService.Status -eq "Running") {
                    Write-Host "Initiating Windows Defender scan as a background job on remote machine..."
                    $scanJob = Start-MpScan -ScanType FullScan -AsJob -ErrorAction Stop
                    
                    # Monitor job status in a loop to get updates
                    $timeout = 3600 # 1 hour timeout
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    do {
                        Start-Sleep -Seconds 10
                        $job = Get-Job -Id $scanJob.Id
                        Write-Progress -Activity "Windows Defender Scan" -Status "Progress: $($job.State)" -SecondsRemaining ($timeout - $sw.Elapsed.TotalSeconds)
                    } while ($job.State -eq "Running" -and $sw.Elapsed.TotalSeconds -lt $timeout)
                    $sw.Stop()

                    if ($job.State -eq "Running") {
                        Write-Warning "Windows Defender scan job timed out after $($timeout / 60) minutes on remote machine."
                        Stop-Job -Job $scanJob -Force -ErrorAction SilentlyContinue
                    }

                    $scanResult = Receive-Job -Job $scanJob -Keep
                    Remove-Job -Job $scanJob

                    if ($scanResult) {
                        $scanResult | Out-File $DefenderLogPath -Encoding UTF8
                        Write-Host "Windows Defender scan complete on remote machine. Results saved to ${DefenderLogPath}"
                    } else {
                        Write-Warning "Windows Defender scan completed but returned no results on remote machine. Check logs for details."
                        "Windows Defender scan completed but returned no results on remote machine." | Out-File $DefenderLogPath -Encoding UTF8
                    }

                    if ($job.State -eq "Failed") {
                        Write-Warning "Windows Defender scan job failed on remote machine. Error details: $($job.ChildJobs[0].Host.UI.RawUI.GetBufferContents())"
                        "Windows Defender scan job failed on remote machine. Error details: $($job.ChildJobs[0].JobStateInfo.Reason)" | Out-File $DefenderLogPath -Append -Encoding UTF8
                    }
                } else {
                    Write-Warning "Windows Defender Service ('WinDefend') is not running on remote machine. Skipping scan."
                    "Windows Defender Service ('WinDefend') is not running on remote machine. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
                }
            } else {
                Write-Warning "Start-MpScan cmdlet not found on remote machine. Ensure Windows Defender is enabled and the Defender module is available. Skipping scan."
                "Start-MpScan cmdlet not found on remote machine. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
            }
        } catch {
            Write-Warning "Windows Defender scan failed on remote machine: ${PSItem}"
            "Windows Defender scan failed on remote machine: ${PSItem}" | Out-File $DefenderLogPath -Encoding UTF8
        }

        Write-Host "--- Gather_Info.ps1: Remote Collection Complete ---"

    } -ArgumentList @{RemoteRawDataPath = $RawDataPath}

    # Copy results back from remote machine
    Write-Host "Copying results from remote machine to local results folder..."
    try {
        Copy-Item -Path (Join-Path $RawDataPath "*") -Destination $RawDataPath -FromSession $session -Recurse -Force
        Write-Host "Results copied successfully."
    } catch {
        Write-Error "Failed to copy results from remote machine: ${PSItem}"
        Remove-PSSession -Session $session
        exit 1
    }

    Remove-PSSession -Session $session
    Write-Host "Remote session disconnected."

} else {
    # Local Execution
    Write-Host "--- Gather_Info.ps1: Starting local data collection ---"

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
    Get-CimInstance -ClassName Win32_Process |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate |
        ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "processes_snapshot.json") -Encoding UTF8

    # I. Volatile Data: Network Connections (Network Evidence)
    Write-Host "Collecting Network Connection State (Network)..."
    Get-NetTCPConnection |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "netstat_snapshot.json") -Encoding UTF8

    # III. Credential and User Activity: Security Event Logs (Credential Access Evidence)
    Write-Host "Collecting Security Event Logs (Logons)..."
    try {
        Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4672)]]" -MaxEvents 500 |
            Select-Object TimeCreated, Id, Message |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "security_logons.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect security event logs. Error: ${PSItem}"
        New-Item -Path (Join-Path $RawDataPath "security_logons.json") -ItemType File -Force | Out-Null
    }

    # --- 3. Antivirus Scans ---

    # ClamAV Scan
    Write-Host "Starting ClamAV scan..."
    $ClamAVPath = (Get-Command clamscan.exe -ErrorAction SilentlyContinue).Path
    if (-not $ClamAVPath) {
        # Try common installation paths if not found in PATH
        $ClamAVCommonPaths = @(
            "C:\Program Files\ClamAV\clamscan.exe",
            "C:\Program Files (x86)\ClamAV\clamscan.exe"
        )
        foreach ($path in $ClamAVCommonPaths) {
            if (Test-Path $path) {
                $ClamAVPath = $path
                break
            }
        }
    }
    if ($ClamAVPath) {
        $ClamAVLogPath = Join-Path -Path $RawDataPath -ChildPath "clamav_scan_results.txt"
        try {
            & "${ClamAVPath}" -r "C:\" | Out-File $ClamAVLogPath -Encoding UTF8
            Write-Host "ClamAV scan complete. Results saved to ${ClamAVLogPath}"
        } catch {
            Write-Warning "ClamAV scan failed: ${PSItem}"
        }
    } else {
        Write-Warning "ClamAV (clamscan.exe) not found. Skipping scan."
    }

    # Windows Defender Scan
    Write-Host "Starting Windows Defender Full Scan..."
    $DefenderLogPath = Join-Path -Path $RawDataPath -ChildPath "defender_scan_results.txt"
    try {
        # Explicitly import the Defender module
        Import-Module -Name Defender -ErrorAction SilentlyContinue

        if (Get-Command Start-MpScan -ErrorAction SilentlyContinue) {
            # Check if Windows Defender Service is running
            $DefenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
            if ($DefenderService -and $DefenderService.Status -eq "Running") {
                Write-Host "Initiating Windows Defender scan as a background job..."
                $scanJob = Start-MpScan -ScanType FullScan -AsJob -ErrorAction Stop
                
                # Monitor job status in a loop to get updates
                $timeout = 3600 # 1 hour timeout
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                do {
                    Start-Sleep -Seconds 10
                    $job = Get-Job -Id $scanJob.Id
                    Write-Progress -Activity "Windows Defender Scan" -Status "Progress: $($job.State)" -SecondsRemaining ($timeout - $sw.Elapsed.TotalSeconds)
                } while ($job.State -eq "Running" -and $sw.Elapsed.TotalSeconds -lt $timeout)
                $sw.Stop()

                if ($job.State -eq "Running") {
                    Write-Warning "Windows Defender scan job timed out after $($timeout / 60) minutes."
                    Stop-Job -Job $scanJob -Force -ErrorAction SilentlyContinue
                }

                $scanResult = Receive-Job -Job $scanJob -Keep
                Remove-Job -Job $scanJob

                if ($scanResult) {
                    $scanResult | Out-File $DefenderLogPath -Encoding UTF8
                    Write-Host "Windows Defender scan complete. Results saved to ${DefenderLogPath}"
                } else {
                    Write-Warning "Windows Defender scan completed but returned no results. Check logs for details."
                    "Windows Defender scan completed but returned no results." | Out-File $DefenderLogPath -Encoding UTF8
                }

                if ($job.State -eq "Failed") {
                    Write-Warning "Windows Defender scan job failed. Error details: $($job.ChildJobs[0].Host.UI.RawUI.GetBufferContents())"
                    "Windows Defender scan job failed. Error details: $($job.ChildJobs[0].JobStateInfo.Reason)" | Out-File $DefenderLogPath -Append -Encoding UTF8
                }
            } else {
                Write-Warning "Windows Defender Service ('WinDefend') is not running. Skipping scan."
                "Windows Defender Service ('WinDefend') is not running. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
            }
        } else {
            Write-Warning "Start-MpScan cmdlet not found. Ensure Windows Defender is enabled and the Defender module is available. Skipping scan."
            "Start-MpScan cmdlet not found. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
        }
    } catch {
        Write-Warning "Windows Defender scan failed: ${PSItem}"
        "Windows Defender scan failed: ${PSItem}" | Out-File $DefenderLogPath -Encoding UTF8
    }

    Write-Host "--- Gather_Info.ps1: Local Collection Complete ---"
}

Write-Host "--- Gather_Info.ps1: Collection Complete ---"

# --- 4. Automatically Parse Results ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Parsing Collected Data" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ParseScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Parse_Results.ps1"
try {
    & $ParseScriptPath
    Write-Host "Data parsing completed successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to parse results: $_"
    Write-Host "Continuing to AI analysis with raw data..." -ForegroundColor Yellow
}

# --- 5. Launch Qwen CLI with OpenRouter ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Launching AI Triage Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Get or prompt for API token
$TokenScriptPath = Join-Path -Path $PSScriptRoot -ChildPath "Manage_API_Token.ps1"
Write-Host "Checking for OpenRouter API token..."

$apiToken = & $TokenScriptPath -Action "Prompt"

if ([string]::IsNullOrWhiteSpace($apiToken)) {
    Write-Error "No API token available. Cannot proceed with AI analysis."
    Write-Host "Please obtain an API token from https://openrouter.ai/keys and run this script again." -ForegroundColor Yellow
    exit 1
}

# Set environment variables for qwen CLI with OpenRouter
$env:OPENROUTER_API_KEY = $apiToken
# Note: qwen CLI may use different env var names, adjust as needed based on actual CLI behavior

# Prepare system prompt
$SystemPromptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "system_prompt.txt"
Write-Host "System prompt loaded: $SystemPromptPath"

# OpenRouter model - Using Qwen3 Coder 480B A35B (free tier)
# Alternative free models: qwen/qwen-2.5-72b-instruct:free, qwen/qwen-2.5-coder-32b-instruct:free
$OpenRouterModel = "qwen/qwen3-coder:free"
Write-Host "Model: $OpenRouterModel (via OpenRouter)" -ForegroundColor Cyan
Write-Host ""

# Configure qwen CLI settings for OpenRouter
Write-Host "Configuring qwen CLI for OpenRouter..." -ForegroundColor Cyan
$qwenConfigDir = Join-Path $env:USERPROFILE ".qwen"
$qwenSettingsPath = Join-Path $qwenConfigDir "settings.json"

# Create .qwen directory if it doesn't exist
if (-(Test-Path $qwenConfigDir)) {
    New-Item -ItemType Directory -Path $qwenConfigDir -Force | Out-Null
}

# Create/Update settings.json for OpenRouter
$qwenSettings = @{
    ideMode = $true
    selectedAuthType = "openai"
    apiConfiguration = @{
        apiKey = $apiToken
        baseURL = "https://openrouter.ai/api/v1"
        modelId = $OpenRouterModel
    }
    hasSeenIdeIntegrationNudge = $true
}

# Use UTF8NoBOM to avoid BOM characters that break JSON parsing
$jsonContent = $qwenSettings | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($qwenSettingsPath, $jsonContent, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Qwen CLI configured successfully." -ForegroundColor Green
Write-Host ""

# Launch Qwen CLI with OpenRouter configuration
# qwen CLI supports OpenAI-compatible endpoints via --openai-base-url
# Using -p with file path to avoid command-line parsing issues
# Using --yolo mode to automatically approve all tool executions for full automation
Write-Host "Launching Qwen CLI in automated triage mode..." -ForegroundColor Cyan
Write-Host "The AI will now analyze the collected data and make a final determination." -ForegroundColor Yellow
Write-Host ""

try {
    # Change to repository root for qwen CLI execution
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    Set-Location $repoRoot

    Write-Host "Executing qwen CLI..." -ForegroundColor Gray
    Write-Host ""

    # Read system prompt
    $SystemPromptContent = Get-Content $SystemPromptPath -Raw

    # Create a temporary file with the system prompt to avoid command-line parsing issues
    $tempPromptFile = Join-Path $env:TEMP "fos_system_prompt.txt"
    $SystemPromptContent | Out-File -FilePath $tempPromptFile -Encoding UTF8 -NoNewline

    # Since qwen settings are now configured, we can simply run qwen CLI
    # It will use the settings from ~/.qwen/settings.json
    $command = "type `"$tempPromptFile`" | npx --yes @qwen-code/qwen-code --yolo -p `"`""

    Write-Host "Command: $command" -ForegroundColor Gray
    Write-Host ""

    # Execute via cmd for proper pipe handling
    cmd /c $command

    # Clean up temp file
    if (Test-Path $tempPromptFile) {
        Remove-Item $tempPromptFile -Force
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Triage Analysis Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Check the results directory for the final analysis:" -ForegroundColor Cyan
    Write-Host "  - results/findings.txt (AI analysis report)"
    Write-Host "  - results/Steps_Taken.txt (audit log)"
    Write-Host ""
}
catch {
    Write-Error "Failed to launch Qwen CLI: $_"
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}