        Write-Error "Failed to establish remote session to ${ComputerName}: ${PSItem}"        exit 1
    }
}

# --- Winget and Software Installation Check ---
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

    Write-Host "Checking for $FriendlyName..."
    try {
        $installed = winget list --id $PackageId --exact -q
        if ($installed) {
            Write-Host "$FriendlyName is already installed."
        } else {
            Write-Host "Installing $FriendlyName..."
            winget install --id $PackageId --exact --accept-package-agreements --accept-source-agreements -q
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$FriendlyName installed successfully."
            } else {
                Write-Warning "Failed to install $FriendlyName. Winget exit code: $LASTEXITCODE"
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
    Install-Software -PackageId "Malwarebytes.Malwarebytes" -FriendlyName "Malwarebytes" # Assuming a winget package ID
} else {
    Write-Warning "Skipping software installation as Winget is not available."
}

$RawDataPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results"

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
    Write-Host "Attempting to establish remote session to $ComputerName..."
    try {
        if ($Credential) {
            $session = New-PSSession -ComputerName $ComputerName -Credential $Credential
        } else {
            $session = New-PSSession -ComputerName $ComputerName
        }
        Write-Host "Remote session established successfully."
    } catch {
        Write-Error "Failed to establish remote session to $ComputerName: ${PSItem}"
        exit 1
    }
}

# --- Winget and Software Installation Check ---
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

    Write-Host "Checking for $FriendlyName..."
    try {
        $installed = winget list --id $PackageId --exact -q
        if ($installed) {
            Write-Host "$FriendlyName is already installed."
        } else {
            Write-Host "Installing $FriendlyName..."
            winget install --id $PackageId --exact --accept-package-agreements --accept-source-agreements -q
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$FriendlyName installed successfully."
            } else {
                Write-Warning "Failed to install $FriendlyName. Winget exit code: $LASTEXITCODE"
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
    Install-Software -PackageId "Malwarebytes.Malwarebytes" -FriendlyName "Malwarebytes" # Assuming a winget package ID
} else {
    Write-Warning "Skipping software installation as Winget is not available."
}

$RawDataPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results"

if ($session) {
    # Remote Execution
    Write-Host "--- Gather_Info.ps1: Starting remote data collection on $ComputerName ---"
    Invoke-Command -Session $session -ScriptBlock {
        param($RemoteRawDataPath)

        # Ensure results directory exists on remote machine
        if (-not (Test-Path $RemoteRawDataPath)) {
            New-Item -Path $RemoteRawDataPath -ItemType Directory | Out-Null
            Write-Host "Created remote results directory: $RemoteRawDataPath"
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
        Write-Host "Collecting Network Connection State (Network) on remote machine..."
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
        if ($ClamAVPath) {
            $ClamAVLogPath = Join-Path -Path $RemoteRawDataPath -ChildPath "clamav_scan_results.txt"
            try {
                & "$ClamAVPath" -r "C:\" | Out-File $ClamAVLogPath -Encoding UTF8
                Write-Host "ClamAV scan complete on remote machine. Results saved to $ClamAVLogPath"
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
            # Start-MpScan is a cmdlet from the Defender module
            # It might not output directly to stdout, so we'll capture its object output and format it.
            $scanResult = Start-MpScan -ScanType FullScan -ErrorAction Stop
            $scanResult | Out-File $DefenderLogPath -Encoding UTF8
            Write-Host "Windows Defender scan complete on remote machine. Results saved to $DefenderLogPath"
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
    if (-not (Test-Path $RawDataPath)) {
        New-Item -Path $RawDataPath -ItemType Directory | Out-Null
        Write-Host "Created results directory: $RawDataPath"
    }

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
    if ($ClamAVPath) {
        $ClamAVLogPath = Join-Path -Path $RawDataPath -ChildPath "clamav_scan_results.txt"
        try {
            & "$ClamAVPath" -r "C:\" | Out-File $ClamAVLogPath -Encoding UTF8
            Write-Host "ClamAV scan complete. Results saved to $ClamAVLogPath"
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
        # Start-MpScan is a cmdlet from the Defender module
        # It might not output directly to stdout, so we'll capture its object output and format it.
        $scanResult = Start-MpScan -ScanType FullScan -ErrorAction Stop
        $scanResult | Out-File $DefenderLogPath -Encoding UTF8
        Write-Host "Windows Defender scan complete. Results saved to $DefenderLogPath"
    } catch {
        Write-Warning "Windows Defender scan failed: ${PSItem}"
        "Windows Defender scan failed: ${PSItem}" | Out-File $DefenderLogPath -Encoding UTF8
    }

    Write-Host "--- Gather_Info.ps1: Local Collection Complete ---"
}

Write-Host "--- Gather_Info.ps1: Collection Complete ---"

# Launch Gemini CLI with system prompt
$SystemPromptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "system_prompt.txt"
Write-Host "Launching Gemini CLI with system prompt: $SystemPromptPath"
Start-Process -FilePath "npx" -ArgumentList "gemini", "-p", "$SystemPromptPath" -NoNewWindow -Wait
