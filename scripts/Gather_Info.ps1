<#
.SYNOPSIS
    Gathers essential volatile and persistent system artifacts for Triage Agent analysis.
.DESCRIPTION
    Collects live processes, network state, basic persistence mechanisms, and event logs
    using only native PowerShell and stores raw output in the 'results' directory.
.PARAMETER ComputerName
    The name of the computer to collect data from. Default is "localhost" for local execution.
    For remote execution, provide the remote computer name (requires WinRM/PSRemoting enabled).
.PARAMETER Credential
    Optional credentials for remote execution. If not provided, current user credentials are used.
.PARAMETER CustomProblemScript
    Optional path to a custom PowerShell script that will be called instead of the default
    Problem_Detected.ps1 action. This script will receive the REASON_CODE as its first parameter.
.PARAMETER CustomAllClearScript
    Optional path to a custom PowerShell script that will be called instead of the default
    All_Clear.ps1 action.
.PARAMETER BrandName
    Optional custom brand name to use in reports instead of "First-On-Scene".
.PARAMETER LogoPath
    Optional path to a logo image file to include in generated reports.
.PARAMETER RunRkill
    Optional switch to execute rkill.exe for malware process termination.
    WARNING: Rkill modifies system state and will terminate processes, potentially destroying
    volatile evidence. Only use this flag if you are NOT concerned with forensic evidence integrity
    or if you have already collected volatile data (memory, network connections, processes).
    Default: $false (rkill will NOT run unless explicitly requested)
.PARAMETER EnableDefender
    Optional switch to enable Windows Defender if it is currently disabled.
    WARNING: Enabling Defender may alert advanced malware to your presence and could trigger
    anti-forensics behavior (evidence destruction, lateral movement, C2 alerting).
    Default: $false (Defender will only be used if already running)
.PARAMETER CaptureMemory
    Optional switch to capture a full memory dump using WinPmem.
    WARNING: Memory dumps are very large (typically RAM size, e.g., 8GB, 16GB, 32GB) and can take
    several minutes to capture. This will consume significant disk space. Only use this flag if you
    need full memory forensics for malware analysis, rootkit detection, or credential extraction.
    Default: $false (memory will NOT be captured unless explicitly requested)
.EXAMPLE
    .\Gather_Info.ps1
    Run local forensic collection with default settings (no rkill, no Defender enabling).
.EXAMPLE
    .\Gather_Info.ps1 -ComputerName "RemotePC" -Credential (Get-Credential)
    Run remote forensic collection on RemotePC with prompted credentials.
.EXAMPLE
    .\Gather_Info.ps1 -CustomProblemScript "C:\MyScripts\SendAlert.ps1" -BrandName "Acme Security"
    Run with custom action scripts and custom branding.
.EXAMPLE
    .\Gather_Info.ps1 -RunRkill -EnableDefender
    Run with rkill execution and Defender auto-enable (WARNING: modifies system state).
.EXAMPLE
    .\Gather_Info.ps1 -CaptureMemory
    Run with full memory capture for advanced forensics (WARNING: creates large dump file).
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [string]$CustomProblemScript,

    [Parameter(Mandatory=$false)]
    [string]$CustomAllClearScript,

    [Parameter(Mandatory=$false)]
    [string]$BrandName = "First-On-Scene",

    [Parameter(Mandatory=$false)]
    [string]$LogoPath,

    [Parameter(Mandatory=$false)]
    [switch]$RunRkill = $false,

    [Parameter(Mandatory=$false)]
    [switch]$EnableDefender = $false,

    [Parameter(Mandatory=$false)]
    [switch]$CaptureMemory = $false
)

# Check for administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires administrator privileges to collect all artifacts. Please run as an administrator."
}

# --- WinRM Corruption Detection and Fix ---
function Test-AndFixWinRM {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Host "Testing WinRM configuration on ${ComputerName}..."

    # First, test if we can actually create a session (more reliable than Test-WSMan)
    try {
        Write-Host "Attempting test PSSession..."
        if ($Credential) {
            $testSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
        } else {
            $testSession = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
        }

        # If we got here, WinRM is working
        Remove-PSSession $testSession -ErrorAction SilentlyContinue
        Write-Host "WinRM is configured correctly on ${ComputerName}." -ForegroundColor Green
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message

        # Check if this is specifically a WinRM corruption error
        if ($errorMsg -like "*WS-Management configuration is corrupted*" -or
            $errorMsg -like "*CorruptedWinRMConfig*") {

            Write-Warning "WinRM corruption detected on ${ComputerName}!"
            Write-Host "Attempting to restore WinRM defaults on ${ComputerName}..."

            # Try to fix WinRM using WMI
            try {
                # Method 1: Use WMI to execute the fix remotely
                Write-Host "Executing WinRM restore via WMI..."
                $fixCommand = "cmd.exe /c `"winrm invoke Restore http://schemas.microsoft.com/wbem/wsman/1/config @{} && winrm set winrm/config/client @{TrustedHosts=`"*`"}`""

                $result = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $fixCommand -ErrorAction Stop

                if ($result.ReturnValue -eq 0) {
                    Write-Host "WinRM restore command sent. Waiting for service to reconfigure..." -ForegroundColor Cyan
                    Start-Sleep -Seconds 8

                    # Try to re-enable PSRemoting
                    Write-Host "Re-enabling PSRemoting..."
                    $enableCommand = "powershell.exe -Command `"Enable-PSRemoting -Force -SkipNetworkProfileCheck`""
                    $result2 = Invoke-WmiMethod -ComputerName $ComputerName -Class Win32_Process -Name Create -ArgumentList $enableCommand -ErrorAction Stop
                    Start-Sleep -Seconds 5

                    # Test again with actual session
                    Write-Host "Testing repaired WinRM configuration..."
                    if ($Credential) {
                        $testSession2 = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
                    } else {
                        $testSession2 = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
                    }

                    Remove-PSSession $testSession2 -ErrorAction SilentlyContinue
                    Write-Host "WinRM has been successfully repaired on ${ComputerName}!" -ForegroundColor Green
                    return $true
                }
                else {
                    Write-Warning "WinRM restore command returned error code: $($result.ReturnValue)"
                    return $false
                }
            }
            catch {
                Write-Warning "Unable to automatically fix WinRM on ${ComputerName}: ${PSItem}"
                Write-Host ""
                Write-Host "Manual Fix Required:" -ForegroundColor Yellow
                Write-Host "  1. Log into ${ComputerName}" -ForegroundColor Yellow
                Write-Host "  2. Run PowerShell as Administrator" -ForegroundColor Yellow
                Write-Host "  3. Execute: winrm invoke Restore http://schemas.microsoft.com/wbem/wsman/1/config '@{}'" -ForegroundColor Yellow
                Write-Host "  4. Execute: Enable-PSRemoting -Force" -ForegroundColor Yellow
                Write-Host ""
                return $false
            }
        }
        else {
            # Different error (not WinRM corruption)
            Write-Warning "PSSession failed but not due to WinRM corruption: $errorMsg"
            return $false
        }
    }
}

# --- Remote Session Setup ---
$session = $null
if ($ComputerName -ne "localhost") {
    Write-Host "Attempting to establish remote session to ${ComputerName}..."

    # Test and fix WinRM if needed
    $winrmReady = if ($Credential) {
        Test-AndFixWinRM -ComputerName $ComputerName -Credential $Credential
    } else {
        Test-AndFixWinRM -ComputerName $ComputerName
    }

    if (-not $winrmReady) {
        Write-Warning "Unable to establish remote connection to ${ComputerName}. Falling back to local execution."
        Write-Host "Note: You are running on localhost but specified -ComputerName ${ComputerName}."
        Write-Host "If you need to collect from ${ComputerName}, please fix WinRM manually and try again."
        # Don't exit - fall through to local execution
    }
    else {
        try {
            if ($Credential) {
                $session = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            } else {
                $session = New-PSSession -ComputerName $ComputerName -ErrorAction Stop
            }
            Write-Host "Remote session established successfully."
        } catch {
            Write-Warning "Failed to establish remote session despite WinRM being available: ${PSItem}"
            Write-Host "Falling back to local execution."
            $session = $null
        }
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

# Save configuration for AI Triage Agent
$ConfigPath = Join-Path -Path $RawDataPath -ChildPath "config.json"
$Config = @{
    ComputerName = $ComputerName
    BrandName = $BrandName
    LogoPath = if ($LogoPath) { $LogoPath } else { $null }
    CustomProblemScript = if ($CustomProblemScript) { $CustomProblemScript } else { $null }
    CustomAllClearScript = if ($CustomAllClearScript) { $CustomAllClearScript } else { $null }
    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}
$Config | ConvertTo-Json -Depth 3 | Out-File $ConfigPath -Encoding UTF8
Write-Host "Configuration saved to $ConfigPath"

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

        # --- 0. Pre-Scan Remediation: rkill.exe (OPTIONAL - MODIFIES SYSTEM STATE) ---
        if ($RunRkill) {
            Write-Host "Pre-Scan Remediation: Downloading and executing rkill.exe on remote machine..."
            Write-Warning "Rkill will terminate malicious processes, modifying system state and destroying volatile evidence!"

            $rkillUrl = "https://download.bleepingcomputer.com/grinler/rkill.exe"
            $rkillPath = Join-Path -Path $env:TEMP -ChildPath "rkill.exe"
            $rkillLogPath = Join-Path -Path $RemoteRawDataPath -ChildPath "rkill_execution.log"

            try {
                # Download rkill.exe
                Invoke-WebRequest -Uri $rkillUrl -OutFile $rkillPath -UseBasicParsing -ErrorAction Stop
                Write-Host "rkill.exe downloaded successfully to ${rkillPath}"

                # Execute rkill.exe silently
                $rkillProcess = Start-Process -FilePath $rkillPath -ArgumentList "-s" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $rkillLogPath
                Write-Host "rkill.exe executed. Exit code: $($rkillProcess.ExitCode)"

                # Log action to Steps_Taken.txt
                $stepsLog = Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt"
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe executed (Exit Code: $($rkillProcess.ExitCode))" |
                    Out-File $stepsLog -Append -Encoding UTF8

                # Clean up rkill executable
                if (Test-Path $rkillPath) {
                    Remove-Item -Path $rkillPath -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Warning "rkill.exe execution failed on remote machine: ${PSItem}"
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe failed - ${PSItem}" |
                    Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
            }
        } else {
            Write-Host "Rkill execution SKIPPED (use -RunRkill flag to enable). Preserving volatile evidence integrity." -ForegroundColor Cyan
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe SKIPPED (preserving evidence integrity)" |
                Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
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

        # II. Persistent System Artifacts: Scheduled Tasks (Persistence Evidence)
        Write-Host "Collecting Scheduled Tasks (Persistence) on remote machine..."
        try {
            Get-ScheduledTask |
                Select-Object TaskName, TaskPath, State,
                    @{Name='Actions';Expression={($_.Actions | Where-Object {$_.Execute} | ForEach-Object {$_.Execute}) -join '; '}},
                    @{Name='Arguments';Expression={($_.Actions | Where-Object {$_.Arguments} | ForEach-Object {$_.Arguments}) -join '; '}},
                    @{Name='Author';Expression={$_.Author}},
                    @{Name='Principal';Expression={$_.Principal.UserId}},
                    @{Name='Enabled';Expression={$_.Settings.Enabled}} |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "scheduled_tasks.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect scheduled tasks on remote machine. Error: ${PSItem}"
            "[]" | Out-File (Join-Path $RemoteRawDataPath "scheduled_tasks.json") -Encoding UTF8
        }

        # II. Persistent System Artifacts: Windows Services (Persistence Evidence)
        Write-Host "Collecting Windows Services (Persistence) on remote machine..."
        try {
            Get-CimInstance -ClassName Win32_Service |
                Select-Object Name, DisplayName, State, StartMode, PathName,
                    StartName, ProcessId, Description,
                    @{Name='CreationClassName';Expression={$_.CreationClassName}} |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "services_config.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect Windows services on remote machine. Error: ${PSItem}"
            "[]" | Out-File (Join-Path $RemoteRawDataPath "services_config.json") -Encoding UTF8
        }

        # II. Persistent System Artifacts: WMI Event Subscriptions (Persistence Evidence)
        Write-Host "Collecting WMI Event Subscriptions (Persistence) on remote machine..."
        try {
            $WMIPersistence = @{
                EventFilters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
                    Select-Object Name, Query, QueryLanguage, EventNamespace)
                EventConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
                    Select-Object Name, @{Name='Type';Expression={$_.CimClass.CimClassName}})
                FilterBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
                    Select-Object @{Name='Filter';Expression={$_.Filter.Name}}, @{Name='Consumer';Expression={$_.Consumer.Name}})
            }
            $WMIPersistence | ConvertTo-Json -Depth 4 | Out-File (Join-Path $RemoteRawDataPath "wmi_persistence.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect WMI event subscriptions on remote machine. Error: ${PSItem}"
            "@{EventFilters=@();EventConsumers=@();FilterBindings=@()}" | ConvertTo-Json | Out-File (Join-Path $RemoteRawDataPath "wmi_persistence.json") -Encoding UTF8
        }

        # 0. MOST VOLATILE: Memory Capture (Optional - Large File)
        if ($CaptureMemory) {
            Write-Host "Capturing full memory dump on remote machine (this may take several minutes)..." -ForegroundColor Yellow
            Write-Warning "Memory capture will create a file approximately the size of installed RAM!"

            $WinPmemUrl = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"
            $WinPmemPath = Join-Path $RemoteRawDataPath "winpmem.exe"
            $MemoryDumpPath = Join-Path $RemoteRawDataPath "memory.raw"

            try {
                # Download WinPmem
                Write-Host "  Downloading WinPmem to remote machine..."
                Invoke-WebRequest -Uri $WinPmemUrl -OutFile $WinPmemPath -UseBasicParsing -ErrorAction Stop

                # Execute memory capture
                Write-Host "  Executing memory capture (this will take time - progress may not be visible)..."
                $captureStart = Get-Date
                & $WinPmemPath $MemoryDumpPath -dd 2>&1 | Out-Null
                $captureEnd = Get-Date
                $captureDuration = ($captureEnd - $captureStart).TotalSeconds

                if (Test-Path $MemoryDumpPath) {
                    $memorySize = (Get-Item $MemoryDumpPath).Length
                    $memorySizeMB = [math]::Round($memorySize / 1MB, 2)
                    Write-Host "  Memory capture completed: $memorySizeMB MB in $([math]::Round($captureDuration, 2)) seconds" -ForegroundColor Green

                    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture: $memorySizeMB MB captured in $([math]::Round($captureDuration, 2))s" |
                        Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
                } else {
                    Write-Warning "Memory capture may have failed - dump file not found."
                }

                # Clean up WinPmem executable
                Remove-Item $WinPmemPath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "Could not capture memory on remote machine: $_"
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture FAILED: $_" |
                    Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
            }
        } else {
            Write-Host "Memory capture SKIPPED (use -CaptureMemory flag to enable). Memory forensics not performed." -ForegroundColor Cyan
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture SKIPPED (preserving time and disk space)" |
                Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
        }

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

        # I. Volatile Data: Open Files and Handles
        Write-Host "Collecting Open Files and Handles (Volatile Evidence) on remote machine..."
        $OpenFilesData = @{
            OpenFiles = @()
            SMBSessions = @()
            MappedDrives = @()
        }

        # Collect open files via openfiles command (requires admin)
        try {
            $openFilesOutput = openfiles /query /fo csv /v 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
            $OpenFilesData.OpenFiles = $openFilesOutput | Select-Object -First 500
        } catch {
            Write-Warning "Could not collect open files via openfiles command on remote machine: $_"
        }

        # Collect SMB sessions
        try {
            $OpenFilesData.SMBSessions = Get-SmbSession -ErrorAction SilentlyContinue |
                Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
        } catch {
            Write-Warning "Could not collect SMB sessions on remote machine: $_"
        }

        # Collect mapped network drives
        try {
            $OpenFilesData.MappedDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
                Where-Object {$_.DisplayRoot} |
                Select-Object Name, Root, DisplayRoot
        } catch {
            Write-Warning "Could not collect mapped drives on remote machine: $_"
        }

        $OpenFilesData | ConvertTo-Json -Depth 4 | Out-File (Join-Path $RemoteRawDataPath "open_files.json") -Encoding UTF8

        # III. Comprehensive Event Log Collection

        # Security Event Logs (Logons, Process Creation, Services, Users, Object Access)
        Write-Host "Collecting Security Event Logs on remote machine..."
        try {
            # Event IDs: 4624 (Logon), 4672 (Admin), 4688 (Process Creation),
            #            4697 (Service Install), 4720 (User Creation), 4663 (Object Access)
            Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4720 or EventID=4663)]]" -MaxEvents 1000 |
                Select-Object TimeCreated, Id, Message,
                    @{Name='ProcessName';Expression={$_.Properties[5].Value}},
                    @{Name='ProcessCommandLine';Expression={$_.Properties[8].Value}} |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "security_events.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect security event logs on remote machine. Error: ${PSItem}"
            "[]" | Out-File (Join-Path $RemoteRawDataPath "security_events.json") -Encoding UTF8
        }

        # PowerShell Operational Logs (Script Block Logging)
        Write-Host "Collecting PowerShell Operational Logs on remote machine..."
        try {
            Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 500 |
                Select-Object TimeCreated, Id, Message, LevelDisplayName |
                ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "powershell_logs.json") -Encoding UTF8
        }
        catch {
            Write-Warning "Could not collect PowerShell logs on remote machine. Error: ${PSItem}"
            "[]" | Out-File (Join-Path $RemoteRawDataPath "powershell_logs.json") -Encoding UTF8
        }

        # IV. Browser History and Downloads (Execution History Evidence)
        Write-Host "Collecting Browser History and Downloads on remote machine..."
        $BrowserArtifacts = @()

        # Chrome/Edge Chromium-based browsers
        $ChromePaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
        )

        # Firefox
        $FirefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
        if (Test-Path $FirefoxProfilePath) {
            $FirefoxProfiles = Get-ChildItem -Path $FirefoxProfilePath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $FirefoxProfiles) {
                $ChromePaths += Join-Path $profile.FullName "places.sqlite"
            }
        }

        foreach ($browserDbPath in $ChromePaths) {
            if (Test-Path $browserDbPath) {
                try {
                    $browserName = if ($browserDbPath -like "*Chrome*") { "Chrome" }
                                   elseif ($browserDbPath -like "*Edge*") { "Edge" }
                                   elseif ($browserDbPath -like "*Firefox*") { "Firefox" }
                                   else { "Unknown" }

                    $destFileName = "${browserName}_History_$(Get-Date -Format 'yyyyMMdd_HHmmss').db"
                    $destPath = Join-Path $RemoteRawDataPath $destFileName

                    # Copy database file (locked files may fail, but we try)
                    Copy-Item -Path $browserDbPath -Destination $destPath -Force -ErrorAction Stop

                    $BrowserArtifacts += @{
                        Browser = $browserName
                        SourcePath = $browserDbPath
                        CopiedTo = $destFileName
                        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    }

                    Write-Host "  Copied ${browserName} history database"
                }
                catch {
                    Write-Warning "  Could not copy browser history from ${browserDbPath}: ${PSItem}"
                }
            }
        }

        # Save manifest of collected browser artifacts
        $BrowserArtifacts | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "browser_artifacts.json") -Encoding UTF8

        # IV. Execution History Artifacts: Prefetch, Jump Lists, LNK Files

        # Prefetch Files (Program Execution History)
        Write-Host "Collecting Prefetch files (execution history) on remote machine..."
        $PrefetchDest = Join-Path $RemoteRawDataPath "prefetch"
        $PrefetchPath = "C:\Windows\Prefetch"

        if (Test-Path $PrefetchPath) {
            try {
                New-Item -ItemType Directory -Path $PrefetchDest -Force | Out-Null
                Copy-Item -Path "$PrefetchPath\*.pf" -Destination $PrefetchDest -Force -ErrorAction SilentlyContinue

                $prefetchCount = (Get-ChildItem $PrefetchDest -Filter "*.pf" -ErrorAction SilentlyContinue).Count
                Write-Host "  Collected $prefetchCount prefetch files"

                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Prefetch collection: $prefetchCount files" |
                    Out-File (Join-Path -Path $RemoteRawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
            } catch {
                Write-Warning "Could not collect prefetch files on remote machine: $_"
            }
        } else {
            Write-Warning "Prefetch directory not found on remote machine."
        }

        # Jump Lists (Recent Items Accessed)
        Write-Host "Collecting Jump Lists (recent items) on remote machine..."
        $JumpListDest = Join-Path $RemoteRawDataPath "jumplists"
        New-Item -ItemType Directory -Path $JumpListDest -Force | Out-Null

        $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
        $jumpListCount = 0
        foreach ($profile in $userProfiles) {
            $jumpListPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"

            if (Test-Path $jumpListPath) {
                try {
                    $userDest = Join-Path $JumpListDest $profile.Name
                    New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                    Copy-Item -Path "$jumpListPath\*" -Destination $userDest -Force -Recurse -ErrorAction SilentlyContinue
                    $jumpListCount += (Get-ChildItem $userDest -Recurse -File -ErrorAction SilentlyContinue).Count
                } catch {
                    Write-Warning "Could not collect jump lists for user $($profile.Name): $_"
                }
            }
        }
        Write-Host "  Collected $jumpListCount jump list files"

        # LNK Files (Shortcuts - Recent File Access)
        Write-Host "Collecting LNK files (shortcuts) on remote machine..."
        $LnkDest = Join-Path $RemoteRawDataPath "lnk_files"
        New-Item -ItemType Directory -Path $LnkDest -Force | Out-Null

        $lnkCount = 0
        foreach ($profile in $userProfiles) {
            $recentPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\Recent"
            $desktopPath = Join-Path $profile.FullName "Desktop"

            if (Test-Path $recentPath) {
                try {
                    $userDest = Join-Path $LnkDest "$($profile.Name)_Recent"
                    New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                    Copy-Item -Path "$recentPath\*.lnk" -Destination $userDest -Force -ErrorAction SilentlyContinue
                    $lnkCount += (Get-ChildItem $userDest -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
                } catch {
                    Write-Warning "Could not collect LNK files from Recent for user $($profile.Name): $_"
                }
            }

            if (Test-Path $desktopPath) {
                try {
                    $userDest = Join-Path $LnkDest "$($profile.Name)_Desktop"
                    New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                    Copy-Item -Path "$desktopPath\*.lnk" -Destination $userDest -Force -ErrorAction SilentlyContinue
                    $lnkCount += (Get-ChildItem $userDest -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
                } catch {
                    Write-Warning "Could not collect LNK files from Desktop for user $($profile.Name): $_"
                }
            }
        }
        Write-Host "  Collected $lnkCount LNK files"

        # V. MACE Timestamps for Suspicious Files (File System Artifacts)
        Write-Host "Collecting MACE timestamps for referenced executables on remote machine..."
        $FileMetadata = @()
        $UniqueFilePaths = @{}

        # Extract file paths from Run keys
        try {
            $runKeysContent = Get-Content (Join-Path $RemoteRawDataPath "registry_run_keys.json") -Raw | ConvertFrom-Json
            foreach ($runKey in $runKeysContent) {
                $runKey.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    if ($_.Value -match '([A-Za-z]:\\[^"]+\.exe)') {
                        $UniqueFilePaths[$matches[1]] = $true
                    }
                }
            }
        } catch { }

        # Extract file paths from Scheduled Tasks
        try {
            $tasksContent = Get-Content (Join-Path $RemoteRawDataPath "scheduled_tasks.json") -Raw | ConvertFrom-Json
            foreach ($task in $tasksContent) {
                if ($task.Actions -and (Test-Path $task.Actions -ErrorAction SilentlyContinue)) {
                    $UniqueFilePaths[$task.Actions] = $true
                }
            }
        } catch { }

        # Extract file paths from Services
        try {
            $servicesContent = Get-Content (Join-Path $RemoteRawDataPath "services_config.json") -Raw | ConvertFrom-Json
            foreach ($service in $servicesContent) {
                if ($service.PathName -match '([A-Za-z]:\\[^"]+\.exe)') {
                    $UniqueFilePaths[$matches[1]] = $true
                }
            }
        } catch { }

        # Extract file paths from Processes
        try {
            $processesContent = Get-Content (Join-Path $RemoteRawDataPath "processes_snapshot.json") -Raw | ConvertFrom-Json
            foreach ($process in $processesContent) {
                if ($process.ExecutablePath -and (Test-Path $process.ExecutablePath -ErrorAction SilentlyContinue)) {
                    $UniqueFilePaths[$process.ExecutablePath] = $true
                }
            }
        } catch { }

        # Collect MACE timestamps for all unique file paths
        foreach ($filePath in $UniqueFilePaths.Keys) {
            try {
                if (Test-Path $filePath) {
                    $fileInfo = Get-Item -Path $filePath -Force -ErrorAction Stop
                    $FileMetadata += @{
                        FilePath = $filePath
                        CreationTime = $fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                        LastWriteTime = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        LastAccessTime = $fileInfo.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss")
                        Length = $fileInfo.Length
                        Attributes = $fileInfo.Attributes.ToString()
                    }
                }
            }
            catch {
                # Silently skip files we can't access
            }
        }

        $FileMetadata | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RemoteRawDataPath "file_metadata.json") -Encoding UTF8
        Write-Host "  Collected MACE timestamps for $($FileMetadata.Count) files"

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
                $wasDefenderDisabled = $false

                if ($DefenderService -and $DefenderService.Status -ne "Running") {
                    if ($EnableDefender) {
                        Write-Warning "Windows Defender Service ('WinDefend') is not running on remote machine. Attempting to start it..."
                        Write-Warning "Enabling Defender may alert advanced malware and trigger anti-forensics behavior!"
                        try {
                            Start-Service -Name WinDefend -ErrorAction Stop
                            Start-Sleep -Seconds 5  # Give the service time to fully start
                            $DefenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                            if ($DefenderService.Status -eq "Running") {
                                Write-Host "Windows Defender Service started successfully." -ForegroundColor Green
                                $wasDefenderDisabled = $true
                            }
                        }
                        catch {
                            Write-Warning "Failed to start Windows Defender Service on remote machine: $_"
                            "Windows Defender Service could not be started on remote machine. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
                        }
                    } else {
                        Write-Host "Windows Defender Service is not running. Skipping scan (use -EnableDefender to force enable)." -ForegroundColor Yellow
                        "Windows Defender Service not running. Scan SKIPPED (preserving stealth)." | Out-File $DefenderLogPath -Encoding UTF8
                    }
                }

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

                    # Disable Defender if it was disabled before
                    if ($wasDefenderDisabled) {
                        Write-Host "Stopping Windows Defender Service (was disabled before scan)..." -ForegroundColor Yellow
                        try {
                            Stop-Service -Name WinDefend -Force -ErrorAction Stop
                            Write-Host "Windows Defender Service stopped successfully." -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Failed to stop Windows Defender Service on remote machine: $_"
                        }
                    }
                } else {
                    Write-Warning "Windows Defender Service ('WinDefend') is not available on remote machine. Skipping scan."
                    "Windows Defender Service ('WinDefend') is not available on remote machine. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
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

    # --- 0. Pre-Scan Remediation: rkill.exe (OPTIONAL - MODIFIES SYSTEM STATE) ---
    if ($RunRkill) {
        Write-Host "Pre-Scan Remediation: Downloading and executing rkill.exe..."
        Write-Warning "Rkill will terminate malicious processes, modifying system state and destroying volatile evidence!"

        $rkillUrl = "https://download.bleepingcomputer.com/grinler/rkill.exe"
        $rkillPath = Join-Path -Path $env:TEMP -ChildPath "rkill.exe"
        $rkillLogPath = Join-Path -Path $RawDataPath -ChildPath "rkill_execution.log"

        try {
            # Download rkill.exe
            Invoke-WebRequest -Uri $rkillUrl -OutFile $rkillPath -UseBasicParsing -ErrorAction Stop
            Write-Host "rkill.exe downloaded successfully to ${rkillPath}"

            # Execute rkill.exe silently
            $rkillProcess = Start-Process -FilePath $rkillPath -ArgumentList "-s" -Wait -PassThru -NoNewWindow -RedirectStandardOutput $rkillLogPath
            Write-Host "rkill.exe executed. Exit code: $($rkillProcess.ExitCode)"

            # Log action to Steps_Taken.txt
            $stepsLog = Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe executed (Exit Code: $($rkillProcess.ExitCode))" |
                Out-File $stepsLog -Append -Encoding UTF8

            # Clean up rkill executable
            if (Test-Path $rkillPath) {
                Remove-Item -Path $rkillPath -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Warning "rkill.exe execution failed: ${PSItem}"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe failed - ${PSItem}" |
                Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
        }
    } else {
        Write-Host "Rkill execution SKIPPED (use -RunRkill flag to enable). Preserving volatile evidence integrity." -ForegroundColor Cyan
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Pre-Scan Remediation: rkill.exe SKIPPED (preserving evidence integrity)" |
            Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
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

    # II. Persistent System Artifacts: Scheduled Tasks (Persistence Evidence)
    Write-Host "Collecting Scheduled Tasks (Persistence)..."
    try {
        Get-ScheduledTask |
            Select-Object TaskName, TaskPath, State,
                @{Name='Actions';Expression={($_.Actions | Where-Object {$_.Execute} | ForEach-Object {$_.Execute}) -join '; '}},
                @{Name='Arguments';Expression={($_.Actions | Where-Object {$_.Arguments} | ForEach-Object {$_.Arguments}) -join '; '}},
                @{Name='Author';Expression={$_.Author}},
                @{Name='Principal';Expression={$_.Principal.UserId}},
                @{Name='Enabled';Expression={$_.Settings.Enabled}} |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "scheduled_tasks.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect scheduled tasks. Error: ${PSItem}"
        "[]" | Out-File (Join-Path $RawDataPath "scheduled_tasks.json") -Encoding UTF8
    }

    # II. Persistent System Artifacts: Windows Services (Persistence Evidence)
    Write-Host "Collecting Windows Services (Persistence)..."
    try {
        Get-CimInstance -ClassName Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, PathName,
                StartName, ProcessId, Description,
                @{Name='CreationClassName';Expression={$_.CreationClassName}} |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "services_config.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect Windows services. Error: ${PSItem}"
        "[]" | Out-File (Join-Path $RawDataPath "services_config.json") -Encoding UTF8
    }

    # II. Persistent System Artifacts: WMI Event Subscriptions (Persistence Evidence)
    Write-Host "Collecting WMI Event Subscriptions (Persistence)..."
    try {
        $WMIPersistence = @{
            EventFilters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
                Select-Object Name, Query, QueryLanguage, EventNamespace)
            EventConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer |
                Select-Object Name, @{Name='Type';Expression={$_.CimClass.CimClassName}})
            FilterBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
                Select-Object @{Name='Filter';Expression={$_.Filter.Name}}, @{Name='Consumer';Expression={$_.Consumer.Name}})
        }
        $WMIPersistence | ConvertTo-Json -Depth 4 | Out-File (Join-Path $RawDataPath "wmi_persistence.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect WMI event subscriptions. Error: ${PSItem}"
        "@{EventFilters=@();EventConsumers=@();FilterBindings=@()}" | ConvertTo-Json | Out-File (Join-Path $RawDataPath "wmi_persistence.json") -Encoding UTF8
    }

    # 0. MOST VOLATILE: Memory Capture (Optional - Large File)
    if ($CaptureMemory) {
        Write-Host "Capturing full memory dump (this may take several minutes)..." -ForegroundColor Yellow
        Write-Warning "Memory capture will create a file approximately the size of installed RAM!"

        $WinPmemUrl = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"
        $WinPmemPath = Join-Path $RawDataPath "winpmem.exe"
        $MemoryDumpPath = Join-Path $RawDataPath "memory.raw"

        try {
            # Download WinPmem
            Write-Host "  Downloading WinPmem..."
            Invoke-WebRequest -Uri $WinPmemUrl -OutFile $WinPmemPath -UseBasicParsing -ErrorAction Stop

            # Execute memory capture
            Write-Host "  Executing memory capture (this will take time - progress may not be visible)..."
            $captureStart = Get-Date
            & $WinPmemPath $MemoryDumpPath -dd 2>&1 | Out-Null
            $captureEnd = Get-Date
            $captureDuration = ($captureEnd - $captureStart).TotalSeconds

            if (Test-Path $MemoryDumpPath) {
                $memorySize = (Get-Item $MemoryDumpPath).Length
                $memorySizeMB = [math]::Round($memorySize / 1MB, 2)
                Write-Host "  Memory capture completed: $memorySizeMB MB in $([math]::Round($captureDuration, 2)) seconds" -ForegroundColor Green

                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture: $memorySizeMB MB captured in $([math]::Round($captureDuration, 2))s" |
                    Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
            } else {
                Write-Warning "Memory capture may have failed - dump file not found."
            }

            # Clean up WinPmem executable
            Remove-Item $WinPmemPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Could not capture memory: $_"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture FAILED: $_" |
                Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
        }
    } else {
        Write-Host "Memory capture SKIPPED (use -CaptureMemory flag to enable). Memory forensics not performed." -ForegroundColor Cyan
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Memory capture SKIPPED (preserving time and disk space)" |
            Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
    }

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

    # I. Volatile Data: Open Files and Handles
    Write-Host "Collecting Open Files and Handles (Volatile Evidence)..."
    $OpenFilesData = @{
        OpenFiles = @()
        SMBSessions = @()
        MappedDrives = @()
    }

    # Collect open files via openfiles command (requires admin)
    try {
        $openFilesOutput = openfiles /query /fo csv /v 2>$null | ConvertFrom-Csv -ErrorAction SilentlyContinue
        $OpenFilesData.OpenFiles = $openFilesOutput | Select-Object -First 500
    } catch {
        Write-Warning "Could not collect open files via openfiles command: $_"
    }

    # Collect SMB sessions
    try {
        $OpenFilesData.SMBSessions = Get-SmbSession -ErrorAction SilentlyContinue |
            Select-Object ClientComputerName, ClientUserName, NumOpens, SessionId
    } catch {
        Write-Warning "Could not collect SMB sessions: $_"
    }

    # Collect mapped network drives
    try {
        $OpenFilesData.MappedDrives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object {$_.DisplayRoot} |
            Select-Object Name, Root, DisplayRoot
    } catch {
        Write-Warning "Could not collect mapped drives: $_"
    }

    $OpenFilesData | ConvertTo-Json -Depth 4 | Out-File (Join-Path $RawDataPath "open_files.json") -Encoding UTF8

    # III. Comprehensive Event Log Collection

    # Security Event Logs (Logons, Process Creation, Services, Users, Object Access)
    Write-Host "Collecting Security Event Logs..."
    try {
        # Event IDs: 4624 (Logon), 4672 (Admin), 4688 (Process Creation),
        #            4697 (Service Install), 4720 (User Creation), 4663 (Object Access)
        Get-WinEvent -LogName 'Security' -FilterXPath "*[System[(EventID=4624 or EventID=4672 or EventID=4688 or EventID=4697 or EventID=4720 or EventID=4663)]]" -MaxEvents 1000 |
            Select-Object TimeCreated, Id, Message,
                @{Name='ProcessName';Expression={$_.Properties[5].Value}},
                @{Name='ProcessCommandLine';Expression={$_.Properties[8].Value}} |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "security_events.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect security event logs. Error: ${PSItem}"
        "[]" | Out-File (Join-Path $RawDataPath "security_events.json") -Encoding UTF8
    }

    # PowerShell Operational Logs (Script Block Logging)
    Write-Host "Collecting PowerShell Operational Logs..."
    try {
        Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 500 |
            Select-Object TimeCreated, Id, Message, LevelDisplayName |
            ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "powershell_logs.json") -Encoding UTF8
    }
    catch {
        Write-Warning "Could not collect PowerShell logs. Error: ${PSItem}"
        "[]" | Out-File (Join-Path $RawDataPath "powershell_logs.json") -Encoding UTF8
    }

    # IV. Browser History and Downloads (Execution History Evidence)
    Write-Host "Collecting Browser History and Downloads..."
    $BrowserArtifacts = @()

    # Chrome/Edge Chromium-based browsers
    $ChromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    )

    # Firefox
    $FirefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $FirefoxProfilePath) {
        $FirefoxProfiles = Get-ChildItem -Path $FirefoxProfilePath -Directory -ErrorAction SilentlyContinue
        foreach ($profile in $FirefoxProfiles) {
            $ChromePaths += Join-Path $profile.FullName "places.sqlite"
        }
    }

    foreach ($browserDbPath in $ChromePaths) {
        if (Test-Path $browserDbPath) {
            try {
                $browserName = if ($browserDbPath -like "*Chrome*") { "Chrome" }
                               elseif ($browserDbPath -like "*Edge*") { "Edge" }
                               elseif ($browserDbPath -like "*Firefox*") { "Firefox" }
                               else { "Unknown" }

                $destFileName = "${browserName}_History_$(Get-Date -Format 'yyyyMMdd_HHmmss').db"
                $destPath = Join-Path $RawDataPath $destFileName

                # Copy database file (locked files may fail, but we try)
                Copy-Item -Path $browserDbPath -Destination $destPath -Force -ErrorAction Stop

                $BrowserArtifacts += @{
                    Browser = $browserName
                    SourcePath = $browserDbPath
                    CopiedTo = $destFileName
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }

                Write-Host "  Copied ${browserName} history database"
            }
            catch {
                Write-Warning "  Could not copy browser history from ${browserDbPath}: ${PSItem}"
            }
        }
    }

    # Save manifest of collected browser artifacts
    $BrowserArtifacts | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "browser_artifacts.json") -Encoding UTF8

    # IV. Execution History Artifacts: Prefetch, Jump Lists, LNK Files

    # Prefetch Files (Program Execution History)
    Write-Host "Collecting Prefetch files (execution history)..."
    $PrefetchDest = Join-Path $RawDataPath "prefetch"
    $PrefetchPath = "C:\Windows\Prefetch"

    if (Test-Path $PrefetchPath) {
        try {
            New-Item -ItemType Directory -Path $PrefetchDest -Force | Out-Null
            Copy-Item -Path "$PrefetchPath\*.pf" -Destination $PrefetchDest -Force -ErrorAction SilentlyContinue

            $prefetchCount = (Get-ChildItem $PrefetchDest -Filter "*.pf" -ErrorAction SilentlyContinue).Count
            Write-Host "  Collected $prefetchCount prefetch files"

            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Prefetch collection: $prefetchCount files" |
                Out-File (Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt") -Append -Encoding UTF8
        } catch {
            Write-Warning "Could not collect prefetch files: $_"
        }
    } else {
        Write-Warning "Prefetch directory not found."
    }

    # Jump Lists (Recent Items Accessed)
    Write-Host "Collecting Jump Lists (recent items)..."
    $JumpListDest = Join-Path $RawDataPath "jumplists"
    New-Item -ItemType Directory -Path $JumpListDest -Force | Out-Null

    $userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    $jumpListCount = 0
    foreach ($profile in $userProfiles) {
        $jumpListPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"

        if (Test-Path $jumpListPath) {
            try {
                $userDest = Join-Path $JumpListDest $profile.Name
                New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                Copy-Item -Path "$jumpListPath\*" -Destination $userDest -Force -Recurse -ErrorAction SilentlyContinue
                $jumpListCount += (Get-ChildItem $userDest -Recurse -File -ErrorAction SilentlyContinue).Count
            } catch {
                Write-Warning "Could not collect jump lists for user $($profile.Name): $_"
            }
        }
    }
    Write-Host "  Collected $jumpListCount jump list files"

    # LNK Files (Shortcuts - Recent File Access)
    Write-Host "Collecting LNK files (shortcuts)..."
    $LnkDest = Join-Path $RawDataPath "lnk_files"
    New-Item -ItemType Directory -Path $LnkDest -Force | Out-Null

    $lnkCount = 0
    foreach ($profile in $userProfiles) {
        $recentPath = Join-Path $profile.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        $desktopPath = Join-Path $profile.FullName "Desktop"

        if (Test-Path $recentPath) {
            try {
                $userDest = Join-Path $LnkDest "$($profile.Name)_Recent"
                New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                Copy-Item -Path "$recentPath\*.lnk" -Destination $userDest -Force -ErrorAction SilentlyContinue
                $lnkCount += (Get-ChildItem $userDest -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
            } catch {
                Write-Warning "Could not collect LNK files from Recent for user $($profile.Name): $_"
            }
        }

        if (Test-Path $desktopPath) {
            try {
                $userDest = Join-Path $LnkDest "$($profile.Name)_Desktop"
                New-Item -ItemType Directory -Path $userDest -Force | Out-Null
                Copy-Item -Path "$desktopPath\*.lnk" -Destination $userDest -Force -ErrorAction SilentlyContinue
                $lnkCount += (Get-ChildItem $userDest -Filter "*.lnk" -ErrorAction SilentlyContinue).Count
            } catch {
                Write-Warning "Could not collect LNK files from Desktop for user $($profile.Name): $_"
            }
        }
    }
    Write-Host "  Collected $lnkCount LNK files"

    # V. MACE Timestamps for Suspicious Files (File System Artifacts)
    Write-Host "Collecting MACE timestamps for referenced executables..."
    $FileMetadata = @()
    $UniqueFilePaths = @{}

    # Extract file paths from Run keys
    try {
        $runKeysContent = Get-Content (Join-Path $RawDataPath "registry_run_keys.json") -Raw | ConvertFrom-Json
        foreach ($runKey in $runKeysContent) {
            $runKey.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                if ($_.Value -match '([A-Za-z]:\\[^"]+\.exe)') {
                    $UniqueFilePaths[$matches[1]] = $true
                }
            }
        }
    } catch { }

    # Extract file paths from Scheduled Tasks
    try {
        $tasksContent = Get-Content (Join-Path $RawDataPath "scheduled_tasks.json") -Raw | ConvertFrom-Json
        foreach ($task in $tasksContent) {
            if ($task.Actions -and (Test-Path $task.Actions -ErrorAction SilentlyContinue)) {
                $UniqueFilePaths[$task.Actions] = $true
            }
        }
    } catch { }

    # Extract file paths from Services
    try {
        $servicesContent = Get-Content (Join-Path $RawDataPath "services_config.json") -Raw | ConvertFrom-Json
        foreach ($service in $servicesContent) {
            if ($service.PathName -match '([A-Za-z]:\\[^"]+\.exe)') {
                $UniqueFilePaths[$matches[1]] = $true
            }
        }
    } catch { }

    # Extract file paths from Processes
    try {
        $processesContent = Get-Content (Join-Path $RawDataPath "processes_snapshot.json") -Raw | ConvertFrom-Json
        foreach ($process in $processesContent) {
            if ($process.ExecutablePath -and (Test-Path $process.ExecutablePath -ErrorAction SilentlyContinue)) {
                $UniqueFilePaths[$process.ExecutablePath] = $true
            }
        }
    } catch { }

    # Collect MACE timestamps for all unique file paths
    foreach ($filePath in $UniqueFilePaths.Keys) {
        try {
            if (Test-Path $filePath) {
                $fileInfo = Get-Item -Path $filePath -Force -ErrorAction Stop
                $FileMetadata += @{
                    FilePath = $filePath
                    CreationTime = $fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    LastWriteTime = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    LastAccessTime = $fileInfo.LastAccessTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Length = $fileInfo.Length
                    Attributes = $fileInfo.Attributes.ToString()
                }
            }
        }
        catch {
            # Silently skip files we can't access
        }
    }

    $FileMetadata | ConvertTo-Json -Depth 3 | Out-File (Join-Path $RawDataPath "file_metadata.json") -Encoding UTF8
    Write-Host "  Collected MACE timestamps for $($FileMetadata.Count) files"

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
            $wasDefenderDisabled = $false

            if ($DefenderService -and $DefenderService.Status -ne "Running") {
                if ($EnableDefender) {
                    Write-Warning "Windows Defender Service ('WinDefend') is not running. Attempting to start it..."
                    Write-Warning "Enabling Defender may alert advanced malware and trigger anti-forensics behavior!"
                    try {
                        Start-Service -Name WinDefend -ErrorAction Stop
                        Start-Sleep -Seconds 5  # Give the service time to fully start
                        $DefenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
                        if ($DefenderService.Status -eq "Running") {
                            Write-Host "Windows Defender Service started successfully." -ForegroundColor Green
                            $wasDefenderDisabled = $true
                        }
                    }
                    catch {
                        Write-Warning "Failed to start Windows Defender Service: $_"
                        "Windows Defender Service could not be started. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
                    }
                } else {
                    Write-Host "Windows Defender Service is not running. Skipping scan (use -EnableDefender to force enable)." -ForegroundColor Yellow
                    "Windows Defender Service not running. Scan SKIPPED (preserving stealth)." | Out-File $DefenderLogPath -Encoding UTF8
                }
            }

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

                # Disable Defender if it was disabled before
                if ($wasDefenderDisabled) {
                    Write-Host "Stopping Windows Defender Service (was disabled before scan)..." -ForegroundColor Yellow
                    try {
                        Stop-Service -Name WinDefend -Force -ErrorAction Stop
                        Write-Host "Windows Defender Service stopped successfully." -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "Failed to stop Windows Defender Service: $_"
                    }
                }
            } else {
                Write-Warning "Windows Defender Service ('WinDefend') is not available. Skipping scan."
                "Windows Defender Service ('WinDefend') is not available. Skipping scan." | Out-File $DefenderLogPath -Encoding UTF8
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

    # Use LLM to diagnose the parsing error if available
    if (Get-Command Invoke-LLMErrorDiagnostics -ErrorAction SilentlyContinue) {
        $parseScriptContent = Get-Content $ParseScriptPath -Raw
        $codeContext = if ($parseScriptContent.Length -gt 2000) {
            $parseScriptContent.Substring(0, 2000) + "`n... (truncated)"
        } else {
            $parseScriptContent
        }

        Invoke-LLMErrorDiagnostics `
            -ErrorMessage $_.Exception.Message `
            -CodeContext $codeContext `
            -ScriptSection "Parse_Results.ps1 Execution"
    }
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

# --- LLM-Based Error Handler (Available after API token is validated) ---
function Invoke-LLMErrorDiagnostics {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ErrorMessage,

        [Parameter(Mandatory=$true)]
        [string]$CodeContext,

        [Parameter(Mandatory=$false)]
        [string]$ScriptSection = "Unknown"
    )

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  LLM Error Diagnostics Engine" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "An error occurred. Consulting AI for diagnosis..." -ForegroundColor Yellow
    Write-Host ""

    $diagnosticPrompt = @"
You are a PowerShell scripting expert helping debug an error in the First-On-Scene forensic toolkit.

**Error Details:**
- Section: $ScriptSection
- Error Message: $ErrorMessage

**Code Context:**
``````powershell
$CodeContext
``````

**Your Task:**
1. Analyze the error and identify the root cause
2. Explain what went wrong in simple terms
3. Provide a specific fix with corrected code
4. If the error is environmental (e.g., permissions, missing dependencies), provide remediation steps

**Format your response as:**
## Root Cause
[Brief explanation]

## Fix
``````powershell
[Corrected code or remediation commands]
``````

## Explanation
[Why this fix works]
"@

    try {
        # Save diagnostic prompt to temp file
        $tempPromptFile = Join-Path $env:TEMP "fos_error_diagnostic.txt"
        $diagnosticPrompt | Out-File -FilePath $tempPromptFile -Encoding UTF8 -NoNewline

        # Call LLM via qwen CLI (using already configured settings)
        Write-Host "Querying LLM for error analysis..." -ForegroundColor Cyan
        $diagnosticResult = cmd /c "type `"$tempPromptFile`" | npx --yes @qwen-code/qwen-code -p `"`""

        # Clean up temp file
        if (Test-Path $tempPromptFile) {
            Remove-Item $tempPromptFile -Force
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  AI Diagnosis Complete" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host $diagnosticResult
        Write-Host ""
        Write-Host "Note: Review the AI's suggestions before applying any fixes." -ForegroundColor Yellow
        Write-Host ""

        # Log diagnostic to Steps_Taken.txt
        $stepsLog = Join-Path -Path $RawDataPath -ChildPath "Steps_Taken.txt"
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: LLM Error Diagnostics - Section: $ScriptSection - Error: $ErrorMessage" |
            Out-File $stepsLog -Append -Encoding UTF8

        return $diagnosticResult
    }
    catch {
        Write-Warning "LLM error diagnostics failed: ${PSItem}"
        Write-Host "Continuing with standard error handling..."
        return $null
    }
}

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
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Generating DOCX Report" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Generate professional DOCX report
    $GenerateReportScript = Join-Path -Path $PSScriptRoot -ChildPath "Generate_Report.ps1"
    if (Test-Path $GenerateReportScript) {
        try {
            & $GenerateReportScript -ComputerName $ComputerName
        }
        catch {
            Write-Warning "DOCX report generation failed: $_"
            Write-Host "Continuing without DOCX report. See error details above." -ForegroundColor Yellow
        }
    } else {
        Write-Warning "Generate_Report.ps1 not found. Skipping DOCX report generation."
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Triage Analysis Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Check the results directory for the final analysis:" -ForegroundColor Cyan
    Write-Host "  - results/Incident_Report_*.html (Professional HTML report)"
    Write-Host "  - results/Incident_Report_*.docx (Professional DOCX report - if Word conversion succeeded)"
    Write-Host "  - results/findings.txt (AI analysis report)"
    Write-Host "  - results/Steps_Taken.txt (audit log)"
    Write-Host ""
}
catch {
    Write-Error "Failed to launch Qwen CLI: $_"
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}