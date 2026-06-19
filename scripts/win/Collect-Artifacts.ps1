<#
.SYNOPSIS
    First-On-Scene READ-ONLY forensic collector (Windows).
.DESCRIPTION
    Collects volatile and persistent artifacts from the local machine and writes
    a single schema-conformant bundle.json plus a tamper-evident chain of custody.

    Design guarantees:
      * READ-ONLY: never terminates processes, toggles Defender, or modifies the system.
      * ZERO EGRESS: makes no outbound network connections.
      * ZERO DEPENDENCIES: pure PowerShell 5.1+. Nothing to install on the endpoint.
      * NEVER ABORTS: a single failed artifact is logged to metadata.errors and skipped.

    Output is consumed by Invoke-Triage.ps1 (which performs all analysis).
.PARAMETER CaseDir
    Output directory. Defaults to <repo>/results/<caseId>.
.PARAMETER StartTime / EndTime
    Optional event-log collection window.
.PARAMETER MaxEvents
    Cap per event channel (default 1000).
#>
[CmdletBinding()]
param(
    [string]$CaseDir,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [int]$MaxEvents = 1000
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

$collectorVersion = Get-FosEngineVersion
$caseId = New-FosCaseId
if (-not $CaseDir) {
    $root = Split-Path -Parent (Split-Path -Parent $here)
    $CaseDir = Join-Path $root "results\$caseId"
}
New-Item -ItemType Directory -Path $CaseDir -Force | Out-Null

$errors = New-Object System.Collections.ArrayList
function Add-CollErr($component, $message) {
    [void]$errors.Add([ordered]@{ component = $component; message = "$message"; timestampUtc = (Get-FosUtcNow) })
    Write-FosLog -Message "[$component] $message" -Level WARN -CaseDir $CaseDir
}
function Get-Capped($x) { @($x) | Select-Object -First $MaxEvents }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Add-CollErr 'privilege' 'Not elevated; Security event log and some artifacts may be incomplete.' }

Write-FosLog -Message "First-On-Scene collector $collectorVersion | case $caseId" -Level STEP -CaseDir $CaseDir
Add-FosCocEntry -CaseDir $CaseDir -Action 'COLLECT_START' -Detail "host=$env:COMPUTERNAME admin=$isAdmin" | Out-Null

# Event time filter
$evtFilter = @{ LogName = 'Security' }
if ($StartTime) { $evtFilter['StartTime'] = $StartTime }
if ($EndTime)   { $evtFilter['EndTime']   = $EndTime }

# --- Registry Run keys ---
$runKeys = New-Object System.Collections.ArrayList
try {
    $paths = @(
        @{ hive='HKLM'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ hive='HKLM'; path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' },
        @{ hive='HKLM'; path='HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run' },
        @{ hive='HKCU'; path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' },
        @{ hive='HKCU'; path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' }
    )
    foreach ($p in $paths) {
        if (Test-Path $p.path) {
            $item = Get-ItemProperty -Path $p.path
            foreach ($prop in $item.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS') {
                    [void]$runKeys.Add([ordered]@{ hive=$p.hive; keyPath=$p.path; valueName=$prop.Name; valueData=[string]$prop.Value })
                }
            }
        }
    }
} catch { Add-CollErr 'registryRunKeys' $_.Exception.Message }

# --- Scheduled tasks ---
$tasks = New-Object System.Collections.ArrayList
try {
    foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) {
        $actions = ($t.Actions | ForEach-Object { ($_.Execute, $_.Arguments) -join ' ' }) -join ' ; '
        $triggers = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
        $info = $null; try { $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue } catch {}
        [void]$tasks.Add([ordered]@{
            taskName=$t.TaskName; path=$t.TaskPath; state=[string]$t.State
            enabled=($t.Settings.Enabled -ne $false); author=[string]$t.Author
            actions=$actions; triggers=$triggers
        })
    }
} catch { Add-CollErr 'scheduledTasks' $_.Exception.Message }

# --- Services ---
$services = New-Object System.Collections.ArrayList
try {
    foreach ($s in (Get-CimInstance Win32_Service -ErrorAction Stop)) {
        [void]$services.Add([ordered]@{
            name=$s.Name; displayName=$s.DisplayName; state=$s.State; startMode=$s.StartMode; pathName=$s.PathName
        })
    }
} catch { Add-CollErr 'services' $_.Exception.Message }

# --- WMI event subscriptions ---
$wmi = [ordered]@{ eventFilters=@(); eventConsumers=@(); filterBindings=@() }
try {
    $wmi.eventFilters   = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query)
    $wmi.eventConsumers = @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate, ExecutablePath)
    $wmi.eventConsumers += @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, ScriptText)
    $wmi.filterBindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer)
} catch { Add-CollErr 'wmiEventSubscriptions' $_.Exception.Message }

# --- Processes ---
$processes = New-Object System.Collections.ArrayList
try {
    # NOTE: GetOwner per-process is extremely slow on busy hosts and no rule consumes it,
    # so process ownership is intentionally not resolved here (keeps collection RMM-fast).
    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction Stop)) {
        [void]$processes.Add([ordered]@{
            processId=[int]$p.ProcessId; name=$p.Name; executablePath=[string]$p.ExecutablePath
            commandLine=[string]$p.CommandLine; parentProcessId=[int]$p.ParentProcessId; user=''
        })
    }
} catch { Add-CollErr 'processes' $_.Exception.Message }

# --- Network connections ---
$connections = New-Object System.Collections.ArrayList
try {
    $procMap = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }
    foreach ($c in (Get-NetTCPConnection -ErrorAction Stop)) {
        [void]$connections.Add([ordered]@{
            protocol='TCP'; localAddress=$c.LocalAddress; localPort=[int]$c.LocalPort
            remoteAddress=$c.RemoteAddress; remotePort=[int]$c.RemotePort; state=[string]$c.State
            processId=[int]$c.OwningProcess; processName=[string]$procMap[[int]$c.OwningProcess]
        })
    }
} catch { Add-CollErr 'connections' $_.Exception.Message }

# --- Security events ---
function Get-SecEvents($ids) {
    $f = $evtFilter.Clone(); $f['Id'] = $ids
    try { Get-WinEvent -FilterHashtable $f -MaxEvents $MaxEvents -ErrorAction Stop } catch { @() }
}
$logonEvents = New-Object System.Collections.ArrayList
$userCreate  = New-Object System.Collections.ArrayList
$svcInstall  = New-Object System.Collections.ArrayList
$privEsc     = New-Object System.Collections.ArrayList
try {
    foreach ($e in (Get-SecEvents @(4624,4672,4720,4697))) {
        $msg = ($e.Message -split "`n" | Select-Object -First 6) -join ' '
        $ts  = $e.TimeCreated.ToUniversalTime().ToString('o')
        switch ($e.Id) {
            4624 { $lt=0; try { $lt=[int]$e.Properties[8].Value } catch {}; [void]$logonEvents.Add([ordered]@{ eventId=4624; timestamp=$ts; logonType=$lt; account=''; sourceAddress=''; message=$msg }) }
            4672 { [void]$privEsc.Add([ordered]@{ eventId=4672; timestamp=$ts; user=''; privileges=$msg }); [void]$logonEvents.Add([ordered]@{ eventId=4672; timestamp=$ts; logonType=0; account=''; sourceAddress=''; message=$msg }) }
            4720 { [void]$userCreate.Add([ordered]@{ eventId=4720; timestamp=$ts; message=$msg }) }
            4697 { [void]$svcInstall.Add([ordered]@{ eventId=4697; timestamp=$ts; message=$msg }) }
        }
    }
} catch { Add-CollErr 'securityEvents' $_.Exception.Message }

# --- PowerShell script-block logs (4104) ---
$psLogs = New-Object System.Collections.ArrayList
try {
    $f = @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 }
    if ($StartTime) { $f['StartTime']=$StartTime }; if ($EndTime) { $f['EndTime']=$EndTime }
    foreach ($e in (Get-WinEvent -FilterHashtable $f -MaxEvents $MaxEvents -ErrorAction Stop)) {
        [void]$psLogs.Add([ordered]@{ timestamp=$e.TimeCreated.ToUniversalTime().ToString('o'); scriptBlock=$e.Message; path='' })
    }
} catch { Add-CollErr 'powerShellLogs' "No script-block logs (channel may be disabled): $($_.Exception.Message)" }

# --- File metadata for autostart/temp locations (light, read-only) ---
$fileMeta = New-Object System.Collections.ArrayList
try {
    $scan = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:TEMP", "$env:windir\Temp"
    )
    foreach ($dir in $scan) {
        if (Test-Path $dir) {
            Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
                [void]$fileMeta.Add([ordered]@{
                    fileName=$_.FullName; size=[int64]$_.Length; permissions=''
                    modified=$_.LastWriteTimeUtc.ToString('o'); accessed=$_.LastAccessTimeUtc.ToString('o'); created=$_.CreationTimeUtc.ToString('o')
                })
            }
        }
    }
} catch { Add-CollErr 'fileMetadata' $_.Exception.Message }

# --- Existing Windows Defender detections (READ-ONLY: does NOT run a scan) ---
$defender = [ordered]@{ executed=$false; threatsFound=0; threats=@() }
try {
    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
    if ($threats.Count -gt 0) {
        $defender.executed = $true; $defender.threatsFound = $threats.Count
        $defender.threats = @($threats | Select-Object -First 50 | ForEach-Object { [ordered]@{ name=[string]$_.ThreatID; file=[string]($_.Resources -join ';'); time=[string]$_.InitialDetectionTime } })
    } else { $defender.executed = $true }
} catch { Add-CollErr 'defender' "Get-MpThreatDetection unavailable: $($_.Exception.Message)" }

# --- Assemble bundle ---
$op = Get-FosOperator
$timeRange = $null
if ($StartTime -or $EndTime) {
    $timeRange = [ordered]@{}
    if ($StartTime) { $timeRange.startUtc = $StartTime.ToUniversalTime().ToString('o') }
    if ($EndTime)   { $timeRange.endUtc   = $EndTime.ToUniversalTime().ToString('o') }
}

$bundle = [ordered]@{
    schemaVersion = '3.0.0'
    metadata = [ordered]@{
        caseId = $caseId
        collectionTimestampUtc = (Get-FosUtcNow)
        targetHostname = $env:COMPUTERNAME
        platform = 'windows'
        osVersion = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        collectorVersion = $collectorVersion
        executionMode = 'local'
        evidenceIntegrityMode = $true
        operator = $op
        timeRange = $timeRange
        errors = @($errors)
    }
    artifacts = [ordered]@{
        persistence = [ordered]@{
            registryRunKeys = @($runKeys)
            scheduledTasks  = @($tasks)
            services        = @($services)
            wmiEventSubscriptions = $wmi
        }
        execution = [ordered]@{
            processes = @($processes)
            processCreationEvents = @()
        }
        network = [ordered]@{ connections = @($connections) }
        credentialAccess = [ordered]@{
            logonEvents = @($logonEvents)
            privilegeEscalationEvents = @($privEsc)
            userCreationEvents = @($userCreate)
            serviceInstallEvents = @($svcInstall)
        }
        fileSystem = [ordered]@{ fileMetadata = @($fileMeta); browserArtifacts = @() }
        powerShellActivity = [ordered]@{ scriptBlockLogs = @($psLogs) }
        antivirusScans = [ordered]@{
            defenderScan = $defender
            clamavScan = [ordered]@{ executed=$false; threatsFound=0; threats=@() }
        }
    }
}

$bundlePath = Join-Path $CaseDir 'bundle.json'
Write-FosJsonFile -InputObject $bundle -Path $bundlePath -Depth 12
Add-FosCocEntry -CaseDir $CaseDir -Action 'COLLECT_DONE' -Detail "runKeys=$($runKeys.Count) tasks=$($tasks.Count) svc=$($services.Count) proc=$($processes.Count) conn=$($connections.Count)" -Files @($bundlePath) | Out-Null
Write-FosLog -Message "Bundle written: $bundlePath" -Level OK -CaseDir $CaseDir

# Emit the bundle path on stdout for the orchestrator
Write-Output $bundlePath
