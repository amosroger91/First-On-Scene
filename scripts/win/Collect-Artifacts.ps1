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
    [int]$MaxEvents = 1000,
    [string]$ExpectedRemoteTools = '',
    [switch]$Deep
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

# --- Remote-access / RMM tool inventory (read-only) ---
$RemoteToolDefs = @(
    @{ tool='AnyDesk'; rx='anydesk' },
    @{ tool='TeamViewer'; rx='teamviewer' },
    @{ tool='ScreenConnect / ConnectWise Control'; rx='screenconnect|connectwise.?control' },
    @{ tool='ConnectWise Automate (LabTech)'; rx='ltsvc|labtech|connectwise automate' },
    @{ tool='NinjaOne (NinjaRMM)'; rx='ninjarmm|ninjaone' },
    @{ tool='Atera'; rx='ateraagent|\batera\b' },
    @{ tool='Splashtop'; rx='splashtop|srservice|srmanager' },
    @{ tool='RustDesk'; rx='rustdesk' },
    @{ tool='LogMeIn'; rx='logmein' },
    @{ tool='GoTo / GoToAssist'; rx='gotoassist|gotoresolve|g2comm|logmeinrescue' },
    @{ tool='VNC (Ultra/Tight/Real)'; rx='winvnc|tvnserver|vncserver|uvnc|realvnc|tightvnc' },
    @{ tool='Ammyy Admin'; rx='ammyy|aa_v3' },
    @{ tool='Remote Utilities'; rx='rutserv|rfusclient|remote utilities' },
    @{ tool='DWAgent'; rx='dwagent' },
    @{ tool='Supremo'; rx='supremo' },
    @{ tool='Action1'; rx='action1' },
    @{ tool='Syncro'; rx='syncro|kabuto' },
    @{ tool='Datto RMM'; rx='cagservice|centrastage|datto rmm' },
    @{ tool='Kaseya'; rx='kaseya|agentmon' },
    @{ tool='BeyondTrust / Bomgar'; rx='bomgar|beyondtrust' },
    @{ tool='Chrome Remote Desktop'; rx='remoting_host|chrome remote desktop|chromoting' },
    @{ tool='ToDesk'; rx='todesk' },
    @{ tool='Parsec'; rx='\bparsec' },
    @{ tool='Quick Assist / Remote Assistance'; rx='quickassist|msra\.exe' }
)
$expectedTokens = @()
if ($ExpectedRemoteTools) { $expectedTokens = $ExpectedRemoteTools -split '[,;]' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } }
$remoteTools = New-Object System.Collections.ArrayList
try {
    $installed = @()
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        $installed += Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object -ExpandProperty DisplayName
    }
    $procNames = @($processes | ForEach-Object { $_.name })
    $svcText   = @($services  | ForEach-Object { "$($_.name) $($_.displayName) $($_.pathName)" })
    foreach ($def in $RemoteToolDefs) {
        $ev = @()
        if ($procNames | Where-Object { $_ -match $def.rx }) { $ev += 'process' }
        if ($svcText   | Where-Object { $_ -match $def.rx }) { $ev += 'service' }
        $instMatch = @($installed | Where-Object { $_ -match $def.rx })
        if ($instMatch.Count -gt 0) { $ev += 'installed' }
        if ($ev.Count -gt 0) {
            $tl = $def.tool.ToLower()
            $auth = $false
            foreach ($tok in $expectedTokens) { if ($tl -like "*$tok*") { $auth = $true; break } }
            [void]$remoteTools.Add([ordered]@{ tool=$def.tool; evidence=($ev -join ','); detail=([string]($instMatch | Select-Object -First 1)); authorized=$auth })
        }
    }
} catch { Add-CollErr 'remoteAccess' $_.Exception.Message }

# --- Security posture: Microsoft Defender health & tamper state ---
$defenderPosture = [ordered]@{ available=$false; realTimeEnabled=$null; antivirusEnabled=$null; tamperProtectionEnabled=$null; exclusionPaths=@(); exclusionExtensions=@(); exclusionProcesses=@() }
try {
    $st = Get-MpComputerStatus -ErrorAction Stop
    $pf = Get-MpPreference -ErrorAction SilentlyContinue
    $defenderPosture.available = $true
    $defenderPosture.realTimeEnabled = [bool]$st.RealTimeProtectionEnabled
    $defenderPosture.antivirusEnabled = [bool]$st.AntivirusEnabled
    $defenderPosture.tamperProtectionEnabled = [bool]$st.IsTamperProtected
    if ($pf) { $defenderPosture.exclusionPaths=@($pf.ExclusionPath|Where-Object{$_}); $defenderPosture.exclusionExtensions=@($pf.ExclusionExtension|Where-Object{$_}); $defenderPosture.exclusionProcesses=@($pf.ExclusionProcess|Where-Object{$_}) }
} catch { Add-CollErr 'securityPosture' "Defender status unavailable: $($_.Exception.Message)" }

# --- Process signature + SHA-256 + image-deleted (dedup by path) ---
try {
    $sigCache=@{}
    foreach ($pr in $processes) {
        $path=[string]$pr.executablePath
        $pr['signatureStatus']=''; $pr['signer']=''; $pr['sha256']=''; $pr['imageDeleted']=$false
        if ($path -match '^[A-Za-z]:\\') {
            if (Test-Path -LiteralPath $path) {
                if (-not $sigCache.ContainsKey($path)) {
                    $s=''; $signer=''; $hash=''
                    try { $sig=Get-AuthenticodeSignature -LiteralPath $path -ErrorAction SilentlyContinue; if($sig){$s=[string]$sig.Status; if($sig.SignerCertificate){$signer=$sig.SignerCertificate.Subject}} } catch {}
                    try { $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower() } catch {}
                    $sigCache[$path]=@{status=$s;signer=$signer;sha256=$hash}
                }
                $pr['signatureStatus']=$sigCache[$path].status; $pr['signer']=$sigCache[$path].signer; $pr['sha256']=$sigCache[$path].sha256
            } else { $pr['imageDeleted']=$true }
        }
    }
} catch { Add-CollErr 'processSignatures' $_.Exception.Message }

# --- ASEP: high-value autostart hijacks (only anomalies recorded) ---
$asep = New-Object System.Collections.ArrayList
try {
    $ifeoRoot='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $accessib='sethc\.exe|utilman\.exe|osk\.exe|magnify\.exe|narrator\.exe|displayswitch\.exe|atbroker\.exe'
    if (Test-Path $ifeoRoot) {
        foreach ($k in (Get-ChildItem $ifeoRoot -ErrorAction SilentlyContinue)) {
            $dbg=(Get-ItemProperty -Path $k.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if ($dbg) { $cat=if($k.PSChildName -match $accessib){'Accessibility'}else{'IFEO'}; [void]$asep.Add([ordered]@{category=$cat;location=$k.PSChildName;name='Debugger';value=[string]$dbg}) }
        }
    }
    foreach ($w in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $ai=(Get-ItemProperty -Path $w -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
        if ($ai -and $ai.Trim()) { [void]$asep.Add([ordered]@{category='AppInitDLLs';location=$w;name='AppInit_DLLs';value=[string]$ai}) }
    }
    $wl='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell=(Get-ItemProperty -Path $wl -Name Shell -ErrorAction SilentlyContinue).Shell
    $userinit=(Get-ItemProperty -Path $wl -Name Userinit -ErrorAction SilentlyContinue).Userinit
    if ($shell -and $shell -notmatch '^explorer\.exe\s*$') { [void]$asep.Add([ordered]@{category='Winlogon';location=$wl;name='Shell';value=[string]$shell}) }
    if ($userinit -and $userinit -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?\s*$') { [void]$asep.Add([ordered]@{category='Winlogon';location=$wl;name='Userinit';value=[string]$userinit}) }
} catch { Add-CollErr 'asep' $_.Exception.Message }

# --- Access control posture (context) ---
$accessControl=[ordered]@{ localAdmins=@(); rdpEnabled=$null; shares=@() }
try {
    try { $accessControl.localAdmins=@(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { [string]$_.Name }) }
    catch { $accessControl.localAdmins=@((net localgroup administrators) 2>$null | Where-Object { $_ -and $_ -notmatch '----|completed|^Members|^Alias|^Comment' }) }
    $deny=(Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    $accessControl.rdpEnabled=($deny -eq 0)
    $accessControl.shares=@(Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { "$($_.Name) -> $($_.Path)" })
} catch { Add-CollErr 'accessControl' $_.Exception.Message }

# --- Log tampering: Security(1102)/System(104) cleared ---
$logClear=New-Object System.Collections.ArrayList
foreach ($spec in @(@{log='Security';id=1102},@{log='System';id=104})) {
    $f=@{LogName=$spec.log;Id=$spec.id}; if($StartTime){$f['StartTime']=$StartTime}; if($EndTime){$f['EndTime']=$EndTime}
    try { foreach($e in (Get-WinEvent -FilterHashtable $f -MaxEvents 20 -ErrorAction Stop)){ [void]$logClear.Add([ordered]@{eventId=$spec.id;timestamp=$e.TimeCreated.ToUniversalTime().ToString('o');log=$spec.log;message=(($e.Message -split "`n"|Select-Object -First 2) -join ' ')}) } } catch {}
}

# --- Deep-mode artifacts: prefetch + possible-injection modules ---
$prefetch=New-Object System.Collections.ArrayList
$injectedModules=New-Object System.Collections.ArrayList
if ($Deep) {
    try { $pfDir="$env:windir\Prefetch"; if(Test-Path $pfDir){ Get-ChildItem -LiteralPath $pfDir -Filter *.pf -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 300|ForEach-Object{ [void]$prefetch.Add([ordered]@{name=$_.Name;lastRunUtc=$_.LastWriteTimeUtc.ToString('o')}) } } } catch { Add-CollErr 'prefetch' $_.Exception.Message }
    try {
        $modCache=@{}
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            try { foreach ($m in $p.Modules) { $mp=$m.FileName; if ($mp -match '\\(Users|Temp|AppData|ProgramData)\\') { if(-not $modCache.ContainsKey($mp)){ $stt='';try{$stt=[string](Get-AuthenticodeSignature -LiteralPath $mp -ErrorAction SilentlyContinue).Status}catch{}; $modCache[$mp]=$stt }; if($modCache[$mp] -ne 'Valid'){ [void]$injectedModules.Add([ordered]@{process=$p.ProcessName;module=$mp;signatureStatus=$modCache[$mp]}) } } } } catch {}
        }
    } catch { Add-CollErr 'injectedModules' $_.Exception.Message }
}

# --- Network state: listeners (TCP+UDP), DNS client cache, hosts file (read-only, local) ---
$listeners = New-Object System.Collections.ArrayList
try {
    $procMap2 = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap2[$_.Id] = $_.ProcessName }
    foreach ($l in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        [void]$listeners.Add([ordered]@{ protocol='TCP'; localAddress=[string]$l.LocalAddress; localPort=[int]$l.LocalPort; processId=[int]$l.OwningProcess; processName=[string]$procMap2[[int]$l.OwningProcess] })
    }
    foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        [void]$listeners.Add([ordered]@{ protocol='UDP'; localAddress=[string]$u.LocalAddress; localPort=[int]$u.LocalPort; processId=[int]$u.OwningProcess; processName=[string]$procMap2[[int]$u.OwningProcess] })
    }
} catch { Add-CollErr 'listeners' $_.Exception.Message }

$dnsCache = New-Object System.Collections.ArrayList
try {
    foreach ($d in (Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First $MaxEvents)) {
        [void]$dnsCache.Add([ordered]@{ entry=[string]$d.Entry; name=[string]$d.Name; data=[string]$d.Data; type=[string]$d.Type; ttl=[int]$d.TimeToLive })
    }
} catch { Add-CollErr 'dnsCache' $_.Exception.Message }

$hostsEntries = New-Object System.Collections.ArrayList
try {
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hostsPath) {
        foreach ($line in (Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#')) { continue }
            $parts = $t -split '\s+'
            if ($parts.Count -ge 2) {
                [void]$hostsEntries.Add([ordered]@{ ipAddress=$parts[0]; hostnames=(($parts[1..($parts.Count-1)] | Where-Object { $_ -and -not $_.StartsWith('#') }) -join ' '); raw=$t })
            }
        }
    }
} catch { Add-CollErr 'hostsFile' $_.Exception.Message }

# --- Security posture: Windows Firewall profiles (read-only) ---
$firewall = [ordered]@{ available=$false; profiles=@() }
try {
    $fwp = @(Get-NetFirewallProfile -ErrorAction Stop)
    if ($fwp.Count -gt 0) {
        $firewall.available = $true
        $firewall.profiles = @($fwp | ForEach-Object { [ordered]@{ name=[string]$_.Name; enabled=[bool]$_.Enabled; defaultInboundAction=[string]$_.DefaultInboundAction; defaultOutboundAction=[string]$_.DefaultOutboundAction } })
    }
} catch { Add-CollErr 'firewall' "Firewall profile state unavailable: $($_.Exception.Message)" }

# --- Deep-mode: running kernel drivers with signature status ---
$drivers = New-Object System.Collections.ArrayList
if ($Deep) {
    try {
        $drvSig = @{}
        foreach ($drv in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' })) {
            $dp = [string]$drv.PathName -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$env:windir\"
            $sg = ''; $sn = ''
            if ($dp -match '^[A-Za-z]:\\' -and (Test-Path -LiteralPath $dp)) {
                if (-not $drvSig.ContainsKey($dp)) {
                    try { $s = Get-AuthenticodeSignature -LiteralPath $dp -ErrorAction SilentlyContinue; if ($s) { $sg = [string]$s.Status; if ($s.SignerCertificate) { $sn = $s.SignerCertificate.Subject } } } catch {}
                    $drvSig[$dp] = @{ status=$sg; signer=$sn }
                }
                $sg = $drvSig[$dp].status; $sn = $drvSig[$dp].signer
            }
            [void]$drivers.Add([ordered]@{ name=[string]$drv.Name; displayName=[string]$drv.DisplayName; pathName=$dp; state=[string]$drv.State; startMode=[string]$drv.StartMode; signatureStatus=$sg; signer=$sn })
        }
    } catch { Add-CollErr 'drivers' $_.Exception.Message }
}

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
        expectedRemoteTools = @($expectedTokens)
        operator = $op
        timeRange = $timeRange
        errors = @($errors)
    }
    artifacts = [ordered]@{
        remoteAccess = [ordered]@{ tools = @($remoteTools) }
        securityPosture = [ordered]@{ defender = $defenderPosture; firewall = $firewall }
        accessControl = $accessControl
        defenseEvasion = [ordered]@{ logClearEvents = @($logClear) }
        persistence = [ordered]@{
            registryRunKeys = @($runKeys)
            scheduledTasks  = @($tasks)
            services        = @($services)
            wmiEventSubscriptions = $wmi
            asep = @($asep)
        }
        execution = [ordered]@{
            processes = @($processes)
            processCreationEvents = @()
            prefetch = @($prefetch)
            injectedModules = @($injectedModules)
            drivers = @($drivers)
        }
        network = [ordered]@{ connections = @($connections); listeners = @($listeners); dnsCache = @($dnsCache); hostsFileEntries = @($hostsEntries) }
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
