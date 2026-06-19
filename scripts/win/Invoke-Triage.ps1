<#
.SYNOPSIS
    First-On-Scene deterministic triage analyzer (Windows).
.DESCRIPTION
    Loads an artifact bundle and the versioned ruleset, evaluates every rule,
    computes a weighted score, classifies the result, and writes findings.json
    + findings.md. Runs with ZERO AI and ZERO network egress.

    Exit codes (RMM-friendly):
        0  ALL_CLEAR
        10 MONITOR (low-confidence findings)
        20 PROBLEM_DETECTED (Incident)
        21 PROBLEM_DETECTED (Breach)
        1  runtime error
.PARAMETER BundlePath
    Path to bundle.json produced by Collect-Artifacts.ps1.
.PARAMETER CaseDir
    Output directory for findings.json / findings.md / chain-of-custody.
.PARAMETER RulesPath
    Path to detections.json. Defaults to ../../rules/detections.json.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BundlePath,
    [Parameter(Mandatory)][string]$CaseDir,
    [string]$RulesPath,
    [string]$BrandName = 'First-On-Scene'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force
$root = Split-Path -Parent (Split-Path -Parent $here)
if (-not $RulesPath) { $RulesPath = Join-Path $root 'rules\detections.json' }

$SeverityRank = @{ info = 0; low = 1; medium = 2; high = 3; critical = 4 }

function Resolve-FosPath {
    param($Root, [string]$Path)
    $node = $Root
    foreach ($seg in $Path.Split('.')) {
        if ($null -eq $node) { return $null }
        $prop = $node.PSObject.Properties[$seg]
        if (-not $prop) { return $null }
        $node = $prop.Value
    }
    $node
}

function Test-FosCondition {
    param($Item, $Cond)
    $val = $null
    $p = $Item.PSObject.Properties[$Cond.field]
    if ($p) { $val = $p.Value }
    $sval = if ($null -ne $val) { [string]$val } else { '' }

    switch ($Cond.op) {
        'regexI'      { return [regex]::IsMatch($sval, $Cond.value, 'IgnoreCase') }
        'notRegexI'   { return -not [regex]::IsMatch($sval, $Cond.value, 'IgnoreCase') }
        'containsI'   { return $sval.IndexOf([string]$Cond.value, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 }
        'notContainsI'{ return $sval.IndexOf([string]$Cond.value, [System.StringComparison]::OrdinalIgnoreCase) -lt 0 }
        'eq'          { return ($sval -eq [string]$Cond.value) }
        'ne'          { return ($sval -ne [string]$Cond.value) }
        'gt'          { return ([double]$val -gt [double]$Cond.value) }
        'lt'          { return ([double]$val -lt [double]$Cond.value) }
        'ge'          { return ([double]$val -ge [double]$Cond.value) }
        'le'          { return ([double]$val -le [double]$Cond.value) }
        'in'          { return (@($Cond.value) -contains $val) }
        'notIn'       { return (-not (@($Cond.value) -contains $val)) }
        'exists'      { return ($sval -ne '') }
        'isTrue'      { return ($val -eq $true) }
        'isFalse'     { return ($val -eq $false -or $null -eq $val) }
        default       { return $false }
    }
}

function Test-FosItem {
    param($Item, $Rule)
    $results = foreach ($c in $Rule.conditions) { Test-FosCondition -Item $Item -Cond $c }
    if ($Rule.match -eq 'any') { return (@($results) -contains $true) }
    return (-not (@($results) -contains $false))   # 'all'
}

function Invoke-FosBuiltin {
    param($Bundle, $Rule)
    # Returns an array of evidence objects (empty = no fire).
    switch ($Rule.id) {
        'FOS-PER-004' {
            $w = Resolve-FosPath $Bundle 'artifacts.persistence.wmiEventSubscriptions'
            if (-not $w) { return @() }
            # Only the executable consumer types (CommandLine/ActiveScript) are dangerous.
            # Windows and some management agents ship benign default filters/bindings; do not fire on those.
            $consumers = @($w.eventConsumers)
            if ($consumers.Count -gt 0) {
                return @([pscustomobject]@{ consumerCount = $consumers.Count; consumers = $consumers })
            }
            return @()
        }
        'FOS-CRD-001' {
            $ca = Resolve-FosPath $Bundle 'artifacts.credentialAccess'
            if (-not $ca) { return @() }
            $admin = @($ca.privilegeEscalationEvents) + @($ca.logonEvents | Where-Object { $_.eventId -eq 4672 })
            $svc   = @($ca.logonEvents | Where-Object { $_.eventId -eq 4624 -and $_.logonType -eq 5 })
            if ((@($admin).Count -gt 0) -and (@($svc).Count -gt 0)) {
                return @([pscustomobject]@{ privilegedLogons = @($admin).Count; serviceLogons = @($svc).Count })
            }
            return @()
        }
        'FOS-AF-001' {
            $fm = Resolve-FosPath $Bundle 'artifacts.fileSystem.fileMetadata'
            $hits = foreach ($f in @($fm)) {
                try {
                    $cr = [datetime]::Parse($f.created); $mo = [datetime]::Parse($f.modified)
                    if ($cr -gt $mo) { $f }
                } catch {}
            }
            return @($hits)
        }
        'FOS-AV-001' {
            $s = Resolve-FosPath $Bundle 'artifacts.antivirusScans.defenderScan'
            if ($s -and ([int]$s.threatsFound -gt 0)) { return @([pscustomobject]@{ scanner='Windows Defender'; threatsFound=$s.threatsFound; threats=$s.threats }) }
            return @()
        }
        'FOS-AV-002' {
            $s = Resolve-FosPath $Bundle 'artifacts.antivirusScans.clamavScan'
            if ($s -and ([int]$s.threatsFound -gt 0)) { return @([pscustomobject]@{ scanner='ClamAV'; threatsFound=$s.threatsFound; threats=$s.threats }) }
            return @()
        }
        'FOS-RAT-001' {
            $t = @(Resolve-FosPath $Bundle 'artifacts.remoteAccess.tools')
            return @($t | Where-Object { $_ -and ($_.authorized -eq $false) })
        }
        'FOS-RAT-002' {
            $t = @(Resolve-FosPath $Bundle 'artifacts.remoteAccess.tools')
            return @($t | Where-Object { $_ -and ($_.authorized -eq $true) })
        }
        'FOS-DEF-001' {
            $d = Resolve-FosPath $Bundle 'artifacts.securityPosture.defender'
            if ($d -and ($d.available -eq $true) -and ($d.realTimeEnabled -eq $false)) { return @([pscustomobject]@{ realTimeEnabled=$false; antivirusEnabled=$d.antivirusEnabled }) }
            return @()
        }
        'FOS-DEF-002' {
            $d = Resolve-FosPath $Bundle 'artifacts.securityPosture.defender'
            if (-not $d) { return @() }
            $ex = @($d.exclusionPaths) + @($d.exclusionExtensions) + @($d.exclusionProcesses)
            if (@($ex | Where-Object { $_ }).Count -gt 0) { return @([pscustomobject]@{ paths=$d.exclusionPaths; extensions=$d.exclusionExtensions; processes=$d.exclusionProcesses }) }
            return @()
        }
        'FOS-DEF-003' {
            $d = Resolve-FosPath $Bundle 'artifacts.securityPosture.defender'
            if ($d -and ($d.available -eq $true) -and ($d.tamperProtectionEnabled -eq $false)) { return @([pscustomobject]@{ tamperProtectionEnabled=$false }) }
            return @()
        }
        'FOS-DEF-004' {
            $fw = Resolve-FosPath $Bundle 'artifacts.securityPosture.firewall'
            if ($fw -and ($fw.available -eq $true)) {
                $off = @($fw.profiles | Where-Object { $_ -and ($_.enabled -eq $false) })
                if ($off.Count -gt 0) { return @([pscustomobject]@{ disabledProfiles = @($off | ForEach-Object { $_.name }); profiles = $fw.profiles }) }
            }
            return @()
        }
        default { return @() }
    }
}

# --- Load inputs ---
Write-FosLog -Message "Loading bundle: $BundlePath" -Level STEP -CaseDir $CaseDir
$bundle = Get-Content -LiteralPath $BundlePath -Raw | ConvertFrom-Json
$bv = Test-FosBundle -Bundle $bundle
if (-not $bv.Valid) { Write-FosLog -Message "Invalid bundle: $($bv.Errors -join ', ')" -Level ERROR -CaseDir $CaseDir; exit 1 }

$ruleset = Get-Content -LiteralPath $RulesPath -Raw | ConvertFrom-Json
$thr = $ruleset.scoring.thresholds
Add-FosCocEntry -CaseDir $CaseDir -Action 'ANALYSIS_START' -Detail "ruleset $($ruleset.rulesetVersion); $(@($ruleset.rules).Count) rules" -Files @($BundlePath) | Out-Null

# --- Evaluate rules ---
$EVIDENCE_CAP = 25
$findings = @()
foreach ($rule in $ruleset.rules) {
    $evidence = @()
    if ($rule.type -eq 'builtin') {
        $evidence = Invoke-FosBuiltin -Bundle $bundle -Rule $rule
    } else {
        $items = @(Resolve-FosPath $bundle $rule.selector)
        $evidence = @($items | Where-Object { $_ -and (Test-FosItem -Item $_ -Rule $rule) })
    }
    if (@($evidence).Count -gt 0) {
        $count = @($evidence).Count
        $findings += [pscustomobject]@{
            ruleId        = $rule.id
            name          = $rule.name
            category      = $rule.category
            mitre         = $rule.mitre
            severity      = $rule.severity
            weight        = [int]$rule.weight
            rationale     = $rule.rationale
            falsePositive = $rule.falsePositive
            reasonCode    = $rule.reasonCode
            escalate      = [bool]$rule.escalateToBreach
            evidenceCount = $count
            evidence      = @($evidence | Select-Object -First $EVIDENCE_CAP)
        }
    }
}

# --- Score / classify ---
# Severity-based multiplier cap so one noisy low/medium category cannot dominate the verdict.
$MultCap = @{ info = 1; low = 1; medium = 2; high = 3; critical = 3 }
$score = 0
foreach ($f in $findings) {
    $cap = $MultCap[$f.severity]; if (-not $cap) { $cap = 1 }
    $score += ($f.weight * [Math]::Min($f.evidenceCount, $cap))
}

$verdict = 'ALL_CLEAR'; $classification = 'None'; $exit = 0
if ($score -ge [int]$thr.problem) { $verdict = 'PROBLEM_DETECTED' }
elseif ($score -ge [int]$thr.monitor) { $verdict = 'MONITOR' }

$isBreach = ($score -ge [int]$thr.breach) -or (@($findings | Where-Object { $_.escalate }).Count -gt 0)
switch ($verdict) {
    'ALL_CLEAR'        { $classification = 'None';  $exit = 0 }
    'MONITOR'          { $classification = 'Event'; $exit = 10 }
    'PROBLEM_DETECTED' { if ($isBreach) { $classification = 'Breach'; $exit = 21 } else { $classification = 'Incident'; $exit = 20 } }
}

$maxSev = 'info'
foreach ($f in $findings) { if ($SeverityRank[$f.severity] -gt $SeverityRank[$maxSev]) { $maxSev = $f.severity } }

# reason code = from highest-weight finding
$topFinding = $findings | Sort-Object -Property @{ Expression = { $_.weight * [Math]::Min($_.evidenceCount,3) } } -Descending | Select-Object -First 1
$reasonCode = if ($topFinding) { $topFinding.reasonCode } else { 'NO_FINDINGS' }

$summaryCounts = @{}
foreach ($f in $findings) {
    $key = $f.category
    if ($summaryCounts.ContainsKey($key)) { $summaryCounts[$key] += $f.evidenceCount } else { $summaryCounts[$key] = $f.evidenceCount }
}

$op = Get-FosOperator
$result = [ordered]@{
    caseId               = $bundle.metadata.caseId
    analyzedTimestampUtc = (Get-FosUtcNow)
    engineVersion        = (Get-FosEngineVersion)
    rulesetVersion       = $ruleset.rulesetVersion
    targetHostname       = $bundle.metadata.targetHostname
    analyst              = [ordered]@{ user = $op.user; host = $op.host }
    verdict              = $verdict
    score                = $score
    severity             = $maxSev
    classification       = $classification
    reasonCode           = $reasonCode
    thresholds           = $thr
    summaryCounts        = $summaryCounts
    findings             = @($findings)
}

$findingsJson = Join-Path $CaseDir 'findings.json'
Write-FosJsonFile -InputObject $result -Path $findingsJson

# --- findings.md ---
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# $BrandName - Triage Findings")
[void]$md.AppendLine("")
[void]$md.AppendLine("| Field | Value |")
[void]$md.AppendLine("|---|---|")
[void]$md.AppendLine("| Case ID | $($result.caseId) |")
[void]$md.AppendLine("| Host | $($result.targetHostname) |")
[void]$md.AppendLine("| Analyzed (UTC) | $($result.analyzedTimestampUtc) |")
[void]$md.AppendLine("| **Verdict** | **$($result.verdict)** |")
[void]$md.AppendLine("| Classification | $($result.classification) |")
[void]$md.AppendLine("| Severity | $($result.severity) |")
[void]$md.AppendLine("| Score | $($result.score) (monitor=$($thr.monitor), problem=$($thr.problem), breach=$($thr.breach)) |")
[void]$md.AppendLine("| Reason Code | $($result.reasonCode) |")
[void]$md.AppendLine("| Ruleset | $($result.rulesetVersion) · Engine $($result.engineVersion) |")
[void]$md.AppendLine("")
if (@($findings).Count -eq 0) {
    [void]$md.AppendLine("_No detections fired. System appears clean based on collected artifacts._")
} else {
    [void]$md.AppendLine("## Detections ($(@($findings).Count))")
    [void]$md.AppendLine("")
    foreach ($f in ($findings | Sort-Object -Property @{Expression={$_.weight};Descending=$true})) {
        [void]$md.AppendLine("### [$($f.ruleId)] $($f.name)")
        [void]$md.AppendLine("- **Category:** $($f.category)  |  **Severity:** $($f.severity)  |  **Weight:** $($f.weight)  |  **Matches:** $($f.evidenceCount)")
        if ($f.mitre) { [void]$md.AppendLine("- **MITRE ATT&CK:** $($f.mitre.tactic) / $($f.mitre.technique)") }
        [void]$md.AppendLine("- **Why it matters:** $($f.rationale)")
        [void]$md.AppendLine("- **False-positive guidance:** $($f.falsePositive)")
        [void]$md.AppendLine("")
    }
}
Write-FosTextFile -Text ($md.ToString()) -Path (Join-Path $CaseDir 'findings.md')

Add-FosCocEntry -CaseDir $CaseDir -Action 'ANALYSIS_DONE' -Detail "verdict=$verdict score=$score class=$classification findings=$(@($findings).Count)" -Files @($findingsJson) | Out-Null
Write-FosLog -Message "Verdict: $verdict | Score: $score | Class: $classification | Findings: $(@($findings).Count)" -Level OK -CaseDir $CaseDir

exit $exit
