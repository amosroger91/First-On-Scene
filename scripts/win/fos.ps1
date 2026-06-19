<#
.SYNOPSIS
    First-On-Scene orchestrator (Windows). One command: collect -> triage -> report -> seal -> act.
.DESCRIPTION
    Runs the full deterministic triage pipeline with zero network egress by default.
    An optional LOCAL-ONLY AI narrative (Ollama) can be enabled; it never changes the verdict.

    Exit codes (consumed by NinjaOne / any RMM):
        0  ALL_CLEAR       10 MONITOR
        20 PROBLEM (Incident)   21 PROBLEM (Breach)    1 runtime error
.PARAMETER Mode
    full (default) | collect | analyze
.PARAMETER EnableLocalAI
    Add a local Ollama narrative (off by default; CJIS-safe when on because it is localhost-only).
.PARAMETER NoAction
    Produce report/verdict but do not invoke the Action-* decision scripts (collect-and-report only).
.EXAMPLE
    .\fos.ps1
.EXAMPLE
    .\fos.ps1 -EnableLocalAI -BrandName "Acme SOC" -CustomProblemScript C:\rmm\alert.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('full','collect','analyze')][string]$Mode = 'full',
    [string]$CaseDir,
    [string]$BundlePath,
    [datetime]$StartTime,
    [datetime]$EndTime,
    [string]$BrandName = 'First-On-Scene',
    [string]$LogoPath,
    [switch]$EnableLocalAI,
    [string]$OllamaModel = 'llama3.1:8b',
    [string]$OllamaEndpoint = 'http://127.0.0.1:11434',
    [string]$CustomProblemScript,
    [string]$CustomAllClearScript,
    [string]$ExpectedRemoteTools = '',
    [switch]$Deep,
    [switch]$NoAction
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

try {
    # 1. COLLECT
    if ($Mode -ne 'analyze') {
        $collectArgs = @{ }
        if ($CaseDir)   { $collectArgs['CaseDir']   = $CaseDir }
        if ($StartTime) { $collectArgs['StartTime'] = $StartTime }
        if ($EndTime)   { $collectArgs['EndTime']   = $EndTime }
        if ($ExpectedRemoteTools) { $collectArgs['ExpectedRemoteTools'] = $ExpectedRemoteTools }
        if ($Deep) { $collectArgs['Deep'] = $true }
        $BundlePath = & (Join-Path $here 'Collect-Artifacts.ps1') @collectArgs | Select-Object -Last 1
        if (-not $CaseDir) { $CaseDir = Split-Path -Parent $BundlePath }
    } else {
        if (-not $BundlePath) { throw "analyze mode requires -BundlePath" }
        if (-not $CaseDir) { $CaseDir = Split-Path -Parent $BundlePath }
    }
    if ($Mode -eq 'collect') {
        New-FosManifest -CaseDir $CaseDir -CaseId (Get-Content $BundlePath -Raw | ConvertFrom-Json).metadata.caseId | Out-Null
        Write-FosLog -Message "Collection complete (collect mode). Bundle: $BundlePath" -Level OK -CaseDir $CaseDir
        Write-Output $CaseDir
        exit 0
    }

    # 2. TRIAGE (deterministic verdict)
    $rulesPath = Join-Path (Split-Path -Parent (Split-Path -Parent $here)) 'rules\detections.json'
    & (Join-Path $here 'Invoke-Triage.ps1') -BundlePath $BundlePath -CaseDir $CaseDir -RulesPath $rulesPath -BrandName $BrandName | Out-Null
    $triageExit = $LASTEXITCODE
    $findingsPath = Join-Path $CaseDir 'findings.json'
    $findings = Get-Content $findingsPath -Raw | ConvertFrom-Json

    # 3. OPTIONAL LOCAL AI NARRATIVE (localhost only; advisory)
    if ($EnableLocalAI) {
        $aiScript = Join-Path $here 'Invoke-LocalAI.ps1'
        if (Test-Path $aiScript) {
            try { & $aiScript -FindingsPath $findingsPath -CaseDir $CaseDir -Model $OllamaModel -Endpoint $OllamaEndpoint }
            catch { Write-FosLog -Message "Local AI narrative skipped: $($_.Exception.Message)" -Level WARN -CaseDir $CaseDir }
        }
    }

    # 4. REPORT
    & (Join-Path $here 'Write-Report.ps1') -FindingsPath $findingsPath -BundlePath $BundlePath -CaseDir $CaseDir -BrandName $BrandName -LogoPath $LogoPath | Out-Null

    # 5. SEAL (manifest over the whole case folder)
    New-FosManifest -CaseDir $CaseDir -CaseId $findings.caseId | Out-Null

    # 6. DECISIVE ACTION
    $exitCode = switch ($findings.verdict) { 'ALL_CLEAR' {0} 'MONITOR' {10} default { if ($findings.classification -eq 'Breach') {21} else {20} } }
    if (-not $NoAction) {
        if ($findings.verdict -eq 'PROBLEM_DETECTED') {
            & (Join-Path $here 'Action-ProblemDetected.ps1') -ReasonCode $findings.reasonCode -CaseDir $CaseDir -CustomActionScript $CustomProblemScript -BrandName $BrandName | Out-Null
        } else {
            & (Join-Path $here 'Action-AllClear.ps1') -CaseDir $CaseDir -CustomActionScript $CustomAllClearScript -BrandName $BrandName | Out-Null
        }
    }

    Write-Host ""
    Write-FosLog -Message "DONE. Verdict=$($findings.verdict) Score=$($findings.score) Class=$($findings.classification) Case=$CaseDir" -Level STEP -CaseDir $CaseDir
    Write-Output $CaseDir
    exit $exitCode
}
catch {
    Write-Host "FATAL: $($_.Exception.Message)" -ForegroundColor Red
    if ($CaseDir) { Write-FosLog -Message "FATAL: $($_.Exception.Message)" -Level ERROR -CaseDir $CaseDir }
    exit 1
}
