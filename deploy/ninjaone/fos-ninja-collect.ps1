<#
.SYNOPSIS
    First-On-Scene runner for NinjaOne (Windows). Paste into Script Library, run as System.
.DESCRIPTION
    Runs the deterministic First-On-Scene pipeline on the endpoint, then publishes the
    verdict into NinjaOne custom fields and returns a verdict-based exit code so you can
    branch automation off Conditions (auto-ticket / alert on PROBLEM_DETECTED).

    CJIS NOTE: No data leaves the device. Local AI is OFF here. Stage the toolkit from an
    INTERNAL source (network share or your RMM software repo) - not the public internet -
    when operating in a regulated environment.

    Exit codes: 0 ALL_CLEAR | 10 MONITOR | 20 PROBLEM (Incident) | 21 PROBLEM (Breach) | 1 error

    NinjaOne setup (see docs/DEPLOYMENT_NINJAONE.md):
      * Script Library -> New (PowerShell), Architecture: 64-bit, Run As: System.
      * Pre-create custom fields (Role/Device): fosVerdict, fosScore, fosClassification,
        fosReasonCode, fosCasePath (text) and fosFindings (WYSIWYG/multiline).
      * Optionally pass parameters via the "Preset Parameter" field below.

    Parameters (via NinjaOne preset parameter string or script variables):
      -InstallPath  Where the toolkit lives on the endpoint (default C:\ProgramData\FirstOnScene)
      -StageFrom    Optional internal share/URL to copy the toolkit from before running
      -BrandName    Branding for the report
#>
[CmdletBinding()]
param(
    [string]$InstallPath = 'C:\ProgramData\FirstOnScene',
    [string]$StageFrom,
    [string]$BrandName = 'First-On-Scene'
)
$ErrorActionPreference = 'Stop'

function Set-NinjaField {
    param([string]$Name, [string]$Value)
    # Ninja-Property-Set is provided by the NinjaOne agent at runtime.
    if (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) {
        try { Ninja-Property-Set $Name $Value | Out-Null } catch { Write-Host "WARN: could not set field $Name : $($_.Exception.Message)" }
    } else {
        Write-Host "[no-ninja] $Name = $Value"
    }
}

try {
    # 1. Optionally stage the toolkit from an internal source (NOT public internet for CJIS).
    if ($StageFrom) {
        Write-Host "Staging First-On-Scene from $StageFrom -> $InstallPath"
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
        if ($StageFrom -match '^https?://') {
            $zip = Join-Path $env:TEMP 'fos.zip'
            Invoke-WebRequest -Uri $StageFrom -OutFile $zip -UseBasicParsing
            Expand-Archive -Path $zip -DestinationPath $InstallPath -Force
        } else {
            Copy-Item -Path (Join-Path $StageFrom '*') -Destination $InstallPath -Recurse -Force
        }
    }

    # 2. Locate fos.ps1
    $fos = Get-ChildItem -Path $InstallPath -Recurse -Filter 'fos.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $fos) { throw "fos.ps1 not found under $InstallPath. Stage the toolkit first (-StageFrom)." }

    # 3. Run full pipeline (collect + triage + report + seal). -NoAction: NinjaOne owns the response.
    $caseRoot = Join-Path $env:ProgramData 'FirstOnScene\cases'
    New-Item -ItemType Directory -Path $caseRoot -Force | Out-Null
    $caseDir = Join-Path $caseRoot ("case-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    & $fos.FullName -Mode full -CaseDir $caseDir -BrandName $BrandName -NoAction | Out-Null
    $exit = $LASTEXITCODE

    # 4. Publish verdict to NinjaOne custom fields
    $findingsPath = Join-Path $caseDir 'findings.json'
    if (Test-Path $findingsPath) {
        $f = Get-Content $findingsPath -Raw | ConvertFrom-Json
        Set-NinjaField 'fosVerdict'        $f.verdict
        Set-NinjaField 'fosScore'          ([string]$f.score)
        Set-NinjaField 'fosClassification' $f.classification
        Set-NinjaField 'fosReasonCode'     $f.reasonCode
        Set-NinjaField 'fosCasePath'       $caseDir
        $top = ($f.findings | Sort-Object weight -Descending | Select-Object -First 8 |
                ForEach-Object { "[$($_.severity)] $($_.ruleId) $($_.name) (x$($_.evidenceCount))" }) -join "`n"
        Set-NinjaField 'fosFindings' $top
        Write-Host "First-On-Scene: $($f.verdict) (score $($f.score), $($f.classification)). Case: $caseDir"
    } else {
        Write-Host "First-On-Scene: findings.json not produced."; exit 1
    }

    exit $exit
}
catch {
    Write-Host "First-On-Scene ERROR: $($_.Exception.Message)"
    Set-NinjaField 'fosVerdict' 'ERROR'
    exit 1
}
