<#
.SYNOPSIS
    Escalation action for a confirmed incident/breach.
.DESCRIPTION
    Logs the decisive call to the chain of custody and Steps_Taken.txt, then
    optionally invokes a customer-supplied automation script (ticketing, alerting,
    isolation, etc.). Performs NO destructive action itself.
.PARAMETER ReasonCode
    Capitalized, concise reason (e.g. RANSOMWARE_ENCRYPTED_FILES).
.PARAMETER CustomActionScript
    Optional path to an MSP automation script. Receives -ReasonCode and -CaseDir.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReasonCode,
    [Parameter(Mandatory)][string]$CaseDir,
    [string]$CustomActionScript,
    [string]$BrandName = 'First-On-Scene'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Red
Write-Host "  $BrandName :: PROBLEM DETECTED" -ForegroundColor Red
Write-Host "  REASON CODE: $ReasonCode" -ForegroundColor Red
Write-Host "  CASE DIR   : $CaseDir" -ForegroundColor Red
Write-Host "==================================================================" -ForegroundColor Red
Write-Host ""

Write-FosLog -Message "FINAL CALL: PROBLEM_DETECTED ($ReasonCode)" -Level ERROR -CaseDir $CaseDir
Add-FosCocEntry -CaseDir $CaseDir -Action 'FINAL_PROBLEM_DETECTED' -Detail $ReasonCode | Out-Null

if ($CustomActionScript) {
    if (Test-Path $CustomActionScript) {
        Write-FosLog -Message "Invoking custom action script: $CustomActionScript" -Level STEP -CaseDir $CaseDir
        try {
            & $CustomActionScript -ReasonCode $ReasonCode -CaseDir $CaseDir
            Add-FosCocEntry -CaseDir $CaseDir -Action 'CUSTOM_ACTION_RAN' -Detail $CustomActionScript | Out-Null
        } catch {
            Write-FosLog -Message "Custom action script failed: $($_.Exception.Message)" -Level WARN -CaseDir $CaseDir
        }
    } else {
        Write-FosLog -Message "Custom action script not found: $CustomActionScript" -Level WARN -CaseDir $CaseDir
    }
}
exit 20
