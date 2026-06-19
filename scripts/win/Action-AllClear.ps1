<#
.SYNOPSIS
    Clearance action for a false positive or contained event.
.DESCRIPTION
    Logs the all-clear decision to the chain of custody and Steps_Taken.txt, then
    optionally invokes a customer-supplied automation script (close ticket, notify).
.PARAMETER CustomActionScript
    Optional path to an MSP automation script. Receives -CaseDir.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CaseDir,
    [string]$CustomActionScript,
    [string]$BrandName = 'First-On-Scene'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "  $BrandName :: ALL CLEAR" -ForegroundColor Green
Write-Host "  CASE DIR: $CaseDir" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""

Write-FosLog -Message "FINAL CALL: ALL_CLEAR" -Level OK -CaseDir $CaseDir
Add-FosCocEntry -CaseDir $CaseDir -Action 'FINAL_ALL_CLEAR' -Detail 'No actionable threat confirmed.' | Out-Null

if ($CustomActionScript) {
    if (Test-Path $CustomActionScript) {
        Write-FosLog -Message "Invoking custom action script: $CustomActionScript" -Level STEP -CaseDir $CaseDir
        try {
            & $CustomActionScript -CaseDir $CaseDir
            Add-FosCocEntry -CaseDir $CaseDir -Action 'CUSTOM_ACTION_RAN' -Detail $CustomActionScript | Out-Null
        } catch {
            Write-FosLog -Message "Custom action script failed: $($_.Exception.Message)" -Level WARN -CaseDir $CaseDir
        }
    } else {
        Write-FosLog -Message "Custom action script not found: $CustomActionScript" -Level WARN -CaseDir $CaseDir
    }
}
exit 0
