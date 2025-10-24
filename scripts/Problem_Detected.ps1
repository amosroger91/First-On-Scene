<# ... (omitted for brevity) ... #>
param(
    [Parameter(Mandatory=$true)]
    [string]$REASON_CODE
)
$LogPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results\Steps_Taken.txt"

Write-Host ""
Write-Host "****************************************************************" -ForegroundColor Red
Write-Host "*** CRITICAL INCIDENT DETECTED ***" -ForegroundColor Red
Write-Host "REASON CODE: $REASON_CODE" -ForegroundColor Red
Write-Host "Triage Agent Halted for Escalation." -ForegroundColor Red
Write-Host "****************************************************************" -ForegroundColor Red

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("CRITICAL INCIDENT DETECTED! REASON CODE: $REASON_CODE. Triage Agent Halted for Escalation.", 'Problem Detected', 'OK', 'Error')

"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: FINAL ACTION: Problem_Detected.ps1 [$REASON_CODE]" | Out-File $LogPath -Append -Encoding UTF8
Exit 1
