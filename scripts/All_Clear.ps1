<# ... (omitted for brevity) ... #>
param()
$LogPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results\Steps_Taken.txt"

Write-Host ""
Write-Host "****************************************************************" -ForegroundColor Green
Write-Host "*** ALL CLEAR ***" -ForegroundColor Green
Write-Host "No definitive security incident (Breach/Uncontained Incident) confirmed." -ForegroundColor Green
Write-Host "Triage Agent Complete." -ForegroundColor Green
Write-Host "****************************************************************" -ForegroundColor Green

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show('No definitive security incident confirmed. Triage Agent Complete.', 'All Clear', 'OK', 'Information')

"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: FINAL ACTION: All_Clear.ps1 (Contained Event/False Positive)" | Out-File $LogPath -Append -Encoding UTF8
Exit 0
