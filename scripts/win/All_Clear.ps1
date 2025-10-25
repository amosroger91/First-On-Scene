<#
.SYNOPSIS
    *** CUSTOMIZABLE ACTION TEMPLATE: NO PROBLEM DETECTED (ALL CLEAR) ***

.DESCRIPTION
    This script is automatically executed when the AI Triage Agent determines that
    no immediate cybersecurity problem has been detected, and the system state is
    clear, nominal, or represents a contained/resolved event.

    **THIS IS A TEMPLATE** - You are encouraged to replace the entire body of this
    script with your own custom automation logic while keeping the parameter structure.

.PARAMETER CustomActionScript
    Optional path to a custom PowerShell script that will be executed instead of the
    default actions below.

.NOTES
    CUSTOMIZATION EXAMPLES:
    Replace the default implementation below with your own custom logic, such as:

    1. **Log a Successful System Check or Status Report**
       ```powershell
       $statusReport = @{
           hostname = $env:COMPUTERNAME
           status = "ALL_CLEAR"
           timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
           message = "First-On-Scene triage completed - no threats detected"
       } | ConvertTo-Json
       Add-Content -Path "C:\Logs\security_status.log" -Value $statusReport
       ```

    2. **Clear a Previous Alert or Close an Associated Ticket**
       Example (ServiceNow):
       ```powershell
       $ticketNumber = "INC0010001"  # Could be retrieved from previous run
       $closeData = @{
           state = "7"  # Closed
           close_notes = "First-On-Scene analysis: No security incident confirmed"
           close_code = "Solved (Permanently)"
       } | ConvertTo-Json
       Invoke-RestMethod -Uri "https://your-instance.service-now.com/api/now/table/incident/$ticketNumber" `
           -Method Patch -Body $closeData -Headers @{Authorization="Basic YOUR_API_KEY"}
       ```

    3. **Update a Status Dashboard to Green via API**
       ```powershell
       $dashboardUrl = "https://your-status-dashboard.com/api/update"
       $body = @{
           system = $env:COMPUTERNAME
           status = "healthy"
           last_check = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
       } | ConvertTo-Json
       Invoke-RestMethod -Uri $dashboardUrl -Method Post -Body $body -ContentType "application/json"
       ```

    4. **Send "All Clear" Notification to Teams or Slack**
       Example (Microsoft Teams):
       ```powershell
       $teamsWebhook = "https://outlook.office.com/webhook/YOUR/WEBHOOK/URL"
       $teamsMessage = @{
           "@type" = "MessageCard"
           "themeColor" = "00FF00"
           "title" = "First-On-Scene: All Clear"
           "text" = "System $($env:COMPUTERNAME) analyzed - no security threats detected."
       } | ConvertTo-Json
       Invoke-RestMethod -Uri $teamsWebhook -Method Post -Body $teamsMessage -ContentType "application/json"
       ```

    5. **Update a Configuration Management Database (CMDB)**
       ```powershell
       $cmdbUrl = "https://your-cmdb.com/api/assets/$($env:COMPUTERNAME)"
       $updateData = @{
           last_security_scan = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
           security_status = "CLEAN"
           scan_result = "No threats detected"
       } | ConvertTo-Json
       Invoke-RestMethod -Uri $cmdbUrl -Method Patch -Body $updateData -ContentType "application/json"
       ```

    SECURITY NOTE:
    This script runs with the same permissions as the user who executed Gather_Info.ps1.
    Be mindful of the commands you add, especially when running with administrative privileges.

.EXAMPLE
    # Called automatically by AI when no problem detected
    .\All_Clear.ps1

.EXAMPLE
    # Called with custom action script
    .\All_Clear.ps1 -CustomActionScript "C:\MyScripts\CustomClearance.ps1"

#>
param(
    [Parameter(Mandatory=$false)]
    [string]$CustomActionScript
)

$LogPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results\Steps_Taken.txt"

# Execute custom action script if provided
if ($CustomActionScript -and (Test-Path $CustomActionScript)) {
    Write-Host "Executing custom action script: $CustomActionScript" -ForegroundColor Cyan
    try {
        & $CustomActionScript
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: FINAL ACTION: All_Clear.ps1 [Custom Script: $CustomActionScript] (Contained Event/False Positive)" |
            Out-File $LogPath -Append -Encoding UTF8
        Exit 0
    }
    catch {
        Write-Warning "Custom action script failed: $_"
        Write-Host "Falling back to default action..." -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------------
# DEFAULT ACTION (Replace everything below with your custom logic)
# --------------------------------------------------------------------------------

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
