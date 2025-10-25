<#
.SYNOPSIS
    *** CUSTOMIZABLE ACTION TEMPLATE: PROBLEM DETECTED ***

.DESCRIPTION
    This script is automatically executed when the AI Triage Agent determines that
    a cybersecurity problem, anomaly, or incident requiring action has been detected.

    **THIS IS A TEMPLATE** - You are encouraged to replace the entire body of this
    script with your own custom automation logic while keeping the parameter structure.

.PARAMETER REASON_CODE
    A capitalized string indicating the type of problem detected (e.g., "MALWARE_DETECTED",
    "UNAUTHORIZED_ACCESS", "RANSOMWARE_ENCRYPTED_FILES", "SUSPICIOUS_NETWORK_ACTIVITY").
    This code is determined by the AI based on its analysis.

.PARAMETER CustomActionScript
    Optional path to a custom PowerShell script that will be executed instead of the
    default actions below. If provided, the custom script will receive the REASON_CODE
    as its first parameter.

.NOTES
    CUSTOMIZATION EXAMPLES:
    Replace the default implementation below with your own custom logic, such as:

    1. **Create a Ticket in Your PSA/Ticketing System**
       Example (ConnectWise):
       ```powershell
       $ticketData = @{
           summary = "First-On-Scene Alert: $REASON_CODE"
           board = "/service/boards/1"
           company = @{ identifier = "YourCompany" }
           priority = @{ id = 1 }
       } | ConvertTo-Json
       Invoke-RestMethod -Uri "https://your-cw-instance.com/v4_6_release/apis/3.0/service/tickets" `
           -Method Post -Body $ticketData -Headers @{Authorization="Basic YOUR_API_KEY"}
       ```

    2. **Trigger a Webhook/Automation Platform (e.g., n8n, Zapier, Make)**
       ```powershell
       $webhookUrl = "https://your-n8n-instance.com/webhook/incident-alert"
       $body = @{
           incident = "First-On-Scene Detection"
           reason = $REASON_CODE
           hostname = $env:COMPUTERNAME
           timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
       } | ConvertTo-Json
       Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $body -ContentType "application/json"
       ```

    3. **Send Alert to Slack, Teams, or PagerDuty**
       Example (Slack):
       ```powershell
       $slackWebhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
       $slackMessage = @{
           text = ":rotating_light: *CRITICAL INCIDENT DETECTED* :rotating_light:"
           attachments = @(
               @{
                   color = "danger"
                   fields = @(
                       @{ title = "Reason"; value = $REASON_CODE; short = $true }
                       @{ title = "Hostname"; value = $env:COMPUTERNAME; short = $true }
                   )
               }
           )
       } | ConvertTo-Json -Depth 3
       Invoke-RestMethod -Uri $slackWebhook -Method Post -Body $slackMessage -ContentType "application/json"
       ```

    4. **Isolate Machine from Network (Advanced)**
       ```powershell
       # Disable all network adapters (USE WITH CAUTION)
       Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Disable-NetAdapter -Confirm:$false
       ```

    SECURITY NOTE:
    This script runs with the same permissions as the user who executed Gather_Info.ps1.
    Be mindful of the commands you add, especially when running with administrative privileges.

.EXAMPLE
    # Called automatically by AI with reason code
    .\Problem_Detected.ps1 -REASON_CODE "MALWARE_DETECTED"

.EXAMPLE
    # Called with custom action script
    .\Problem_Detected.ps1 -REASON_CODE "MALWARE_DETECTED" -CustomActionScript "C:\MyScripts\CustomAlert.ps1"

#>
param(
    [Parameter(Mandatory=$true)]
    [string]$REASON_CODE,

    [Parameter(Mandatory=$false)]
    [string]$CustomActionScript
)

$LogPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath "results\Steps_Taken.txt"

# Execute custom action script if provided
if ($CustomActionScript -and (Test-Path $CustomActionScript)) {
    Write-Host "Executing custom action script: $CustomActionScript" -ForegroundColor Cyan
    try {
        & $CustomActionScript $REASON_CODE
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: FINAL ACTION: Problem_Detected.ps1 [Custom Script: $CustomActionScript] [$REASON_CODE]" |
            Out-File $LogPath -Append -Encoding UTF8
        Exit 1
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
Write-Host "****************************************************************" -ForegroundColor Red
Write-Host "*** CRITICAL INCIDENT DETECTED ***" -ForegroundColor Red
Write-Host "REASON CODE: $REASON_CODE" -ForegroundColor Red
Write-Host "Triage Agent Halted for Escalation." -ForegroundColor Red
Write-Host "****************************************************************" -ForegroundColor Red

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("CRITICAL INCIDENT DETECTED! REASON CODE: $REASON_CODE. Triage Agent Halted for Escalation.", 'Problem Detected', 'OK', 'Error')

"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: FINAL ACTION: Problem_Detected.ps1 [$REASON_CODE]" | Out-File $LogPath -Append -Encoding UTF8
Exit 1
