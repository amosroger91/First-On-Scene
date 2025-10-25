<#
.SYNOPSIS
    Generates a professional DOCX incident report from collected forensic artifacts.
.DESCRIPTION
    Reads structured triage data from Info_Results.txt and raw JSON artifacts,
    uses LLM to generate executive summaries and recommendations, then populates
    the DOCX template with all findings.
.PARAMETER ComputerName
    The target system name for the report title.
.OUTPUTS
    results/Incident_Report_[ComputerName]_[Date].docx
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost"
)

$ErrorActionPreference = "Continue"

# Paths
$ScriptDir = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$ResultsPath = Join-Path -Path $ScriptDir -ChildPath "results"
$OutputPathHTML = Join-Path -Path $ResultsPath -ChildPath "Incident_Report_${ComputerName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$OutputPathDOCX = Join-Path -Path $ResultsPath -ChildPath "Incident_Report_${ComputerName}_$(Get-Date -Format 'yyyyMMdd_HHmmss').docx"
$InfoResultsPath = Join-Path -Path $ResultsPath -ChildPath "Info_Results.txt"
$FindingsPath = Join-Path -Path $ResultsPath -ChildPath "findings.txt"
$StepsLog = Join-Path -Path $ResultsPath -ChildPath "Steps_Taken.txt"

Write-Host "=== DOCX Report Generation Starting ===" -ForegroundColor Cyan

# Log action
"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Generate_Report.ps1: Starting DOCX report generation for $ComputerName" |
    Out-File $StepsLog -Append -Encoding UTF8

# --- 1. Load Triage Data ---
Write-Host "Loading triage data from Info_Results.txt..."

if (-not (Test-Path $InfoResultsPath)) {
    Write-Error "Info_Results.txt not found. Run Parse_Results.ps1 first."
    exit 1
}

$TriageData = Get-Content $InfoResultsPath -Raw -Encoding UTF8 | ConvertFrom-Json

# Load findings.txt if it exists (AI analysis)
$FindingsContent = ""
if (Test-Path $FindingsPath) {
    $FindingsContent = Get-Content $FindingsPath -Raw -Encoding UTF8
}

# --- 2. Determine Classification ---
Write-Host "Analyzing classification and severity..."

$SummaryCounts = $TriageData.summary_counts

# Calculate severity based on findings
$ThreatScore = 0
$ThreatScore += $SummaryCounts.suspicious_run_keys * 5
$ThreatScore += $SummaryCounts.suspicious_scheduled_tasks * 4
$ThreatScore += $SummaryCounts.suspicious_services * 5
$ThreatScore += $SummaryCounts.wmi_persistence_artifacts * 6
$ThreatScore += $SummaryCounts.suspicious_processes * 3
$ThreatScore += $SummaryCounts.suspicious_connections * 4
$ThreatScore += $SummaryCounts.suspicious_powershell_events * 3
$ThreatScore += $SummaryCounts.service_installs * 4
$ThreatScore += $SummaryCounts.user_creations * 5
$ThreatScore += $SummaryCounts.suspicious_timestamps * 2

# Determine severity and classification
$Severity = "Low"
$Classification = "Security Event"
$Determination = "All Clear"

if ($ThreatScore -ge 50) {
    $Severity = "Critical"
    $Classification = "Security Breach"
    $Determination = "Problem Detected"
} elseif ($ThreatScore -ge 30) {
    $Severity = "High"
    $Classification = "Security Incident"
    $Determination = "Problem Detected"
} elseif ($ThreatScore -ge 15) {
    $Severity = "Medium"
    $Classification = "Security Event"
    $Determination = "Monitoring Required"
} elseif ($ThreatScore -gt 0) {
    $Severity = "Low"
    $Classification = "Security Event"
    $Determination = "All Clear (Minor Findings)"
}

Write-Host "Threat Score: $ThreatScore | Severity: $Severity | Classification: $Classification"

# --- 3. Generate LLM Summaries ---
Write-Host "Generating executive summary and recommendations via LLM..."

$ExecutiveSummaryPrompt = @"
You are a cybersecurity analyst for K&S Computing writing an executive summary for an incident response report.

**Target System:** $ComputerName
**Threat Score:** $ThreatScore
**Classification:** $Classification
**Severity:** $Severity

**Summary Statistics:**
- Suspicious Registry Run Keys: $($SummaryCounts.suspicious_run_keys)
- Suspicious Scheduled Tasks: $($SummaryCounts.suspicious_scheduled_tasks)
- Suspicious Services: $($SummaryCounts.suspicious_services)
- WMI Persistence Artifacts: $($SummaryCounts.wmi_persistence_artifacts)
- Suspicious Processes: $($SummaryCounts.suspicious_processes)
- Suspicious Network Connections: $($SummaryCounts.suspicious_connections)
- Suspicious PowerShell Events: $($SummaryCounts.suspicious_powershell_events)
- Service Installations: $($SummaryCounts.service_installs)
- User Creations: $($SummaryCounts.user_creations)
- Suspicious File Timestamps: $($SummaryCounts.suspicious_timestamps)

**AI Analysis Findings:**
$FindingsContent

**Instructions:**
Write a concise 2-3 paragraph executive summary for non-technical stakeholders. Include:
1. What was found during the incident response triage
2. The overall risk level and business impact
3. High-level next steps (investigation, containment, or clearance)

Keep it professional and suitable for management review. Do not use markdown formatting.
"@

$RecommendationsPrompt = @"
You are a cybersecurity analyst for K&S Computing writing actionable recommendations for an incident response report.

**Target System:** $ComputerName
**Threat Score:** $ThreatScore
**Classification:** $Classification
**Severity:** $Severity

**Triage Findings Summary:**
$($TriageData | ConvertTo-Json -Depth 3)

**AI Analysis:**
$FindingsContent

**Instructions:**
Provide 3-5 specific, actionable recommendations based on the findings. Format as a bulleted list.
If severity is Critical/High: focus on containment, forensic preservation, and escalation.
If severity is Medium/Low: focus on monitoring, hardening, and preventive measures.

Each recommendation should be 1-2 sentences and directly tied to the findings. Do not use markdown formatting, just plain text with bullet points (use "- " for bullets).
"@

# Call LLM for Executive Summary
$tempSummaryFile = Join-Path $env:TEMP "fos_exec_summary_prompt.txt"
$ExecutiveSummaryPrompt | Out-File -FilePath $tempSummaryFile -Encoding UTF8 -NoNewline

Write-Host "  -> Generating Executive Summary..." -ForegroundColor Gray
$ExecSummary = ""
try {
    $ExecSummary = cmd /c "type `"$tempSummaryFile`" | npx --yes @qwen-code/qwen-code -p `"`"" 2>&1
    $ExecSummary = $ExecSummary -replace '[\r\n]+$', ''  # Trim trailing newlines
    if ($ExecSummary -match "Error|Exception|Failed") {
        throw "LLM returned error: $ExecSummary"
    }
} catch {
    Write-Warning "Failed to generate executive summary via LLM: $_"
    $ExecSummary = "Automated triage completed on $ComputerName. Review technical findings below for detailed analysis. Classification: $Classification. Severity: $Severity."
}

# Call LLM for Recommendations
$tempRecommendationsFile = Join-Path $env:TEMP "fos_recommendations_prompt.txt"
$RecommendationsPrompt | Out-File -FilePath $tempRecommendationsFile -Encoding UTF8 -NoNewline

Write-Host "  -> Generating Recommendations..." -ForegroundColor Gray
$Recommendations = ""
try {
    $Recommendations = cmd /c "type `"$tempRecommendationsFile`" | npx --yes @qwen-code/qwen-code -p `"`"" 2>&1
    $Recommendations = $Recommendations -replace '[\r\n]+$', ''
    if ($Recommendations -match "Error|Exception|Failed") {
        throw "LLM returned error: $Recommendations"
    }
} catch {
    Write-Warning "Failed to generate recommendations via LLM: $_"
    $Recommendations = @"
- Review all flagged persistence mechanisms and remove unauthorized entries
- Investigate suspicious processes and network connections
- Implement enhanced monitoring on this system
- Review and update security policies as needed
"@
}

# --- 4. Generate Technical Findings Narratives ---
Write-Host "Generating technical findings narratives..."

function Format-TechnicalFindings {
    param($Category, $Data)

    $output = ""

    if ($Data.found -eq $true -and $Data.details) {
        $count = @($Data.details).Count
        $output += "Found $count suspicious items:`n`n"

        # Sample up to 10 items for the report
        $sampleItems = $Data.details | Select-Object -First 10
        foreach ($item in $sampleItems) {
            $output += "- "
            # Format based on object properties
            $properties = $item.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'}
            $formattedProps = $properties | ForEach-Object { "$($_.Name): $($_.Value)" }
            $output += ($formattedProps -join " | ")
            $output += "`n"
        }

        if ($count -gt 10) {
            $output += "`n... and $($count - 10) more items (see raw JSON artifacts for complete details).`n"
        }
    } else {
        $output += "No suspicious items detected in this category.`n"
    }

    return $output
}

$PersistenceText = @"
Registry Run Keys:
$(Format-TechnicalFindings "Registry" $TriageData.Triage_Indicators.Persistence.registry_run_keys)

Scheduled Tasks:
$(Format-TechnicalFindings "Tasks" $TriageData.Triage_Indicators.Persistence.scheduled_tasks)

Services:
$(Format-TechnicalFindings "Services" $TriageData.Triage_Indicators.Persistence.services)

WMI Event Subscriptions:
$(Format-TechnicalFindings "WMI" $TriageData.Triage_Indicators.Persistence.wmi_subscriptions)
"@

$ExecutionText = @"
Suspicious Processes:
$(Format-TechnicalFindings "Processes" $TriageData.Triage_Indicators.Execution.suspicious_processes)

Process Creation Events (Event ID 4688):
$(Format-TechnicalFindings "ProcessCreation" $TriageData.Triage_Indicators.Execution.process_creation_events)
"@

$NetworkText = @"
Suspicious Network Connections:
$(Format-TechnicalFindings "Network" $TriageData.Triage_Indicators.Network.suspicious_connections)
"@

$PowerShellText = @"
Suspicious PowerShell Activity:
$(Format-TechnicalFindings "PowerShell" $TriageData.Triage_Indicators.PowerShell_Activity.suspicious_commands)
"@

# --- 5. Generate Artifact Summary ---
$ArtifactSummary = @"
Artifact Collection Summary for $ComputerName
Analysis Timestamp: $($TriageData.analysis_timestamp)

Total Artifacts Analyzed:
- Registry Run Keys: $($SummaryCounts.suspicious_run_keys) suspicious entries
- Scheduled Tasks: $($SummaryCounts.suspicious_scheduled_tasks) suspicious tasks
- Windows Services: $($SummaryCounts.suspicious_services) suspicious services
- WMI Persistence: $($SummaryCounts.wmi_persistence_artifacts) artifacts
- Running Processes: $($SummaryCounts.suspicious_processes) suspicious processes
- Network Connections: $($SummaryCounts.suspicious_connections) suspicious connections
- PowerShell Events: $($SummaryCounts.suspicious_powershell_events) suspicious events
- Service Installations: $($SummaryCounts.service_installs) events
- User Creations: $($SummaryCounts.user_creations) events
- File Timestamp Anomalies: $($SummaryCounts.suspicious_timestamps) files

All raw artifact JSON files are preserved in the results directory for detailed analysis.
"@

# --- 6. Generate Professional HTML Report ---
Write-Host "Generating HTML report..."

# Escape HTML special characters
function Escape-HTML {
    param($Text)
    if (-not $Text) { return "" }
    return [System.Security.SecurityElement]::Escape($Text.ToString())
}

# Create HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Incident Response Report - $ComputerName</title>
    <style>
        body { font-family: Calibri, Arial, sans-serif; margin: 40px; }
        h1 { color: #0000FF; font-size: 24pt; }
        h2 { color: #0000FF; font-size: 14pt; border-bottom: 1px solid #000; padding-bottom: 5px; }
        h3 { color: #000000; font-size: 12pt; }
        .header { margin-bottom: 30px; }
        .metadata { margin-bottom: 20px; }
        .metadata strong { display: inline-block; width: 150px; }
        .section { margin-bottom: 30px; }
        .finding { background-color: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 3px solid #0000FF; }
        .footer { margin-top: 50px; border-top: 1px solid #000; padding-top: 10px; font-size: 9pt; font-style: italic; color: #666; }
        pre { white-space: pre-wrap; background-color: #f5f5f5; padding: 10px; font-family: Consolas, monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>INCIDENT RESPONSE REPORT</h1>
        <p><strong>K&S Computing</strong><br>Managed Service Provider - Incident Response Team</p>
    </div>

    <div class="metadata">
        <p><strong>Report Date:</strong> $(Get-Date -Format "MMMM dd, yyyy")</p>
        <p><strong>Target System:</strong> $(Escape-HTML $ComputerName)</p>
        <p><strong>Analyst:</strong> $(Escape-HTML $env:USERNAME)</p>
        <p><strong>Case ID:</strong> FOS-$(Get-Date -Format 'yyyyMMdd')-$(Escape-HTML $ComputerName)</p>
    </div>

    <h2>EXECUTIVE SUMMARY</h2>
    <div class="section">
        <p>$(Escape-HTML $ExecSummary)</p>
    </div>

    <h2>INCIDENT CLASSIFICATION</h2>
    <div class="section">
        <p><strong>Classification:</strong> $(Escape-HTML $Classification)</p>
        <p><strong>Severity:</strong> $(Escape-HTML $Severity)</p>
        <p><strong>Determination:</strong> $(Escape-HTML $Determination)</p>
    </div>

    <h2>TECHNICAL FINDINGS</h2>

    <div class="section">
        <h3>Persistence Mechanisms</h3>
        <pre>$(Escape-HTML $PersistenceText)</pre>
    </div>

    <div class="section">
        <h3>Execution Evidence</h3>
        <pre>$(Escape-HTML $ExecutionText)</pre>
    </div>

    <div class="section">
        <h3>Network Activity</h3>
        <pre>$(Escape-HTML $NetworkText)</pre>
    </div>

    <div class="section">
        <h3>PowerShell Activity</h3>
        <pre>$(Escape-HTML $PowerShellText)</pre>
    </div>

    <h2>ARTIFACT SUMMARY</h2>
    <div class="section">
        <pre>$(Escape-HTML $ArtifactSummary)</pre>
    </div>

    <h2>RECOMMENDATIONS</h2>
    <div class="section">
        <p>$(Escape-HTML $Recommendations)</p>
    </div>

    <div class="footer">
        <p>This report was generated by First-On-Scene Automated Triage System</p>
        <p>© K&S Computing - Confidential and Proprietary</p>
    </div>
</body>
</html>
"@

# Save HTML report
$htmlReport | Out-File -FilePath $OutputPathHTML -Encoding UTF8
Write-Host "HTML report created: $OutputPathHTML" -ForegroundColor Green

# Convert HTML to DOCX using Word
Write-Host "Converting to DOCX format..."

try {
    $Word = New-Object -ComObject Word.Application
    $Word.Visible = $false

    # Open HTML file
    $Doc = $Word.Documents.Open($OutputPathHTML)

    # Save as DOCX (16 = wdFormatDocumentDefault)
    $missing = [Type]::Missing
    $Doc.SaveAs($OutputPathDOCX, 16, $missing, $missing, $missing, $missing, $missing, $missing, $missing, $missing, $missing)

    $Doc.Close()
    $Word.Quit()

    # Release COM objects
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Doc) | Out-Null
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Word) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    Write-Host "DOCX report generated successfully!" -ForegroundColor Green
    Write-Host "Output: $OutputPathDOCX" -ForegroundColor Cyan

    # Log completion
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') :: Generate_Report.ps1: HTML and DOCX reports created" |
        Out-File $StepsLog -Append -Encoding UTF8

} catch {
    Write-Warning "Failed to convert HTML to DOCX: $_"
    Write-Host "HTML report is available at: $OutputPathHTML" -ForegroundColor Yellow
    Write-Host "You can manually open it in Word and save as DOCX if needed." -ForegroundColor Yellow
}

Write-Host "`n=== DOCX Report Generation Complete ===" -ForegroundColor Cyan
