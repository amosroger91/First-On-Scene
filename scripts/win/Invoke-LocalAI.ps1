<#
.SYNOPSIS
    OPTIONAL local-only AI narrative for a First-On-Scene case (Windows).
.DESCRIPTION
    Sends the DETERMINISTIC findings summary to a LOCAL Ollama instance and attaches
    a plain-English analyst narrative to findings.json. It is advisory only and never
    changes the verdict, score, or classification.

    CJIS posture:
      * Hard-refuses any endpoint that is not loopback (127.0.0.1 / localhost / ::1).
        This guarantees no Criminal Justice Information leaves the machine.
      * Sends only rule-level findings (names, categories, MITRE, rationale, counts),
        NOT raw artifacts, minimizing data exposure even to the local model.
.PARAMETER Endpoint
    Ollama base URL. MUST be loopback.
.PARAMETER Model
    Local model name (e.g. llama3.1:8b, qwen2.5:7b, gpt-oss:20b).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsPath,
    [Parameter(Mandatory)][string]$CaseDir,
    [string]$Endpoint = 'http://127.0.0.1:11434',
    [string]$Model = 'llama3.1:8b',
    [int]$TimeoutSec = 120
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

# --- CJIS guard: loopback only ---
if ($Endpoint -notmatch '^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?(/|$)') {
    throw "Refusing non-loopback AI endpoint '$Endpoint'. Local AI must be localhost-only to preserve CJIS data boundaries."
}

$f = Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json

# Data minimization: build a compact, artifact-free summary.
$findingLines = ($f.findings | ForEach-Object {
    $m = if ($_.mitre) { "$($_.mitre.technique)" } else { '-' }
    "- [$($_.ruleId)] $($_.name) | sev=$($_.severity) | hits=$($_.evidenceCount) | ATT&CK=$m"
}) -join "`n"

$prompt = @"
You are a SOC analyst writing a concise incident-triage narrative for an MSP client.
A deterministic engine has ALREADY decided the verdict. Do NOT change or second-guess it.
Write 2-3 short paragraphs in plain English for a non-technical stakeholder: what was found,
why it matters, and the immediate recommended next steps. Do not invent facts beyond the data.

VERDICT: $($f.verdict)
CLASSIFICATION: $($f.classification)
SEVERITY: $($f.severity)
SCORE: $($f.score)
HOST: $($f.targetHostname)
DETECTIONS:
$findingLines
"@

$body = @{ model = $Model; prompt = $prompt; stream = $false } | ConvertTo-Json -Depth 4
Write-FosLog -Message "Requesting local AI narrative ($Model @ $Endpoint)" -Level STEP -CaseDir $CaseDir

try {
    $resp = Invoke-RestMethod -Uri "$($Endpoint.TrimEnd('/'))/api/generate" -Method Post -Body $body -ContentType 'application/json' -TimeoutSec $TimeoutSec
    $text = [string]$resp.response
} catch {
    Write-FosLog -Message "Local AI unavailable ($($_.Exception.Message)). Skipping narrative." -Level WARN -CaseDir $CaseDir
    return
}

# Attach (advisory) narrative without altering verdict.
$f | Add-Member -NotePropertyName aiNarrative -NotePropertyValue ([ordered]@{
    enabled  = $true
    model    = $Model
    endpoint = $Endpoint
    text     = $text.Trim()
}) -Force

Write-FosJsonFile -InputObject $f -Path $FindingsPath
Add-FosCocEntry -CaseDir $CaseDir -Action 'AI_NARRATIVE_ADDED' -Detail "model=$Model endpoint=$Endpoint (advisory only)" | Out-Null
Write-FosLog -Message "Local AI narrative attached (advisory)." -Level OK -CaseDir $CaseDir
