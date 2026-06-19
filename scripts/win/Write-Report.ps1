<#
.SYNOPSIS
    Generates a branded, human-readable HTML incident report from findings.json.
.DESCRIPTION
    Deterministic. No AI, no network. Embeds the verdict, scored findings with
    MITRE ATT&CK mapping, evidence snippets, an optional local-AI narrative,
    and an evidence-integrity panel (manifest + chain-of-custody status).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$FindingsPath,
    [string]$BundlePath,
    [Parameter(Mandatory)][string]$CaseDir,
    [string]$BrandName = 'First-On-Scene',
    [string]$LogoPath
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'FOS.Common.psm1') -Force

$f = Get-Content -LiteralPath $FindingsPath -Raw | ConvertFrom-Json
$sevColor = @{ info='#6b7280'; low='#2563eb'; medium='#d97706'; high='#ea580c'; critical='#dc2626' }
$verdictColor = switch ($f.verdict) { 'ALL_CLEAR' {'#16a34a'} 'MONITOR' {'#d97706'} default {'#dc2626'} }

function HtmlEnc($s) { if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }

$logoTag = ''
if ($LogoPath -and (Test-Path $LogoPath)) {
    try {
        $bytes = [System.IO.File]::ReadAllBytes($LogoPath)
        $b64 = [Convert]::ToBase64String($bytes)
        $ext = ([System.IO.Path]::GetExtension($LogoPath)).TrimStart('.')
        $logoTag = "<img src='data:image/$ext;base64,$b64' alt='logo' style='max-height:54px'/>"
    } catch {}
}

# Integrity status
$man = Test-FosManifest -CaseDir $CaseDir
$coc = Test-FosCoc -CaseDir $CaseDir
$manTxt = if ($man.Valid) { "VERIFIED ($($man.Checked) files)" } else { "FAILED: $($man.Mismatches -join '; ')" }
$cocTxt = if ($coc.Valid) { "INTACT ($($coc.Entries) entries)" } else { "BROKEN: $($coc.Error)" }
$manClr = if ($man.Valid) { '#16a34a' } else { '#dc2626' }
$cocClr = if ($coc.Valid) { '#16a34a' } else { '#dc2626' }

$rows = ''
foreach ($d in ($f.findings | Sort-Object -Property @{Expression={$_.weight};Descending=$true})) {
    $clr = $sevColor[$d.severity]
    $mitre = if ($d.mitre) { "$($d.mitre.tactic) / $($d.mitre.technique)" } else { '-' }
    $evJson = HtmlEnc (($d.evidence | ConvertTo-Json -Depth 6 -Compress))
    if ($evJson.Length -gt 1200) { $evJson = $evJson.Substring(0,1200) + ' ...' }
    $rows += @"
<tr>
  <td><code>$(HtmlEnc $d.ruleId)</code></td>
  <td>$(HtmlEnc $d.name)<div class='note'>$(HtmlEnc $d.rationale)</div></td>
  <td>$(HtmlEnc $d.category)</td>
  <td><span class='pill' style='background:$clr'>$(HtmlEnc $d.severity)</span></td>
  <td style='text-align:center'>$($d.weight)</td>
  <td style='text-align:center'>$($d.evidenceCount)</td>
  <td><code>$(HtmlEnc $mitre)</code></td>
</tr>
<tr class='ev'><td></td><td colspan='6'><details><summary>Evidence &amp; false-positive guidance</summary>
  <div class='note'><b>FP guidance:</b> $(HtmlEnc $d.falsePositive)</div>
  <pre>$evJson</pre></details></td></tr>
"@
}
if (-not $rows) { $rows = "<tr><td colspan='7' style='text-align:center;color:#16a34a'>No detections fired.</td></tr>" }

$aiSection = ''
if ($f.aiNarrative -and $f.aiNarrative.enabled) {
    $aiSection = @"
<div class='card'>
  <h2>Analyst Narrative <span class='note'>(local AI: $(HtmlEnc $f.aiNarrative.model) via $(HtmlEnc $f.aiNarrative.endpoint) - advisory only)</span></h2>
  <p>$(HtmlEnc $f.aiNarrative.text)</p>
</div>
"@
}

$reportName = "Incident_Report_$($f.targetHostname)_$((Get-Date).ToString('yyyyMMdd_HHmmss')).html"
$reportPath = Join-Path $CaseDir $reportName

$html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>
<title>$BrandName Incident Report - $($f.caseId)</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f3f4f6;color:#111827}
 header{background:#0f172a;color:#fff;padding:18px 28px;display:flex;align-items:center;justify-content:space-between}
 header h1{font-size:18px;margin:0;font-weight:600}
 .wrap{max-width:1100px;margin:22px auto;padding:0 18px}
 .card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:18px 22px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
 .verdict{font-size:26px;font-weight:700;color:$verdictColor}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{padding:8px 10px;border-bottom:1px solid #eef0f3;text-align:left;vertical-align:top}
 th{background:#f9fafb;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6b7280}
 .pill{color:#fff;padding:2px 9px;border-radius:999px;font-size:11px;text-transform:uppercase}
 .note{color:#6b7280;font-size:12px;margin-top:3px}
 code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px}
 pre{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow:auto;font-size:11px}
 .kv{display:grid;grid-template-columns:200px 1fr;gap:6px 16px;font-size:14px}
 .kv b{color:#374151}
 tr.ev td{padding-top:0;border-bottom:1px solid #eef0f3}
 footer{text-align:center;color:#9ca3af;font-size:12px;padding:20px}
</style></head><body>
<header><h1>$BrandName &middot; Incident Triage Report</h1>$logoTag</header>
<div class='wrap'>
  <div class='card'>
    <div class='verdict'>$($f.verdict)</div>
    <div class='kv'>
      <b>Case ID</b><span>$(HtmlEnc $f.caseId)</span>
      <b>Host</b><span>$(HtmlEnc $f.targetHostname)</span>
      <b>Classification</b><span>$(HtmlEnc $f.classification)</span>
      <b>Severity</b><span><span class='pill' style='background:$($sevColor[$f.severity])'>$(HtmlEnc $f.severity)</span></span>
      <b>Score</b><span>$($f.score) &nbsp;<span class='note'>(monitor=$($f.thresholds.monitor), problem=$($f.thresholds.problem), breach=$($f.thresholds.breach))</span></span>
      <b>Reason Code</b><span><code>$(HtmlEnc $f.reasonCode)</code></span>
      <b>Analyzed (UTC)</b><span>$(HtmlEnc $f.analyzedTimestampUtc)</span>
      <b>Ruleset / Engine</b><span>$(HtmlEnc $f.rulesetVersion) / $(HtmlEnc $f.engineVersion)</span>
    </div>
  </div>
  <div class='card'>
    <h2>Evidence Integrity</h2>
    <div class='kv'>
      <b>Manifest (SHA-256)</b><span style='color:$manClr;font-weight:600'>$(HtmlEnc $manTxt)</span>
      <b>Chain of Custody</b><span style='color:$cocClr;font-weight:600'>$(HtmlEnc $cocTxt)</span>
    </div>
    <div class='note'>This report and its source artifacts were produced with zero network egress. See chain_of_custody.log and manifest.json in the case folder.</div>
  </div>
  $aiSection
  <div class='card'>
    <h2>Detections ($(@($f.findings).Count))</h2>
    <table>
      <tr><th>Rule</th><th>Finding</th><th>Category</th><th>Severity</th><th>Wt</th><th>Hits</th><th>MITRE ATT&amp;CK</th></tr>
      $rows
    </table>
  </div>
</div>
<footer>Generated by $BrandName (open source, CJIS-aligned). Deterministic engine - AI is advisory only and never changes the verdict.</footer>
</body></html>
"@

Write-FosTextFile -Text $html -Path $reportPath
Add-FosCocEntry -CaseDir $CaseDir -Action 'REPORT_GENERATED' -Detail $reportName -Files @($reportPath) | Out-Null
Write-FosLog -Message "Report written: $reportPath" -Level OK -CaseDir $CaseDir
Write-Output $reportPath
