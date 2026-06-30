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
$bundle = $null
if ($BundlePath -and (Test-Path -LiteralPath $BundlePath)) {
    try { $bundle = Get-Content -LiteralPath $BundlePath -Raw | ConvertFrom-Json } catch { $bundle = $null }
}
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
    if ($evJson.Length -gt 6000) { $evJson = $evJson.Substring(0,6000) + ' ... (truncated; see findings.json)' }
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

# --- Context cards built from the bundle (host snapshot, posture, remote access, coverage) ---
# All informational: the verdict is driven solely by the scored detections below.
$hostCard = ''; $postureCard = ''; $remoteCard = ''; $coverageCard = ''
if ($bundle) {
    $hi = $bundle.metadata.host
    if ($hi -and $hi.system) {
        $si = $hi.system
        $domTxt = if ($si.partOfDomain) { HtmlEnc $si.domain } else { (HtmlEnc $si.domain) + ' (workgroup)' }
        $diskRows = ''
        foreach ($dk in @($hi.disks)) { $pf=[double]$dk.percentFree; $dcol=if($pf -lt 10){'#dc2626'}elseif($pf -lt 20){'#d97706'}else{'#111827'}; $diskRows += "<tr><td><code>$(HtmlEnc $dk.drive)</code> $(HtmlEnc $dk.volumeName)</td><td>$($dk.sizeGB) GB</td><td>$($dk.freeGB) GB</td><td style='color:$dcol'>$($dk.percentFree)% free</td></tr>" }
        if (-not $diskRows) { $diskRows = "<tr><td colspan='4' style='color:#6b7280'>none</td></tr>" }
        $userList = (@($hi.loggedOnUsers) | ForEach-Object { (HtmlEnc $_.user) + " <span class='note'>(" + (HtmlEnc $_.session) + ")</span>" }) -join ', '
        if (-not $userList) { $userList = "<span class='note'>none detected</span>" }
        $hostCard = "<div class='card'><h2>Host</h2><div class='kv'><b>Machine</b><span>$(HtmlEnc $si.manufacturer) $(HtmlEnc $si.model)</span><b>Serial</b><span>$(HtmlEnc $si.serialNumber)</span><b>OS</b><span>$(HtmlEnc $si.osCaption) (build $(HtmlEnc $si.osBuild), $(HtmlEnc $si.osArchitecture))</span><b>CPU</b><span>$(HtmlEnc $si.cpu) ($($si.cpuCores)C/$($si.cpuLogical)T)</span><b>RAM</b><span>$($si.ramGB) GB</span><b>Domain</b><span>$domTxt</span><b>Uptime</b><span>$(HtmlEnc $si.uptime)</span><b>Logged-on users</b><span>$userList</span></div><table style='margin-top:12px'><tr><th>Disk</th><th>Size</th><th>Free</th><th>Capacity</th></tr>$diskRows</table></div>"
    }
    $kv = ''
    $sp = if ($bundle.artifacts) { $bundle.artifacts.securityPosture } else { $null }
    $dp = if ($sp) { $sp.defender } else { $null }
    if ($dp -and $dp.available) { $rtp=if($dp.realTimeEnabled){'on'}else{"<b style='color:#dc2626'>OFF</b>"}; $tpp=if($dp.tamperProtectionEnabled){'on'}else{"<b style='color:#d97706'>OFF</b>"}; $exC=(@($dp.exclusionPaths)+@($dp.exclusionExtensions)+@($dp.exclusionProcesses)|Where-Object{$_}).Count; $kv += "<b>Defender</b><span>real-time=$rtp &nbsp; tamper-protection=$tpp &nbsp; exclusions=$exC</span>" }
    $fw = if ($sp) { $sp.firewall } else { $null }
    if ($fw -and $fw.available) { $fwTxt=(@($fw.profiles)|ForEach-Object{ $st=if($_.enabled){'on'}else{"<b style='color:#dc2626'>OFF</b>"}; "$(HtmlEnc $_.name)=$st" }) -join ' &nbsp; '; $kv += "<b>Firewall</b><span>$fwTxt</span>" }
    $ac = if ($bundle.artifacts) { $bundle.artifacts.accessControl } else { $null }
    if ($ac) { $rdp=if($ac.rdpEnabled){'enabled'}else{'disabled'}; $adms=(@($ac.localAdmins)|ForEach-Object{HtmlEnc $_}) -join ', '; if(-not $adms){$adms="<span class='note'>none</span>"}; $shr=(@($ac.shares)|ForEach-Object{HtmlEnc $_}) -join ', '; if(-not $shr){$shr="<span class='note'>none</span>"}; $kv += "<b>RDP</b><span>$rdp</span><b>Local admins</b><span>$adms</span><b>Non-default shares</b><span>$shr</span>" }
    $net = if ($bundle.artifacts) { $bundle.artifacts.network } else { $null }
    if ($net) {
        $kv += "<b>Listening ports</b><span>$(@($net.listeners).Count) <span class='note'>(TCP+UDP)</span></span><b>DNS cache entries</b><span>$(@($net.dnsCache).Count)</span>"
        $hfRedir = @(@($net.hostsFileEntries) | Where-Object { $_.ipAddress -and ($_.ipAddress -notmatch '^(0\.0\.0\.0|127\.|::1|::$|255\.)') })
        $hfTxt = if ($hfRedir.Count -gt 0) { (@($hfRedir|Select-Object -First 10)|ForEach-Object{ (HtmlEnc $_.ipAddress)+' -> '+(HtmlEnc $_.hostnames) }) -join '<br>' } else { "<span class='note'>none (no non-loopback redirects)</span>" }
        $kv += "<b>Hosts-file redirects</b><span>$hfTxt</span>"
    }
    if ($kv) { $postureCard = "<div class='card'><h2>Security posture &amp; network <span class='note'>(informational)</span></h2><div class='kv'>$kv</div></div>" }
    $rtools = if ($bundle.artifacts -and $bundle.artifacts.remoteAccess) { @($bundle.artifacts.remoteAccess.tools) } else { @() }
    if ($rtools.Count -gt 0) {
        $rrows = (@($rtools) | ForEach-Object { $lab=if($_.authorized){"<span class='pill' style='background:#6b7280'>expected</span>"}else{"<span class='pill' style='background:#0891b2'>undeclared</span>"}; "<tr><td>$(HtmlEnc $_.tool)</td><td>$(HtmlEnc $_.evidence)</td><td>$lab</td></tr>" }) -join ''
        $remoteCard = "<div class='card'><h2>Remote access / RMM <span class='note'>(informational - never affects the verdict)</span></h2><table><tr><th>Tool</th><th>Evidence</th><th>Status</th></tr>$rrows</table><div class='note'>undeclared = not in the operator's -ExpectedRemoteTools allow-list; confirm each is one you installed.</div></div>"
    }
    $errs = @($bundle.metadata.errors)
    if ($errs.Count -gt 0) {
        $eul = (@($errs|Select-Object -First 20)|ForEach-Object{ "<li><code>$(HtmlEnc $_.component)</code> $(HtmlEnc $_.message)</li>" }) -join ''
        $coverageCard = "<div class='card' style='border-left:4px solid #d97706'><h2>Collection coverage</h2><div class='note'>These artifacts could not be fully collected (e.g. not elevated, or a log channel was disabled). Findings in these areas may be incomplete - escalate if in doubt.</div><ul style='font-size:13px;margin:8px 0 0'>$eul</ul></div>"
    }
}

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
  $coverageCard
  $hostCard
  $postureCard
  $remoteCard
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
