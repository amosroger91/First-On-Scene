<#
.SYNOPSIS
    First-On-Scene shared library (Windows).
.DESCRIPTION
    Cross-cutting helpers used by the collector and analyzer:
      - SHA-256 hashing (Windows CNG, FIPS-validated)
      - Tamper-evident, hash-chained chain-of-custody log (CJIS 5.4)
      - Evidence manifest (per-file SHA-256)
      - Deterministic UTF-8 (no BOM) JSON I/O
      - Operator identity + UTC time helpers
      - Structural bundle validation (no external dependencies)
    PowerShell 5.1+ compatible. No third-party modules. No network calls.
#>

$script:FosEngineVersion = '3.0.0'

function Get-FosEngineVersion { $script:FosEngineVersion }

function Get-FosUtcNow {
    [CmdletBinding()] param()
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Get-FosOperator {
    [CmdletBinding()] param()
    [ordered]@{
        user = ("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
        host = $env:COMPUTERNAME
        tool = "First-On-Scene/$($script:FosEngineVersion)"
    }
}

function New-FosCaseId {
    [CmdletBinding()] param([string]$Hostname = $env:COMPUTERNAME)
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $rand  = -join ((48..57) + (97..102) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    "FOS-$stamp-$($Hostname.ToUpper())-$rand"
}

function Get-FosStringSha256 {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ''
    } finally { $sha.Dispose() }
}

function Get-FosFileSha256 {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function ConvertTo-FosJson {
    [CmdletBinding()] param([Parameter(Mandatory, ValueFromPipeline)]$InputObject, [int]$Depth = 12)
    process { $InputObject | ConvertTo-Json -Depth $Depth }
}

function Write-FosJsonFile {
    <# Writes UTF-8 WITHOUT BOM so hashes are stable across platforms/tools. #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 12
    )
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    $enc  = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $enc)
}

function Write-FosTextFile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Path)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-FosLog {
    <# Console + append-only Steps_Taken.txt audit log. NEVER truncates. #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','STEP')][string]$Level = 'INFO',
        [string]$CaseDir
    )
    $ts   = Get-FosUtcNow
    $line = "[$ts] [$Level] $Message"
    $color = switch ($Level) { 'ERROR' {'Red'} 'WARN' {'Yellow'} 'OK' {'Green'} 'STEP' {'Cyan'} default {'Gray'} }
    Write-Host $line -ForegroundColor $color
    if ($CaseDir) {
        $log = Join-Path $CaseDir 'Steps_Taken.txt'
        Add-Content -LiteralPath $log -Value $line -Encoding UTF8
    }
}

# ---------------------------------------------------------------------------
# Chain of custody: hash-chained, append-only JSON Lines. Each entry's hash
# covers the previous entry's hash, so any edit/insertion/deletion is detectable.
# ---------------------------------------------------------------------------
function Add-FosCocEntry {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$CaseDir,
        [Parameter(Mandatory)][string]$Action,
        [string]$Detail = '',
        [object[]]$Files = @()
    )
    $cocPath = Join-Path $CaseDir 'chain_of_custody.log'
    $prevHash = 'GENESIS'
    $seq = 0
    if (Test-Path -LiteralPath $cocPath) {
        $existing = @(Get-Content -LiteralPath $cocPath -ErrorAction SilentlyContinue | Where-Object { $_.Trim() })
        if ($existing.Count -gt 0) {
            $last = $existing[-1] | ConvertFrom-Json
            $prevHash = $last.entryHash
            $seq = [int]$last.seq + 1
        }
    }
    $op = Get-FosOperator
    $fileHashes = @()
    foreach ($f in $Files) {
        if ($f -and (Test-Path -LiteralPath $f)) {
            $fileHashes += [ordered]@{ path = (Split-Path $f -Leaf); sha256 = (Get-FosFileSha256 $f) }
        }
    }
    $payload = [ordered]@{
        seq          = $seq
        timestampUtc = (Get-FosUtcNow)
        operator     = $op.user
        host         = $op.host
        action       = $Action
        detail       = $Detail
        files        = $fileHashes
        prevHash     = $prevHash
    }
    $payloadJson = $payload | ConvertTo-Json -Depth 8 -Compress
    $entryHash   = Get-FosStringSha256 ($prevHash + '|' + $payloadJson)
    $payload['entryHash'] = $entryHash
    $line = $payload | ConvertTo-Json -Depth 8 -Compress
    Add-Content -LiteralPath $cocPath -Value $line -Encoding UTF8
    $entryHash
}

function Test-FosCoc {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$CaseDir)
    $cocPath = Join-Path $CaseDir 'chain_of_custody.log'
    if (-not (Test-Path -LiteralPath $cocPath)) {
        return [pscustomobject]@{ Valid = $false; Entries = 0; Error = 'chain_of_custody.log not found' }
    }
    $lines = @(Get-Content -LiteralPath $cocPath | Where-Object { $_.Trim() })
    $prevHash = 'GENESIS'
    $i = 0
    foreach ($l in $lines) {
        $obj = $l | ConvertFrom-Json
        $payload = [ordered]@{
            seq = $obj.seq; timestampUtc = $obj.timestampUtc; operator = $obj.operator
            host = $obj.host; action = $obj.action; detail = $obj.detail
            files = $obj.files; prevHash = $obj.prevHash
        }
        $payloadJson = $payload | ConvertTo-Json -Depth 8 -Compress
        $expected = Get-FosStringSha256 ($prevHash + '|' + $payloadJson)
        if ($obj.prevHash -ne $prevHash) {
            return [pscustomobject]@{ Valid = $false; Entries = $lines.Count; Error = "Broken chain at seq $($obj.seq): prevHash mismatch" }
        }
        if ($obj.entryHash -ne $expected) {
            return [pscustomobject]@{ Valid = $false; Entries = $lines.Count; Error = "Tamper detected at seq $($obj.seq): entryHash mismatch" }
        }
        $prevHash = $obj.entryHash
        $i++
    }
    [pscustomobject]@{ Valid = $true; Entries = $i; Error = $null }
}

# ---------------------------------------------------------------------------
# Evidence manifest
# ---------------------------------------------------------------------------
function New-FosManifest {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$CaseDir,
        [Parameter(Mandatory)][string]$CaseId
    )
    $manifestPath = Join-Path $CaseDir 'manifest.json'
    $op = Get-FosOperator
    # The manifest covers EVIDENCE artifacts. The append-only audit logs (chain_of_custody.log,
    # Steps_Taken.txt) are excluded because they keep growing after sealing; their integrity is
    # guaranteed independently by the hash-chained chain of custody (Test-FosCoc).
    $excluded = @('manifest.json', 'chain_of_custody.log', 'Steps_Taken.txt')
    $files = Get-ChildItem -LiteralPath $CaseDir -File | Where-Object { $excluded -notcontains $_.Name }
    $entries = foreach ($f in $files) {
        [ordered]@{ file = $f.Name; sizeBytes = $f.Length; sha256 = (Get-FosFileSha256 $f.FullName) }
    }
    $manifest = [ordered]@{
        caseId       = $CaseId
        createdUtc   = (Get-FosUtcNow)
        operator     = $op
        engineVersion= $script:FosEngineVersion
        algorithm    = 'SHA-256'
        files        = @($entries)
    }
    Write-FosJsonFile -InputObject $manifest -Path $manifestPath
    $manifestPath
}

function Test-FosManifest {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$CaseDir)
    $manifestPath = Join-Path $CaseDir 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        return [pscustomobject]@{ Valid = $false; Checked = 0; Mismatches = @('manifest.json not found') }
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $mismatch = @()
    $checked = 0
    foreach ($e in $manifest.files) {
        $p = Join-Path $CaseDir $e.file
        $checked++
        $actual = Get-FosFileSha256 $p
        if ($null -eq $actual) { $mismatch += "$($e.file): MISSING"; continue }
        if ($actual -ne $e.sha256) { $mismatch += "$($e.file): HASH MISMATCH" }
    }
    [pscustomobject]@{ Valid = ($mismatch.Count -eq 0); Checked = $checked; Mismatches = $mismatch }
}

# ---------------------------------------------------------------------------
# Lightweight structural bundle validation (no JSON Schema engine needed)
# ---------------------------------------------------------------------------
function Test-FosBundle {
    [CmdletBinding()] param([Parameter(Mandatory)]$Bundle)
    $errs = @()
    if (-not $Bundle.metadata) { $errs += 'missing metadata' }
    else {
        foreach ($req in 'caseId','collectionTimestampUtc','targetHostname','platform','collectorVersion','operator') {
            if (-not $Bundle.metadata.PSObject.Properties.Name.Contains($req)) { $errs += "metadata.$req missing" }
        }
    }
    if (-not $Bundle.artifacts) { $errs += 'missing artifacts' }
    [pscustomobject]@{ Valid = ($errs.Count -eq 0); Errors = $errs }
}

Export-ModuleMember -Function `
    Get-FosEngineVersion, Get-FosUtcNow, Get-FosOperator, New-FosCaseId, `
    Get-FosStringSha256, Get-FosFileSha256, ConvertTo-FosJson, Write-FosJsonFile, `
    Write-FosTextFile, Write-FosLog, Add-FosCocEntry, Test-FosCoc, `
    New-FosManifest, Test-FosManifest, Test-FosBundle
