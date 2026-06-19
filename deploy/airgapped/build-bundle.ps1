<#
.SYNOPSIS
    Builds a self-contained, offline First-On-Scene kit for air-gapped / CJIS networks.
.DESCRIPTION
    Produces a ZIP containing the full toolkit (engine, rules, scripts, docs) that runs
    with ZERO internet access on the target. PowerShell 5.1 and bash+jq are the only
    runtime requirements (PowerShell ships with Windows; jq ships with most Linux).

    Optionally bakes in instructions for staging a local Ollama model so the optional
    AI narrative also works fully offline. Transfer the ZIP via approved removable media.
.PARAMETER OutputPath
    Where to write the kit ZIP. Default: ./dist/first-on-scene-airgapped-<date>.zip
#>
[CmdletBinding()]
param(
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutputPath) {
    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    $OutputPath = Join-Path $dist ("first-on-scene-airgapped-" + (Get-Date -Format 'yyyyMMdd') + ".zip")
}

$include = @('scripts','rules','schemas','docs','deploy','README.md','LICENSE','CHANGELOG.md')
$staging = Join-Path $env:TEMP ("fos_kit_" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

foreach ($item in $include) {
    $src = Join-Path $root $item
    if (Test-Path $src) { Copy-Item -Path $src -Destination $staging -Recurse -Force }
}

# Offline runbook
$runbook = @"
FIRST-ON-SCENE - AIR-GAPPED KIT
===============================
This kit runs with NO internet access. Nothing phones home.

WINDOWS:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\win\fos.ps1

LINUX/macOS (requires jq):
  sudo bash scripts/nix/fos.sh

OPTIONAL OFFLINE AI (local narrative, stays on the box):
  1. On an internet-connected staging machine, install Ollama and run:
        ollama pull llama3.1:8b
  2. Copy the model blobs from the Ollama models directory
     (Windows: %USERPROFILE%\.ollama\models, Linux: ~/.ollama/models)
     onto the air-gapped host's Ollama models directory.
  3. Start ollama on the air-gapped host, then run with -EnableLocalAI:
        scripts\win\fos.ps1 -EnableLocalAI
  The AI endpoint is hard-locked to localhost; it cannot egress.

INTEGRITY:
  Every case folder contains manifest.json (SHA-256 of evidence) and
  chain_of_custody.log (tamper-evident). Verify with the helpers in
  scripts/win/FOS.Common.psm1 (Test-FosManifest / Test-FosCoc) or
  scripts/nix/fos-common.sh (fos_manifest_verify / fos_coc_verify).

See docs/CJIS_COMPLIANCE.md and docs/DEPLOYMENT_AIRGAPPED.md.
"@
$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $staging 'OFFLINE_RUNBOOK.txt'), $runbook, $enc)

if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $OutputPath -Force
Remove-Item $staging -Recurse -Force

$hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLower()
Write-Host "Air-gapped kit:   $OutputPath"
Write-Host "SHA-256:          $hash"
Write-Host "Transfer this ZIP and its SHA-256 to the air-gapped network via approved media."
