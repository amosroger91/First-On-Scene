# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project Overview

**First-On-Scene** is a free, open-source incident-response triage toolkit for MSPs. It collects
forensic artifacts from a host, decides **All Clear / Monitor / Problem Detected** with a
**deterministic** rule engine, and seals the evidence. It is built to be **CJIS-ready**: zero
network egress by default, optional AI is **local-only**, and every case is sealed with a SHA-256
manifest + tamper-evident chain of custody.

**Core philosophy:** deterministic proof over narrative; skepticism over alarmism; find *everything*
worth surfacing while keeping false positives from crying wolf; never let data leave the device.

## Architecture (v3.0)

Collection and analysis are separated:

- **Collector** (runs on the endpoint, read-only, zero deps, zero egress) -> `bundle.json`.
- **Analyzer** (runs anywhere, deterministic rule engine) -> verdict + `findings.json` + report.
- **Optional local AI** (Ollama, loopback-locked, advisory) -> narrative only; never changes the verdict.

### Key files
- `scripts/win/` - Windows implementation (pure PowerShell 5.1):
  - `FOS.Common.psm1` - shared lib: SHA-256, chain of custody, manifest, logging, bundle validation
  - `Collect-Artifacts.ps1` - read-only collector -> bundle + COC
  - `Invoke-Triage.ps1` - rule engine, scoring, classification -> findings.json/.md
  - `Write-Report.ps1` - branded HTML report
  - `Invoke-LocalAI.ps1` - optional loopback-only Ollama narrative
  - `Action-ProblemDetected.ps1` / `Action-AllClear.ps1` - decisive action + custom hooks
  - `fos.ps1` - orchestrator (collect -> triage -> report -> seal -> act)
- `scripts/nix/` - Linux/macOS mirror (pure Bash + jq), functionally identical, same exit codes
- `rules/detections.json` - versioned, MITRE ATT&CK-mapped ruleset (the engine reads this)
- `schemas/` - `artifact_schema.json` (bundle) + `findings_schema.json` (analyzer output)
- `deploy/` - `ninjaone/`, `rmm/`, `airgapped/`
- `docs/` - CJIS, NinjaOne, RMM, air-gapped, local-AI, rule-authoring, architecture
- `tests/` - Pester (`fos.Tests.ps1`) + bats (`fos.bats`) + `fixtures/`
- `src/` - OPTIONAL Node/TS launcher (thin wrapper over the native scripts; not required)

### Exit-code contract (used by RMM automation)
`0` ALL_CLEAR · `10` MONITOR · `20` PROBLEM_DETECTED (Incident) · `21` PROBLEM_DETECTED (Breach) · `1` error

## Running

```powershell
.\scripts\win\fos.ps1                 # full pipeline
.\scripts\win\fos.ps1 -Mode collect   # collect only
.\scripts\win\fos.ps1 -Mode analyze -BundlePath <bundle.json>
.\scripts\win\fos.ps1 -EnableLocalAI  # optional local narrative
```
```bash
sudo bash scripts/nix/fos.sh [--mode collect|analyze] [--bundle <path>] [--enable-local-ai]
```

## Tests
```powershell
Invoke-Pester .\tests\fos.Tests.ps1     # requires Pester 5+
```
```bash
bats tests/fos.bats                     # requires bats + jq
```

## Conventions & constraints
- **PowerShell scripts must be ASCII-only** (PS 5.1 reads no-BOM files as ANSI; non-ASCII breaks parsing).
- **JSON files are written UTF-8 without BOM** so hashes are stable cross-platform.
- **Collection is read-only.** No process termination, no Defender toggling, no runtime binary downloads.
- **No network egress** except the optional loopback AI (enforced; refuses non-loopback endpoints).
- **Append-only logs** (`Steps_Taken.txt`, `chain_of_custody.log`) are never truncated.
- **Windows and Linux analyzers must stay at parity** - same rules, scoring, verdicts, exit codes.
- Detection logic lives in `rules/detections.json`, not in code (except `builtin` correlation rules,
  which exist in both `Invoke-Triage.ps1` and `invoke-triage.sh` keyed by rule id).

## Scoring model
`contribution = weight x min(matchCount, cap[severity])`, `cap = {info:1, low:1, medium:2, high:3, critical:3}`.
`score >= problem -> PROBLEM_DETECTED`; `>= monitor -> MONITOR`; else `ALL_CLEAR`. Breach when
`score >= breach` or a matched rule sets `escalateToBreach`.

## History
v3 removed the legacy cloud-AI pipeline (OpenRouter/qwen `--yolo`) that sent forensic data off-box -
a CJIS violation. The old PowerShell collector/parser/report scripts are superseded and removed
(available in git history). See `CHANGELOG.md`.
