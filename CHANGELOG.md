# Changelog

## 3.0.0 - CJIS-ready, MSP-grade rewrite

### Breaking
- **Removed the public-cloud AI path** (OpenRouter / qwen / `--yolo`). Forensic data is no longer
  sent off the device. The deterministic engine now owns the verdict; AI is optional and local-only.
- New entry points: `scripts/win/fos.ps1` and `scripts/nix/fos.sh` replace the old
  `Gather_Info.ps1` -> `Parse_Results.ps1` -> qwen workflow.
- New data contracts: `schemas/artifact_schema.json` (bundle) and `schemas/findings_schema.json`.

### Added
- **Deterministic, MITRE ATT&CK-mapped rule engine** driven by versioned `rules/detections.json`.
- **Evidence integrity:** SHA-256 `manifest.json` + tamper-evident, hash-chained `chain_of_custody.log`,
  with offline verifiers (`Test-FosManifest`/`Test-FosCoc`, `fos_manifest_verify`/`fos_coc_verify`).
- **Optional local-only AI narrative** via Ollama, hard-locked to loopback (advisory; never changes the verdict).
- **Severity-capped scoring** to suppress false positives from ubiquitous-but-legit patterns.
- **RMM-native deployment:** clean exit codes (0/10/20/21/1), NinjaOne wrapper with custom-field output,
  generic RMM one-liners, and an air-gapped kit builder.
- **Full Windows + Linux/macOS parity** (PowerShell and Bash+jq implementations verified identical).
- Comprehensive docs: CJIS posture, NinjaOne, generic RMM, air-gapped, local AI, rule authoring, architecture.
- Pester + bats test suites and clean/infected fixtures.

### Changed
- Collection is **read-only by default**; `rkill`/Defender-toggle removed from the default path and
  no longer downloads binaries from the internet at runtime.
- Reports are deterministic HTML with an evidence-integrity panel.

### Security
- Zero network egress by default. Local AI cannot egress (loopback enforced).
- Operator identity recorded in metadata, manifest, and every chain-of-custody entry.

## 2.x (legacy)
- Hybrid Node/TypeScript scaffold + PowerShell collector with cloud (OpenRouter/qwen) AI analysis.
  Retained in git history; superseded by 3.0.0.
