# Changelog

## 3.5.0 - Windows collection depth + richer reports

### Added (Windows collector: `scripts/win/Collect-Artifacts.ps1` + standalone `deploy/standalone/Invoke-FosTriage.ps1`)
- **Network state** (read-only, zero egress): `artifacts.network.listeners` (listening TCP/UDP
  endpoints with owning process), `artifacts.network.dnsCache` (local DNS client cache - shows
  resolved/beaconing names without any new lookup), and `artifacts.network.hostsFileEntries`
  (parsed hosts-file mappings).
- **Windows Firewall posture** (`artifacts.securityPosture.firewall`): per-profile
  (Domain/Private/Public) enabled state + default inbound/outbound action.
- **Kernel driver inventory** under `-Deep` (`artifacts.execution.drivers`): running drivers with
  Authenticode signature status + signer, path-normalized from the service image path.

### Added (rules, `rules/detections.json`)
- **FOS-NET-003** Hosts-file redirect to a non-loopback address (medium; ad-block 0.0.0.0/127.* are
  intentionally excluded to avoid false positives).
- **FOS-NET-004** Process listening on a known bind-shell / C2 port, bound to a non-loopback address
  (medium).
- **FOS-DEF-004** A Windows Firewall profile is disabled (medium; builtin correlator).
- **FOS-EXE-006** Unsigned kernel driver loaded from outside `system32\drivers` (high; `-Deep`).

### Added (reports)
- The **modular HTML report** (`Write-Report.ps1`) now renders the Host snapshot, a **Security
  posture & network** panel (Defender, firewall, RDP/admins/shares, listener & DNS counts,
  hosts-file redirects), a **Remote access / RMM** table, and a **Collection coverage** banner that
  surfaces `metadata.errors` (e.g. not-elevated, disabled log channels) so blind spots are explicit.
- The **standalone report + console** gain the same Security posture & network panel, hosts-file
  redirect callouts, firewall line, and the Collection coverage banner.

### Changed
- Engine/standalone version bumped to `3.5.0`. New checks are Windows-only context/detections and
  do not regress Linux verdicts; informational signals (remote access, posture, coverage) never
  affect the score.

## 3.4.0 - Linux/macOS collector reaches parity with Windows

### Added (Linux/macOS collector, `scripts/nix/collect-artifacts.sh`)
- **Remote-access / RMM inventory** (`artifacts.remoteAccess.tools`, drives `FOS-RAT-001/002`):
  detects 25 agent families (AnyDesk, TeamViewer, RustDesk, ScreenConnect, NinjaOne, Atera,
  Splashtop, VNC, MeshCentral, Tactical RMM, Chrome Remote Desktop, etc.) across processes,
  systemd units, and installed packages (dpkg/rpm). Honors `--expected-remote-tools` as the
  sanctioned allow-list, mirroring the Windows `-ExpectedRemoteTools`.
- **Access-control snapshot** (`artifacts.accessControl`): local admins (sudo/wheel/admin groups
  + uid-0 accounts), RDP/xrdp state, and Samba/NFS shares.
- **Process image enrichment** via `/proc`: real `executablePath`, **deleted-image flag**
  (`imageDeleted`, drives `FOS-EXE-004`), and `sha256` under `--deep`.
- **Account-creation events** synthesized from auth logs as event 4720 (drives `FOS-CRD-002`).
- **ClamAV detections** read from existing logs only (never runs a scan; drives `FOS-AV-002`).
- **ISO-8601 file timestamps** + suspicious-dir scan (`/tmp`, `/var/tmp`, `/dev/shm`, Desktop,
  Downloads), so ransom-note (`FOS-RAN-001`) and timestomping (`FOS-AF-001`) fire on *nix.
- **Non-fatal error capture** into `metadata.errors`, `platform` auto-detection (linux/darwin),
  and `--deep` / `--max-events` / `--case-dir` flags wired through `fos.sh`.

### Changed
- Engine version bumped to `3.4.0`. The Linux and Windows collectors now emit the same artifact
  shape and the analyzers stay at full verdict/scoring/exit-code parity.
- `reasonCode` tie-break in the Linux analyzer aligned with Windows (highest `weight x min(hits,3)`),
  and the findings report gained the Score-thresholds + Ruleset/Engine rows.

## 3.3.0 - Host snapshot + remote-access tools are informational

### Added
- **Host snapshot** in the standalone triage console + HTML report: make/model, serial number,
  OS + build + architecture, CPU (cores/threads), RAM, per-disk capacity & free space (with a
  low-space highlight), system uptime, domain, and **logged-on interactive users**. Captured into
  the sealed bundle under `metadata.host`.

### Changed
- **Remote-access / RMM tools are now informational and never affect the verdict** (`FOS-RAT-001`
  dropped from high/weight-9 to info/weight-0; reason code `UNAUTHORIZED_REMOTE_ACCESS` -> 
  `UNDECLARED_REMOTE_ACCESS`). MSPs run RMMs by design, so their mere presence is no longer scored
  as a compromise. Tools not in `-ExpectedRemoteTools` are listed as `[undeclared]` (neutral) for
  review instead of `[UNAUTHORIZED]` (red). The verdict is driven solely by actual attack indicators.
- Ruleset bumped to `1.1.0`. Change flows to the Windows + Linux analyzers and the standalone (all
  read the shared `rules/detections.json`), so verdict/scoring parity is preserved.

## 3.2.0 - Deeper compromise checks (Tier A default + `-Deep`)

### Added (default - cheap native reads, big signal)
- **Defender health & tamper state** (`FOS-DEF-001/002/003`): real-time protection OFF,
  tamper protection OFF, and configured exclusions (paths/extensions/processes).
- **Process integrity** (`FOS-EXE-003/004`): Authenticode signature + SHA-256 for every running
  binary; flags unsigned executables from user/temp paths and processes whose on-disk image was deleted.
- **ASEP hijacks** (`FOS-PER-005..008`): IFEO debuggers, AppInit_DLLs, Winlogon Shell/Userinit, and
  **accessibility/sticky-keys backdoors** (sethc/utilman/osk) - the last escalates to Breach.
- **Log-tamper detection** (`FOS-AF-002`): Security (1102) / System (104) log-clear events.
- **Access-control context**: local administrators, RDP-enabled state, non-default shares.

### Added (`-Deep` - a minute or two more, still no dependencies)
- **Prefetch** execution evidence and a **possible-injection scan** (`FOS-EXE-005`): unsigned modules
  loaded from user/temp paths into running processes.

### Notes
- Wired into the Windows + Linux analyzers and the standalone; clean/infected fixture parity preserved
  across both platforms. `-Deep` artifacts (Prefetch, module enumeration) need elevation for full coverage.
- The deepest layers (full memory image / disk imaging / firmware) remain a documented offline-DFIR
  escalation path, not part of the fast live triage. See README "how deep" discussion.

## 3.1.0 - Single-file "suspect a box is compromised" triage

### Added
- **`deploy/standalone/Invoke-FosTriage.ps1`** - a fully self-contained, single-file Windows
  triage script (no dependencies, no external files, no internet for analysis). Built for the
  "we have NinjaOne/ScreenConnect on this device and think it's compromised - run something now"
  workflow: paste it into an RMM / ScreenConnect run-command window and get a console verdict.
- **Unauthorized remote-access / RMM detection (MITRE T1219).** Collector inventories known
  remote-access agents (AnyDesk, TeamViewer, ScreenConnect, NinjaOne, Atera, Splashtop, RustDesk,
  VNC, LabTech, Kaseya, Datto, and more) from processes/services/installed programs. The
  `-ExpectedRemoteTools` allow-list marks sanctioned agents; anything else is flagged
  (`FOS-RAT-001`), expected ones shown as context (`FOS-RAT-002`). Wired into both analyzers.
- **One-command README entry** for the suspected-compromise workflow.
- `tools/Build-Standalone.ps1` keeps the standalone's embedded ruleset in sync with
  `rules/detections.json` (single source of truth).

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
