<div align="center">
  <img src="assets/logo.png" alt="First-On-Scene" width="280"/>
  <h1>First-On-Scene</h1>
  <p><strong>The free, open-source incident-response triage toolkit for MSPs.</strong></p>
  <p>Collects forensic artifacts, decides <strong>All Clear / Monitor / Problem Detected</strong> with a deterministic engine, and seals the evidence — <strong>fully offline, CJIS-ready, RMM-native.</strong></p>

  <p>
    <img alt="license" src="https://img.shields.io/badge/license-MIT-blue"/>
    <img alt="platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-informational"/>
    <img alt="ai" src="https://img.shields.io/badge/AI-optional%20%26%20local--only-success"/>
    <img alt="egress" src="https://img.shields.io/badge/network%20egress-zero%20by%20default-success"/>
  </p>
</div>

---

## Why MSP pros keep this in the toolbox

- **Decisive, not noisy.** A deterministic, MITRE ATT&CK-mapped rule engine produces a clear verdict and score — tuned to avoid the false positives that make triage tools cry wolf on healthy machines.
- **Actually CJIS-ready.** Zero network egress by default. Optional AI is **local-only** (Ollama, loopback-locked). Forensic data never leaves the endpoint. See [CJIS posture](docs/CJIS_COMPLIANCE.md).
- **Forensically sound.** Every case is sealed with a SHA-256 **manifest** and a tamper-evident, hash-chained **chain of custody**. Change one byte and verification fails.
- **Zero dependencies on the endpoint.** Pure PowerShell 5.1 on Windows, pure Bash + jq on Linux/macOS. Nothing to install on the box you're triaging.
- **RMM-native.** Clean exit codes + custom-field output. First-class [NinjaOne](docs/DEPLOYMENT_NINJAONE.md), [generic RMM](docs/DEPLOYMENT_RMM.md), and [air-gapped](docs/DEPLOYMENT_AIRGAPPED.md) deployment.
- **Free and open source.** MIT. All tools free and open. No API keys, no SaaS, no per-seat cost.

---

## Quick start

### Windows (PowerShell as Administrator)
```powershell
.\scripts\win\fos.ps1
```

### Linux / macOS (requires jq)
```bash
sudo bash scripts/nix/fos.sh
```

That single command runs the whole pipeline and prints a verdict. It exits:

| Exit | Verdict | Meaning |
|---|---|---|
| `0` | ALL_CLEAR | nothing actionable |
| `10` | MONITOR | low-confidence findings worth a look |
| `20` | PROBLEM_DETECTED | Incident |
| `21` | PROBLEM_DETECTED | Breach |
| `1` | error | run failed |

---

## What it produces

Every run creates a **sealed case folder** under `results/<caseId>/`:

```
bundle.json             Raw collected artifacts (read-only collection)
findings.json           Deterministic verdict + scored, ATT&CK-mapped findings (machine-readable)
findings.md             Human-readable findings
Incident_Report_*.html  Branded, shareable report
manifest.json           SHA-256 of every evidence file
chain_of_custody.log    Tamper-evident, hash-chained audit trail
Steps_Taken.txt         Append-only action log
```

---

## How it works

```
            ┌──────────────────────┐        ┌───────────────────────────┐
 endpoint   │  COLLECTOR (native)  │ bundle │   ANALYZER (deterministic) │
 (read-only)│  PowerShell / Bash   ├───────▶│   rule engine + scoring    │
            │  zero deps, zero net │ .json  │   verdict + classification │
            └──────────────────────┘        └─────────────┬─────────────┘
                                                           │
                          ┌────────────────────────────────┼───────────────────────┐
                          ▼                                 ▼                        ▼
                   findings.json / .md              HTML report            decisive action
                   (+ optional LOCAL AI               (branded)            (All Clear /
                    narrative, advisory)                                   Problem Detected
                                                                           + your hook)
```

- **Collector** runs on the (possibly compromised) endpoint. Read-only, no dependencies, no egress.
- **Analyzer** runs anywhere — on the endpoint or a clean analyst workstation — and owns the verdict.
- **AI is optional, local-only, and advisory** — it writes a plain-English narrative and never changes the verdict. [Setup](docs/AI_LOCAL_SETUP.md).

Detections live in [`rules/detections.json`](rules/detections.json) — versioned, ATT&CK-mapped, and easy to extend. See [authoring guide](docs/RULES.md).

---

## Deployment

| Target | Guide |
|---|---|
| **NinjaOne** (custom fields, Conditions, exit codes) | [docs/DEPLOYMENT_NINJAONE.md](docs/DEPLOYMENT_NINJAONE.md) |
| **Any RMM** (ConnectWise, Datto, Action1, Syncro, Atera, Tactical…) | [docs/DEPLOYMENT_RMM.md](docs/DEPLOYMENT_RMM.md) |
| **Air-gapped / CJIS network** (offline USB kit) | [docs/DEPLOYMENT_AIRGAPPED.md](docs/DEPLOYMENT_AIRGAPPED.md) |

---

## Common options

```powershell
# Branding + custom response hooks
.\scripts\win\fos.ps1 -BrandName "Acme SOC" -CustomProblemScript C:\rmm\alert.ps1

# Collect only (pull the bundle for offline analysis on a clean workstation)
.\scripts\win\fos.ps1 -Mode collect

# Analyze a previously collected bundle
.\scripts\win\fos.ps1 -Mode analyze -BundlePath .\results\<case>\bundle.json

# Add a LOCAL AI narrative (requires Ollama on localhost; stays on the box)
.\scripts\win\fos.ps1 -EnableLocalAI
```
Linux equivalents use `--brand`, `--mode collect|analyze`, `--bundle`, `--enable-local-ai`.

---

## Verifying evidence integrity

```powershell
Import-Module .\scripts\win\FOS.Common.psm1
Test-FosManifest -CaseDir .\results\<case>   # SHA-256 of every evidence file
Test-FosCoc      -CaseDir .\results\<case>   # tamper-evident chain of custody
```
```bash
. scripts/nix/fos-common.sh
fos_manifest_verify results/<case>
fos_coc_verify      results/<case>
```

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [CJIS compliance posture](docs/CJIS_COMPLIANCE.md)
- [Writing detection rules](docs/RULES.md)
- [Local AI setup (Ollama)](docs/AI_LOCAL_SETUP.md)
- [Changelog](CHANGELOG.md)

## License

MIT — see [LICENSE](LICENSE). Free and open source, forever.
