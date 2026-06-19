<div align="center">
  <img src="assets/logo-v2.png" alt="First-On-Scene" width="280"/>
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

## 🚨 Suspect a machine is compromised? Run this one command.

You've got NinjaOne / ScreenConnect on a box and think it might be popped. Run this **single,
self-contained command** on that machine (locally, or paste it into your RMM / ScreenConnect
run-command window). It needs **nothing installed**, makes **no internet calls** during analysis,
and prints a clear verdict plus a **host snapshot** — make/model, serial, OS, CPU/RAM, disk free
space, logged-on users — and an inventory of every remote-access / RMM agent on the box.

```powershell
$p="$env:TEMP\Invoke-FosTriage.ps1"; iwr "https://raw.githubusercontent.com/amosroger91/First-On-Scene/main/deploy/standalone/Invoke-FosTriage.ps1" -OutFile $p -UseBasicParsing; & $p -ExpectedRemoteTools 'NinjaOne,ScreenConnect'
```

> **Remote-access / RMM tools are shown as *informational* — they never drive the verdict.** MSPs
> run RMMs by design, so finding NinjaOne, ScreenConnect, Splashtop, etc. is not a compromise. List
> the agents you *expect* in `-ExpectedRemoteTools` (comma-separated) to label them `[expected]`;
> anything else (AnyDesk, TeamViewer, RustDesk, an unexpected LabTech...) is listed as `[undeclared]`
> so you can eyeball it and confirm it's one you installed. The verdict is decided by the actual
> attack indicators below — not by which remote tools are present.

By default it runs a fast pass that also checks **Defender health/tamper state**, **Windows Firewall
posture**, **code signatures + SHA-256 of every running process**, **autostart hijacks** (IFEO /
AppInit / Winlogon / sticky-keys backdoors), **network state** (listening ports, DNS cache, hosts-file
redirects), and **log-clear events**. Add **`-Deep`** for Prefetch execution evidence, a
possible-injection scan (unsigned modules loaded into running processes), and a kernel-driver
signature scan — a minute or two more, still no dependencies. (Run as Administrator/SYSTEM for full coverage.)

It prints a console verdict like:

```
============================================================
  FIRST-ON-SCENE  ::  PROBLEM_DETECTED (Incident)
  HOST: WS-01    SCORE: 28    REASON: AV_DISABLED
============================================================
  Machine:
   Dell Inc. Latitude 5440   S/N 7XYZ123
   OS: Microsoft Windows 11 Pro (build 26200, 64-bit)
   CPU: 13th Gen Intel(R) Core(TM) i5-1345U  (10C/12T)   RAM: 15.7 GB   Uptime: 2d 4h 11m
   Domain: client.local
  Disks:
   C:  41 GB free of 476 GB (9% free)
  Logged-on users:
   CLIENT\jsmith (interactive)
============================================================
  Top findings:
   [critical] FOS-DEF-001  Microsoft Defender real-time protection is OFF
   [medium  ] FOS-DEF-003  Defender tamper protection is OFF
  Remote-access / RMM tools (informational - does not affect verdict):
   [expected]   ScreenConnect / ConnectWise Control (process,service)
   [undeclared] RustDesk (installed)
   (undeclared = not in your -ExpectedRemoteTools list; confirm each is one you installed)
============================================================
  Report:   C:\ProgramData\FirstOnScene\cases\...\Incident_Report_*.html
```

It exits `0` (clear) / `10` (monitor) / `20` (incident) / `21` (breach) so your RMM can branch on it,
and it seals a full evidence case folder (bundle + SHA-256 manifest + chain of custody). Air-gapped /
CJIS? Pre-stage the single file instead of using the URL — see [air-gapped guide](docs/DEPLOYMENT_AIRGAPPED.md).
The script lives at [`deploy/standalone/Invoke-FosTriage.ps1`](deploy/standalone/Invoke-FosTriage.ps1).

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

## What it inspects (and how deep)

A fast, **read-only, live** pass — designed to answer "is this box compromised?" in well under a minute, then tell you when something warrants a deeper dive.

**Default pass:**
- **Persistence** — Run/RunOnce keys, scheduled tasks, services, WMI event subscriptions, and high-value **ASEP hijacks**: IFEO debuggers, AppInit_DLLs, Winlogon Shell/Userinit, and accessibility / sticky-keys backdoors.
- **Execution** — running processes with **Authenticode signature + SHA-256**; unsigned binaries from user/temp paths, processes whose on-disk image was deleted, and Office→LOLBin trees.
- **Remote access / RMM** — inventories AnyDesk, TeamViewer, ScreenConnect, NinjaOne, Atera, Splashtop, RustDesk, VNC, LabTech, Kaseya, Datto and more. **Informational only — never affects the verdict** (MSPs run RMMs by design); anything not in your `-ExpectedRemoteTools` allow-list is surfaced as `[undeclared]` for a quick eyeball.
- **Security posture** — Microsoft Defender real-time/tamper state and configured exclusions, plus **Windows Firewall** profile state (Domain/Private/Public).
- **Network** — connections to high-risk C2 ports and external RDP/SMB exposure, **listening TCP/UDP ports** with owning process (bind-shell detection), the local **DNS client cache**, and **hosts-file redirects** to non-loopback addresses.
- **Credential access** — privileged + service-logon correlation, new local accounts.
- **Defense evasion** — obfuscated/download-cradle PowerShell, timestomping, **Security/System log-clear** events.
- **Malware** — on-box AV detections and ransom-note indicators.

**`-Deep` pass** (a minute or two more, still zero dependencies): Prefetch execution evidence, a possible-injection scan (unsigned modules loaded into running processes), and a **kernel driver signature scan** (unsigned drivers loaded from non-standard paths).

**The honest ceiling:** everything above is live OS-level, so a kernel rootkit can still hide from it. The deepest layers — **full memory image (Volatility), disk imaging / $MFT / super-timeline, and firmware/UEFI** — defeat that by analyzing off the box, but they're a heavy, offline DFIR job and deliberately *not* part of the fast triage. First-On-Scene's role is to make the live call confidently and tell you when to escalate to that.

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
# Declare your own remote-access agents so they show as [expected] instead of [undeclared]
.\scripts\win\fos.ps1 -ExpectedRemoteTools 'NinjaOne,ScreenConnect'

# Deeper pass (Prefetch + possible-injection module scan)
.\scripts\win\fos.ps1 -Deep

# Branding + custom response hooks
.\scripts\win\fos.ps1 -BrandName "Acme SOC" -CustomProblemScript C:\rmm\alert.ps1

# Collect only (pull the bundle for offline analysis on a clean workstation)
.\scripts\win\fos.ps1 -Mode collect

# Analyze a previously collected bundle
.\scripts\win\fos.ps1 -Mode analyze -BundlePath .\results\<case>\bundle.json

# Add a LOCAL AI narrative (requires Ollama on localhost; stays on the box)
.\scripts\win\fos.ps1 -EnableLocalAI
```
Linux equivalents use `--brand`, `--mode collect|analyze`, `--bundle`, `--enable-local-ai` (remote-tool/deep checks are Windows-focused). The self-contained single-file tool is [`deploy/standalone/Invoke-FosTriage.ps1`](deploy/standalone/Invoke-FosTriage.ps1) — see the [suspected-compromise section](#-suspect-a-machine-is-compromised-run-this-one-command).

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
