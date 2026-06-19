# Running First-On-Scene in NinjaOne (NinjaRMM)

First-On-Scene is built to drop straight into NinjaOne: the collector is **zero-dependency
PowerShell**, it returns **meaningful exit codes**, and it can publish its verdict into
**NinjaOne custom fields** so you can drive Conditions, alerts, and tickets automatically.

> **CJIS reminder:** nothing in this workflow sends endpoint data off the device. Stage the
> toolkit from an **internal** source (NinjaOne software repo, network share, or a pre-baked
> image) — not the public internet — for regulated clients. Local AI stays OFF in RMM runs.

---

## 1. One-time setup

### a) Create the custom fields
**Administration -> Devices -> Role Custom Fields** (or Global Custom Fields). Create:

| Field name (machine name) | Type | Purpose |
|---|---|---|
| `fosVerdict` | Text | ALL_CLEAR / MONITOR / PROBLEM_DETECTED |
| `fosScore` | Text/Integer | Weighted score |
| `fosClassification` | Text | None / Event / Incident / Breach |
| `fosReasonCode` | Text | e.g. RANSOMWARE_ENCRYPTED_FILES |
| `fosCasePath` | Text | Path to the sealed case folder on the endpoint |
| `fosFindings` | Multi-line / WYSIWYG | Top findings summary |

Set each field's **Scripts** permission to **Read/Write** so the script can populate it.

### b) Stage the toolkit on endpoints
Pick one (CJIS-friendly options first):
- **Bake into your image / golden build** at `C:\ProgramData\FirstOnScene`.
- **Push via a NinjaOne file/automation** from your internal software repo or share.
- **`-StageFrom` parameter** pointing at an internal share or HTTPS repo (the wrapper copies it before running).

### c) Add the script to the Script Library
**Administration -> Library -> Scripts -> Add (New Script):**
- **Name:** `First-On-Scene Triage`
- **Categories:** Security
- **Language:** PowerShell
- **OS:** Windows
- **Architecture:** 64-bit
- **Run As:** **System** (required for Security event log + registry)
- **Paste** the contents of [`deploy/ninjaone/fos-ninja-collect.ps1`](../deploy/ninjaone/fos-ninja-collect.ps1).

Optionally set the **Preset Parameters** field, e.g.:
```
-InstallPath "C:\ProgramData\FirstOnScene" -BrandName "Acme SOC"
```
or to stage on the fly from an internal share:
```
-StageFrom "\\fileserver\tools\FirstOnScene" -BrandName "Acme SOC"
```

---

## 2. Running it

- **On demand:** Devices -> select endpoints -> **Run Script -> First-On-Scene Triage**.
- **Scheduled:** add the script to a **Scheduled Task** policy (e.g. nightly triage sweep).
- **Reactive (best):** trigger it from a **Condition** — for example when the AV/EDR raises a
  detection, or on a "Suspicious Process" condition — so triage runs the moment something fires.

---

## 3. Acting on the result

The script exits with a verdict-based code **and** writes the custom fields.

### Branch on exit code
| Exit | Meaning | Suggested NinjaOne response |
|---|---|---|
| `0` | ALL_CLEAR | none |
| `10` | MONITOR | informational note / low-priority ticket |
| `20` | PROBLEM_DETECTED (Incident) | create ticket, notify on-call |
| `21` | PROBLEM_DETECTED (Breach) | create high-priority ticket, page, consider isolation |
| `1` | runtime error | alert the tech |

### Branch on a custom-field Condition
Create a **Condition** of type **Custom Field** where `fosVerdict` **is** `PROBLEM_DETECTED`,
and attach an **Automation** (script) and/or **Ticket/Email** response. Because the verdict is
deterministic, this is a reliable trigger.

### Isolation / containment (optional)
Point the wrapper's underlying action hook at your own response script. First-On-Scene never
isolates a machine on its own — you decide the response in NinjaOne, keeping a human/your policy
in the loop.

---

## 4. Retrieving evidence

Each run seals a case folder (default `C:\ProgramData\FirstOnScene\cases\case-<timestamp>`) with
`bundle.json`, `findings.json`, the HTML report, `manifest.json` (SHA-256), and
`chain_of_custody.log`. `fosCasePath` holds the location. Pull it back with a NinjaOne file
transfer or your normal evidence-collection workflow. **Do not** upload CJI to a public cloud;
use an internal, access-controlled evidence store.

---

## 5. Verifying integrity later

On the analyst workstation:
```powershell
Import-Module .\scripts\win\FOS.Common.psm1
Test-FosManifest -CaseDir 'D:\evidence\case-...'   # SHA-256 of every evidence file
Test-FosCoc      -CaseDir 'D:\evidence\case-...'   # tamper-evident chain of custody
```
A single altered byte fails the manifest and breaks the chain — exactly what you want for a
defensible record.
