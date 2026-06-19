# CJIS Compliance Posture

First-On-Scene is designed to be **deployable inside a CJIS-regulated environment** (e.g. a law
enforcement agency that is an MSP client) without violating the FBI CJIS Security Policy.

> **Honest scope boundary.** A *tool* cannot make an organization "CJIS compliant" — compliance
> is organizational (personnel screening, physical security, agreements, audits). What a tool can
> do is **avoid breaking** the policy and **provide the technical controls** the policy expects.
> This document maps what First-On-Scene does to the relevant policy areas, and is explicit about
> what remains the agency's/MSP's responsibility.

## The core design decision

The previous generation of this toolkit sent **all collected forensic data to a public cloud LLM**
(OpenRouter/qwen). Forensic artifacts from a CJIS system can contain Criminal Justice Information
(CJI) and PII. Sending them to a third party with no CJIS Security Addendum is **unauthorized
disclosure** — a disqualifying violation.

First-On-Scene v3 removes that path entirely:

- **The verdict is 100% deterministic** — a rule engine, not a model. It runs fully offline.
- **AI is optional and local-only.** The optional narrative uses Ollama on `localhost`, hard-locked
  to a loopback endpoint. It is OFF by default and refuses any non-loopback address.
- **Zero network egress by default.** The collector and analyzer make no outbound connections.

## Policy-area mapping

| CJIS Policy Area | Requirement (summary) | How First-On-Scene addresses it |
|---|---|---|
| **5.4 Auditing & Accountability** | Tamper-evident audit records of who did what, when | `chain_of_custody.log`: hash-chained JSON-lines (each entry hashes the previous), plus append-only `Steps_Taken.txt`. `Test-FosCoc` / `fos_coc_verify` detect any insertion, edit, or deletion. |
| **5.5 Access Control** | Least privilege; the tool shouldn't expand attack surface | Read-only collection; no listeners; no remote-binary downloads at runtime; no auto-isolation. The operator/RMM decides any response. |
| **5.6 Identification & Authentication** | Actions attributable to a user | Operator identity (`user@host`) is captured in metadata, the manifest, and every chain-of-custody entry. |
| **5.10 System & Communications Protection / Encryption** | FIPS 140-2/3 validated crypto for CJI at rest/in transit | SHA-256 via Windows CNG / OpenSSL (FIPS-validated modules). No CJI in transit because there is no transit. Run Windows in **FIPS mode** for a validated provider. Encrypt the evidence store at rest with your approved FDE (e.g. BitLocker). |
| **5.10 Integrity** | Detect unauthorized changes to evidence | `manifest.json` records the SHA-256 of every evidence file; `Test-FosManifest` / `fos_manifest_verify` flag any change. |
| **5.13 / Cloud & Mobile** | Cloud services touching CJI must meet CJIS requirements | **No cloud is used.** Optional AI is local-only (loopback-enforced). |
| **Media Protection / Transport** | Controlled transfer of CJI | Air-gapped kit (`deploy/airgapped`) is transferred via approved removable media with a published SHA-256. |

## What the tool does NOT do (your responsibility)

- **FIPS mode**: enable it on the OS so the crypto provider is the validated one. (SHA-256 itself
  is a CJIS-approved algorithm; FIPS mode ensures the *module* is validated.)
- **Encryption at rest** of the evidence/case store — use your approved full-disk or container encryption.
- **Personnel screening, CJIS Security Addendum with your MSP, physical security, network segmentation.**
- **Access control** to the case folders and the analyst workstation.
- **Retention & disposal** of evidence per your agency policy.

## Operating recommendations for CJIS environments

1. Stage the toolkit from an **internal** source (image, share, RMM repo) — never the public one-liner.
2. Keep **AI off**, or if you want the narrative, install Ollama locally and run with the loopback
   default. Never point it at a remote endpoint (the tool refuses anyway).
3. Run the analyzer on a **controlled analyst workstation**, not on the suspect host, where practical.
4. Store case folders on **encrypted, access-controlled** media; verify the manifest + chain of
   custody before and after transfer.
5. Keep the append-only logs intact; they are your defensible audit trail.

See also: [`DEPLOYMENT_AIRGAPPED.md`](DEPLOYMENT_AIRGAPPED.md), [`AI_LOCAL_SETUP.md`](AI_LOCAL_SETUP.md),
[`ARCHITECTURE.md`](ARCHITECTURE.md).
