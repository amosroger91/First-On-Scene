# Architecture

First-On-Scene v3 cleanly separates **collection** from **analysis**. This split is what makes it
both forensically sound and CJIS-deployable.

## Components

```
scripts/win/                         scripts/nix/
  FOS.Common.psm1   shared lib         fos-common.sh    shared lib
  Collect-Artifacts.ps1  collector     collect-artifacts.sh  collector
  Invoke-Triage.ps1      analyzer      invoke-triage.sh      analyzer (jq)
  Write-Report.ps1       reporter      write-report.sh       reporter
  Invoke-LocalAI.ps1     opt. AI       invoke-local-ai.sh    opt. AI
  Action-*.ps1           decision      action-*.sh           decision
  fos.ps1                orchestrator  fos.sh                orchestrator
rules/detections.json    versioned, ATT&CK-mapped ruleset (engine reads this)
schemas/                 artifact_schema.json + findings_schema.json (data contracts)
deploy/                  ninjaone/ + rmm/ + airgapped/
```

The Windows (PowerShell) and Linux/macOS (Bash+jq) implementations are **functional mirrors** —
same rule engine semantics, same scoring, same verdicts, same exit codes. Verified by parity tests.

## Data flow

1. **Collector** (read-only, zero deps, zero egress) gathers artifacts on the endpoint and writes a
   schema-conformant `bundle.json`, then opens the chain of custody.
2. **Analyzer** loads the bundle + `rules/detections.json`, evaluates every rule generically,
   computes a **severity-capped weighted score**, classifies the result, and writes
   `findings.json` + `findings.md`. **This is the only thing that decides the verdict.**
3. **(Optional) Local AI** adds an advisory plain-English narrative from a loopback Ollama. It never
   changes the verdict.
4. **Reporter** renders a branded HTML report including an evidence-integrity panel.
5. **Seal**: a SHA-256 `manifest.json` is written over the evidence files.
6. **Action**: `Action-AllClear` or `Action-ProblemDetected` logs the decisive call and optionally
   invokes your custom response script. The orchestrator exits with the verdict code.

## The rule engine

Rules are data, not code. Each rule declares a `selector` (a dotted path into the bundle), a set of
`conditions` (`field` + `op` + `value`), `match` (`all`/`any`), a `severity`, a `weight`, ATT&CK
mapping, and human guidance. A small set of `builtin` rules (correlation, timestomping, AV hits,
WMI consumers) are evaluated in code but still carry their metadata in the ruleset.

**Operators:** `regexI`, `notRegexI`, `containsI`, `notContainsI`, `eq`, `ne`, `gt`, `lt`, `ge`,
`le`, `in`, `notIn`, `exists`, `isTrue`, `isFalse`.

### Scoring

```
contribution(rule) = weight × min(matchCount, cap[severity])
cap = { info:1, low:1, medium:2, high:3, critical:3 }
score = Σ contribution
```

Severity caps stop one noisy low/medium category (e.g. common per-user Run keys) from dominating the
verdict. Thresholds (in the ruleset): `score ≥ problem → PROBLEM_DETECTED`, `≥ monitor → MONITOR`,
else `ALL_CLEAR`. Classification escalates to **Breach** at the breach threshold or when a matched
rule sets `escalateToBreach` (e.g. ransom-note indicator).

## Integrity model

- **Manifest** (`manifest.json`) hashes the **evidence** files (bundle, findings, report). The
  append-only audit logs are intentionally excluded because they keep growing after sealing.
- **Chain of custody** (`chain_of_custody.log`) is a hash-chained JSON-lines log: each entry's hash
  covers the previous entry's hash, so any insertion/edit/deletion is detectable.
- Both are verifiable offline via the shared-lib helpers.

## Design principles

- **Deterministic first.** The verdict must be reproducible and explainable. AI is a convenience layer.
- **Read-only by default.** No process termination, no Defender toggling, no runtime binary downloads.
  Those exist only as explicit, logged, off-by-default options requiring operator-supplied, pinned tooling.
- **No silent egress.** The only optional network call is loopback (local AI), and it is enforced.
- **Zero endpoint dependencies.** Whatever ships in the OS is all that's required to collect.
