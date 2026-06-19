# Writing detection rules

Detections live in [`rules/detections.json`](../rules/detections.json). The analyzer evaluates them
generically, so adding coverage is a data change — no code required for `match`-type rules.

## Anatomy of a rule

```json
{
  "id": "FOS-PER-001",
  "name": "Registry Run key launching from a non-system path",
  "category": "Persistence",
  "mitre": { "tactic": "TA0003", "technique": "T1547.001" },
  "type": "match",
  "selector": "artifacts.persistence.registryRunKeys",
  "match": "all",
  "severity": "low",
  "weight": 2,
  "reasonCode": "PERSISTENCE_RUN_KEY",
  "conditions": [
    { "field": "valueData", "op": "notRegexI", "value": "\\\\(Windows|Program Files)\\\\" },
    { "field": "valueData", "op": "regexI",    "value": "\\.(exe|dll|bat|cmd|ps1|vbs|js|scr)" }
  ],
  "rationale": "Why this matters, in one sentence.",
  "falsePositive": "When this fires benignly and how to confirm."
}
```

| Field | Notes |
|---|---|
| `id` | Stable, unique. Convention: `FOS-<AREA>-<NNN>` (PER, EXE, NET, PSH, CRD, AF, AV, RAN, NIX). |
| `selector` | Dotted path into the bundle to an **array**. The rule runs once per array item. |
| `match` | `all` = every condition true (AND); `any` = at least one (OR). |
| `conditions` | `field` is a property of each item; `op` + `value` define the test. |
| `severity` | `info`/`low`/`medium`/`high`/`critical`. Caps the score multiplier (see below). |
| `weight` | Base points contributed when the rule fires. |
| `reasonCode` | Capitalized code; the highest-contribution finding's code becomes the case reason. |
| `escalateToBreach` | Optional `true` to force Breach classification (e.g. ransomware impact). |
| `type` | `match` (default, data-driven) or `builtin` (code-evaluated correlation/AV/timestomp). |

## Operators

`regexI`, `notRegexI`, `containsI`, `notContainsI`, `eq`, `ne`, `gt`, `lt`, `ge`, `le`,
`in` (value is an array), `notIn`, `exists`, `isTrue`, `isFalse`. Regex is case-insensitive.

> **JSON escaping:** to match a literal backslash in a path, write `\\\\` in JSON (decodes to `\\`,
> which the regex engine treats as one literal backslash).

## Scoring & false positives

```
contribution = weight × min(matchCount, cap[severity])     cap = {info:1, low:1, medium:2, high:3, critical:3}
```

Keep **ubiquitous-but-legit** patterns (per-user Run keys, installers in Temp, encoded PowerShell
used by RMM) at **low severity / low weight** so they surface as MONITOR context without screaming
PROBLEM. Reserve high/critical weights for high-confidence indicators (LOLBin process trees, C2
ports, download cradles, AV detections, ransom-note filenames, WMI command-line consumers).

Always write an honest `falsePositive` note — it's what makes the report trustworthy to a tech.

## Adding a builtin

`builtin` rules (e.g. timestomping, privileged+service logon correlation, AV results) are
implemented in both analyzers (`Invoke-Triage.ps1` `Invoke-FosBuiltin`, and the `builtin` function
in `invoke-triage.sh`) keyed by rule `id`, but still carry their `weight`/`severity`/`mitre`/text in
the ruleset. Add to both implementations to keep Windows/Linux parity.

## Testing your rule

Add a crafted bundle under `tests/fixtures/` and run the analyzer:
```powershell
.\scripts\win\Invoke-Triage.ps1 -BundlePath tests\fixtures\your_bundle.json -CaseDir $env:TEMP\t
```
```bash
bash scripts/nix/invoke-triage.sh tests/fixtures/your_bundle.json /tmp/t
```
Confirm a clean bundle stays `ALL_CLEAR` and your malicious bundle fires the expected rule.
