# Standalone single-file triage

`Invoke-FosTriage.ps1` is a **self-contained** First-On-Scene triage tool for Windows: one file, no
dependencies, no external files, and no internet calls during analysis. It's built for the
"this box might be compromised — run something on it now" workflow via NinjaOne / ScreenConnect / any
RMM, or locally.

## Run it

One command (downloads the single file, then runs it):
```powershell
$p="$env:TEMP\Invoke-FosTriage.ps1"; iwr "https://raw.githubusercontent.com/amosroger91/First-On-Scene/main/deploy/standalone/Invoke-FosTriage.ps1" -OutFile $p -UseBasicParsing; & $p -ExpectedRemoteTools 'NinjaOne,ScreenConnect'
```

Or paste the whole file into a ScreenConnect/NinjaOne run-command window and call it. For air-gapped /
CJIS, copy the single file to the host instead of using the URL.

## Parameters

| Parameter | Purpose |
|---|---|
| `-ExpectedRemoteTools` | Comma-separated allow-list of sanctioned remote-access/RMM agents (e.g. `'NinjaOne,ScreenConnect'`). Anything else found is flagged UNAUTHORIZED. |
| `-CaseDir` | Output case folder (default `C:\ProgramData\FirstOnScene\cases\<caseId>`). |
| `-BrandName` | Branding on the HTML report. |
| `-StartTime` / `-EndTime` | Event-log time window. |
| `-Quiet` | Suppress console output (still writes files; use the exit code). |

## Output

- Console verdict (tech-facing) + exit code: `0` clear · `10` monitor · `20` incident · `21` breach · `1` error.
- A sealed case folder: `bundle.json`, `findings.json`, HTML report, `manifest.json` (SHA-256),
  `chain_of_custody.log` (tamper-evident).

## Maintenance

The engine mirrors the modular `scripts/win` implementation; the embedded ruleset is generated from
`rules/detections.json`. After changing rules, regenerate:
```powershell
.\tools\Build-Standalone.ps1
```
