# Generic RMM Deployment

First-On-Scene works with **any** RMM because it follows two simple contracts: a **zero-dependency
native entry point** and **meaningful exit codes**. If your RMM can run a PowerShell/Bash script and
branch on its exit code, you're done.

> Ready-to-paste commands live in [`deploy/rmm/oneliner.txt`](../deploy/rmm/oneliner.txt).
> For NinjaOne specifically (custom fields + Conditions), see [DEPLOYMENT_NINJAONE.md](DEPLOYMENT_NINJAONE.md).

## Exit-code contract

| Exit | Verdict | Typical RMM response |
|---|---|---|
| `0` | ALL_CLEAR | none |
| `10` | MONITOR | low-priority note/ticket |
| `20` | PROBLEM_DETECTED (Incident) | ticket + notify |
| `21` | PROBLEM_DETECTED (Breach) | high-priority ticket + escalate |
| `1` | runtime error | alert the tech |

## Pattern

1. **Stage the toolkit** to a known path (image bake, software repo, or file push):
   - Windows: `C:\ProgramData\FirstOnScene`
   - Linux/macOS: `/opt/first-on-scene`
   For CJIS, stage from an **internal** source, not the public internet.
2. **Run the entry point** as System/root:
   - `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\FirstOnScene\scripts\win\fos.ps1 -NoAction`
   - `sudo bash /opt/first-on-scene/scripts/nix/fos.sh --no-action`
   `-NoAction` lets the RMM own the response; omit it to let the bundled `Action-*` hooks run.
3. **Branch** on the exit code (and/or parse `findings.json`).

## Tested RMMs / approaches

| RMM | Approach |
|---|---|
| **NinjaOne** | Script Library + custom fields + Conditions ([guide](DEPLOYMENT_NINJAONE.md)) |
| **ConnectWise Automate** | Script step running the PowerShell/Bash one-liner; branch on `%errorlevel%` |
| **Datto RMM** | Component (PowerShell/Shell) running `fos.ps1`/`fos.sh`; map exit codes to alerts |
| **Action1** | Custom script; use the return code in automation logic |
| **Syncro / Atera** | Script asset; parse exit code or `findings.json` into a ticket |
| **Tactical RMM** | Script + collector task; alert on non-zero exit |
| **Kaseya VSA** | Agent procedure invoking the one-liner; branch on result |

## Parsing results in automation

```powershell
$f = Get-Content "C:\ProgramData\FirstOnScene\results\<case>\findings.json" | ConvertFrom-Json
$f.verdict; $f.score; $f.classification; $f.reasonCode
```
```bash
jq -r '.verdict, .score, .classification, .reasonCode' /opt/first-on-scene/results/<case>/findings.json
```

## Custom response hooks

Pass your own ticket/alert/isolation script so the bundled action invokes it:
```powershell
.\fos.ps1 -CustomProblemScript C:\rmm\raise-ticket.ps1 -CustomAllClearScript C:\rmm\close.ps1
```
```bash
bash fos.sh --custom-problem /opt/rmm/raise-ticket.sh --custom-all-clear /opt/rmm/close.sh
```
First-On-Scene never isolates or remediates on its own — your hook + your RMM policy decide.
