# Air-Gapped / CJIS Network Deployment

First-On-Scene is designed to run on networks with **no internet access at all**. Nothing phones
home; the only optional network call is loopback (local AI), which is enforced.

## Build the offline kit (on a connected staging machine)

```powershell
.\deploy\airgapped\build-bundle.ps1
```
```bash
bash deploy/airgapped/build-bundle.sh
```

This produces a single archive under `dist/` containing the engine, rules, scripts, schemas, docs,
and an `OFFLINE_RUNBOOK.txt`, plus prints its **SHA-256**. Record that hash.

## Transfer

Move the archive to the air-gapped network via your **approved removable media** process. On arrival,
verify the SHA-256 matches what the build printed before extracting.

## Run (no internet required)

- **Windows:** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\win\fos.ps1`
- **Linux/macOS:** `sudo bash scripts/nix/fos.sh` (install `jq` from your offline repo if needed)

## Optional offline AI

The local narrative can run fully air-gapped:

1. On a connected staging machine, install Ollama and `ollama pull llama3.1:8b`.
2. Copy the Ollama **models** directory to the air-gapped host:
   - Windows: `%USERPROFILE%\.ollama\models`
   - Linux/macOS: `~/.ollama/models`
3. Start Ollama on the air-gapped host and run with `-EnableLocalAI` / `--enable-local-ai`.

The AI endpoint is hard-locked to `localhost`; it cannot egress even if misconfigured.

## Evidence handling

- Each case folder is sealed with `manifest.json` (SHA-256) and a hash-chained `chain_of_custody.log`.
- Verify before/after any transfer:
  ```powershell
  Import-Module .\scripts\win\FOS.Common.psm1
  Test-FosManifest -CaseDir results\<case>; Test-FosCoc -CaseDir results\<case>
  ```
  ```bash
  . scripts/nix/fos-common.sh
  fos_manifest_verify results/<case>; fos_coc_verify results/<case>
  ```
- Store case folders on **encrypted, access-controlled** media. See [CJIS_COMPLIANCE.md](CJIS_COMPLIANCE.md)
  for the full policy-area mapping and the agency/MSP responsibility boundary.
