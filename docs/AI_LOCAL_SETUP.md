# Optional Local AI (Ollama)

First-On-Scene works perfectly with **no AI at all** — the verdict is always deterministic. The
optional AI layer adds a plain-English **analyst narrative** to the report for non-technical
stakeholders. It is **advisory only** and never changes the verdict, score, or classification.

## Why local-only

For CJIS (and good hygiene generally), forensic data must not leave the device. So this layer:

- Talks **only to `localhost`** (`127.0.0.1` / `::1`). The scripts **refuse any non-loopback endpoint.**
- Is **OFF by default.** You opt in with `-EnableLocalAI` / `--enable-local-ai`.
- Sends only **rule-level findings** (names, categories, ATT&CK, counts) — **not raw artifacts** —
  minimizing exposure even to the local model.

## Install Ollama (free, open source)

- **Windows / macOS:** download from <https://ollama.com> and install.
- **Linux:** `curl -fsSL https://ollama.com/install.sh | sh`

Pull a model (any of these work; pick by hardware):

```bash
ollama pull llama3.1:8b      # good default, ~5 GB
ollama pull qwen2.5:7b       # strong, compact
ollama pull gpt-oss:20b      # higher quality, needs more RAM/VRAM
```

Ollama listens on `http://127.0.0.1:11434` by default.

## Use it

```powershell
.\scripts\win\fos.ps1 -EnableLocalAI -OllamaModel llama3.1:8b
```
```bash
bash scripts/nix/fos.sh --enable-local-ai --ollama-model llama3.1:8b
```

The narrative is attached to `findings.json` (`aiNarrative`) and rendered in the HTML report, clearly
labelled as advisory. If Ollama isn't running, the run **degrades gracefully** — you still get the
full deterministic verdict and report.

## Air-gapped use

You can run the AI fully offline. Pull the model on a staging machine, copy the Ollama `models`
directory to the air-gapped host, start Ollama there, and run with `-EnableLocalAI`. See
[DEPLOYMENT_AIRGAPPED.md](DEPLOYMENT_AIRGAPPED.md).

## Hard guarantee

The endpoint enforcement is a regex on the endpoint URL — anything that isn't loopback throws
before a single byte is sent. There is no configuration that makes First-On-Scene send forensic
data to a remote model.
