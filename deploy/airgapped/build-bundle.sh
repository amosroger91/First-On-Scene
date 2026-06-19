#!/usr/bin/env bash
# Builds a self-contained, offline First-On-Scene kit for air-gapped / CJIS networks (Linux/macOS).
# Produces a tar.gz that runs with ZERO internet access. Transfer via approved removable media.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${1:-$ROOT/dist/first-on-scene-airgapped-$(date +%Y%m%d).tar.gz}"
mkdir -p "$(dirname "$OUT")"

STAGE="$(mktemp -d)/first-on-scene"
mkdir -p "$STAGE"
for item in scripts rules schemas docs deploy README.md LICENSE CHANGELOG.md; do
  [ -e "$ROOT/$item" ] && cp -r "$ROOT/$item" "$STAGE/"
done

cat > "$STAGE/OFFLINE_RUNBOOK.txt" <<'EOF'
FIRST-ON-SCENE - AIR-GAPPED KIT
===============================
Runs with NO internet access.

LINUX/macOS (requires jq: apt install jq / brew install jq):
  sudo bash scripts/nix/fos.sh

WINDOWS:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\win\fos.ps1

OPTIONAL OFFLINE AI (local narrative, stays on the box):
  1. On a staging machine: install Ollama, run `ollama pull llama3.1:8b`.
  2. Copy ~/.ollama/models to the air-gapped host's Ollama models dir.
  3. Start ollama, then: bash scripts/nix/fos.sh --enable-local-ai
  The AI endpoint is hard-locked to localhost; it cannot egress.

INTEGRITY: every case folder has manifest.json + chain_of_custody.log.
Verify: scripts/nix/fos-common.sh -> fos_manifest_verify / fos_coc_verify.
See docs/CJIS_COMPLIANCE.md and docs/DEPLOYMENT_AIRGAPPED.md.
EOF

tar -czf "$OUT" -C "$(dirname "$STAGE")" "first-on-scene"
rm -rf "$(dirname "$STAGE")"

if command -v sha256sum >/dev/null 2>&1; then HASH="$(sha256sum "$OUT" | awk '{print $1}')"; else HASH="$(shasum -a 256 "$OUT" | awk '{print $1}')"; fi
echo "Air-gapped kit: $OUT"
echo "SHA-256:        $HASH"
echo "Transfer this archive and its SHA-256 to the air-gapped network via approved media."
