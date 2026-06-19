#!/usr/bin/env bats
# bats tests for First-On-Scene (Linux/macOS).
# Install bats (apt install bats / brew install bats-core) then:  bats tests/fos.bats

setup() {
  ROOT="$(cd "$(dirname "$BATS_TEST_FILENAME")/.." && pwd)"
  NIX="$ROOT/scripts/nix"
  FIX="$ROOT/tests/fixtures"
  : "${JQ:=jq}"; export JQ
  . "$NIX/fos-common.sh"
}

run_triage() { # $1 = fixture
  CD="$(mktemp -d)"
  cp "$FIX/$1" "$CD/bundle.json"
  run bash "$NIX/invoke-triage.sh" "$CD/bundle.json" "$CD" "$ROOT/rules/detections.json" "Test"
  EXIT="$status"
  VERDICT="$("$JQ" -r .verdict "$CD/findings.json")"
  CLASS="$("$JQ" -r .classification "$CD/findings.json")"
  NF="$("$JQ" -r '.findings|length' "$CD/findings.json")"
}

@test "sha256 of abc is correct" {
  [ "$(fos_sha256_string abc)" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]
}

@test "clean bundle -> ALL_CLEAR / exit 0 / 0 findings" {
  run_triage clean_bundle.json
  [ "$EXIT" -eq 0 ]
  [ "$VERDICT" = "ALL_CLEAR" ]
  [ "$NF" -eq 0 ]
  rm -rf "$CD"
}

@test "infected bundle -> PROBLEM_DETECTED / Breach / exit 21" {
  run_triage infected_bundle.json
  [ "$EXIT" -eq 21 ]
  [ "$VERDICT" = "PROBLEM_DETECTED" ]
  [ "$CLASS" = "Breach" ]
  rm -rf "$CD"
}

@test "macOS clean bundle -> ALL_CLEAR / exit 0" {
  run_triage macos_clean_bundle.json
  [ "$EXIT" -eq 0 ]
  [ "$VERDICT" = "ALL_CLEAR" ]
  rm -rf "$CD"
}

@test "macOS infected bundle -> PROBLEM_DETECTED (launchd + SIP-off + deleted image + hosts/listener)" {
  run_triage macos_infected_bundle.json
  [ "$EXIT" -ge 20 ]
  [ "$VERDICT" = "PROBLEM_DETECTED" ]
  # the macOS-native rules must be among the detections
  "$JQ" -e '.findings|map(.ruleId)|index("FOS-NIX-003")' "$CD/findings.json" >/dev/null
  "$JQ" -e '.findings|map(.ruleId)|index("FOS-MAC-001")' "$CD/findings.json" >/dev/null
  rm -rf "$CD"
}

@test "chain of custody detects tampering" {
  CD="$(mktemp -d)"
  fos_coc_add "$CD" "A" "one" >/dev/null
  fos_coc_add "$CD" "B" "two" >/dev/null
  run fos_coc_verify "$CD"; [ "$status" -eq 0 ]
  sed -i 's/one/HACKED/' "$CD/chain_of_custody.log"
  run fos_coc_verify "$CD"; [ "$status" -ne 0 ]
  rm -rf "$CD"
}

@test "manifest detects tampering" {
  CD="$(mktemp -d)"
  printf 'evidence' > "$CD/bundle.json"
  fos_manifest_new "$CD" "ID" >/dev/null
  run fos_manifest_verify "$CD"; [ "$status" -eq 0 ]
  printf 'tampered' > "$CD/bundle.json"
  run fos_manifest_verify "$CD"; [ "$status" -ne 0 ]
  rm -rf "$CD"
}
