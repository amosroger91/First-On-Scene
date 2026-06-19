#!/usr/bin/env bash
# First-On-Scene deterministic triage analyzer (Linux/macOS).
# Evaluates rules/detections.json against bundle.json using jq. Zero AI, zero egress.
# Exit codes: 0 ALL_CLEAR | 10 MONITOR | 20 PROBLEM(Incident) | 21 PROBLEM(Breach) | 1 error
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=/dev/null
. "$HERE/fos-common.sh"

BUNDLE="${1:?bundle.json path required}"
CASEDIR="${2:?case dir required}"
RULES="${3:-$ROOT/rules/detections.json}"
BRAND="${4:-First-On-Scene}"
FINDINGS="$CASEDIR/findings.json"

fos_log STEP "Loading bundle: $BUNDLE" "$CASEDIR"
fos_coc_add "$CASEDIR" "ANALYSIS_START" "ruleset=$("$JQ" -r '.rulesetVersion' "$RULES")" "$BUNDLE" >/dev/null

"$JQ" -n \
  --slurpfile b "$BUNDLE" \
  --slurpfile r "$RULES" \
  --arg engine "$FOS_ENGINE_VERSION" \
  --arg analyzedUtc "$(fos_utc_now)" \
  --argjson analyst "$(fos_operator_json | "$JQ" '{user,host}')" '
  ($b[0]) as $bundle | ($r[0]) as $ruleset |
  def opmatch($item;$c):
    (($item[$c.field]) // null) as $raw | ($raw|tostring) as $v | ($v|ascii_downcase) as $vl |
    if   $c.op=="regexI"       then ($v|test($c.value;"i"))
    elif $c.op=="notRegexI"    then (($v|test($c.value;"i"))|not)
    elif $c.op=="containsI"    then ($vl|contains(($c.value|tostring|ascii_downcase)))
    elif $c.op=="notContainsI" then (($vl|contains(($c.value|tostring|ascii_downcase)))|not)
    elif $c.op=="eq"           then ($v==($c.value|tostring))
    elif $c.op=="ne"           then ($v!=($c.value|tostring))
    elif $c.op=="in"           then ([$c.value[]|tostring]|index($v))!=null
    elif $c.op=="notIn"        then (([$c.value[]|tostring]|index($v))==null)
    elif $c.op=="gt"           then ((($raw|tonumber?) // -1e18) > $c.value)
    elif $c.op=="lt"           then ((($raw|tonumber?) //  1e18) < $c.value)
    elif $c.op=="ge"           then ((($raw|tonumber?) // -1e18) >= $c.value)
    elif $c.op=="le"           then ((($raw|tonumber?) //  1e18) <= $c.value)
    elif $c.op=="exists"       then ($v!="")
    elif $c.op=="isTrue"       then ($raw==true)
    elif $c.op=="isFalse"      then ($raw==false or $raw==null)
    else false end;
  def itemmatch($item;$rule):
    [ $rule.conditions[] | opmatch($item;.) ] as $res |
    if ($rule.match=="any") then ($res|any) else ($res|all) end;
  def selvals($rule): (($bundle | getpath($rule.selector|split("."))) // []);
  def builtin($rule):
    ($rule.id) as $id |
    if $id=="FOS-AF-001" then
      [ ($bundle.artifacts.fileSystem.fileMetadata // [])[]
        | select((.created // "")!="" and (.modified // "")!=""
                 and ((.created|fromdateiso8601?) // null)!=null
                 and ((.modified|fromdateiso8601?) // null)!=null
                 and ((.created|fromdateiso8601) > (.modified|fromdateiso8601))) ]
    elif $id=="FOS-CRD-001" then
      ((($bundle.artifacts.credentialAccess.privilegeEscalationEvents // [])
        + (($bundle.artifacts.credentialAccess.logonEvents // [])|map(select(.eventId==4672))))|length) as $admin |
      (($bundle.artifacts.credentialAccess.logonEvents // [])|map(select(.eventId==4624 and .logonType==5))|length) as $svc |
      (if ($admin>0 and $svc>0) then [{privilegedLogons:$admin, serviceLogons:$svc}] else [] end)
    elif $id=="FOS-PER-004" then
      (($bundle.artifacts.persistence.wmiEventSubscriptions.eventConsumers // [])) as $c |
      (if ($c|length>0) then [{consumerCount:($c|length), consumers:$c}] else [] end)
    elif $id=="FOS-AV-001" then
      (if (($bundle.artifacts.antivirusScans.defenderScan.threatsFound // 0) > 0)
       then [{scanner:"Windows Defender", threats:($bundle.artifacts.antivirusScans.defenderScan.threats)}] else [] end)
    elif $id=="FOS-AV-002" then
      (if (($bundle.artifacts.antivirusScans.clamavScan.threatsFound // 0) > 0)
       then [{scanner:"ClamAV", threats:($bundle.artifacts.antivirusScans.clamavScan.threats)}] else [] end)
    elif $id=="FOS-RAT-001" then
      [ ($bundle.artifacts.remoteAccess.tools // [])[] | select(.authorized==false) ]
    elif $id=="FOS-RAT-002" then
      [ ($bundle.artifacts.remoteAccess.tools // [])[] | select(.authorized==true) ]
    elif $id=="FOS-DEF-001" then
      (($bundle.artifacts.securityPosture.defender) as $d |
       if ($d.available==true and $d.realTimeEnabled==false) then [{realTimeEnabled:false}] else [] end)
    elif $id=="FOS-DEF-002" then
      (($bundle.artifacts.securityPosture.defender) as $d |
       (($d.exclusionPaths // [])+($d.exclusionExtensions // [])+($d.exclusionProcesses // [])) as $ex |
       if (($ex|length)>0) then [{paths:$d.exclusionPaths, extensions:$d.exclusionExtensions, processes:$d.exclusionProcesses}] else [] end)
    elif $id=="FOS-DEF-003" then
      (($bundle.artifacts.securityPosture.defender) as $d |
       if ($d.available==true and $d.tamperProtectionEnabled==false) then [{tamperProtectionEnabled:false}] else [] end)
    else [] end;
  {info:0,low:1,medium:2,high:3,critical:4} as $sevrank |
  {info:1,low:1,medium:2,high:3,critical:3} as $cap |
  [ $ruleset.rules[] | . as $rule
    | ( if $rule.type=="builtin" then builtin($rule)
        else [ selvals($rule)[]? | select(itemmatch(.;$rule)) ] end ) as $ev
    | select(($ev|length)>0)
    | { ruleId:$rule.id, name:$rule.name, category:$rule.category, mitre:$rule.mitre,
        severity:$rule.severity, weight:$rule.weight, rationale:$rule.rationale,
        falsePositive:$rule.falsePositive, reasonCode:$rule.reasonCode,
        escalate:($rule.escalateToBreach // false),
        contribution:($rule.weight * ([($ev|length), $cap[$rule.severity]]|min)),
        evidenceCount:($ev|length), evidence:($ev[0:25]) }
  ] as $findings |
  ($findings|map(.contribution)|add // 0) as $score |
  ($ruleset.scoring.thresholds) as $thr |
  (if $score>=$thr.problem then "PROBLEM_DETECTED" elif $score>=$thr.monitor then "MONITOR" else "ALL_CLEAR" end) as $verdict |
  (($score>=$thr.breach) or (($findings|map(select(.escalate))|length)>0)) as $isBreach |
  (if $verdict=="ALL_CLEAR" then "None" elif $verdict=="MONITOR" then "Event" elif $isBreach then "Breach" else "Incident" end) as $classification |
  (if $verdict=="ALL_CLEAR" then 0 elif $verdict=="MONITOR" then 10 elif $isBreach then 21 else 20 end) as $exitCode |
  (($findings|map($sevrank[.severity])|max) // 0) as $maxrankNum |
  (($sevrank|to_entries|map(select(.value==$maxrankNum))|.[0].key) // "info") as $maxSev |
  (($findings|sort_by(-.contribution)|.[0].reasonCode) // "NO_FINDINGS") as $reasonCode |
  ($findings|reduce .[] as $f ({}; .[$f.category] = ((.[$f.category]//0) + $f.evidenceCount))) as $summary |
  {
    caseId: $bundle.metadata.caseId,
    analyzedTimestampUtc: $analyzedUtc,
    engineVersion: $engine,
    rulesetVersion: $ruleset.rulesetVersion,
    targetHostname: $bundle.metadata.targetHostname,
    analyst: $analyst,
    verdict: $verdict,
    score: $score,
    severity: $maxSev,
    classification: $classification,
    reasonCode: $reasonCode,
    exitCode: $exitCode,
    thresholds: $thr,
    summaryCounts: $summary,
    findings: $findings
  }
' > "$FINDINGS"

VERDICT="$("$JQ" -r '.verdict' "$FINDINGS")"
SCORE="$("$JQ" -r '.score' "$FINDINGS")"
CLASS="$("$JQ" -r '.classification' "$FINDINGS")"
NF="$("$JQ" -r '.findings|length' "$FINDINGS")"
EXITCODE="$("$JQ" -r '.exitCode' "$FINDINGS")"

# --- findings.md ---
{
  echo "# $BRAND - Triage Findings"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Case ID | $("$JQ" -r '.caseId' "$FINDINGS") |"
  echo "| Host | $("$JQ" -r '.targetHostname' "$FINDINGS") |"
  echo "| Analyzed (UTC) | $("$JQ" -r '.analyzedTimestampUtc' "$FINDINGS") |"
  echo "| **Verdict** | **$VERDICT** |"
  echo "| Classification | $CLASS |"
  echo "| Severity | $("$JQ" -r '.severity' "$FINDINGS") |"
  echo "| Score | $SCORE |"
  echo "| Reason Code | $("$JQ" -r '.reasonCode' "$FINDINGS") |"
  echo ""
  if [ "$NF" -eq 0 ]; then
    echo "_No detections fired. System appears clean based on collected artifacts._"
  else
    echo "## Detections ($NF)"
    echo ""
    "$JQ" -r '.findings | sort_by(-.weight)[] |
      "### [\(.ruleId)] \(.name)\n- **Category:** \(.category) | **Severity:** \(.severity) | **Weight:** \(.weight) | **Matches:** \(.evidenceCount)\n- **MITRE ATT&CK:** \(.mitre.tactic // "-") / \(.mitre.technique // "-")\n- **Why it matters:** \(.rationale)\n- **False-positive guidance:** \(.falsePositive)\n"' "$FINDINGS"
  fi
} > "$CASEDIR/findings.md"

fos_coc_add "$CASEDIR" "ANALYSIS_DONE" "verdict=$VERDICT score=$SCORE class=$CLASS findings=$NF" "$FINDINGS" >/dev/null
fos_log OK "Verdict: $VERDICT | Score: $SCORE | Class: $CLASS | Findings: $NF" "$CASEDIR"
exit "$EXITCODE"
