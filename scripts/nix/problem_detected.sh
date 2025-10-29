#!/bin/bash

# problem_detected.sh
# Default action for when a problem is detected.

REASON_CODE=$1

echo "****************************************************************"
echo "*** CRITICAL INCIDENT DETECTED ***"
echo "REASON CODE: $REASON_CODE"
echo "Triage Agent Halted for Escalation."
echo "****************************************************************"

# Log the action
LOG_PATH="results/Steps_Taken.txt"
echo "$(date --iso-8601=seconds) :: FINAL ACTION: problem_detected.sh [$REASON_CODE]" >> "$LOG_PATH"

exit 1
