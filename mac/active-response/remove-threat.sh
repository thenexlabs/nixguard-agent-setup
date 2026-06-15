#!/bin/bash

# Set the local directory to the script's directory
LOCAL=$(dirname "$0")
cd "$LOCAL"
cd ../

PWD=$(pwd)

# Read input JSON
read -r INPUT_JSON
FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo "$INPUT_JSON" | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"

#------------------------ Analyze command -------------------------#
if [ "$COMMAND" = "add" ]; then
  # Send control message to execd
  printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'

  read -r RESPONSE
  COMMAND2=$(echo "$RESPONSE" | jq -r .command)
  if [ "$COMMAND2" != "continue" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') $0: $INPUT_JSON Remove threat active response aborted" >> "$LOG_FILE"
    exit 0
  fi
fi

# Removing file
rm -f "$FILENAME"
if [ $? -eq 0 ]; then
  echo "$(date '+%Y/%m/%d %H:%M:%S') $0: $INPUT_JSON Successfully removed threat" >> "$LOG_FILE"
else
  echo "$(date '+%Y/%m/%d %H:%M:%S') $0: $INPUT_JSON Error removing threat" >> "$LOG_FILE"
fi

exit 0
