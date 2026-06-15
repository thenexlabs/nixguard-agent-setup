#!/bin/bash
# Wazuh Active Response script for safe threat quarantine/removal on Linux.

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

log_msg() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') nixguard-remove-threat: $1" >> "$LOG_FILE"
}

log_msg "Initiating threat removal active response."

# Ensure quarantine directory exists with restrictive permissions
if [ ! -d "$QUARANTINE_DIR" ]; then
    mkdir -p "$QUARANTINE_DIR"
    chmod 700 "$QUARANTINE_DIR"
    chown root:root "$QUARANTINE_DIR"
fi

# Read JSON payload from stdin
read -r INPUT_JSON
if [ -z "$INPUT_JSON" ]; then
    log_msg "Error: No input received from stdin."
    exit 1
fi

# Parse the threat file path using jq
FILE_PATH=""

# 1. Check extra_args (direct command execution)
FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[0] // empty')

# 2. Fallback to Syscheck FIM alert path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // empty')
fi

# 3. Fallback to VirusTotal integration alert path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.virustotal.source.file // empty')
fi

# 4. Fallback to ClamAV alert path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.clamav.file // empty')
fi

# Validate we extracted a path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    log_msg "Error: Could not extract a valid file path from the alert payload."
    exit 1
fi

log_msg "Target threat identified: $FILE_PATH"

# Prevent directory traversal or critical system file quarantine
if [[ "$FILE_PATH" =~ ^/(boot|dev|proc|sys|etc|var/run|var/log)$ ]] || [ "$FILE_PATH" = "/" ]; then
    log_msg "Warning: Blocked attempt to quarantine critical system path: $FILE_PATH"
    exit 1
fi

# Check if the file actually exists on the filesystem
if [ ! -f "$FILE_PATH" ] && [ ! -d "$FILE_PATH" ]; then
    log_msg "Notice: Target path does not exist or is not a regular file/directory: $FILE_PATH"
    exit 0
fi

# Execute safe quarantine
FILENAME=$(basename "$FILE_PATH")
TIMESTAMP=$(date +%s)
QUARANTINE_PATH="$QUARANTINE_DIR/${FILENAME}_${TIMESTAMP}.quarantine"

log_msg "Quarantining '$FILE_PATH' to '$QUARANTINE_PATH'..."

# Move the file to quarantine
if mv "$FILE_PATH" "$QUARANTINE_PATH" 2>/dev/null; then
    # Strip all permissions to neutralize execution capability
    chmod 000 "$QUARANTINE_PATH"
    log_msg "Successfully neutralized and quarantined threat: $FILE_PATH"
else
    log_msg "Error: Failed to move '$FILE_PATH' to quarantine. Attempting direct deletion..."
    if rm -rf "$FILE_PATH" 2>/dev/null; then
        log_msg "Successfully deleted threat directly: $FILE_PATH"
    else
        log_msg "Critical: Failed to delete or quarantine threat: $FILE_PATH. Check permissions."
        exit 1
    fi
fi

exit 0