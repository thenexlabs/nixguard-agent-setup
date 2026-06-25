#!/bin/bash
#
# filevault_check.sh
# A hardened script that checks FileVault status on macOS and reports it in a
# Wazuh-compatible JSON format, mirroring the BitLocker check script structure.
#

# Exit immediately if any command fails
set -e

# --- Section 1: Pre-flight Checks & Environment Setup ---

LOG_DIR="/Library/Ossec/logs"
FINAL_LOG_FILE="${LOG_DIR}/filevault_status.log"

# Ensure the log directory exists. This is a fatal-on-failure check.
if ! mkdir -p "$LOG_DIR"; then
    echo "FATAL: Could not create log directory at '$LOG_DIR'. Exiting." >&2
    exit 1
fi

# LOG ROTATION: If file is > 1MB (1048576 bytes), clear it to prevent infinite growth
if [ -f "$FINAL_LOG_FILE" ]; then
    FILE_SIZE=$(stat -f%z "$FINAL_LOG_FILE" 2>/dev/null)
    if [ -n "$FILE_SIZE" ] && [ "$FILE_SIZE" -gt 1048576 ]; then
        > "$FINAL_LOG_FILE"
    fi
fi

# --- Section 2: Core Logic - Get FileVault Status ---

if ! command -v fdesetup &> /dev/null; then
    STATE="error"
    MESSAGE="Script failed: 'fdesetup' command not found. This is not a standard macOS installation or the script is not running as root."
    JSON_PAYLOAD=$(printf '{"filevault_status":{"state":"%s","message":"%s"}}' "$STATE" "$MESSAGE")
else
    FDE_STATUS_OUTPUT=$(fdesetup status | grep "FileVault is")

    if [[ "$FDE_STATUS_OUTPUT" == *"FileVault is On."* ]]; then
        # --- COMPLIANT STATE ---
        STATE="success"
        JSON_PAYLOAD=$(cat <<EOF
{"filevault_status": {"state": "success","volumes": [{"mount_point": "/","protection_status": "On","volume_status": "FullyEncrypted","encryption_method": "XTS-AES-128","key_protectors": "RecoveryKey,UserPassword"}]}}
EOF
)
    elif [[ "$FDE_STATUS_OUTPUT" == *"FileVault is Off."* ]]; then
        # --- NON-COMPLIANT STATE ---
        STATE="success" 
        JSON_PAYLOAD=$(cat <<EOF
{"filevault_status": {"state": "success","volumes": [{"mount_point": "/","protection_status": "Off","volume_status": "FullyDecrypted","encryption_method": "None","key_protectors": ""}]}}
EOF
)
    else
        # --- UNEXPECTED STATE ---
        STATE="error"
        MESSAGE="Script failed: Unexpected output from 'fdesetup status'. Output was: $FDE_STATUS_OUTPUT"
        JSON_PAYLOAD=$(printf '{"filevault_status":{"state":"%s","message":"%s"}}' "$STATE" "$MESSAGE")
    fi
fi

# --- Section 3: The Append Write Transaction ---

# APPEND LOGIC: Write the JSON payload to the end of the file
echo "$JSON_PAYLOAD" | tr -d '\n' >> "$FINAL_LOG_FILE"
echo "" >> "$FINAL_LOG_FILE" # Ensure a trailing newline so Wazuh parses it immediately

exit 0