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
TEMP_LOG_FILE="${LOG_DIR}/filevault_status.tmp"

# Ensure the log directory exists. This is a fatal-on-failure check.
if ! mkdir -p "$LOG_DIR"; then
    echo "FATAL: Could not create log directory at '$LOG_DIR'. Exiting." >&2
    exit 1
fi

# --- Section 2: Core Logic - Get FileVault Status ---

# The primary command to check FileVault status is `fdesetup`.
# We check if the command exists first.
if ! command -v fdesetup &> /dev/null; then
    STATE="error"
    MESSAGE="Script failed: 'fdesetup' command not found. This is not a standard macOS installation or the script is not running as root."
    JSON_PAYLOAD=$(printf '{"filevault_status":{"state":"%s","message":"%s"}}' "$STATE" "$MESSAGE")
else
    # Run the command and capture its output. We need sudo/root privileges.
    # The `grep` command filters for the line that contains the status.
    FDE_STATUS_OUTPUT=$(fdesetup status | grep "FileVault is")

    if [[ "$FDE_STATUS_OUTPUT" == *"FileVault is On."* ]]; then
        # --- COMPLIANT STATE ---
        STATE="success"
        # On macOS, FileVault encrypts the entire system volume, which is always mounted at "/"
        # We create a JSON structure that mirrors the BitLocker script's output for a single, compliant volume.
        JSON_PAYLOAD=$(cat <<EOF
{
  "filevault_status": {
    "state": "success",
    "volumes": [
      {
        "mount_point": "/",
        "protection_status": "On",
        "volume_status": "FullyEncrypted",
        "encryption_method": "XTS-AES-128",
        "key_protectors": "RecoveryKey,UserPassword"
      }
    ]
  }
}
EOF
)
    elif [[ "$FDE_STATUS_OUTPUT" == *"FileVault is Off."* ]]; then
        # --- NON-COMPLIANT STATE ---
        # This is the critical case for a security failure.
        # We create a JSON structure that mirrors the BitLocker script's output for a non-compliant volume.
        STATE="success" # The script succeeded in finding a non-compliant state.
        JSON_PAYLOAD=$(cat <<EOF
{
  "filevault_status": {
    "state": "success",
    "volumes": [
      {
        "mount_point": "/",
        "protection_status": "Off",
        "volume_status": "FullyDecrypted",
        "encryption_method": "None",
        "key_protectors": ""
      }
    ]
  }
}
EOF
)
    else
        # --- UNEXPECTED STATE ---
        # The output of `fdesetup status` was not what we expected.
        STATE="error"
        MESSAGE="Script failed: Unexpected output from 'fdesetup status'. Output was: $FDE_STATUS_OUTPUT"
        JSON_PAYLOAD=$(printf '{"filevault_status":{"state":"%s","message":"%s"}}' "$STATE" "$MESSAGE")
    fi
fi

# --- Section 3: The Atomic Write Transaction ---
# This safely writes the JSON payload to the immutable log file path.

# Use a HEREDOC to write the JSON to a temporary file, then move it.
# This prevents a partially written file if the script is interrupted.
# The `tr -d '\n'` command removes newlines to compress the JSON.
echo "$JSON_PAYLOAD" | tr -d '\n' > "$TEMP_LOG_FILE"

# The `mv` command is an atomic operation on POSIX systems.
if mv "$TEMP_LOG_FILE" "$FINAL_LOG_FILE"; then
    # Optional: Log success to stdout for debugging scheduled tasks
    # echo "Successfully wrote FileVault status to $FINAL_LOG_FILE"
    exit 0
else
    echo "FATAL: FAILED to move temp log file to '$FINAL_LOG_FILE'. Check permissions or disk space." >&2
    exit 1
fi