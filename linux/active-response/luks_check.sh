#!/bin/bash
# Script to monitor LUKS encryption status on Linux block devices.
# Outputs JSON logs to /var/log/luks_status.log for Wazuh monitoring.
# Scheduled via cron to run every 5 minutes.

LOG_FILE="/var/log/luks_status.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# LOG ROTATION: If file is > 1MB (1048576 bytes), clear it to prevent infinite growth
if [ -f "$LOG_FILE" ]; then
    FILE_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null)
    if [ -n "$FILE_SIZE" ] && [ "$FILE_SIZE" -gt 1048576 ]; then
        > "$LOG_FILE"
    fi
fi

# Ensure log file exists with restrictive permissions
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
chown root:root "$LOG_FILE"

# Temporary file to hold current run's status
TEMP_LOG=$(mktemp)

# Check if lsblk is available
if ! command -v lsblk >/dev/null 2>&1; then
    echo "{\"timestamp\":\"$TIMESTAMP\",\"error\":\"lsblk command not found\"}" >> "$TEMP_LOG"
else
    # Get list of block devices (excluding loop and rom devices)
    lsblk -o NAME,FSTYPE,MOUNTPOINT,TYPE,PKNAME -p -n -l | while read -r NAME FSTYPE MOUNTPOINT TYPE PKNAME; do
        if [ "$TYPE" = "loop" ] || [ "$TYPE" = "rom" ]; then
            continue
        fi

        if [ -z "$NAME" ]; then
            continue
        fi

        ENCRYPTED="false"
        
        if [ "$FSTYPE" = "crypto_LUKS" ] || [ "$TYPE" = "crypt" ]; then
            ENCRYPTED="true"
        fi

        if [ -n "$MOUNTPOINT" ] || [ "$ENCRYPTED" = "true" ]; then
            [ -z "$FSTYPE" ] && FSTYPE="unknown"
            [ -z "$MOUNTPOINT" ] && MOUNTPOINT="none"
            [ -z "$TYPE" ] && TYPE="unknown"

            echo "{\"timestamp\":\"$TIMESTAMP\",\"device\":\"$NAME\",\"fstype\":\"$FSTYPE\",\"mountpoint\":\"$MOUNTPOINT\",\"type\":\"$TYPE\",\"encrypted\":$ENCRYPTED}" >> "$TEMP_LOG"
        fi
    done
fi

# APPEND LOGIC: Append the new status to the log file
cat "$TEMP_LOG" >> "$LOG_FILE"
rm -f "$TEMP_LOG"

exit 0