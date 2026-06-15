#!/bin/bash
# Script to monitor LUKS encryption status on Linux block devices.
# Outputs JSON logs to /var/log/luks_status.log for Wazuh monitoring.
# Scheduled via cron to run every 5 minutes.

LOG_FILE="/var/log/luks_status.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Ensure log file exists with restrictive permissions
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"
chown root:root "$LOG_FILE"

# Temporary file to hold current run's status
TEMP_LOG=$(mktemp)

# Check if lsblk is available
if ! command -v lsblk >/dev/null 2>&1; then
    echo "{\"timestamp\":\"$TIMESTAMP\",\"error\":\"lsblk command not found\"}" >> "$LOG_FILE"
    exit 1
fi

# Get list of block devices (excluding loop and rom devices)
# Columns: NAME (full path), FSTYPE, MOUNTPOINT, TYPE, PKNAME (parent kernel name)
lsblk -o NAME,FSTYPE,MOUNTPOINT,TYPE,PKNAME -p -n -l | while read -r NAME FSTYPE MOUNTPOINT TYPE PKNAME; do
    # Skip loop and rom devices
    if [ "$TYPE" = "loop" ] || [ "$TYPE" = "rom" ]; then
        continue
    fi

    # Skip empty lines or devices without a name
    if [ -z "$NAME" ]; then
        continue
    fi

    ENCRYPTED="false"
    
    # Determine encryption status:
    # 1. If FSTYPE is crypto_LUKS, the partition is encrypted.
    # 2. If TYPE is crypt, the active mapped device is encrypted.
    if [ "$FSTYPE" = "crypto_LUKS" ] || [ "$TYPE" = "crypt" ]; then
        ENCRYPTED="true"
    fi

    # We log the device if it is actively mounted, OR if it is a physical partition that is encrypted
    if [ -n "$MOUNTPOINT" ] || [ "$ENCRYPTED" = "true" ]; then
        # Clean up empty values for clean JSON output
        [ -z "$FSTYPE" ] && FSTYPE="unknown"
        [ -z "$MOUNTPOINT" ] && MOUNTPOINT="none"
        [ -z "$TYPE" ] && TYPE="unknown"

        # Construct flat JSON line
        echo "{\"timestamp\":\"$TIMESTAMP\",\"device\":\"$NAME\",\"fstype\":\"$FSTYPE\",\"mountpoint\":\"$MOUNTPOINT\",\"type\":\"$TYPE\",\"encrypted\":$ENCRYPTED}" >> "$TEMP_LOG"
    fi
done

# Append the new status to the log file
cat "$TEMP_LOG" >> "$LOG_FILE"
rm -f "$TEMP_LOG"

exit 0