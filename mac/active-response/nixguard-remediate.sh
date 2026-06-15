#!/bin/bash
# Wazuh Active Response script for general OS-level remediation on macOS.

LOG_FILE="/Library/Ossec/logs/active-responses.log"

log_msg() {
    echo "$(date '+%Y/%m/%d %H:%M:%S') nixguard-remediate: $1" >> "$LOG_FILE"
}

log_msg "Initiating NixGuard remediation active response."

# Read JSON payload from stdin
read -r INPUT_JSON
if [ -z "$INPUT_JSON" ]; then
    log_msg "Error: No input received from stdin."
    exit 1
fi

log_msg "Raw input received: $INPUT_JSON"

# Extract target and action parameters using jq
TARGET=$(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[0] // empty')
ACTION=$(echo "$INPUT_JSON" | jq -r '.parameters.program // .parameters.action // empty')

if [ -z "$TARGET" ] || [ "$TARGET" = "null" ]; then
    log_msg "Error: No target argument provided in extra_args. Exiting."
    exit 1
fi

log_msg "Target extracted: $TARGET | Action extracted: $ACTION"

# ==========================================
# REMEDIATION ROUTING
# ==========================================

# 1. IP Blocking (nixguard-block-ip or target is an IP address)
if [ "$ACTION" = "nixguard-block-ip" ] || [[ "$TARGET" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    log_msg "Action: Blocking IP $TARGET in macOS Packet Filter (pf)."
    
    if command -v pfctl >/dev/null 2>&1; then
        # Enable Packet Filter if not already active
        pfctl -e >/dev/null 2>&1
        
        # Dynamically inject a block rule without overwriting pf.conf
        (pfctl -sr 2>/dev/null; echo "block drop quick from $TARGET to any") | pfctl -f - >/dev/null 2>&1
        log_msg "Successfully blocked IP $TARGET via pfctl."
    else
        log_msg "Error: pfctl not found. Cannot block IP."
        exit 1
    fi

# 2. Service Management (nixguard-service-toggle)
elif [ "$ACTION" = "nixguard-service-toggle" ]; then
    log_msg "Action: Attempting to restart launchd service '$TARGET'."
    
    if command -v launchctl >/dev/null 2>&1; then
        # macOS 11+ uses kickstart to restart system services
        if launchctl kickstart -k "system/$TARGET" >/dev/null 2>&1; then
            log_msg "Successfully restarted service: system/$TARGET"
        else
            # Fallback for user-level services
            CONSOLE_USER=$(stat -f "%Su" /dev/console)
            CONSOLE_UID=$(id -u "$CONSOLE_USER")
            if launchctl asuser "$CONSOLE_UID" launchctl kickstart -k "gui/$CONSOLE_UID/$TARGET" >/dev/null 2>&1; then
                log_msg "Successfully restarted service: gui/$CONSOLE_UID/$TARGET"
            else
                log_msg "Error: Failed to restart service '$TARGET' via launchctl."
                exit 1
            fi
        fi
    else
        log_msg "Error: launchctl not found."
        exit 1
    fi

# 3. Package Patching (nixguard-patch)
elif [ "$ACTION" = "nixguard-patch" ]; then
    log_msg "Action: Attempting package upgrade for '$TARGET'."
    
    if command -v brew >/dev/null 2>&1; then
        # Homebrew strictly forbids running as root. We must execute it as the active console user.
        CONSOLE_USER=$(stat -f "%Su" /dev/console)
        if [ "$CONSOLE_USER" != "root" ] && [ -n "$CONSOLE_USER" ]; then
            log_msg "Executing Homebrew upgrade as console user: $CONSOLE_USER"
            if sudo -u "$CONSOLE_USER" brew upgrade "$TARGET" >> "$LOG_FILE" 2>&1; then
                log_msg "Successfully patched package: $TARGET"
            else
                log_msg "Error: Failed to patch package: $TARGET via brew."
                exit 1
            fi
        else
            log_msg "Error: No active console user found to run Homebrew."
            exit 1
        fi
    else
        log_msg "Error: Homebrew (brew) not found on this system."
        exit 1
    fi

# 4. Fallback Smart Routing (If action is generic or missing)
else
    log_msg "Warning: Unknown action '$ACTION'. Attempting smart routing based on target format."
    
    # Check if target is a launchd service
    if command -v launchctl >/dev/null 2>&1 && launchctl list | grep -Fq "$TARGET"; then
        log_msg "Smart Route: Target identified as launchd service. Restarting..."
        launchctl kickstart -k "system/$TARGET" && log_msg "Successfully restarted service: $TARGET"
    else
        # Fallback to Homebrew upgrade
        log_msg "Smart Route: Target not identified as a service. Attempting Homebrew upgrade..."
        CONSOLE_USER=$(stat -f "%Su" /dev/console)
        if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ] && command -v brew >/dev/null 2>&1; then
            sudo -u "$CONSOLE_USER" brew upgrade "$TARGET" >> "$LOG_FILE" 2>&1
        fi
    fi
fi

log_msg "Remediation execution completed successfully."
exit 0