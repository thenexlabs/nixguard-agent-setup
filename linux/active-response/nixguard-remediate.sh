#!/bin/bash
# Wazuh Active Response script for general OS-level remediation on Linux.

LOG_FILE="/var/ossec/logs/active-responses.log"

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

# Only two kinds of target are ever acted on: an IPv4 address (blocked), or a plain package or service name. A name
# never starts with "-", so it cannot be read as an option by apt-get, yum or systemctl.
IPV4_RE='^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$'
NAME_RE='^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,63}$'
IS_IP=0
if [[ "$TARGET" =~ $IPV4_RE ]]; then
    IS_IP=1
elif [ "$ACTION" = "nixguard-block-ip" ] || ! [[ "$TARGET" =~ $NAME_RE ]]; then
    log_msg "Error: Refused target (not an IPv4 address or a plain package/service name). Exiting."
    exit 1
fi

# ==========================================
# REMEDIATION ROUTING
# ==========================================

# 1. IP Blocking (the target is an IPv4 address)
if [ "$IS_IP" = "1" ]; then
    log_msg "Action: Blocking IP $TARGET in firewall."
    
    if command -v iptables >/dev/null 2>&1; then
        # NixGuard's own rule carries a comment, so it differs from the plain "-s IP -j DROP" rule that Wazuh's
        # timed firewall-drop adds and later deletes. Without it, a block found "already in place" vanished
        # when firewall-drop's timeout expired.
        MARK="nixguard-block"
        if ! iptables -C INPUT -s "$TARGET" -m comment --comment "$MARK" -j DROP >/dev/null 2>&1; then
            if iptables -I INPUT -s "$TARGET" -m comment --comment "$MARK" -j DROP 2>/dev/null; then
                iptables -I FORWARD -s "$TARGET" -m comment --comment "$MARK" -j DROP 2>/dev/null
                log_msg "Successfully blocked IP $TARGET via iptables (rule tagged $MARK)."
            else
                # No comment module: fall back to a plain rule.
                iptables -I INPUT -s "$TARGET" -j DROP
                iptables -I FORWARD -s "$TARGET" -j DROP
                log_msg "Successfully blocked IP $TARGET via iptables (untagged: comment module unavailable)."
            fi
        else
            log_msg "Notice: IP $TARGET is already blocked by NixGuard in iptables."
        fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$TARGET' reject" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        log_msg "Successfully blocked IP $TARGET via firewalld."
    else
        log_msg "Error: Neither iptables nor firewalld found. Cannot block IP."
        exit 1
    fi

# 2. Service Management (nixguard-service-toggle)
elif [ "$ACTION" = "nixguard-service-toggle" ]; then
    log_msg "Action: Attempting to restart service '$TARGET'."
    
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl restart "$TARGET" >/dev/null 2>&1; then
            log_msg "Successfully restarted service: $TARGET via systemctl."
        else
            log_msg "Error: Failed to restart service: $TARGET via systemctl."
            exit 1
        fi
    elif command -v service >/dev/null 2>&1; then
        if service "$TARGET" restart >/dev/null 2>&1; then
            log_msg "Successfully restarted service: $TARGET via sysvinit."
        else
            log_msg "Error: Failed to restart service: $TARGET via sysvinit."
            exit 1
        fi
    else
        log_msg "Error: No service manager (systemctl/service) found."
        exit 1
    fi

# 3. Package Patching (nixguard-patch)
elif [ "$ACTION" = "nixguard-patch" ]; then
    log_msg "Action: Attempting package upgrade for '$TARGET'."
    
    if command -v apt-get >/dev/null 2>&1; then
        log_msg "Using apt-get to upgrade $TARGET..."
        if DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y "$TARGET" >> "$LOG_FILE" 2>&1; then
            log_msg "Successfully patched package: $TARGET"
        else
            log_msg "Error: Failed to patch package: $TARGET via apt-get."
            exit 1
        fi
    elif command -v yum >/dev/null 2>&1; then
        log_msg "Using yum to upgrade $TARGET..."
        if yum update -y "$TARGET" >> "$LOG_FILE" 2>&1; then
            log_msg "Successfully patched package: $TARGET"
        else
            log_msg "Error: Failed to patch package: $TARGET via yum."
            exit 1
        fi
    else
        log_msg "Error: No supported package manager (apt-get/yum) found."
        exit 1
    fi

# 4. Fallback Smart Routing (If action is generic or missing)
else
    log_msg "Warning: Unknown action '$ACTION'. Attempting smart routing based on target format."
    
    # Try restarting as a service first
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files | grep -Fq "$TARGET.service"; then
        log_msg "Smart Route: Target identified as a systemd service. Restarting..."
        systemctl restart "$TARGET" && log_msg "Successfully restarted service: $TARGET"
    else
        # Fallback to package upgrade
        log_msg "Smart Route: Target not identified as a service. Attempting package upgrade..."
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y "$TARGET" >> "$LOG_FILE" 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum update -y "$TARGET" >> "$LOG_FILE" 2>&1
        fi
    fi
fi

log_msg "Remediation execution completed successfully."
exit 0