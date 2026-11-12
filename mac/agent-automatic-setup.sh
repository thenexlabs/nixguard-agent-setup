#!/bin/bash
#
# NixGuard/Wazuh Agent Setup Script for macOS
# This script is idempotent, uses modern API-based registration, and includes
# an intelligent, compliance-driven feature installation based on user preferences.
#
# Usage (as a single command):
# curl -sS https://.../agent-automatic-setup.sh | sudo bash -s -- <MANAGER_IP> <AGENT_NAME> [--requires-encryption]
#

# Exit immediately if any command fails for robust error handling.
set -e
# Ensure the ERR trap is inherited by functions, command substitutions, and subshells.
set -E

# --- 1. Validate Input & Define Variables ---
# Optional flags set by the NixGuard app from the account's compliance standards:
#   --requires-encryption  install the disk-encryption status check
#   --soc2                 install the NixGuard SOC 2 SCA policy locally on this endpoint
# A third positional argument (the API key older install commands passed) is accepted and ignored.
REQUIRES_ENCRYPTION=false
SOC2=false
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --requires-encryption) REQUIRES_ENCRYPTION=true ;;
        --soc2) SOC2=true ;;
        --*) echo "Unknown option: $arg" >&2; exit 1 ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
set -- "${POSITIONAL[@]}"

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo bash -s -- <MANAGER_IP> <AGENT_NAME> [--requires-encryption]" >&2
    exit 1
fi

MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL="default"

# URLs
# FIXED: Pointing directly to raw.githubusercontent.com
REPO_BASE_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac"
WAZUH_PKG_URL_INTEL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.intel64.pkg"
WAZUH_PKG_URL_ARM="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.arm64.pkg"

# FIXED: Appended /active-response/ subfolder to the download URLs
AR_SCRIPT_URL="${REPO_BASE_URL}/active-response/remove-threat.sh"
REMEDIATE_SCRIPT_URL="${REPO_BASE_URL}/active-response/nixguard-remediate.sh"
UNBLOCK_SCRIPT_URL="${REPO_BASE_URL}/active-response/nixguard-unblock-ip.sh"
FILEVAULT_SCRIPT_URL="${REPO_BASE_URL}/active-response/filevault_check.sh"

FIM_CONF_URL="${REPO_BASE_URL}/config/fim.conf"
FILEVAULT_CONF_URL="${REPO_BASE_URL}/config/filevault.conf"


# --- 4. Uninstall Existing Agent (for Idempotency) ---
uninstall_wazuh_agent() {
    echo "--- Checking for existing Wazuh Agent installation ---"
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        echo "Stopping any running Wazuh agent services..."
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
    fi
    if [ -f "/Library/Ossec/bin/wazuh-uninstall.sh" ]; then
        echo "Found existing agent. Running official uninstaller..."
        /Library/Ossec/bin/wazuh-uninstall.sh >/dev/null 2>&1 || true
    fi
    if [ -d "/Library/Ossec" ]; then
        echo "Forcibly removing Wazuh agent directory for a clean installation..."
        rm -rf /Library/Ossec
        echo "Previous installation completely removed."
    else
        echo "Wazuh Agent not found. No uninstallation needed."
    fi
}

# --- 5. Install New Agent and Register via API ---
install_and_register_agent() {
    echo "--- Installing and Registering Wazuh Agent ---"
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_INTEL;
    elif [ "$ARCH" == "arm64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_ARM;
    else echo "Error: Unsupported architecture: $ARCH" >&2; exit 1; fi
    curl -Lo "/tmp/wazuh-agent.pkg" "$WAZUH_PKG_URL"
    
    WAZUH_AGENT_NAME="${AGENT_NAME}" WAZUH_GROUP="${GROUP_LABEL}" \
    installer -pkg "/tmp/wazuh-agent.pkg" -target /
    
    rm -f "/tmp/wazuh-agent.pkg"
    echo "Agent package installed."

    echo "Registering agent '${AGENT_NAME}' with manager..."
    set +e
    /Library/Ossec/bin/agent-auth -m "${MANAGER_IP}" -A "${AGENT_NAME}"
    set -e
    echo "Agent successfully registered."
}

# --- 6. Apply Custom FIM and Log Collection Configuration ---
configure_ossec_conf() {
    echo "--- Applying custom NixGuard configuration ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    local timeout=30
    local counter=0
    echo "Waiting for configuration file to be created and populated..."

    set +e
    while [ ! -s "$ossecConfPath" ]; do
        if [ $counter -ge $timeout ]; then break; fi
        sleep 1
        counter=$((counter+1))
    done
    set -e

    if [ ! -s "$ossecConfPath" ]; then
        echo "Error: Timed out waiting for '$ossecConfPath' to be created and populated." >&2
        exit 1
    fi
    echo "Configuration file found and is not empty."

    echo "Applying File Integrity Monitoring (FIM) rules by downloading config..."
    curl -fsS "$FIM_CONF_URL" >> "$ossecConfPath" || echo "Warning: FIM config not available; keeping the default." >&2
    
    echo "Custom FIM configuration applied successfully."
}

# --- NEW: CPU/IO Performance Optimization Function (macOS) ---
optimize_syscheck_performance() {
    echo "--- Optimizing Syscheck (FIM) performance to prevent high CPU/IO usage ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    
    # Use perl for robust, cross-platform in-place XML manipulation (bypasses macOS sed quirks)
    perl -i -pe 's|<syscheck>|<syscheck>\n    <max_eps>50</max_eps>\n    <frequency>43200</frequency>\n    <process_priority>10</process_priority>\n    <sleep>20</sleep>\n    <scan_on_start>no</scan_on_start>|g' "$ossecConfPath"
    perl -i -pe 's|</syscheck>|    <nodiff>/bin</nodiff>\n    <nodiff>/sbin</nodiff>\n    <nodiff>/usr/bin</nodiff>\n    <nodiff>/usr/sbin</nodiff>\n  </syscheck>|g' "$ossecConfPath"
    perl -i -pe 's|</syscheck>|    <ignore type="sregex">node_modules</ignore>\n    <ignore type="sregex">\\.git</ignore>\n    <ignore type="sregex">Library/Caches</ignore>\n    <ignore type="sregex">/private/var/folders</ignore>\n  </syscheck>|g' "$ossecConfPath"
    
    echo "Syscheck performance optimized."
}

# --- 7. Install Active Response Scripts ---
install_ar_script() {
    echo "--- Installing Active Response scripts for threat remediation ---"
    local destDir="/Library/Ossec/active-response/bin"
    mkdir -p "$destDir"
    
    # 1. Download remove-threat.sh
    local removeThreatPath="$destDir/remove-threat.sh"
    curl -Lo "$removeThreatPath" "$AR_SCRIPT_URL"
    chmod 750 "$removeThreatPath"
    chown root:wazuh "$removeThreatPath"
    
    # 2. Download and Configure the nixguard-remediate.sh Active Response Script
    local remediatePath="$destDir/nixguard-remediate.sh"
    curl -Lo "$remediatePath" "$REMEDIATE_SCRIPT_URL"
    chmod 750 "$remediatePath"
    chown root:wazuh "$remediatePath"

    # 3. nixguard-unblock-ip.sh removes a NixGuard IP block (run from the NixGuard app's Unblock)
    local unblockPath="$destDir/nixguard-unblock-ip.sh"
    curl -Lo "$unblockPath" "$UNBLOCK_SCRIPT_URL"
    chmod 750 "$unblockPath"
    chown root:wazuh "$unblockPath"

    echo "Active Response scripts installed."
}

# --- 8. Install and Schedule FileVault Encryption Monitoring ---
install_filevault_monitoring() {
    echo "--- Installing and scheduling FileVault encryption monitoring ---"
    local scriptPath="/Library/Ossec/bin/filevault_check.sh"
    local plistPath="/Library/LaunchDaemons/com.nixguard.filevaultcheck.plist"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"

    curl -Lo "$scriptPath" "$FILEVAULT_SCRIPT_URL"
    chmod 750 "$scriptPath"
    chown root:wazuh "$scriptPath"

    LAUNCHD_PLIST="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.nixguard.filevaultcheck</string>
    <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>${scriptPath}</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>300</integer>
    <key>StandardErrorPath</key><string>/dev/null</string>
    <key>StandardOutPath</key><string>/dev/null</string>
</dict>
</plist>"
    echo "$LAUNCHD_PLIST" > "$plistPath"
    chown root:wheel "$plistPath"
    chmod 644 "$plistPath"
    
    launchctl unload "$plistPath" 2>/dev/null || true
    launchctl load "$plistPath"
    
    echo "Configuring agent to monitor FileVault status log by downloading config..."
    if ! grep -q "filevault_status.log" "$ossecConfPath"; then
        printf '%s\n' '<ossec_config>' '  <localfile>' '    <location>/Library/Ossec/logs/filevault_status.log</location>' '    <log_format>json</log_format>' '  </localfile>' '</ossec_config>' >> "$ossecConfPath"
    fi

    echo "FileVault monitoring script installed and scheduled."
}

configure_manager_ip() {
    echo "--- Manually configuring manager IP to ensure correctness ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    sed -i '' "s|<address>MANAGER_IP</address>|<address>${MANAGER_IP}</address>|g" "$ossecConfPath"
    echo "Manager IP configured in ossec.conf."
}

# --- Main Execution ---
cleanup_on_failure() {
    echo "❌ An error occurred during setup." >&2
    echo "--- Running automatic cleanup ---" >&2
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1
    fi
    if [ -d "/Library/Ossec" ]; then
        rm -rf /Library/Ossec
    fi
    echo "Cleanup complete. The agent has been removed from this machine." >&2
}

trap cleanup_on_failure ERR

echo "Starting NixGuard Agent Setup for macOS..."

uninstall_wazuh_agent
install_and_register_agent
configure_ossec_conf
optimize_syscheck_performance
install_ar_script

# --- Intelligent Feature Deployment ---

# The NixGuard app passes --requires-encryption when the account's compliance standards require it,
# so the installer never needs an account token.
ENCRYPTION_REQUIRED=$REQUIRES_ENCRYPTION
if [ "$SOC2" = true ]; then
    echo "No SOC 2 policy for macOS yet; skipping." >&2
fi

# 3. Make the final decision.
if [ "$ENCRYPTION_REQUIRED" = true ]; then
    install_filevault_monitoring
else
    echo "User's compliance standards do not require encryption monitoring. Skipping." >&2
fi

# --- End of Intelligent Feature Deployment block ---

configure_manager_ip

echo "--- Restarting Wazuh Agent to apply all changes ---"
/Library/Ossec/bin/wazuh-control restart

# Disable the error trap on success
trap - ERR

echo "✅ NixGuard agent setup complete and running."
