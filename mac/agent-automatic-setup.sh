#!/bin/bash
#
# NixGuard/Wazuh Agent Setup Script for macOS
# This script is idempotent, uses modern API-based registration, and includes
# an intelligent, compliance-driven feature installation based on user preferences.
#
# Usage (as a single command):
# curl -sS https://.../agent-automatic-setup.sh | sudo bash -s -- <MANAGER_IP> <AGENT_NAME> <API_KEY>
#

# Exit immediately if any command fails for robust error handling.
set -e
# Ensure the ERR trap is inherited by functions, command substitutions, and subshells.
set -E

# --- 1. Validate Input & Define Variables ---
if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo bash -s -- <MANAGER_IP> <AGENT_NAME> <API_KEY>" >&2
    exit 1
fi

MANAGER_IP=$1
AGENT_NAME_BASE=$2 # Store the base name
API_KEY=$3
GROUP_LABEL="default"

# URLs
REPO_BASE_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac"
WAZUH_PKG_URL_INTEL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.intel64.pkg"
WAZUH_PKG_URL_ARM="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.arm64.pkg"
AR_SCRIPT_URL="${REPO_BASE_URL}/remove-threat.sh"
# UPDATED: Removed /scripts/ from the URLs to match the flattened directory structure
REMEDIATE_SCRIPT_URL="${REPO_BASE_URL}/nixguard-remediate.sh"
FILEVAULT_SCRIPT_URL="${REPO_BASE_URL}/filevault_check.sh"
GET_USER_API_URL="https://api.thenex.world/get-user"
FIM_CONF_URL="${REPO_BASE_URL}/config/fim.conf"
FILEVAULT_CONF_URL="${REPO_BASE_URL}/config/filevault.conf"


# --- 2. Dependency Management ---
check_dependencies() {
    echo "--- Checking for required dependencies (jq) ---"
    if ! command -v jq &> /dev/null; then
        echo "jq is not installed. Attempting to install with Homebrew..."
        if ! command -v brew &> /dev/null; then
            echo "Warning: Homebrew not found. Cannot install jq." >&2
            return 1
        fi
        brew install jq
    fi
    echo "jq is available."
    return 0
}

# --- 3. Fetch User Compliance Preferences ---
fetch_user_preferences() {
    echo "--- Fetching user compliance preferences ---" >&2
    
    local user_api_key="$1"
    local api_payload
    api_payload=$(printf '{"apiKey":"%s"}' "$user_api_key")
    local response
    response=$(curl --request POST --header "Content-Type: application/json" --silent --show-error --data "$api_payload" "$GET_USER_API_URL")

    if [ -z "$response" ] || ! echo "$response" | jq -e '.token' > /dev/null 2>&1; then
        echo "Warning: Could not retrieve a valid token from the user API." >&2
        echo "[]"
        return
    fi
    
    local jwt_payload
    jwt_payload=$(echo "$response" | jq -r '.token | split(".")[1] | @base64d | fromjson')
    local standards
    standards=$(echo "$jwt_payload" | jq -r '.cybersecurityPreferences.complianceStandards')
    
    echo "$standards"
}

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
    curl -sS "$FIM_CONF_URL" >> "$ossecConfPath"
    
    echo "Custom FIM configuration applied successfully."
}

# --- NEW: CPU/IO Performance Optimization Function (macOS) ---
optimize_syscheck_performance() {
    echo "--- Optimizing Syscheck (FIM) performance to prevent high CPU/IO usage ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    
    # Use perl for robust, cross-platform in-place XML manipulation (bypasses macOS sed quirks)
    perl -i -pe 's|<syscheck>|<syscheck>\n    <max_eps>50</max_eps>\n    <frequency>43200</frequency>\n    <process_priority>10</process_priority>\n    <sleep>20</sleep>|g' "$ossecConfPath"
    perl -i -pe 's|</syscheck>|    <nodiff>/bin</nodiff>\n    <nodiff>/sbin</nodiff>\n    <nodiff>/usr/bin</nodiff>\n    <nodiff>/usr/sbin</nodiff>\n  </syscheck>|g' "$ossecConfPath"
    
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
    curl -sS "$FILEVAULT_CONF_URL" >> "$ossecConfPath"

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

# 1. Start with the default state: encryption is NOT required.
ENCRYPTION_REQUIRED=false

# 2. Check for reasons to enable it.
if ! check_dependencies; then
    echo "Warning: jq dependency not met. Defaulting to encryption monitoring enabled." >&2
    ENCRYPTION_REQUIRED=true
else
    COMPLIANCE_STANDARDS=$(fetch_user_preferences "$API_KEY")
    
    echo "--- Compliance Standards from API ---" >&2
    echo "$COMPLIANCE_STANDARDS" >&2
    echo "-------------------------------------" >&2

    REQUIRED_STANDARDS=("soc2" "nist_sp_800_53" "iso27001" "gdpr" "hipaa" "pci_dss" "pipeda" "cis_controls")
    
    for standard in "${REQUIRED_STANDARDS[@]}"; do
        if echo "$COMPLIANCE_STANDARDS" | jq -e --arg s "$standard" '. | index($s)' > /dev/null 2>&1; then
            echo "Compliance standard '$standard' found, enabling encryption monitoring." >&2
            ENCRYPTION_REQUIRED=true
            break
        fi
    done
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