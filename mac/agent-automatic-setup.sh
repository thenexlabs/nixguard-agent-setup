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

# --- Create a unique agent name for CI/CD environments ---
# Check if the GITHUB_RUN_ID environment variable exists.
if [ -n "$GITHUB_RUN_ID" ]; then
  # If it exists, append it to the agent name to ensure uniqueness.
  AGENT_NAME="${AGENT_NAME_BASE}-${GITHUB_RUN_ID}"
  echo "GitHub Actions environment detected. Using unique agent name: ${AGENT_NAME}"
else
  # Otherwise, use the name as provided.
  AGENT_NAME="${AGENT_NAME_BASE}"
fi

# URLs for Wazuh packages and NixGuard scripts
WAZUH_PKG_URL_INTEL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.intel64.pkg"
WAZUH_PKG_URL_ARM="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.arm64.pkg"
AR_SCRIPT_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/remove-threat.sh"
FILEVAULT_SCRIPT_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/scripts/filevault_check.sh"
GET_USER_API_URL="https://api.thenex.world/get-user"


# --- 2. Dependency Management ---
check_dependencies() {
    echo "--- Checking for required dependencies (jq) ---"
    if ! command -v jq &> /dev/null; then
        echo "jq is not installed. Attempting to install with Homebrew..."
        if ! command -v brew &> /dev/null; then
            echo "Warning: Homebrew not found. Cannot install jq." >&2
            echo "FileVault monitoring will be enabled by default as a security fallback."
            return 1
        fi
        brew install jq
    fi
    echo "jq is available."
    return 0
}

# --- 3. Fetch User Compliance Preferences ---
fetch_user_preferences() {
    local user_api_key="$1"
    echo "--- Fetching user compliance preferences ---"
    
    local api_payload
    api_payload=$(printf '{"apiKey":"%s"}' "$user_api_key")

    local response
    response=$(curl --request POST \
        --header "Content-Type: application/json" \
        --silent --show-error \
        --data "$api_payload" \
        "$GET_USER_API_URL")

    local jwt_payload
    jwt_payload=$(echo "$response" | jq -r '.token | split(".")[1] | @base64d | fromjson')
    
    local standards
    standards=$(echo "$jwt_payload" | jq -r '.cybersecurityPreferences.complianceStandards')
    
    echo "$standards"
}

# --- 4. Uninstall Existing Agent (for Idempotency) ---
uninstall_wazuh_agent() {
    echo "--- Checking for existing Wazuh Agent installation ---"
    # First, try to gracefully stop any running agent services.
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        echo "Stopping any running Wazuh agent services..."
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
    fi

    # Attempt to run the official uninstaller if it exists.
    if [ -f "/Library/Ossec/bin/wazuh-uninstall.sh" ]; then
        echo "Found existing agent. Running official uninstaller..."
        /Library/Ossec/bin/wazuh-uninstall.sh >/dev/null 2>&1 || true
    fi
    
    # Finally, forcibly remove the directory to ensure a completely clean state.
    # This is critical for idempotency and successful re-registration.
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
    
    WAZUH_MANAGER="${MANAGER_IP}" \
    WAZUH_AGENT_NAME="${AGENT_NAME}" \
    WAZUH_GROUP="${GROUP_LABEL}" \
    installer -pkg "/tmp/wazuh-agent.pkg" -target /
    
    rm -f "/tmp/wazuh-agent.pkg"
    echo "Agent package installed."

    # --- THE FIX: Removed the unsupported `-f` flag ---
    echo "Registering agent '${AGENT_NAME}' with manager..."
    /Library/Ossec/bin/agent-auth -m "${MANAGER_IP}" -A "${AGENT_NAME}"
    # --- END FIX ---
    
    echo "Agent successfully registered."
}

# --- 6. Apply Custom FIM and Log Collection Configuration ---
configure_ossec_conf() {
    echo "--- Applying custom NixGuard configuration ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    
    local timeout=30
    local counter=0
    echo "Waiting for configuration file to be created..."
    while [ ! -f "$ossecConfPath" ]; do
        if [ $counter -ge $timeout ]; then
            echo "Error: Timed out waiting for '$ossecConfPath' to be created." >&2
            exit 1
        fi
        sleep 1
        counter=$((counter+1))
    done
    echo "Configuration file found."

    echo "Applying File Integrity Monitoring (FIM) rules..."
    read -r -d '' SYSCHECK_CONFIG <<'EOM'
<syscheck>
  <directories check_all="yes" realtime="yes">/Applications</directories>
  <directories check_all="yes" realtime="yes">/System</directories>
  <directories check_all="yes" realtime="yes">/Library</directories>
  <directories check_all="yes" realtime="yes">/Users/Shared</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/private/etc</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/usr/local/bin</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/usr/local/sbin</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/Users/%(user)/Downloads</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/Users/%(user)/Desktop</directories>
  <directories check_all="yes" realtime="yes" whodata="yes">/Users/%(user)/Documents</directories>
  <ignore>/private/var/log/wazuh</ignore>
  <ignore type="sregex">.log$|.swp$|.DS_Store$</ignore>
  <ignore>/Users/*/Library</ignore>
  <ignore>/Users/*/Pictures</ignore>
  <ignore>/Users/*/Music</ignore>
  <ignore>/Users/*/Videos</ignore>
</syscheck>
EOM
    # --- FINAL FIX: Use perl for robust multi-line replacement ---
    export SYSCHECK_CONFIG
    perl -i -p0e 's|<syscheck>.*?</syscheck>|$ENV{SYSCHECK_CONFIG}|s' "$ossecConfPath"
    unset SYSCHECK_CONFIG
    # --- END FIX ---

    echo "Custom FIM configuration applied successfully."
}

# --- 7. Install Active Response Script ---
install_ar_script() {
    echo "--- Installing Active Response script for threat remediation ---"
    local destDir="/Library/Ossec/active-response/bin"
    local removeThreatPath="$destDir/remove-threat.sh"
    mkdir -p "$destDir"
    curl -Lo "$removeThreatPath" "$AR_SCRIPT_URL"
    chmod 750 "$removeThreatPath"
    chown root:wazuh "$removeThreatPath"
    echo "Active Response script installed."
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

    read -r -d '' LAUNCHD_PLIST <<EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
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
</plist>
EOM
    echo "$LAUNCHD_PLIST" > "$plistPath"
    chown root:wheel "$plistPath"
    chmod 644 "$plistPath"
    launchctl unload "$plistPath" || true
    launchctl load "$plistPath"
    
    echo "Configuring agent to monitor FileVault status log..."
    read -r -d '' FILEVAULT_LOG_CONFIG <<'EOM'
<localfile>
  <location>/Library/Ossec/logs/filevault_status.log</location>
  <log_format>json</log_format>
</localfile>
EOM
    # --- FINAL FIX: Use perl to insert config before the final tag ---
    export FILEVAULT_LOG_CONFIG
    perl -i -p0e 's|(</ossec_config>)|$ENV{FILEVAULT_LOG_CONFIG}\n$1|' "$ossecConfPath"
    unset FILEVAULT_LOG_CONFIG
    # --- END FIX ---

    echo "FileVault monitoring script installed and scheduled."
}

# --- Main Execution ---
cleanup_on_failure() {
    echo "❌ An error occurred during setup." >&2
    echo "--- Running automatic cleanup ---" >&2
    # Forcefully uninstall the agent to clean the local state
    # This ensures the next run can succeed with the same agent name
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1
    fi
    if [ -d "/Library/Ossec" ]; then
        rm -rf /Library/Ossec
    fi
    echo "Cleanup complete. The agent has been removed from this machine." >&2
    # Note: This does not remove the agent from the manager, but allows re-registration.
}

# Trap any error signal (non-zero exit code) and run the cleanup function.
trap cleanup_on_failure ERR

echo "Starting NixGuard Agent Setup for macOS..."

uninstall_wazuh_agent
install_and_register_agent
configure_ossec_conf
install_ar_script

# --- Intelligent Feature Deployment ---
ENCRYPTION_REQUIRED=false
if check_dependencies; then
    COMPLIANCE_STANDARDS=$(fetch_user_preferences "$API_KEY")
    REQUIRED_STANDARDS=("soc2" "nist_sp_800_53" "iso27001" "gdpr" "hipaa" "pci_dss" "pipeda" "cis_controls")
    
    for standard in "${REQUIRED_STANDARDS[@]}"; do
        if echo "$COMPLIANCE_STANDARDS" | jq -e --arg s "$standard" '.[] | contains($s)' > /dev/null; then
            echo "Compliance standard '$standard' found, enabling encryption monitoring."
            ENCRYPTION_REQUIRED=true
            break
        fi
    done
else
    ENCRYPTION_REQUIRED=true
fi

if [ "$ENCRYPTION_REQUIRED" = true ]; then
    install_filevault_monitoring
else
    echo "User's compliance standards do not require encryption monitoring. Skipping."
fi

echo "--- Restarting Wazuh Agent to apply all changes ---"
/Library/Ossec/bin/wazuh-control restart

trap - ERR

echo "✅ NixGuard agent setup complete and running."
