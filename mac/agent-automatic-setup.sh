#!/bin/bash
#
# NixGuard/Wazuh Agent Setup Script for macOS
# This script is idempotent and uses modern installation methods.
# It now includes automated FileVault encryption status monitoring.
#
# Usage:
# curl -sS https://.../agent-automatic-setup.sh | sudo bash -s -- <MANAGER_IP> <AGENT_NAME>
#

# Exit immediately if any command fails
set -e

# --- 1. Validate Input ---
if [ "$#" -ne 2 ]; then
    echo "Usage: sudo bash -s -- <MANAGER_IP> <AGENT_NAME>"
    echo "Example: sudo bash -s -- 37.27.1.100 'macOS-Dev-Elias'"
    exit 1
fi

MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL="default"
WAZUH_PKG_URL_INTEL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.intel64.pkg"
WAZUH_PKG_URL_ARM="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.arm64.pkg"
AR_SCRIPT_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/remove-threat.sh"
# --- NEW: URL for the FileVault check script ---
FILEVAULT_SCRIPT_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/scripts/filevault_check.sh"


# --- 2. Uninstall Existing Agent (Idempotency) ---
uninstall_wazuh_agent() {
    echo "--- Checking for existing Wazuh Agent installation ---"
    if [ -f "/Library/Ossec/bin/wazuh-uninstall.sh" ]; then
        echo "Found existing agent. Running official uninstaller..."
        /Library/Ossec/bin/wazuh-uninstall.sh
    elif [ -d "/Library/Ossec" ]; {
        echo "Found legacy agent directory. Forcibly removing..."
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
        rm -rf /Library/Ossec
    } else
        echo "Wazuh Agent not found. No uninstallation needed."
    fi
}

# --- 3. Install New Agent ---
install_wazuh_agent() {
    echo "--- Installing Wazuh Agent ---"
    # ... (This function remains unchanged) ...
    if ! command -v brew &> /dev/null; then echo "Warning: Homebrew not found."; fi
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_INTEL; echo "Detected Intel architecture (x86_64).";
    elif [ "$ARCH" == "arm64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_ARM; echo "Detected Apple Silicon architecture (arm64).";
    else echo "Error: Unsupported architecture: $ARCH"; exit 1; fi
    echo "Downloading Wazuh agent package..."
    curl -Lo "/tmp/wazuh-agent.pkg" "$WAZUH_PKG_URL"
    echo "Running installer with registration variables..."
    WAZUH_MANAGER="${MANAGER_IP}" WAZUH_AGENT_NAME="${AGENT_NAME}" WAZUH_GROUP="${GROUP_LABEL}" \
    installer -pkg "/tmp/wazuh-agent.pkg" -target /
    rm -f "/tmp/wazuh-agent.pkg"
    echo "Agent package installed."
}

# --- 4. Apply Custom Configuration ---
configure_ossec_conf() {
    echo "--- Applying custom NixGuard configuration ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"

    # --- FIM Configuration ---
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
  <ignore>/Users/*
/Library</ignore>
  <ignore>/Users/*
/Pictures</ignore>
  <ignore>/Users/*
/Music</ignore>
  <ignore>/Users/*
/Videos</ignore>
</syscheck>
EOM
    awk -v new_config="$SYSCHECK_CONFIG" 'BEGIN {p=1} /<syscheck>/ {if(!x){print new_config; x=1}; p=0} /<\/syscheck>/ {p=1; next} p' "$ossecConfPath" > "$ossecConfPath.tmp" && mv "$ossecConfPath.tmp" "$ossecConfPath"
    
    # --- FileVault Log Collection ---
    echo "Configuring agent to monitor FileVault status log..."
    # This block tells the agent to read the JSON output from our script.
    read -r -d '' FILEVAULT_LOG_CONFIG <<'EOM'
<localfile>
  <location>/Library/Ossec/logs/filevault_status.log</location>
  <log_format>json</log_format>
</localfile>
EOM
    # Insert the log collection block before the closing </ossec_config> tag
    # This is safer than trying to find a specific line.
    awk -v new_config="$FILEVAULT_LOG_CONFIG" '/<\/ossec_config>/ {print new_config} 1' "$ossecConfPath" > "$ossecConfPath.tmp" && mv "$ossecConfPath.tmp" "$ossecConfPath"

    echo "Custom configuration applied successfully."
}

# --- 5. Install Active Response Script ---
install_remove_threat_script() {
    # ... (This function remains unchanged) ...
    echo "--- Installing Active Response script for threat remediation ---"
    local destDir="/Library/Ossec/active-response/bin"
    local removeThreatPath="$destDir/remove-threat.sh"
    mkdir -p "$destDir"
    echo "Downloading remove-threat.sh..."
    curl -Lo "$removeThreatPath" "$AR_SCRIPT_URL"
    echo "Setting permissions..."
    chmod 750 "$removeThreatPath"
    chown root:wazuh "$removeThreatPath"
    echo "Active Response script installed."
}

# --- NEW: 6. Install and Schedule FileVault Monitoring ---
install_filevault_monitoring() {
    echo "--- Installing and scheduling FileVault encryption monitoring ---"
    local scriptPath="/Library/Ossec/bin/filevault_check.sh"
    local plistPath="/Library/LaunchDaemons/com.nixguard.filevaultcheck.plist"

    # Download the check script
    echo "Downloading FileVault check script..."
    curl -Lo "$scriptPath" "$FILEVAULT_SCRIPT_URL"
    
    # Set correct permissions for the script
    chmod 750 "$scriptPath"
    chown root:wazuh "$scriptPath"

    # Define the launchd service configuration using a HEREDOC
    read -r -d '' LAUNCHD_PLIST <<EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nixguard.filevaultcheck</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${scriptPath}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer> <!-- Run every 300 seconds (5 minutes) -->
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>
EOM

    # Write the plist file
    echo "Creating launchd service file at ${plistPath}..."
    echo "$LAUNCHD_PLIST" > "$plistPath"

    # Set correct ownership and permissions for the plist
    chown root:wheel "$plistPath"
    chmod 644 "$plistPath"

    # Unload any existing version of the service before loading the new one
    # The `|| true` prevents the script from exiting if the service isn't already loaded.
    launchctl unload "$plistPath" || true
    
    # Load the new service into launchd
    launchctl load "$plistPath"

    echo "FileVault monitoring script installed and scheduled."
}


# --- Main Execution ---
echo "Starting NixGuard Agent Setup for macOS..."

uninstall_wazuh_agent
install_wazuh_agent
configure_ossec_conf
install_remove_threat_script
install_filevault_monitoring # <-- NEW function call

echo "--- Restarting Wazuh Agent to apply all changes ---"
/Library/Ossec/bin/wazuh-control restart

echo "✅ NixGuard agent setup complete and running."