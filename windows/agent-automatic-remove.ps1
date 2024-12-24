# Check if the system is 64-bit or 32-bit
if ([IntPtr]::Size -eq 8) {
    # For 64-bit Windows
    $ossecAgentPath = "C:\\Program Files (x86)\\ossec-agent"
} else {
    # For 32-bit Windows
    $ossecAgentPath = "C:\\Program Files\\ossec-agent"
}

# Define the script as a function
function Uninstall-WazuhAgent {
    # Stop the Wazuh service
    Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

    # Wait a bit to ensure the service stops
    Start-Sleep -Seconds 5

    # Kill any leftover Wazuh processes
    Get-Process -Name "WazuhSvc" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    # Uninstall the Wazuh agent using msiexec
    msiexec.exe /x $env:tmp\wazuh-agent.msi /quiet /norestart

    # Ensure the uninstallation is complete
    Start-Sleep -Seconds 10

    # Remove the Wazuh agent installation directory
    Remove-Item -Recurse -Force $ossecAgentPath -ErrorAction SilentlyContinue

    # Remove the Wazuh agent installation directory
    Remove-Item -Recurse -Force "C:\wazuh-agent" -ErrorAction SilentlyContinue
}

# Run the script twice
# Uninstall-WazuhAgent function
Uninstall-WazuhAgent
