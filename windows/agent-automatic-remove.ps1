# Check if the system is 64-bit or 32-bit
if ([IntPtr]::Size -eq 8) {
    # For 64-bit Windows
    $ossecAgentPath = "C:\\Program Files (x86)\\ossec-agent"
} else {
    # For 32-bit Windows
    $ossecAgentPath = "C:\\Program Files\\ossec-agent"
}

# Debugging output
# Write-Output "OSSEC Agent Path: $ossecAgentPath"

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

    # Debugging output
    Write-Output "Attempting to remove $ossecAgentPath"

    # Remove the Wazuh agent installation directory
    Remove-Item -Recurse -Force $ossecAgentPath -ErrorAction SilentlyContinue

    # Verify if the directory was removed
    if (-Not (Test-Path -Path $ossecAgentPath)) {
        Write-Output "$ossecAgentPath was successfully removed."
    } else {
        Write-Error "$ossecAgentPath could not be removed."
    }
}

# Run the Uninstall-WazuhAgent function
Uninstall-WazuhAgent
