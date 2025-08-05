# Open PowerShell as an Administrator to run this script

# --- Final Robust Uninstall Function ---
function Uninstall-WazuhAgent {

    Write-Host "--- Starting Wazuh Agent Uninstall Process ---" -ForegroundColor Yellow

    # Step 1: Attempt to stop the service first to release file locks.
    Write-Host "Attempting to stop the Wazuh Agent service (WazuhSvc)..."
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        # Give the service a few seconds to fully terminate its processes
        Write-Host "Waiting 5 seconds for processes to terminate..."
        Start-Sleep -Seconds 5
    }

    # Step 2: Find the Wazuh Agent installation by checking the registry (much faster and more reliable than Get-WmiObject).
    Write-Host "Searching for Wazuh Agent in the list of installed programs..."
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $wazuhApp = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Wazuh Agent" }

    # Step 3: Check if the agent was found and act accordingly.
    if (-not $wazuhApp) {
        # --- AGENT NOT FOUND ---
        Write-Host "SUCCESS: Wazuh Agent was not found in the list of installed programs. No action needed." -ForegroundColor Green
        # The return command exits the function immediately.
        return
    }

    # --- AGENT WAS FOUND ---
    Write-Host "Found Wazuh Agent. Running the official uninstaller silently..."
    
    # The UninstallString contains the command to run, e.g., "MsiExec.exe /I{PRODUCT-CODE-GUID}"
    # We will modify it to run silently.
    $uninstallCommand = $wazuhApp.UninstallString
    if ($uninstallCommand -like "MsiExec.exe*") {
        # For MSI packages, we replace the interactive flag (/I) with the uninstall flag (/X) and add the quiet flag (/q).
        $productCode = $wazuhApp.PSChildName
        $command = "msiexec.exe"
        $arguments = "/x $productCode /q"
        Write-Host "Executing: $command $arguments"
        Start-Process -FilePath $command -ArgumentList $arguments -Wait -NoNewWindow
    } else {
        # Fallback for non-MSI installers, though Wazuh uses MSI.
        Write-Host "Executing non-MSI uninstaller: $uninstallCommand"
        Start-Process -FilePath $uninstallCommand -ArgumentList "/S" -Wait -NoNewWindow # /S is a common silent flag
    }
    
    Write-Host "Uninstaller process has finished."

    # --- Final Cleanup ---
    # After a proper uninstall, the directory should be gone, but we check just in case.
    $agentDir = "C:\Program Files (x86)\ossec-agent"
    if (Test-Path $agentDir) {
        Write-Host "Performing post-uninstall cleanup of the installation directory..."
        Remove-Item -Recurse -Force $agentDir -ErrorAction SilentlyContinue
        
        # Final check
        if (!(Test-Path $agentDir)) {
            Write-Host "Directory successfully removed." -ForegroundColor Green
        } else {
            # If it still fails, it's likely a stubborn orphaned process.
            Write-Error "FAILED to remove directory: $agentDir. A process may still be locking it. Please remove it manually or reboot."
        }
    } else {
        Write-Host "Wazuh Agent uninstall complete." -ForegroundColor Green
    }
}

# --- Run the function ---
Uninstall-WazuhAgent