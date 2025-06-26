param (
  [string]$agentName,
  [string]$ipAddress
)

# Check if the system is 64-bit or 32-bit
if ([IntPtr]::Size -eq 8) {
    # For 64-bit Windows
    $ossecAgentPath = "C:\\Program Files (x86)\\ossec-agent"
} else {
    # For 32-bit Windows
    $ossecAgentPath = "C:\\Program Files\\ossec-agent"
}

$configPath = $ossecAgentPath + "\\ossec.conf"

# Open PowerShell as an Administrator to run this script

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

# Kill the cached file
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "agent-automatic-setup.ps1") -ErrorAction SilentlyContinue

# Install the Wazuh agent
## loop until file is gone
$fileExists = $true
while ($fileExists) {
    if (Test-Path -Path $configPath) {
        Write-Host ".."
        Start-Sleep -Seconds 3
    } else {
        $fileExists = $false
        Write-Host "."
    }
}

$maxRetries = 4
$retryCount = 0

do {
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi -OutFile "${env:tmp}\wazuh-agent"

    $workingCommand = "msiexec.exe /i `"`${env:tmp}\wazuh-agent`" /q WAZUH_MANAGER='$ipAddress' WAZUH_REGISTRATION_SERVER='$ipAddress' WAZUH_AGENT_GROUP='$groupLabel' WAZUH_AGENT_NAME='$agentName'"

    $wazuhInstaller = Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$workingCommand`"" -PassThru -Wait

    if ($wazuhInstaller.ExitCode -ne 0) {
        Write-Host "Installer process exited with code $($wazuhInstaller.ExitCode)"
        $retryCount++
        if ($retryCount -le $maxRetries) {
            Write-Host "Retrying installation ($retryCount of $maxRetries)..."
            Start-Sleep -Seconds 10
        } else {
            Write-Host "Installation failed after $maxRetries attempts."
            exit $wazuhInstaller.ExitCode
        }
    } else {
        break
    }
} while ($true)

$counter = 0
$fileExists = $false
while (-not $fileExists) {
    if (Test-Path -Path $configPath) {
        $fileExists = $true
        Write-Host "."
    } else {
        Write-Host ".."
        Start-Sleep -Seconds 3
    }
    $counter++
}

# This acts as a final safeguard to ensure the IP is correct.
$config = Get-Content -Path $configPath
$config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
Set-Content -Path $configPath -Value $config

# Define the enrollment section
$enrollmentSection = @"
<enrollment>
    <enabled>yes</enabled>
    <manager_address>${ipAddress}</manager_address>
    <agent_name>${agentName}</agent_name>
</enrollment>
"@

# Write-Host "enrollment sec: $enrollmentSection"

# Read the ossec.conf file
$content = Get-Content -Path $configPath -Raw

# Check if the enrollment section already exists
if ($content -notmatch '<enrollment>') {
    # Add the enrollment section to the ossec.conf file
    $content = $content -replace '(?s)(<client>.*?)(</client>)', "`$1`n$enrollmentSection`n`$2"
}

# Write the modified content back to the ossec.conf
$content | Set-Content -Path $configPath

# File Integrity Monitoring Configuration
$newDirectory = @"
<directories check_all="yes" whodata="yes" realtime="yes">$env:USERPROFILE\Downloads</directories>
"@
[xml]$ossecConf = Get-Content -Path $configPath

# Wait until the file is found
while (-not $ossecConf) {
    Start-Sleep -Seconds 1
}

$syscheckNode = $ossecConf.ossec_config.syscheck

if (-not $syscheckNode) {
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode) | Out-Null
}

# Find the comment and add the new directory after it
$commentNode = $ossecConf.ossec_config.syscheck.SelectSingleNode("comment()[contains(.,'<!-- Default files to be monitored. -->')]")
if ($commentNode) {
    $directories = @(
        "$env:WINDIR\System32",  # Critical system files
        "$env:ProgramFiles",  # Installed programs
        "$env:ProgramFiles(x86)",  # 32-bit installed programs
        "HKEY_LOCAL_MACHINE\SYSTEM",  # Registry settings
        "$env:USERPROFILE",  # User profile
        "$env:ProgramData",  # Program data
        "$env:ProgramFiles\Common Files",  # Common program files
        "$env:ProgramFiles(x86)\Common Files",  # 32-bit common program files
        "$env:USERPROFILE\Downloads"  # User Downloads directory
    )

    foreach ($directory in $directories) {
        $newDirectoryNode = $ossecConf.CreateElement("directories")
        $newDirectoryNode.SetAttribute("check_all", "yes")
        $newDirectoryNode.SetAttribute("whodata", "yes")
        $newDirectoryNode.SetAttribute("realtime", "yes")
        $newDirectoryNode.InnerText = $directory
        $syscheckNode.InsertAfter($newDirectoryNode, $commentNode) | Out-Null
    }
} else {
    $fragment = $ossecConf.CreateDocumentFragment()
    $fragment.InnerXml = $newDirectory
    $syscheckNode.AppendChild($fragment) | Out-Null
}

$ossecConf.Save($configPath)
Write-Host "Directory monitoring configuration added successfully."

###########################################################################################

# Define the URL of the Python installer
$pythonUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"

# Define the path to save the Python installer
$pythonInstallerPath = Join-Path -Path $env:TEMP -ChildPath "python-installer.exe"

# Download the Python installer
Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstallerPath

# Run the Python installer
Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait

# Start a new PowerShell session to install PyInstaller
py -m pip install pyinstaller

# Define the URL of the remove-threat.py script
$removeThreatUrl = "https://github.com/thenexlabs/nixguard-agent-setup/raw/main/windows/remove-threat.py"

# Define the path to save the remove-threat.py script
$removeThreatPath = Join-Path -Path $env:TEMP -ChildPath "remove-threat.py"

# Download the remove-threat.py script
Invoke-WebRequest -Uri $removeThreatUrl -OutFile $removeThreatPath

# Change the current location to the directory containing remove-threat.py
Set-Location -Path $env:TEMP

# Convert the remove-threat.py script to a Windows executable
Invoke-Expression -Command "py -m PyInstaller -F $removeThreatPath"

# Define the path of the executable file
$exePath = Join-Path -Path $env:TEMP -ChildPath "dist\remove-threat.exe"

# Define the destination directory
$destDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

# Move the executable file to the destination directory
Move-Item -Path $exePath -Destination $destDir

# Define the paths of the spec file and the dist and build directories
$specPath = Join-Path -Path $env:TEMP -ChildPath "remove-threat.spec"
$distDir = Join-Path -Path $env:TEMP -ChildPath "dist"
$buildDir = Join-Path -Path $env:TEMP -ChildPath "build"

# Delete the spec file and the dist and build directories
Remove-Item -Path $specPath -ErrorAction SilentlyContinue
Remove-Item -Path $distDir -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $buildDir -Recurse -ErrorAction SilentlyContinue

Write-Host "Virus threat response configuration added successfully."

###########################################################################################

Write-Host "NixGuard agent setup successfully."

# Start Wazuh agent
Start-Process -FilePath "NET" -ArgumentList "START WazuhSvc"

Write-Host "NixGuard agent started successfully."
