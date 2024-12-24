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

# run Uninstall-WazuhAgent function
Uninstall-WazuhAgent

# Install the Wazuh agent
## loop until file is gone
$fileExists = $true
while ($fileExists) {
    # Check if the file exists
    if (Test-Path -Path $configPath) {
        # If the file exists, print the message and wait for a while before checking again
        # Write-Host "File found at $configPath, waiting for 5 seconds before checking again..."
        Write-Host ".."
        Start-Sleep -Seconds 3
    } else {
        # If the file does not exist, set the control variable to false to exit the loop
        $fileExists = $false
        # Write-Host "File not found at $configPath"
        Write-Host "."
    }
}

# Set a maximum number of retries
$maxRetries = 4
$retryCount = 0

# Write-Host "agent name: $agentName"
# Write-Host "cloud soc ip: $ipAddress"

do {
    # Download the Wazuh agent installer
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi -OutFile "${env:tmp}\wazuh-agent"
    $wazuhInstaller = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "${env:tmp}\wazuh-agent", "/q", "WAZUH_MANAGER='$ipAddress'", "WAZUH_AGENT_NAME='$agentName'", "WAZUH_AGENT_GROUP='default'", "WAZUH_REGISTRATION_SERVER='$ipAddress'" -PassThru -Wait

    # Check the exit code of the installer
    if ($wazuhInstaller.ExitCode -ne 0) {
        Write-Host "Installer exited with code $($wazuhInstaller.ExitCode)"
        $retryCount++
        if ($retryCount -le $maxRetries) {
            Write-Host "Retrying installation ($retryCount of $maxRetries)..."
            Start-Sleep -Seconds 10  # Wait before retrying
        } else {
            Write-Host "Installation failed after $maxRetries attempts."
            exit $wazuhInstaller.ExitCode
        }
    } else {
        # If the exit code is 0, break the loop
        break
    }
} while ($true)

# loop until file exists
$counter = 0
$fileExists = $false
while (-not $fileExists) {
    # Check if the file exists
    if (Test-Path -Path $configPath) {
        # If the file exists, set the control variable to true to exit the loop
        $fileExists = $true
        Write-Host "."
    } else {
        # If the file does not exist, wait for a while before checking again
        Write-Host ".."
        Start-Sleep -Seconds 3
    }
    $counter++
}

# Update the ossec.conf file
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
