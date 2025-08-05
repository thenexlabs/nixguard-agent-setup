# bitlocker_check.ps1
# This script robustly checks BitLocker status and writes the output to a log file.

# --- THIS IS THE NEW, ROBUST LOG DIRECTORY SETUP ---
$logDir = "C:\ProgramData\Wazuh\logs"
# Ensure the directory exists before we do anything else. This is the fix.
try {
    if (-not (Test-Path -Path $logDir)) {
        # The -Force switch creates the entire path (C:\ProgramData\Wazuh\logs) if needed.
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
}
catch {
    # If we can't create the directory, the script cannot succeed. Exit immediately.
    Write-Error "CRITICAL FAILURE: Could not create log directory at '$logDir'. Error: $($_.Exception.Message)"
    exit 1
}
# --- End of new code block ---


# --- The rest of your script now runs safely ---
try {
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available."
    }
    $allFixedVolumes = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"
    $validDriveLetters = @()
    if ($null -ne $allFixedVolumes) {
        foreach ($volume in $allFixedVolumes) {
            if (-not [string]::IsNullOrWhiteSpace($volume.DriveLetter)) {
                $validDriveLetters += $volume.DriveLetter
            }
        }
    }
    if ($validDriveLetters.Count -eq 0) {
        throw "Found fixed volumes, but none have an assigned drive letter to check for BitLocker status."
    }
    
    # This compatible filter works on all systems, regardless of drive name
    $bitlockerVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'Fixed' }

    if ($null -eq $bitlockerVolumes -or $bitlockerVolumes.Count -eq 0) {
        $output = @{ "bitlocker_status" = @{ "state" = "not_found"; "message" = "No BitLocker-managed volumes found on fixed drives." } }
    } else {
        $volume_reports = @()
        foreach ($volume in $bitlockerVolumes) {
            $volume_report = @{
                "mount_point" = $volume.MountPoint;
                "protection_status" = $volume.ProtectionStatus.ToString();
                "volume_status" = $volume.VolumeStatus.ToString();
                "encryption_method" = $volume.EncryptionMethod.ToString();
                "key_protectors" = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
            $volume_reports += $volume_report
        }
        $output = @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = $volume_reports } }
    }
}
catch {
    $output = @{ "bitlocker_status" = @{ "state" = "error"; "message" = "Script failed to execute. Error: $($_.Exception.Message)" } }
}

# --- This section now works reliably because the directory is guaranteed to exist ---

$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
$tempLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.tmp"

# 1. Convert the final object to JSON
$finalJson = ConvertTo-Json -InputObject $output -Compress -Depth 5

# 2. Write the JSON to a temporary file.
$finalJson | Out-File -FilePath $tempLogFile -Encoding utf8

# 3. Rename the temporary file to the final file name. This is an atomic operation.
Move-Item -Path $tempLogFile -Destination $finalLogFile -Force
