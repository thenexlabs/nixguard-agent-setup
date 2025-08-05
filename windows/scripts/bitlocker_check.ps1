# bitlocker_check.ps1 (FINAL PRODUCTION VERSION)
# This script robustly checks BitLocker status and writes the output to a log file.

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

    $bitlockerVolumes = Get-BitLockerVolume -MountPoint $validDriveLetters
    
    # --- THIS IS THE FINAL CORRECTED LOGIC ---
    # It now correctly identifies both a null result AND an empty result as a failure.
    if ($null -eq $bitlockerVolumes -or $bitlockerVolumes.Count -eq 0) {
        $output = @{ "bitlocker_status" = @{ "state" = "error"; "message" = "No BitLocker-managed volumes found on fixed drives." } }
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

# Write the JSON output to the dedicated log file.
$logFile = "C:\ProgramData\Wazuh\logs\bitlocker_status.log"
$finalJson = ConvertTo-Json -InputObject $output -Compress
$finalJson | Out-File -FilePath $logFile -Encoding utf8
