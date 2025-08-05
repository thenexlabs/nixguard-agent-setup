# bitlocker_check.ps1
# This script checks the BitLocker status for all FixedData drives and outputs in JSON format for Wazuh.

try {
    $bitlockerVolumes = Get-BitLockerVolume -MountPoint (Get-Volume -DriveType Fixed).DriveLetter
    if ($null -eq $bitlockerVolumes) {
        # No BitLocker volumes found, which could be an issue in itself.
        $output = @{
            "bitlocker_status" = @{
                "state" = "error";
                "message" = "No BitLocker-managed volumes found on fixed drives."
            }
        }
    } else {
        # Process each volume
        $volume_reports = @()
        foreach ($volume in $bitlockerVolumes) {
            $volume_report = @{
                "mount_point" = $volume.MountPoint;
                "capacity_gb" = [math]::Round($volume.CapacityGB, 2);
                "protection_status" = $volume.ProtectionStatus.ToString(); # 'On', 'Off'
                "volume_status" = $volume.VolumeStatus.ToString(); # 'FullyEncrypted', 'FullyDecrypted', 'Encrypting'
                "encryption_method" = $volume.EncryptionMethod.ToString(); # e.g. 'XtsAes256'
                "key_protectors" = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
            $volume_reports += $volume_report
        }
        $output = @{
            "bitlocker_status" = @{
                "state" = "success";
                "volumes" = $volume_reports
            }
        }
    }
}
catch {
    # Catch any errors during script execution
    $output = @{
        "bitlocker_status" = @{
            "state" = "error";
            "message" = "Script failed to execute. Error: $($_.Exception.Message)"
        }
    }
}

# Convert the final object to a single-line JSON string for Wazuh
Write-Output (ConvertTo-Json -InputObject $output -Compress)