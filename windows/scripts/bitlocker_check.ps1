# bitlocker_check.ps1
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

# --- THIS IS THE NEW, ROBUST LOG WRITING SECTION ---

$logDir = "C:\ProgramData\Wazuh\logs"
$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
$tempLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.tmp"

# Ensure the directory exists
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# 1. Convert the final object to JSON
$finalJson = ConvertTo-Json -InputObject $output -Compress -Depth 5

# 2. Write the JSON to a temporary file. This will never be locked.
$finalJson | Out-File -FilePath $tempLogFile -Encoding utf8

# 3. Rename the temporary file to the final file name. This is an atomic operation.
#    The Wazuh agent will detect this change and read the new file.
Move-Item -Path $tempLogFile -Destination $finalLogFile -Force

