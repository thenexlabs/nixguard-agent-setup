# bitlocker_check.ps1
# A hardened script that checks BitLocker status and ensures a compliant or non-compliant state is always reported.
# Outputs flat JSON lines to ensure 100% compatibility with the Wazuh JSON decoder.

# --- Section 1: Pre-flight Checks & Environment Setup ---

$logDir = "C:\ProgramData\Wazuh\logs"
try {
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
}
catch {
    Write-Error "FATAL: Could not create log directory at '$logDir'. Error: $($_.Exception.Message)"
    exit 1
}


# --- Section 2: Core Logic - Get BitLocker Status ---

$output = try {
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available on this system."
    }

    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -eq 'Fixed' }

    if ($null -eq $bitlockerVolumes) {
        # No volumes found is a security failure. Report C: as decrypted.
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $failure_report = @{
            "bitlocker_status" = @{
                "state"             = "success"
                "mount_point"       = $systemDrive
                "protection_status" = "Off"
                "volume_status"     = "FullyDecrypted"
                "encryption_method" = "None"
                "key_protectors"    = ""
            }
        }
        @($failure_report)
    }
    else {
        # Process each volume as a separate flat object
        foreach ($volume in $bitlockerVolumes) {
            @{
                "bitlocker_status" = @{
                    "state"             = "success"
                    "mount_point"       = $volume.MountPoint
                    "protection_status" = $volume.ProtectionStatus.ToString()
                    "volume_status"     = $volume.VolumeStatus.ToString()
                    "encryption_method" = $volume.EncryptionMethod.ToString()
                    "key_protectors"    = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
                }
            }
        }
    }
}
catch {
    # Handle script execution errors
    $err_report = @{
        "bitlocker_status" = @{
            "state"   = "error"
            "message" = "Script failed during execution. Error: $($_.Exception.Message)"
        }
    }
    @($err_report)
}


# --- Section 3: The Atomic Write Transaction ---

$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
$tempLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.tmp"

try {
    # Convert each volume report to a single-line compressed JSON and join them with newlines
    $jsonLines = foreach ($report in $output) {
        $report | ConvertTo-Json -Compress -Depth 5
    }
    $finalContent = $jsonLines -join "`r`n"
    
    $finalContent | Out-File -FilePath $tempLogFile -Encoding utf8 -NoNewline
    Move-Item -Path $tempLogFile -Destination $finalLogFile -Force
}
catch {
    Write-Error "FATAL: FAILED to write the final log file at '$finalLogFile'. Error: $($_.Exception.Message)"
    exit 1
}