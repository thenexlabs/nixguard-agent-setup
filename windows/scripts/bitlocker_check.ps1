# bitlocker_check.ps1
# A hardened script to check BitLocker status and reliably write the output to a fixed log file.
# The final output path and JSON structure are immutable to match the Wazuh parser.

# --- Section 1: Pre-flight Checks & Environment Setup ---

$logDir = "C:\ProgramData\Wazuh\logs"
# CRITICAL FIX: Ensure the log directory exists. This prevents the most common silent failure.
try {
    if (-not (Test-Path -Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
}
catch {
    # If this fails, the script cannot succeed. This is a fatal error.
    Write-Error "FATAL: Could not create log directory at '$logDir'. Error: $($_.Exception.Message)"
    exit 1
}


# --- Section 2: Core Logic - Get BitLocker Status ---

$output = try {
    # Compatibility Check: Ensure the BitLocker module is even installed.
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available on this system."
    }

    # Use the most compatible method to get all BitLocker-managed fixed drives.
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -eq 'Fixed' }

    if ($null -eq $bitlockerVolumes) {
        #
        # CRITICAL LOGIC FIX: A machine with no BitLocker IS a security failure.
        # Create a failure report that the existing Wazuh rules WILL catch as a high-severity alert.
        #
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $failure_report = @{
            "mount_point"       = $systemDrive;
            "protection_status" = "Off";            # This will trigger rule 100102
            "volume_status"     = "FullyDecrypted"; # This will trigger rule 100103
            "encryption_method" = "None";
            "key_protectors"    = ""
        }
        # The script's state is "success" because it successfully discovered a non-compliant state.
        @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = @($failure_report) } }
    }
    else {
        # If volumes were found, process them normally into the correct JSON structure.
        $volume_reports = foreach ($volume in $bitlockerVolumes) {
            @{
                "mount_point"       = $volume.MountPoint;
                "protection_status" = $volume.ProtectionStatus.ToString();
                "volume_status"     = $volume.VolumeStatus.ToString();
                "encryption_method" = $volume.EncryptionMethod.ToString();
                "key_protectors"    = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
        }
        # Build the success object with the exact required schema.
        @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = $volume_reports } }
    }
}
catch {
    # This block handles SCRIPT EXECUTION errors (e.g., module not found), not compliance states.
    @{ "bitlocker_status" = @{ "state" = "error"; "message" = "Script failed during execution. Error: $($_.Exception.Message)" } }
}


# --- Section 3: The Atomic Write Transaction ---
# This safely writes the $output variable to the immutable log file path.

$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
$tempLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.tmp"

try {
    $finalJson = $output | ConvertTo-Json -Compress -Depth 5
    $finalJson | Out-File -FilePath $tempLogFile -Encoding utf8
    Move-Item -Path $tempLogFile -Destination $finalLogFile -Force
}
catch {
    # Final safety net if the disk is full or AV blocks the write.
    Write-Error "FATAL: FAILED to write the final log file at '$finalLogFile'. Check disk space or AV logs. Error: $($_.Exception.Message)"
    exit 1
}
