# bitlocker_check.ps1
# A hardened script that checks BitLocker status and ensures a compliant or non-compliant state is always reported.
# The final output path and JSON structure are immutable to match the Wazuh parser.

# --- Section 1: Pre-flight Checks & Environment Setup ---

$logDir = "C:\ProgramData\Wazuh\logs"
# Ensure the log directory exists. This is a fatal-on-failure check.
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

    # Use the most compatible method to get all BitLocker-managed fixed drives.
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -eq 'Fixed' }

    if ($null -eq $bitlockerVolumes) {
        #
        # --- THIS IS THE CRITICAL FIX ---
        # A machine with no BitLocker volumes IS a security failure.
        # We will now create a failure report that the existing Wazuh rules WILL catch.
        #
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $failure_report = @{
            "mount_point"       = $systemDrive;
            "protection_status" = "Off"; # This will trigger rule 100102
            "volume_status"     = "FullyDecrypted"; # This will trigger rule 100103
            "encryption_method" = "None";
            "key_protectors"    = ""
        }
        # The script's state is "success" because it successfully discovered a non-compliant state.
        @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = @($failure_report) } }
    }
    else {
        # If volumes were found, process them normally.
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
    # This block handles SCRIPT EXECUTION errors, not compliance states.
    @{ "bitlocker_status" = @{ "state" = "error"; "message" = "Script failed during execution. Error: $($_.Exception.Message)" } }
}


# --- Section 3: The Atomic Write Transaction ---
# This safely writes the $output variable to the immutable log file path.

$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
$tempLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.tmp"

try {
    $finalJson = $output | ConvertTo-Json -Compress -Depth 5
    $finalJson | Out-File -FilePath $tempLogFile -Encoding utf8 -NoNewline
    Move-Item -Path $tempLogFile -Destination $finalLogFile -Force
}
catch {
    Write-Error "FATAL: FAILED to write the final log file at '$finalLogFile'. Check disk space or AV logs. Error: $($_.Exception.Message)"
    exit 1
}
