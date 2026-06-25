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
        # A machine with no BitLocker volumes IS a security failure.
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $failure_report = @{
            "mount_point"       = $systemDrive;
            "protection_status" = "Off"; 
            "volume_status"     = "FullyDecrypted"; 
            "encryption_method" = "None";
            "key_protectors"    = ""
        }
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
        @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = $volume_reports } }
    }
}
catch {
    @{ "bitlocker_status" = @{ "state" = "error"; "message" = "Script failed during execution. Error: $($_.Exception.Message)" } }
}


# --- Section 3: The Append Write Transaction ---

$finalLogFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"

try {
    $finalJson = $output | ConvertTo-Json -Compress -Depth 5
    
    # LOG ROTATION: If file is > 1MB, clear it to prevent infinite growth
    if ((Test-Path $finalLogFile) -and ((Get-Item $finalLogFile).Length -gt 1MB)) {
        Clear-Content -Path $finalLogFile
    }
    
    # APPEND LOGIC: Guarantees Wazuh logcollector reads the new line
    $finalJson | Out-File -FilePath $finalLogFile -Encoding utf8 -Append
}
catch {
    Write-Error "FATAL: FAILED to write the final log file at '$finalLogFile'. Check disk space or AV logs. Error: $($_.Exception.Message)"
    exit 1
}