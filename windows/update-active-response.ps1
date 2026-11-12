# Updates only NixGuard's active-response programs on a Windows endpoint that already runs the NixGuard Wazuh agent.
# The setup script builds these once, at install, and re-running it reinstalls (and re-enrolls) the agent; this rebuilds
# just nixguard-remediate.exe and nixguard-unblock-ip.exe with the Python and PyInstaller the setup script installed.
# Run in PowerShell as Administrator:
#   Invoke-WebRequest -Uri https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/windows/update-active-response.ps1 -OutFile update-active-response.ps1
#   powershell -ExecutionPolicy Bypass -File .\update-active-response.ps1
$ErrorActionPreference = 'Stop'

$destDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$baseUrl = "https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/windows/active-response"
if (-not (Test-Path $destDir)) { throw "$destDir not found: install the NixGuard agent first (agent-automatic-setup.ps1)." }
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw "Python (py) not found: re-run agent-automatic-setup.ps1." }
py -m pip install --quiet pyinstaller

$work = Join-Path -Path $env:TEMP -ChildPath ("nixguard-ar-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    Set-Location -Path $work
    foreach ($name in @('nixguard-remediate', 'nixguard-unblock-ip')) {
        $source = Join-Path -Path $work -ChildPath "$name.py"
        Invoke-WebRequest -Uri "$baseUrl/$name.py" -OutFile $source -UseBasicParsing
        py -m PyInstaller -F $source | Out-Null
        $exe = Join-Path -Path $work -ChildPath "dist\$name.exe"
        if (-not (Test-Path $exe)) { throw "Building $name.exe failed; the installed copy (if any) is unchanged." }
        Move-Item -Path $exe -Destination $destDir -Force
        Write-Host "Updated $destDir\$name.exe"
    }
} finally {
    Set-Location -Path $env:TEMP
    Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "NixGuard active-response programs are up to date."
