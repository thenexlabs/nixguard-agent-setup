# NixGuard Agent Setup — Wazuh agent installer for the NixGuard AI SOC

Wazuh agent installers for NixGuard, the AI-native SOC and continuous compliance platform. One script per OS (Linux, macOS, Windows) enrolls an endpoint.

## What is it

This repository holds the endpoint onboarding scripts for [NixGuard](https://nixguard.com), an AI-native active security operations center (SOC) and continuous compliance platform built on Wazuh open-source SIEM/XDR telemetry.

Each setup script installs the official [Wazuh](https://wazuh.com) agent, points it at your NixGuard manager, applies a tuned file integrity monitoring (FIM) profile, and deploys NixGuard active-response scripts used for threat remediation. Matching removal scripts uninstall the agent cleanly.

For the variant that enrolls agents into a group label instead of using an API key, see [nixguard-free-agent-setup](https://github.com/thenexlabs/nixguard-free-agent-setup).

## Features

- **Cross-platform endpoint security agent**: Linux (Debian, Ubuntu, Kali, CentOS, RHEL, Fedora), macOS (Intel and Apple silicon) and Windows.
- **Clean reinstall**: any existing Wazuh agent is stopped and removed before the new one is installed, so the scripts can be re-run safely.
- **Tuned file integrity monitoring**: rate-limited, low-priority syscheck scans (12-hour baseline, no scan on start) with noisy paths such as `node_modules`, `.git` and container storage ignored to keep CPU and disk I/O low.
- **Compliance-driven encryption monitoring**: the script reads your account's compliance preferences from the NixGuard API. If they include SOC 2, NIST SP 800-53, ISO 27001, GDPR, HIPAA, PCI DSS, PIPEDA or CIS Controls, it installs a disk-encryption check (LUKS on Linux, FileVault on macOS, BitLocker on Windows) whose JSON output the agent forwards for compliance reporting.
- **Active response for threat detection and remediation**: installs `remove-threat` (quarantine or delete a flagged file) and `nixguard-remediate` (block an IP, restart a service, or upgrade a package) so NixGuard can act on alerts.
- **Linux audit support**: installs and enables `auditd`.

## Requirements

| Platform | Requirements |
| --- | --- |
| Linux | Debian, Ubuntu or Kali (apt/dpkg) or CentOS, RHEL or Fedora (yum/rpm); x86_64 or aarch64; systemd; root via `sudo` |
| macOS | Intel (x86_64) or Apple silicon (arm64); root via `sudo`; Homebrew recommended (used to install `jq`) |
| Windows | 64-bit Windows; PowerShell run as Administrator |

You also need:

- The **address of your NixGuard manager**, an **agent name** for this machine, and your **NixGuard API key**.
- Outbound network access from the endpoint (see [What the scripts change](#what-the-scripts-change)).

## Quick start / Installation

Download the script for your platform, review it, then run it with administrator rights. Replace the placeholders in angle brackets.

### Linux

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> <api_key>
```

### macOS

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> <api_key>
```

### Windows (PowerShell as Administrator)

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/windows/agent-automatic-setup.ps1 -OutFile agent-automatic-setup.ps1
powershell -ExecutionPolicy Bypass -File .\agent-automatic-setup.ps1 -agentName <agent_name> -ipAddress <manager_address> -apiKey <api_key>
```

Note the argument order differs on Windows: agent name comes first.

## Usage

### Uninstall the agent

Run from a clone of this repository (`git clone https://github.com/thenexlabs/nixguard-agent-setup.git`):

| Platform | Command |
| --- | --- |
| Linux | `sudo bash linux/agent-automatic-remove.sh` |
| macOS | `sudo bash mac/agent-automatic-remove.sh` |
| Windows | `.\windows\agent-automatic-remove.ps1` (PowerShell as Administrator) |

### Verify the agent is running

- Linux: `systemctl status wazuh-agent` (logs: `journalctl -u wazuh-agent`)
- macOS: `sudo /Library/Ossec/bin/wazuh-control status`
- Windows: `Get-Service WazuhSvc`

### What the scripts change

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Wazuh agent | 4.9.1 (`.deb` / `.rpm`), service `wazuh-agent` | 4.7.4 (`.pkg`), installed under `/Library/Ossec` | 4.9.1 (`.msi`), service `WazuhSvc` |
| Extra packages | `curl`, `jq`, `wget`, `auditd` (`audit` on RHEL family) | `jq` via Homebrew if missing | Python 3.12.4 (all users) and PyInstaller, used to build the active-response `.exe` files |
| Encryption check (if your compliance standards require it) | `luks_check.sh` via root cron every 10 minutes | `filevault_check.sh` via LaunchDaemon `com.nixguard.filevaultcheck` every 5 minutes | `bitlocker_check.ps1` via scheduled task `Wazuh-BitLocker-Check` every 5 minutes, as SYSTEM |
| Active response | `remove-threat.sh`, `nixguard-remediate.sh` | `remove-threat.sh`, `nixguard-remediate.sh` | `remove-threat.exe`, `nixguard-remediate.exe` |
| Config | Rewrites the `<syscheck>` block in `ossec.conf` (backup saved alongside) | Appends FIM tuning to `ossec.conf` | Adds FIM directories and tuning to `ossec.conf` |

**Network:** the agent connects outbound to your NixGuard manager using the standard Wazuh agent ports (1514/TCP for events, 1515/TCP for enrollment; the scripts do not change them). During setup the scripts also make HTTPS requests to `packages.wazuh.com`, `raw.githubusercontent.com` (this repository), the NixGuard API (to read your compliance preferences), and on Windows `python.org` and PyPI. No inbound ports are opened.

**Warning:** setup removes any existing Wazuh agent on the machine first. On macOS the whole `/Library/Ossec` directory is deleted.

## Repository layout

```text
linux/    agent-automatic-setup.sh, agent-automatic-remove.sh, active-response/
mac/      agent-automatic-setup.sh, agent-automatic-remove.sh, active-response/
windows/  agent-automatic-setup.ps1, agent-automatic-remove.ps1, active-response/
```

## Security

The setup scripts run with root or Administrator rights, so read them before running. To report a vulnerability, please use the security contact listed on [nixguard.com](https://nixguard.com) rather than opening a public issue.

## About NEX Level Labs

NixGuard is built by NEX Level Labs Inc., a deeptech cybersecurity company. Learn more about the [NixGuard AI SOC platform](https://nixguard.com) and [NEX Level Labs](https://thenex.world).
