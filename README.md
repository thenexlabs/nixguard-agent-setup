# NixGuard Agent Setup — Wazuh agent installer for the NixGuard AI SOC

Wazuh agent installers for NixGuard, the AI-native SOC and continuous compliance platform. One script per OS (Linux, macOS, Windows) enrolls an endpoint.

## What is it

This repository holds the endpoint onboarding scripts for [NixGuard](https://nixguard.com), an AI-native active security operations center (SOC) and continuous compliance platform built on Wazuh open-source SIEM/XDR telemetry.

Each setup script installs the official [Wazuh](https://wazuh.com) agent, points it at your NixGuard manager, applies a tuned file integrity monitoring (FIM) profile, and deploys NixGuard active-response scripts used for threat remediation. Matching removal scripts uninstall the agent cleanly.

For the variant that enrolls agents into a group label on a shared manager, see [nixguard-free-agent-setup](https://github.com/thenexlabs/nixguard-free-agent-setup).

## Features

- **Cross-platform endpoint security agent**: Linux (Debian, Ubuntu, Kali, CentOS, RHEL, Fedora), macOS (Intel and Apple silicon) and Windows.
- **Clean reinstall**: any existing Wazuh agent is stopped and removed before the new one is installed, so the scripts can be re-run safely.
- **Tuned file integrity monitoring**: rate-limited, low-priority syscheck scans (12-hour baseline, no scan on start) with noisy paths such as `node_modules`, `.git` and container storage ignored to keep CPU and disk I/O low.
- **Compliance-driven encryption monitoring**: the NixGuard app adds `--requires-encryption` (Windows: `-requiresEncryption`) to the install command when your compliance standards include SOC 2, NIST SP 800-53, ISO 27001, GDPR, HIPAA, PCI DSS, PIPEDA or CIS Controls, and the script then installs a disk-encryption check (LUKS on Linux, FileVault on macOS, BitLocker on Windows) whose JSON output the agent forwards for compliance reporting. With `--soc2` (`-soc2`) it also installs the NixGuard SOC 2 SCA policy (`sca/`) locally on Linux and Windows.
- **Active response for threat detection and remediation**: installs `remove-threat` (quarantine or delete a flagged file) and `nixguard-remediate` (block an IP, restart a service, or upgrade a package) so NixGuard can act on alerts.
- **Linux audit support**: installs and enables `auditd`.

## Requirements

| Platform | Requirements |
| --- | --- |
| Linux | Debian, Ubuntu or Kali (apt/dpkg) or CentOS, RHEL or Fedora (yum/rpm); x86_64 or aarch64; systemd; root via `sudo` |
| macOS | Intel (x86_64) or Apple silicon (arm64); root via `sudo`; Homebrew recommended (used to install `jq`) |
| Windows | 64-bit Windows; PowerShell run as Administrator |

You also need:

- The **address of your NixGuard manager**, and an **agent name** for this machine. No API key is needed (older commands that pass one still work; it is ignored).
- Outbound network access from the endpoint (see [What the scripts change](#what-the-scripts-change)).

## Quick start / Installation

Download the script for your platform, review it, then run it with administrator rights. Replace the placeholders in angle brackets.

### Linux

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> [--requires-encryption] [--soc2]
```

### macOS

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> [--requires-encryption]
```

### Windows (PowerShell as Administrator)

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/windows/agent-automatic-setup.ps1 -OutFile agent-automatic-setup.ps1
powershell -ExecutionPolicy Bypass -File .\agent-automatic-setup.ps1 -agentName <agent_name> -ipAddress <manager_address> [-requiresEncryption] [-soc2]
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

### Update the active-response scripts

The setup script downloads the active-response scripts once, at install time; nothing updates them afterwards, and
re-running setup reinstalls (and re-enrolls) the agent. To get new versions of `nixguard-remediate` and
`nixguard-unblock-ip` onto an endpoint that is already enrolled, run the update script for its platform (as root or
Administrator). It replaces only those scripts; the agent keeps its ID and needs no restart.

| Platform | Command |
| --- | --- |
| Linux | `curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/update-active-response.sh && sudo bash update-active-response.sh` |
| macOS | `curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/update-active-response.sh && sudo bash update-active-response.sh` |
| Windows | `Invoke-WebRequest -Uri https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/windows/update-active-response.ps1 -OutFile update-active-response.ps1; powershell -ExecutionPolicy Bypass -File .\update-active-response.ps1` |

### IP block results and unblock

`nixguard-remediate` blocks an IPv4 address in the host firewall (iptables or firewalld on Linux, pf on macOS, a
Windows Firewall rule named `NixGuard Block <ip>`), reads the rule back, and writes one result line to the agent's
`active-responses.log`, which every Wazuh agent forwards by default:

```text
2026/11/12 10:00:00 active-response/bin/nixguard-remediate: {"version":1,"command":"add","parameters":{"program":"nixguard-remediate"},"nixguard":{"action":"block-ip","target":"203.0.113.7","run":"ngr-...","result":"success","reason":"blocked"}}
```

Wazuh's built-in `ar_log_json` decoder and rule 657 turn that line into an alert, so NixGuard confirms the block from
the alerts index. Rule 657 is level 3, and a manager whose `log_alert_level` is 4 or more (NixGuard-provisioned
managers use 4) never stores it, so install `manager/nixguard_ar_rules.xml` on the manager: it raises the results to
level 5 (success) and 7 (failure). Install steps are in the file.

`nixguard-unblock-ip` removes only what `nixguard-remediate` added (iptables rules tagged `nixguard-block`, its exact
firewalld rich rule, its pf rule, the `NixGuard Block <ip>` Windows rule) and reports the same way. It is a separate
script, so an endpoint that does not have it does nothing when asked to unblock. Both accept only an IPv4 address.

Checks (no firewall is touched; fakes stand in for iptables, firewall-cmd, pfctl and netsh):
`bash tests/linux-active-response.test.sh`, `bash tests/mac-active-response.test.sh`,
`python3 -m unittest discover -s tests -p "test_*.py"`, `python3 tests/manager-rules.test.py` (manager rule levels).

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
| Active response | `remove-threat.sh`, `nixguard-remediate.sh`, `nixguard-unblock-ip.sh` | `remove-threat.sh`, `nixguard-remediate.sh`, `nixguard-unblock-ip.sh` | `remove-threat.exe`, `nixguard-remediate.exe`, `nixguard-unblock-ip.exe` |
| Config | Rewrites the `<syscheck>` block in `ossec.conf` (backup saved alongside) | Appends FIM tuning to `ossec.conf` | Adds FIM directories and tuning to `ossec.conf` |

**Network:** the agent connects outbound to your NixGuard manager using the standard Wazuh agent ports (1514/TCP for events, 1515/TCP for enrollment; the scripts do not change them). During setup the scripts also make HTTPS requests to `packages.wazuh.com`, `raw.githubusercontent.com` (this repository) and on Windows `python.org` and PyPI. No inbound ports are opened.

**Warning:** setup removes any existing Wazuh agent on the machine first. On macOS the whole `/Library/Ossec` directory is deleted.

## Repository layout

```text
linux/    agent-automatic-setup.sh, agent-automatic-remove.sh, update-active-response.sh, active-response/
mac/      agent-automatic-setup.sh, agent-automatic-remove.sh, update-active-response.sh, active-response/
windows/  agent-automatic-setup.ps1, agent-automatic-remove.ps1, update-active-response.ps1, active-response/
manager/  nixguard_ar_rules.xml (Wazuh manager rules that store active-response results at level 5 and 7)
tests/    checks for the IP block and unblock scripts
```

## Security

The setup scripts run with root or Administrator rights, so read them before running. To report a vulnerability, please use the security contact listed on [nixguard.com](https://nixguard.com) rather than opening a public issue.

## About NEX Level Labs

NixGuard is built by NEX Level Labs Inc., a deeptech cybersecurity company. Learn more about the [NixGuard AI SOC platform](https://nixguard.com) and [NEX Level Labs](https://thenex.world).
