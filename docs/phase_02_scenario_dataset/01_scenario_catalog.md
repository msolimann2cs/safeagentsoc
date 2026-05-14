# Phase 2 Scenario Catalog

## Purpose

This catalog defines the controlled scenarios used to generate the SafeAgentSOC Phase 2 Wazuh alert dataset.

The goal is not to generate random alerts. The goal is to create a traceable, repeatable, labeled, MITRE-mapped dataset that supports later phases:

- Alert normalization
- Alert clustering and case building
- MITRE ATT&CK mapping
- LLM hypothesis evaluation
- Attack graph validation
- Risk scoring
- GRC policy-safe response evaluation

## Scenario Design Rules

No scenario may be executed until it has:

- Scenario ID
- Scenario name
- Scenario type
- Host
- Objective
- Analyst hypothesis
- Wrong inference warning
- MITRE mapping or N/A justification
- Expected local signal
- Expected Wazuh signal
- Wazuh query idea
- Commands
- Cleanup
- Safety rating
- Ground-truth label
- Evidence filenames

## Scenario Summary

| ID | Name | Type | Platform | Host | MITRE | Safety | Status |
|---|---|---|---|---|---|---|---|
| S01 | Windows PowerShell execution | attack_like | Windows | safesoc-win-01 | T1059.001 | Low | Ready for execution planning |
| S02 | Windows discovery sequence | attack_like | Windows | safesoc-win-01 | T1082, T1033, T1016 | Low | Ready for execution planning |
| S03 | Windows scheduled task marker | attack_like | Windows | safesoc-win-01 | T1053.005 | Medium | Ready for execution planning |
| S04 | Windows archive/staging behavior | attack_like | Windows | safesoc-win-01 | T1560.001 | Low | Ready for execution planning |
| S05 | Windows normal admin maintenance | benign | Windows | safesoc-win-01 | N/A | Low | Ready for execution planning |
| S06 | Windows repeated benign noise | noise | Windows | safesoc-win-01 | N/A | Low | Ready for execution planning |
| S07 | Linux SSH failed login pattern | attack_like | Linux | safesoc-lnx-01 | T1110.001 | Low | Ready for execution planning |
| S08 | Linux sudo authentication pattern | attack_like | Linux | safesoc-lnx-01 | T1548.003 | Low | Ready for execution planning |
| S09 | Linux discovery sequence | attack_like | Linux | safesoc-lnx-01 | T1082, T1033, T1016 | Low | Ready for execution planning |
| S10 | Linux cron marker | attack_like | Linux | safesoc-lnx-01 | T1053.003 | Medium | Ready for execution planning |
| S11 | Linux normal admin maintenance | benign | Linux | safesoc-lnx-01 | N/A | Low | Ready for execution planning |
| S12 | Repeated typo/noisy authentication | ambiguous/noise | Cross-endpoint | Windows/Linux | N/A | Low | Ready for execution planning |

---

## S01: Windows PowerShell Execution

| Field | Value |
|---|---|
| Scenario ID | S01 |
| Scenario Name | Windows PowerShell execution |
| Scenario Type | attack_like |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | Sysmon process creation, Windows process telemetry |
| MITRE Tactic | Execution |
| MITRE Technique | T1059.001 PowerShell |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger |

### Objective

Generate safe PowerShell execution telemetry that resembles suspicious script execution without executing malicious code.

### Analyst Hypothesis

A Windows endpoint executed PowerShell commands that may represent script-based execution activity.

### Wrong Inference Warning

This scenario must not be labeled as malware execution, command-and-control, credential theft, or confirmed compromise. The ground truth is controlled benign PowerShell activity used to simulate attack-like telemetry.

### MITRE Justification

PowerShell is mapped to T1059.001 because adversaries may abuse PowerShell commands and scripts for execution. This scenario uses benign PowerShell commands only.

### Commands Planned

```powershell
Write-Output "SafeAgentSOC S01 PowerShell execution test"
Get-Date
Get-ChildItem C:\
New-Item -ItemType Directory -Force C:\SafeAgentSOC-Phase2\S01
"SafeAgentSOC S01 marker" | Out-File C:\SafeAgentSOC-Phase2\S01\s01_marker.txt
```

### Expected Local Signal

- PowerShell command history
- Sysmon process creation event
- Optional file creation evidence under `C:\SafeAgentSOC-Phase2\S01`

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01" and powershell
```

More specific query if fields exist:

```text
agent.name: "safesoc-win-01" and data.win.system.providerName: "Microsoft-Windows-Sysmon"
```

### Cleanup

```powershell
Remove-Item -Recurse -Force C:\SafeAgentSOC-Phase2\S01
```

### Evidence Files

```text
YYYY-MM-DD_S01_R001_pre-run_state.png
YYYY-MM-DD_S01_R001_commands_executed.png
YYYY-MM-DD_S01_R001_local_log_proof.png
YYYY-MM-DD_S01_R001_wazuh_results.png
YYYY-MM-DD_S01_R001_wazuh_event_details.png
YYYY-MM-DD_S01_R001_cleanup_proof.png
```

---

## S02: Windows Discovery Sequence

| Field | Value |
|---|---|
| Scenario ID | S02 |
| Scenario Name | Windows discovery sequence |
| Scenario Type | attack_like |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | Process execution, Sysmon, Windows command execution |
| MITRE Tactic | Discovery |
| MITRE Techniques | T1082 System Information Discovery, T1033 System Owner/User Discovery, T1016 System Network Configuration Discovery |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger/supporting |

### Objective

Generate safe discovery telemetry using built-in Windows commands.

### Analyst Hypothesis

A user or process performed system, user, and network discovery commands on the Windows endpoint.

### Wrong Inference Warning

This scenario does not prove lateral movement, privilege escalation, credential theft, or external command-and-control. It only proves local discovery-like behavior.

### Commands Planned

```powershell
whoami
hostname
ipconfig /all
systeminfo
net user
Get-LocalUser
```

### Expected Local Signal

- Process creation events for discovery commands
- Command output screenshots
- Sysmon process telemetry if configured

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01" and whoami
```

Alternative:

```text
agent.name: "safesoc-win-01" and systeminfo
```

### Cleanup

No cleanup required.

### Evidence Files

```text
YYYY-MM-DD_S02_R001_pre-run_state.png
YYYY-MM-DD_S02_R001_commands_executed.png
YYYY-MM-DD_S02_R001_local_log_proof.png
YYYY-MM-DD_S02_R001_wazuh_results.png
YYYY-MM-DD_S02_R001_wazuh_event_details.png
```

---

## S03: Windows Scheduled Task Marker

| Field | Value |
|---|---|
| Scenario ID | S03 |
| Scenario Name | Windows scheduled task marker |
| Scenario Type | attack_like |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | Scheduled task creation/deletion, process creation |
| MITRE Tactic | Persistence / Execution |
| MITRE Technique | T1053.005 Scheduled Task |
| Mapping Confidence | Medium |
| Safety Rating | Medium |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger |

### Objective

Create and remove a harmless scheduled task to generate task-scheduler telemetry safely.

### Analyst Hypothesis

A scheduled task was created on the Windows endpoint, which can resemble persistence or recurring execution behavior.

### Wrong Inference Warning

This scenario must not be labeled as persistent malware. The task is harmless, writes only a marker file, and is removed during cleanup.

### Commands Planned

```powershell
New-Item -ItemType Directory -Force C:\SafeAgentSOC-Phase2\S03
schtasks /Create /TN "SafeAgentSOC_S03_Marker" /SC ONCE /ST 23:59 /TR "cmd.exe /c echo SafeAgentSOC S03 marker > C:\SafeAgentSOC-Phase2\S03\s03_task_marker.txt" /F
schtasks /Query /TN "SafeAgentSOC_S03_Marker"
```

### Expected Local Signal

- Scheduled task creation command output
- Sysmon/process events for `schtasks.exe`
- Windows scheduled task event if available

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01" and schtasks
```

### Cleanup

```powershell
schtasks /Delete /TN "SafeAgentSOC_S03_Marker" /F
Remove-Item -Recurse -Force C:\SafeAgentSOC-Phase2\S03
```

### Evidence Files

```text
YYYY-MM-DD_S03_R001_pre-run_state.png
YYYY-MM-DD_S03_R001_commands_executed.png
YYYY-MM-DD_S03_R001_local_log_proof.png
YYYY-MM-DD_S03_R001_wazuh_results.png
YYYY-MM-DD_S03_R001_wazuh_event_details.png
YYYY-MM-DD_S03_R001_cleanup_proof.png
```

---

## S04: Windows Archive and Staging Behavior

| Field | Value |
|---|---|
| Scenario ID | S04 |
| Scenario Name | Windows archive and staging behavior |
| Scenario Type | attack_like |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | PowerShell, file creation, archive creation |
| MITRE Tactic | Collection |
| MITRE Technique | T1560.001 Archive via Utility |
| Mapping Confidence | Medium |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger/supporting |

### Objective

Create harmless test files and compress them into a ZIP archive to simulate archive/staging telemetry.

### Analyst Hypothesis

A user or process staged local files into an archive, which can resemble pre-exfiltration collection behavior.

### Wrong Inference Warning

This scenario must not be labeled as data theft or exfiltration. The files are synthetic test files and never leave the lab.

### Commands Planned

```powershell
New-Item -ItemType Directory -Force C:\SafeAgentSOC-Phase2\S04\staging
"test file one" | Out-File C:\SafeAgentSOC-Phase2\S04\staging\file1.txt
"test file two" | Out-File C:\SafeAgentSOC-Phase2\S04\staging\file2.txt
Compress-Archive -Path C:\SafeAgentSOC-Phase2\S04\staging\* -DestinationPath C:\SafeAgentSOC-Phase2\S04\s04_archive.zip -Force
Get-ChildItem C:\SafeAgentSOC-Phase2\S04
```

### Expected Local Signal

- PowerShell process event
- File creation
- Archive creation

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01" and archive
```

Alternative:

```text
agent.name: "safesoc-win-01" and powershell
```

### Cleanup

```powershell
Remove-Item -Recurse -Force C:\SafeAgentSOC-Phase2\S04
```

### Evidence Files

```text
YYYY-MM-DD_S04_R001_pre-run_state.png
YYYY-MM-DD_S04_R001_commands_executed.png
YYYY-MM-DD_S04_R001_local_log_proof.png
YYYY-MM-DD_S04_R001_wazuh_results.png
YYYY-MM-DD_S04_R001_wazuh_event_details.png
YYYY-MM-DD_S04_R001_cleanup_proof.png
```

---

## S05: Windows Normal Admin Maintenance

| Field | Value |
|---|---|
| Scenario ID | S05 |
| Scenario Name | Windows normal admin maintenance |
| Scenario Type | benign |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | Normal administrative commands |
| MITRE Tactic | N/A |
| MITRE Technique | N/A |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | benign |
| Expected Event Role | supporting |

### Objective

Generate known-benign Windows administrative activity for false-positive handling and baseline comparison.

### Analyst Hypothesis

A user performed normal endpoint maintenance or inspection.

### Wrong Inference Warning

Do not force this scenario into an adversarial MITRE technique. Although some commands overlap with discovery, the ground truth is benign maintenance.

### Commands Planned

```powershell
Get-Service | Select-Object -First 10
Get-Process | Select-Object -First 10
Get-ComputerInfo | Select-Object WindowsProductName,OsVersion
ipconfig
whoami
```

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01"
```

Optional:

```text
agent.name: "safesoc-win-01" and Get-Service
```

### Cleanup

No cleanup required.

---

## S06: Windows Repeated Benign Noise

| Field | Value |
|---|---|
| Scenario ID | S06 |
| Scenario Name | Windows repeated benign noise |
| Scenario Type | noise |
| Platform | Windows |
| Host | safesoc-win-01 |
| Primary Telemetry | Repeated benign process activity |
| MITRE Tactic | N/A |
| MITRE Technique | N/A |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | noise |
| Expected Event Role | duplicate/noise |

### Objective

Generate repeated low-value Windows events for duplicate suppression and alert fatigue testing.

### Analyst Hypothesis

The endpoint produced repetitive benign activity that should be grouped or suppressed later.

### Wrong Inference Warning

Do not label this as malicious. The purpose is noise generation for case-building evaluation.

### Commands Planned

```powershell
for ($i=1; $i -le 10; $i++) {
  whoami
  hostname
  Start-Process notepad.exe
  Start-Sleep -Seconds 1
  Get-Process notepad | Stop-Process -Force
}
```

### Expected Wazuh Query

```text
agent.name: "safesoc-win-01" and notepad
```

### Cleanup

No persistent cleanup required.

---

## S07: Linux SSH Failed Login Pattern

| Field | Value |
|---|---|
| Scenario ID | S07 |
| Scenario Name | Linux SSH failed login pattern |
| Scenario Type | attack_like |
| Platform | Linux |
| Host | safesoc-lnx-01 |
| Primary Telemetry | SSH failed authentication |
| MITRE Tactic | Credential Access |
| MITRE Technique | T1110.001 Password Guessing |
| Mapping Confidence | Medium |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger |

### Objective

Generate a small number of controlled failed SSH authentication events using a fake user.

### Analyst Hypothesis

An account failed SSH authentication on the Linux endpoint, resembling password guessing or login probing behavior.

### Wrong Inference Warning

This is not a real brute-force attack. It is one or two controlled failed login attempts inside the lab.

### Commands Planned

From `safesoc-wazuh-01` or another lab VM:

```bash
ssh fakeuser@10.10.10.31
```

Enter an incorrect password once or twice, then cancel.

### Expected Local Signal

```bash
journalctl -u ssh --since "10 minutes ago" --no-pager
```

or:

```bash
sudo grep -Ei "failed|sshd|invalid" /var/log/auth.log | tail -30
```

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and ssh
```

Alternative:

```text
agent.name: "safesoc-lnx-01" and failed
```

### Cleanup

No cleanup required.

---

## S08: Linux Sudo Authentication Pattern

| Field | Value |
|---|---|
| Scenario ID | S08 |
| Scenario Name | Linux sudo authentication pattern |
| Scenario Type | attack_like |
| Platform | Linux |
| Host | safesoc-lnx-01 |
| Primary Telemetry | sudo/PAM authentication |
| MITRE Tactic | Privilege Escalation |
| MITRE Technique | T1548.003 Sudo and Sudo Caching |
| Mapping Confidence | Medium |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger |

### Objective

Generate safe sudo authentication telemetry.

### Analyst Hypothesis

A user attempted to run privileged commands through sudo.

### Wrong Inference Warning

This does not prove privilege escalation exploitation. It only proves sudo authentication behavior.

### Commands Planned

```bash
sudo -k
sudo whoami
sudo ls /root
```

Optional failed sudo signal:

```bash
sudo -k
sudo whoami
```

Enter one wrong password, then correct it or cancel.

### Expected Local Signal

```bash
journalctl --since "10 minutes ago" | grep -Ei "sudo|pam|authentication" | tail -30
```

or:

```bash
sudo grep -Ei "sudo|pam|authentication" /var/log/auth.log | tail -30
```

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and sudo
```

### Cleanup

No cleanup required.

---

## S09: Linux Discovery Sequence

| Field | Value |
|---|---|
| Scenario ID | S09 |
| Scenario Name | Linux discovery sequence |
| Scenario Type | attack_like |
| Platform | Linux |
| Host | safesoc-lnx-01 |
| Primary Telemetry | Linux command execution, shell history, logs where applicable |
| MITRE Tactic | Discovery |
| MITRE Techniques | T1082, T1033, T1016 |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger/supporting |

### Objective

Generate safe Linux discovery telemetry using built-in commands.

### Analyst Hypothesis

A user performed local system, user, process, and network discovery.

### Wrong Inference Warning

This scenario does not prove compromise. It only simulates discovery-like command behavior.

### Commands Planned

```bash
whoami
id
hostname
uname -a
ip a
ss -tulpn
ps aux | head
df -h
```

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and whoami
```

Alternative:

```text
agent.name: "safesoc-lnx-01" and uname
```

### Cleanup

No cleanup required.

---

## S10: Linux Cron Marker

| Field | Value |
|---|---|
| Scenario ID | S10 |
| Scenario Name | Linux cron marker |
| Scenario Type | attack_like |
| Platform | Linux |
| Host | safesoc-lnx-01 |
| Primary Telemetry | cron creation, marker file creation, syslog/journald |
| MITRE Tactic | Persistence / Execution |
| MITRE Technique | T1053.003 Cron |
| Mapping Confidence | Medium |
| Safety Rating | Medium |
| Ground-Truth Label | attack_like |
| Expected Event Role | trigger |

### Objective

Create and remove a harmless cron marker to simulate scheduled execution behavior.

### Analyst Hypothesis

A scheduled cron entry was created on the Linux endpoint, which can resemble recurring execution or persistence behavior.

### Wrong Inference Warning

This is not malicious persistence. The cron job only writes a harmless marker and is removed during cleanup.

### Commands Planned

```bash
mkdir -p ~/safeagentsoc_phase2/S10
echo '* * * * * echo "SafeAgentSOC S10 cron marker $(date)" >> ~/safeagentsoc_phase2/S10/s10_cron_marker.txt' > /tmp/safeagentsoc_s10_cron
crontab /tmp/safeagentsoc_s10_cron
crontab -l
```

### Expected Local Signal

```bash
crontab -l
ls -la ~/safeagentsoc_phase2/S10
journalctl --since "10 minutes ago" | grep -Ei "cron|CRON" | tail -30
```

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and cron
```

### Cleanup

```bash
crontab -r
rm -f /tmp/safeagentsoc_s10_cron
rm -rf ~/safeagentsoc_phase2/S10
```

---

## S11: Linux Normal Admin Maintenance

| Field | Value |
|---|---|
| Scenario ID | S11 |
| Scenario Name | Linux normal admin maintenance |
| Scenario Type | benign |
| Platform | Linux |
| Host | safesoc-lnx-01 |
| Primary Telemetry | journald/syslog/admin commands |
| MITRE Tactic | N/A |
| MITRE Technique | N/A |
| Mapping Confidence | High |
| Safety Rating | Low |
| Ground-Truth Label | benign |
| Expected Event Role | supporting |

### Objective

Generate known-benign Linux maintenance telemetry.

### Analyst Hypothesis

A user performed normal Linux administration or health checks.

### Wrong Inference Warning

Do not force this scenario into MITRE Discovery only because it uses admin commands. The ground truth is benign maintenance.

### Commands Planned

```bash
whoami
hostname
ip a
systemctl status ssh --no-pager
journalctl --since "10 minutes ago" --no-pager | tail -30
sudo apt update
```

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and systemctl
```

Alternative:

```text
agent.name: "safesoc-lnx-01"
```

### Cleanup

No cleanup required.

---

## S12: Repeated Typo and Noisy Authentication

| Field | Value |
|---|---|
| Scenario ID | S12 |
| Scenario Name | Repeated typo and noisy authentication |
| Scenario Type | ambiguous/noise |
| Platform | Cross-endpoint |
| Host | safesoc-win-01 or safesoc-lnx-01 |
| Primary Telemetry | Failed login/sudo/auth followed by success |
| MITRE Tactic | N/A |
| MITRE Technique | N/A |
| Mapping Confidence | Medium |
| Safety Rating | Low |
| Ground-Truth Label | ambiguous or noise |
| Expected Event Role | noise/trigger |

### Objective

Generate authentication noise that could look suspicious but has a benign explanation.

### Analyst Hypothesis

Repeated authentication failures may indicate password guessing, user error, or noisy benign activity.

### Wrong Inference Warning

Do not automatically classify this as brute force. The scenario ground truth is typo/noise unless the run is explicitly designed as attack_like.

### Linux Command Option

```bash
sudo -k
sudo whoami
```

Enter wrong password once, then correct password.

### Windows Command Option

```powershell
runas /user:safesoc-win-01\fakeuser cmd
```

Enter wrong password once.

### Expected Wazuh Query

```text
agent.name: "safesoc-lnx-01" and failed
```

or:

```text
agent.name: "safesoc-win-01" and data.win.system.eventID: "4625"
```

### Cleanup

No cleanup required.

---

# Scenario Catalog Research Notes

## Why the catalog includes benign and noisy scenarios

A dataset containing only attack-like events would be unrealistic and weak for alert-fatigue research. The dataset must include benign, noisy, repeated, and ambiguous events so future phases can evaluate alert compression, false-positive handling, and case-building quality.

## Why MITRE is not forced onto benign scenarios

Benign scenarios may resemble attacker techniques at the command level, but forcing every benign event into ATT&CK would inflate technique coverage and damage label quality. Benign scenarios should use N/A or "benign mimic" only when justified.

## Why cleanup is required

Scheduled tasks, cron entries, marker files, archives, and temporary folders must be removed after execution to preserve lab integrity and prevent later scenarios from contaminating the dataset.

## Scenario Execution Status

No scenarios have been executed during Sprint 2. This catalog defines the design only.

