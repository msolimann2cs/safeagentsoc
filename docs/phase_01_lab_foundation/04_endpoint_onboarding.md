# Endpoint Onboarding

## Objective

Document how Windows and Linux endpoints are connected to Wazuh.

---

# Windows Endpoint: safesoc-win-01

## VM Details

| Field | Value |
|---|---|
| Hostname | safesoc-win-01 |
| IP Address | 10.10.10.21 |
| Gateway | 10.10.10.2 |
| Wazuh Manager | 10.10.10.10 |
| Wazuh Agent | Installed and active |
| Sysmon | Installed |
| Sysmon Channel | Microsoft-Windows-Sysmon/Operational |
| Status | Complete |

## Windows Test Events

| Event Type | How Generated | Visible in Wazuh? | Evidence ID |
|---|---|---|---|
| Process creation | notepad.exe / calc.exe / PowerShell commands | Yes | E-P1-015 |
| Login event | Lock/unlock or sign out/sign in | Yes | E-P1-016 |
| Sysmon event | Sysmon Operational Event ID 1 | Yes | E-P1-015 |

## Windows Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-010 | 2026-05-13_win01_static-ip.png | Windows static IP configured |
| E-P1-011 | 2026-05-13_win01_connectivity-to-wazuh.png | Windows endpoint can reach Wazuh |
| E-P1-012 | 2026-05-13_win01_wazuh-agent-installed.png | Wazuh agent installed and running |
| E-P1-013 | 2026-05-13_win01_agent-active-in-wazuh.png | Agent active in Wazuh dashboard |
| E-P1-014 | 2026-05-13_win01_sysmon-installed.png | Sysmon installed |
| E-P1-015 | 2026-05-13_win01_process-event-in-wazuh.png | Wazuh received Windows process/Sysmon event |
| E-P1-016 | 2026-05-13_win01_login-event-in-wazuh.png | Wazuh received Windows login/security event |

---

# Linux Endpoint: safesoc-lnx-01

## VM Details

| Field | Value |
|---|---|
| Hostname | safesoc-lnx-01 |
| IP Address | 10.10.10.31 |
| Gateway | 10.10.10.2 |
| Wazuh Manager | 10.10.10.10 |
| Wazuh Agent | Installed and active |
| SSH/Auth/Sudo Logs | Generated and verified |
| Status | Complete |

## Linux Test Events

| Event Type | How Generated | Visible in Wazuh? | Evidence ID |
|---|---|---|---|
| SSH failed login | ssh fakeuser@10.10.10.31 | Yes | E-P1-024 |
| SSH successful login | ssh safesoc@10.10.10.31 | Yes | E-P1-025 |
| sudo event | sudo whoami / sudo ls /root | Yes | E-P1-026 |

## Linux Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-020 | 2026-05-13_lnx01_hostname-ip.png | Linux hostname/IP configured |
| E-P1-021 | 2026-05-13_lnx01_connectivity-to-wazuh.png | Linux endpoint can reach Wazuh |
| E-P1-022 | 2026-05-13_lnx01_wazuh-agent-installed.png | Wazuh agent installed and running |
| E-P1-023 | 2026-05-13_lnx01_agent-active-in-wazuh.png | Linux agent active in Wazuh |
| E-P1-024 | 2026-05-13_lnx01_ssh-event-in-wazuh.png | SSH event visible in Wazuh |
| E-P1-025 | 2026-05-13_lnx01_sudo-event-in-wazuh.png | sudo event visible in Wazuh |

