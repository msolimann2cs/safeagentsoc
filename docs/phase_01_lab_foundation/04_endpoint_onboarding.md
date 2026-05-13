# Endpoint Onboarding

## Objective

Document how Windows and Linux endpoints are connected to Wazuh.

---

# Windows Endpoint: safesoc-win-01

## VM Details

| Field | Value |
|---|---|
| VM Name | safesoc-win-01 |
| Hostname | safesoc-win-01 |
| OS | Windows 10/11 |
| IP Address | 10.10.10.21 |
| Subnet Mask | 255.255.255.0 |
| Default Gateway | 10.10.10.2 |
| DNS | 8.8.8.8, 1.1.1.1 |
| Role | Endpoint telemetry source |

## Connectivity Validation

| Test | Result |
|---|---|
| Ping NAT gateway 10.10.10.2 | Passed |
| Internet connectivity | Passed |
| DNS resolution | Passed |
| Wazuh dashboard port 443 | Passed |
| Wazuh agent communication port 1514 | Passed |
| Wazuh enrollment port 1515 | Passed |
| Wazuh API port 55000 | Passed |

## Wazuh Agent Installation

| Field | Value |
|---|---|
| Agent Version | 4.14.x |
| Manager IP | 10.10.10.10 |
| Agent Name | safesoc-win-01 |
| Agent Service | WazuhSvc |
| Agent Status | Active |

## Sysmon Installation

| Field | Value |
|---|---|
| Sysmon Installed | Yes |
| Sysmon Service | Sysmon64 |
| Event Channel | Microsoft-Windows-Sysmon/Operational |
| Wazuh Collection Configured | Yes |

## Windows Test Events

| Event Type | How Generated | Visible in Wazuh? | Evidence ID |
|---|---|---|---|
| Process creation | notepad.exe / calc.exe / PowerShell commands | Yes | E-P1-014 |
| Login event | Lock/unlock or sign out/sign in | Yes | E-P1-015 |
| Sysmon event | Sysmon Operational Event ID 1 | Yes | E-P1-016 |

## Windows Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-010 | 2026-05-13_win01_static-ip.png | Windows static IP configured |
| E-P1-011 | 2026-05-13_win01_connectivity-to-wazuh.png | Windows endpoint can reach Wazuh |
| E-P1-012 | 2026-05-13_win01_wazuh-agent-installed.png | Wazuh agent installed and running |
| E-P1-013 | 2026-05-13_win01_agent-active-in-wazuh.png | Agent active in Wazuh dashboard |
| E-P1-014 | 2026-05-13_win01_sysmon-installed.png | Sysmon installed |
| E-P1-015 | 2026-05-13_win01_sysmon-local-process-event.png | Sysmon generated a process event locally |
| E-P1-016 | 2026-05-13_win01_process-event-in-wazuh.png | Wazuh received Windows process/Sysmon event |
| E-P1-017 | 2026-05-13_win01_login-event-in-wazuh.png | Wazuh received Windows login/security event |
