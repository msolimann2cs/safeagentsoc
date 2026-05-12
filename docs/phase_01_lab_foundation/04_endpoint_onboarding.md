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
| Role | Endpoint telemetry source |

## Wazuh Agent Installation

| Field | Value |
|---|---|
| Agent Version | TBD |
| Manager IP | 10.10.10.10 |
| Agent Status | Pending |

## Sysmon Installation

| Field | Value |
|---|---|
| Sysmon Installed | Pending |
| Config Used | TBD |
| Event Channel | Microsoft-Windows-Sysmon/Operational |

## Windows Test Events

| Event Type | How Generated | Visible in Wazuh? | Evidence ID |
|---|---|---|---|
| Login event | TBD | TBD | TBD |
| Failed login | TBD | TBD | TBD |
| Process creation | TBD | TBD | TBD |
| PowerShell event | TBD | TBD | TBD |
| Sysmon process event | TBD | TBD | TBD |

## Windows Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-010 | TBD | Windows hostname/IP configured |
| E-P1-011 | TBD | Wazuh agent installed |
| E-P1-012 | TBD | Windows agent active in Wazuh |
| E-P1-013 | TBD | Sysmon installed |
| E-P1-014 | TBD | Windows event visible in Wazuh |

---

# Linux Endpoint: safesoc-lnx-01

## VM Details

| Field | Value |
|---|---|
| VM Name | safesoc-lnx-01 |
| Hostname | safesoc-lnx-01 |
| OS | Ubuntu Server |
| IP Address | 10.10.10.31 |
| Role | Linux telemetry source |

## Wazuh Agent Installation

| Field | Value |
|---|---|
| Agent Version | TBD |
| Manager IP | 10.10.10.10 |
| Agent Status | Pending |

## Linux Test Events

| Event Type | How Generated | Visible in Wazuh? | Evidence ID |
|---|---|---|---|
| Successful SSH login | TBD | TBD | TBD |
| Failed SSH login | TBD | TBD | TBD |
| sudo command | TBD | TBD | TBD |
| Failed sudo attempt | TBD | TBD | TBD |

## Linux Evidence

| Evidence ID | Screenshot | What it proves |
|---|---|---|
| E-P1-020 | TBD | Linux hostname/IP configured |
| E-P1-021 | TBD | Wazuh agent installed |
| E-P1-022 | TBD | Linux agent active in Wazuh |
| E-P1-023 | TBD | SSH/auth event visible |
| E-P1-024 | TBD | sudo event visible |
