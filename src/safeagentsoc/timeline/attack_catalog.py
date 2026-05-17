from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TechniqueInfo:
    technique_id: str
    name: str
    tactics: tuple[str, ...]


TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


LOCAL_ATTACK_CATALOG: dict[str, TechniqueInfo] = {
    "T1003": TechniqueInfo("T1003", "OS Credential Dumping", ("Credential Access",)),
    "T1016": TechniqueInfo("T1016", "System Network Configuration Discovery", ("Discovery",)),
    "T1021": TechniqueInfo("T1021", "Remote Services", ("Lateral Movement",)),
    "T1021.004": TechniqueInfo("T1021.004", "Remote Services: SSH", ("Lateral Movement",)),
    "T1033": TechniqueInfo("T1033", "System Owner/User Discovery", ("Discovery",)),
    "T1041": TechniqueInfo("T1041", "Exfiltration Over C2 Channel", ("Exfiltration",)),
    "T1049": TechniqueInfo("T1049", "System Network Connections Discovery", ("Discovery",)),
    "T1027": TechniqueInfo("T1027", "Obfuscated Files or Information", ("Defense Evasion",)),
    "T1053": TechniqueInfo("T1053", "Scheduled Task/Job", ("Execution", "Persistence", "Privilege Escalation")),
    "T1053.003": TechniqueInfo("T1053.003", "Scheduled Task/Job: Cron", ("Execution", "Persistence")),
    "T1053.005": TechniqueInfo("T1053.005", "Scheduled Task/Job: Scheduled Task", ("Execution", "Persistence")),
    "T1059": TechniqueInfo("T1059", "Command and Scripting Interpreter", ("Execution",)),
    "T1059.001": TechniqueInfo("T1059.001", "Command and Scripting Interpreter: PowerShell", ("Execution",)),
    "T1059.003": TechniqueInfo("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", ("Execution",)),
    "T1059.004": TechniqueInfo("T1059.004", "Command and Scripting Interpreter: Unix Shell", ("Execution",)),
    "T1057": TechniqueInfo("T1057", "Process Discovery", ("Discovery",)),
    "T1055": TechniqueInfo("T1055", "Process Injection", ("Defense Evasion", "Privilege Escalation")),
    "T1070.002": TechniqueInfo("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs", ("Defense Evasion",)),
    "T1070.004": TechniqueInfo("T1070.004", "Indicator Removal: File Deletion", ("Defense Evasion",)),
    "T1078": TechniqueInfo("T1078", "Valid Accounts", ("Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion")),
    "T1082": TechniqueInfo("T1082", "System Information Discovery", ("Discovery",)),
    "T1087": TechniqueInfo("T1087", "Account Discovery", ("Discovery",)),
    "T1105": TechniqueInfo("T1105", "Ingress Tool Transfer", ("Command and Control",)),
    "T1110.001": TechniqueInfo("T1110.001", "Brute Force: Password Guessing", ("Credential Access",)),
    "T1112": TechniqueInfo("T1112", "Modify Registry", ("Defense Evasion",)),
    "T1135": TechniqueInfo("T1135", "Network Share Discovery", ("Discovery",)),
    "T1136": TechniqueInfo("T1136", "Create Account", ("Persistence",)),
    "T1204": TechniqueInfo("T1204", "User Execution", ("Execution",)),
    "T1486": TechniqueInfo("T1486", "Data Encrypted for Impact", ("Impact",)),
    "T1490": TechniqueInfo("T1490", "Inhibit System Recovery", ("Impact",)),
    "T1484": TechniqueInfo("T1484", "Domain or Tenant Policy Modification", ("Defense Evasion", "Privilege Escalation")),
    "T1485": TechniqueInfo("T1485", "Data Destruction", ("Impact",)),
    "T1531": TechniqueInfo("T1531", "Account Access Removal", ("Impact",)),
    "T1543.003": TechniqueInfo("T1543.003", "Create or Modify System Process: Windows Service", ("Persistence", "Privilege Escalation")),
    "T1546.011": TechniqueInfo("T1546.011", "Event Triggered Execution: Application Shimming", ("Persistence", "Privilege Escalation")),
    "T1548.003": TechniqueInfo("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ("Privilege Escalation", "Defense Evasion")),
    "T1562.001": TechniqueInfo("T1562.001", "Impair Defenses: Disable or Modify Tools", ("Defense Evasion",)),
    "T1565.001": TechniqueInfo("T1565.001", "Data Manipulation: Stored Data Manipulation", ("Impact",)),
    "T1574.001": TechniqueInfo("T1574.001", "Hijack Execution Flow: DLL Search Order Hijacking", ("Persistence", "Privilege Escalation", "Defense Evasion")),
}


BEHAVIOR_FAMILY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "windows_powershell_activity": ("T1059.001",),
    "windows_suspicious_execution": ("T1059.003",),
    "windows_persistence_or_privilege": ("T1546.011",),
    "windows_defender_pua": ("T1204",),
    "linux_privilege_activity": ("T1548.003",),
    "linux_authentication": ("T1110.001",),
    "linux_integrity_monitoring": ("T1565.001",),
}


def technique_info(technique_id: str) -> TechniqueInfo:
    return LOCAL_ATTACK_CATALOG.get(
        technique_id,
        TechniqueInfo(technique_id=technique_id, name=f"ATT&CK technique {technique_id}", tactics=("unknown",)),
    )


def tactic_slug(tactic: str | None) -> str:
    if not tactic:
        return "unknown"
    return tactic.strip().lower().replace(" ", "-")


def tactic_sort_key(tactic: str | None) -> int:
    if tactic in TACTIC_ORDER:
        return TACTIC_ORDER.index(str(tactic))
    return len(TACTIC_ORDER) + 1
