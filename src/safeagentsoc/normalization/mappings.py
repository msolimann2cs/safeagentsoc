from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import get_nested


def as_string(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, list):
        return "|".join(str(item) for item in value)
    return str(value)


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def first_nested(raw: dict[str, Any], paths: list[str]) -> Any:
    for path in paths:
        value = get_nested(raw, path)
        if value not in (None, ""):
            return value
    return None


def basename_from_path(path: str | None) -> str | None:
    if not path:
        return None
    normalized = path.replace("\\", "/").rstrip("/")
    if not normalized:
        return None
    return normalized.split("/")[-1] or None


def extension_from_path(path: str | None) -> str | None:
    name = basename_from_path(path)
    if not name or "." not in name:
        return None
    return name.rsplit(".", 1)[-1].lower()


def split_windows_user(value: str | None) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    if "\\" in value:
        domain, username = value.split("\\", 1)
        return username or None, domain or None
    return value, None


def infer_platform(raw: dict[str, Any]) -> str:
    decoder = (as_string(get_nested(raw, "decoder.name")) or "").lower()
    location = (as_string(get_nested(raw, "location")) or "").lower()
    agent_name = (as_string(get_nested(raw, "agent.name")) or "").lower()

    if get_nested(raw, "data.win") is not None or "windows" in decoder or "eventchannel" in decoder or "eventchannel" in location or "win" in agent_name:
        return "windows"
    if any(token in decoder for token in ["pam", "sudo", "auditd", "sshd", "dpkg", "kernel", "systemd"]) or any(token in agent_name for token in ["lnx", "linux", "ubuntu"]):
        return "linux"
    if get_nested(raw, "data.audit") is not None or get_nested(raw, "data.sca") is not None or get_nested(raw, "data.vulnerability") is not None:
        return "linux"
    return "unknown"


def extract_user(raw: dict[str, Any]) -> dict[str, str | None]:
    raw_user = as_string(
        first_nested(
            raw,
            [
                "data.win.eventdata.targetUserName",
                "data.win.eventdata.subjectUserName",
                "data.win.eventdata.user",
                "data.dstuser",
                "data.srcuser",
            ],
        )
    )
    username, parsed_domain = split_windows_user(raw_user)
    domain = as_string(
        first_nested(
            raw,
            [
                "data.win.eventdata.targetDomainName",
                "data.win.eventdata.subjectDomainName",
            ],
        )
    ) or parsed_domain
    user_id = as_string(
        first_nested(
            raw,
            [
                "data.win.eventdata.targetUserSid",
                "data.win.eventdata.subjectUserSid",
                "data.uid",
            ],
        )
    )
    privilege_hint = as_string(first_nested(raw, ["data.win.eventdata.integrityLevel", "data.euid", "data.auid"]))

    return {
        "username": username,
        "domain": domain,
        "user_id": user_id,
        "privilege_hint": privilege_hint,
    }


def extract_process(raw: dict[str, Any]) -> dict[str, str | int | None]:
    process_path = as_string(first_nested(raw, ["data.win.eventdata.image", "data.win.eventdata.processName"]))
    command_line = as_string(first_nested(raw, ["data.win.eventdata.commandLine", "data.command", "data.audit.command", "data.sca.check.command"]))
    parent_path = as_string(first_nested(raw, ["data.win.eventdata.parentImage"]))
    process_name = basename_from_path(process_path) or basename_from_path(command_line)
    parent_name = basename_from_path(parent_path)

    return {
        "name": process_name,
        "path": process_path,
        "command_line": command_line,
        "pid": as_int(first_nested(raw, ["data.win.eventdata.processId"])),
        "parent_name": parent_name,
        "parent_path": parent_path,
        "parent_pid": as_int(first_nested(raw, ["data.win.eventdata.parentProcessId"])),
    }


def extract_network(raw: dict[str, Any]) -> dict[str, str | int | None]:
    return {
        "src_ip": as_string(first_nested(raw, ["data.srcip", "data.win.eventdata.ipAddress"])),
        "src_port": as_int(first_nested(raw, ["data.srcport", "data.win.eventdata.ipPort"])),
        "dst_ip": as_string(first_nested(raw, ["data.dstip"])),
        "dst_port": as_int(first_nested(raw, ["data.dstport"])),
        "protocol": as_string(first_nested(raw, ["data.protocol"])),
    }


def extract_file(raw: dict[str, Any]) -> dict[str, str | None]:
    file_path = as_string(first_nested(raw, ["syscheck.path", "data.audit.file.name", "data.sca.check.file"]))
    file_name = basename_from_path(file_path)

    if file_name is None:
        package_name = as_string(get_nested(raw, "data.vulnerability.package.name"))
        file_name = package_name

    hash_sha256 = as_string(first_nested(raw, ["syscheck.sha256_after", "syscheck.sha256_before", "data.hash.sha256"]))

    return {
        "path": file_path,
        "name": file_name,
        "extension": extension_from_path(file_path),
        "hash_sha256": hash_sha256,
    }
