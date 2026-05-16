from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterator


JsonObject = dict[str, Any]


@dataclass(frozen=True)
class ParsedWazuhAlert:
    raw: JsonObject
    raw_line: str
    line_number: int


@dataclass(frozen=True)
class InvalidJsonLine:
    line_number: int
    error: str
    raw_line: str


@dataclass(frozen=True)
class ParseResult:
    alerts: list[ParsedWazuhAlert]
    invalid_lines: list[InvalidJsonLine]
    blank_lines: int
    total_lines: int

    @property
    def parsed_count(self) -> int:
        return len(self.alerts)

    @property
    def invalid_count(self) -> int:
        return len(self.invalid_lines)


def iter_wazuh_jsonl(path: Path) -> Iterator[ParsedWazuhAlert]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue

            parsed = json.loads(stripped)
            if not isinstance(parsed, dict):
                raise ValueError(f"Line {line_number} is JSON but not an object.")

            yield ParsedWazuhAlert(
                raw=parsed,
                raw_line=stripped,
                line_number=line_number,
            )


def parse_wazuh_jsonl(path: Path) -> ParseResult:
    alerts: list[ParsedWazuhAlert] = []
    invalid_lines: list[InvalidJsonLine] = []
    blank_lines = 0
    total_lines = 0

    with path.open("r", encoding="utf-8") as file:
        for line_number, raw_line in enumerate(file, start=1):
            total_lines = line_number
            stripped = raw_line.strip()

            if not stripped:
                blank_lines += 1
                continue

            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                invalid_lines.append(
                    InvalidJsonLine(
                        line_number=line_number,
                        error=str(exc),
                        raw_line=stripped[:500],
                    )
                )
                continue

            if not isinstance(parsed, dict):
                invalid_lines.append(
                    InvalidJsonLine(
                        line_number=line_number,
                        error="JSON value is not an object",
                        raw_line=stripped[:500],
                    )
                )
                continue

            alerts.append(
                ParsedWazuhAlert(
                    raw=parsed,
                    raw_line=stripped,
                    line_number=line_number,
                )
            )

    return ParseResult(
        alerts=alerts,
        invalid_lines=invalid_lines,
        blank_lines=blank_lines,
        total_lines=total_lines,
    )


def flatten_json(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}

    if isinstance(value, dict):
        for key, child in value.items():
            child_key = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(flatten_json(child, child_key))
        return flattened

    if isinstance(value, list):
        flattened[prefix] = value
        for index, item in enumerate(value):
            item_key = f"{prefix}[]"
            if isinstance(item, dict):
                flattened.update(flatten_json(item, item_key))
            else:
                flattened[item_key] = item
        return flattened

    flattened[prefix] = value
    return flattened


def get_nested(data: JsonObject, path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
