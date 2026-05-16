from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable, Protocol


class DatabaseConnection(Protocol):
    def execute(self, query: str, params: object | None = None) -> object:
        ...

    def commit(self) -> None:
        ...


@dataclass(frozen=True)
class DatabaseConfig:
    dsn: str

    @classmethod
    def from_env(cls) -> "DatabaseConfig":
        dsn = os.environ.get("SAFEAGENTSOC_DATABASE_URL")
        if not dsn:
            dsn = "postgresql://safeagentsoc:safeagentsoc@localhost:5432/safeagentsoc"
        return cls(dsn=dsn)


def connect(config: DatabaseConfig | None = None):
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeError(
            "psycopg is required for PostgreSQL connections. Install psycopg before running database ingestion or API queries."
        ) from exc

    return psycopg.connect((config or DatabaseConfig.from_env()).dsn, row_factory=dict_row)


def read_sql_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def execute_sql_file(connection: DatabaseConnection, path: Path) -> None:
    connection.execute(read_sql_file(path))
    connection.commit()


def execute_sql_files(connection: DatabaseConnection, paths: Iterable[Path]) -> None:
    for path in paths:
        execute_sql_file(connection, path)


def default_schema_files(repo_root: Path) -> list[Path]:
    schema_dir = repo_root / "db" / "schemas"
    return [
        schema_dir / "runtime_schema.sql",
        schema_dir / "eval_schema.sql",
        schema_dir / "indexes.sql",
        schema_dir / "views_runtime.sql",
        schema_dir / "views_eval.sql",
    ]
