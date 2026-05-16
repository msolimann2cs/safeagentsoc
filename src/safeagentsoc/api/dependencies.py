from __future__ import annotations

import os
from typing import Any, Iterator

from safeagentsoc.storage.db import connect


def get_db() -> Iterator[Any]:
    connection = connect()
    try:
        yield connection
    finally:
        connection.close()


def eval_api_enabled() -> bool:
    return os.environ.get("SAFEAGENTSOC_ENABLE_EVAL_API", "").lower() in {"1", "true", "yes"}


def eval_api_token() -> str | None:
    return os.environ.get("SAFEAGENTSOC_EVAL_API_TOKEN")
