"""Variable substitution and JSON path extraction for the API driver.

Template syntax
---------------
Both the ``request_template`` body and individual header values may contain
``${VARIABLE_NAME}`` placeholders.  The special variable ``${PAYLOAD}`` is
always the test string being delivered.

JSON path extraction
--------------------
Supports the subset of JSONPath used by the spec::

    $.choices[0].message.content
    $.choices[0].delta.content

Implemented with a small recursive descent parser — no third-party lib.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

_log = logging.getLogger(__name__)


# ── Variable substitution ─────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r"\$\{(\w+)\}")


def resolve_variables(template: str, variables: dict[str, str]) -> str:
    """Replace every ``${KEY}`` in *template* with ``variables[KEY]``.

    Unknown keys are left as-is so the caller can detect them.

    Security note: ``re.sub`` is single-pass — replacement text is never
    re-scanned.  A payload containing ``${API_KEY}`` cannot cause the variable
    table to be expanded a second time; the literal string is inserted as-is.
    """
    def _sub(m: re.Match[str]) -> str:
        return variables.get(m.group(1), m.group(0))

    return _PLACEHOLDER.sub(_sub, template)


def build_request_body(
    template: str,
    payload: str,
    variables: dict[str, str] | None = None,
) -> str:
    """Return the request body with ``${PAYLOAD}`` and all other vars filled in.

    When the template looks like a JSON object (starts with ``{`` after stripping),
    the payload is JSON-escaped before substitution so that newlines, quotes, and
    other control characters in the payload do not produce invalid JSON (which
    causes the target API to return 400 Bad Request).
    """
    stripped = template.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        # JSON template: escape the payload value so it is safe inside a JSON string
        safe_payload = json.dumps(payload)[1:-1]  # encode then strip surrounding quotes
    else:
        safe_payload = payload
    all_vars = {**(variables or {}), "PAYLOAD": safe_payload}
    return resolve_variables(template, all_vars)


def build_headers(
    headers: dict[str, str],
    variables: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return a new header dict with all ``${VAR}`` placeholders resolved."""
    vars_ = variables or {}
    return {k: resolve_variables(v, vars_) for k, v in headers.items()}


# ── JSON path extraction ───────────────────────────────────────────────────────

_PATH_PART = re.compile(r"([^\.\[]+)|\[(\d+)\]")


def extract_json_path(data: Any, path: str) -> str:
    """Extract a value from *data* using a simple JSONPath expression.

    Handles patterns like ``$.choices[0].delta.content``.
    Returns an empty string on any error rather than raising.
    """
    # strip leading "$." or "$"
    path = path.lstrip("$").lstrip(".")
    if not path:
        return str(data) if data is not None else ""

    current: Any = data
    for m in _PATH_PART.finditer(path):
        key_part, idx_part = m.group(1), m.group(2)
        try:
            if idx_part is not None:
                current = current[int(idx_part)]
            else:
                current = current[key_part]
        except (KeyError, IndexError, TypeError) as exc:
            _log.debug(
                "json_path_extraction_failed: path=%s, segment=%s, error=%s",
                path, m.group(0), exc,
            )
            return ""

    return str(current) if current is not None else ""


# ── SSE / ndjson chunk parsing ─────────────────────────────────────────────────

def parse_sse_chunk(line: str, delimiter: str, stream_path: str) -> str:
    """Extract text content from one SSE data line.

    Returns an empty string for heartbeats, ``[DONE]`` signals, or parse errors.
    """
    line = line.strip()
    if not line.startswith(delimiter):
        return ""
    json_part = line[len(delimiter):].strip()
    if json_part in ("[DONE]", ""):
        return ""
    try:
        data = json.loads(json_part)
        return extract_json_path(data, stream_path)
    except json.JSONDecodeError:
        return ""


def parse_ndjson_chunk(line: str, stream_path: str) -> str:
    """Extract text content from one newline-delimited JSON line."""
    line = line.strip()
    if not line:
        return ""
    try:
        data = json.loads(line)
        return extract_json_path(data, stream_path)
    except json.JSONDecodeError:
        return ""
