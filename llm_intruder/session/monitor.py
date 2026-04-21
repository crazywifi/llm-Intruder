"""Logout detection monitor.

Evaluates a set of LogoutTrigger rules against runtime evidence collected
from a Playwright page (URL, cookies, response status, response body,
DOM selectors).  Pure-logic layer — takes plain data, returns bool — so it
is fully unit-testable without a browser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from llm_intruder.session.models import LogoutTrigger


@dataclass
class PageSnapshot:
    """Evidence collected from a live Playwright page at a point in time."""
    url: str = ""
    http_status: int | None = None
    response_body: str = ""
    cookie_names: list[str] = field(default_factory=list)
    # dom_selectors_present is populated by the caller after running
    # playwright page.query_selector_all() for each trigger selector
    dom_selectors_present: list[str] = field(default_factory=list)


def _trigger_fired(trigger: LogoutTrigger, snap: PageSnapshot) -> bool:
    """Return True if *trigger* matches the evidence in *snap*."""
    match trigger.type:
        case "http_status":
            if snap.http_status is not None and trigger.codes:
                return snap.http_status in trigger.codes

        case "url_redirect":
            if trigger.patterns:
                for pattern in trigger.patterns:
                    # Support glob-style '*' wildcards
                    regex = re.escape(pattern).replace(r"\*", ".*")
                    if re.search(regex, snap.url, re.IGNORECASE):
                        return True

        case "dom_element":
            if trigger.selectors:
                return bool(
                    set(trigger.selectors) & set(snap.dom_selectors_present)
                )

        case "cookie_missing":
            if trigger.names:
                return any(name not in snap.cookie_names for name in trigger.names)

        case "response_body":
            if trigger.patterns:
                for pattern in trigger.patterns:
                    if pattern in snap.response_body:
                        return True

    return False


def is_logged_out(triggers: list[LogoutTrigger], snap: PageSnapshot) -> bool:
    """Return True if *any* trigger indicates the session has expired."""
    return any(_trigger_fired(t, snap) for t in triggers)


def which_trigger_fired(
    triggers: list[LogoutTrigger], snap: PageSnapshot
) -> LogoutTrigger | None:
    """Return the first trigger that fired, or None."""
    for t in triggers:
        if _trigger_fired(t, snap):
            return t
    return None
