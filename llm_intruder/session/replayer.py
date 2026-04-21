"""Session replayer — drives a Playwright page through recorded actions.

Designed for testability: all browser interactions go through the injected
``page`` object, so tests can pass a Mock in its place.
"""
from __future__ import annotations

import re
import time
from typing import Any

import structlog

from llm_intruder.session.models import (
    ClickAction,
    ConditionalAction,
    FillAction,
    NavigateAction,
    PauseAction,
    ReplaySettings,
    SessionAction,
    SessionTemplateData,
    SuccessCheck,
    WaitForSelectorAction,
)
from llm_intruder.session.monitor import PageSnapshot, is_logged_out

log = structlog.get_logger()


class ReplayError(Exception):
    """Raised when the replayer cannot complete the login flow."""


def _resolve_variables(value: str, variables: dict[str, str]) -> str:
    """Replace ``${KEY}`` placeholders with values from *variables*."""
    def _sub(m: re.Match[str]) -> str:
        key = m.group(1)
        return variables.get(key, m.group(0))  # leave unchanged if missing

    return re.sub(r"\$\{(\w+)\}", _sub, value)


def _execute_action(
    page: Any,
    action: SessionAction,
    variables: dict[str, str],
    slow_mo_ms: int,
) -> None:
    """Execute a single recorded action against *page*."""
    if slow_mo_ms:
        time.sleep(slow_mo_ms / 1000)

    if isinstance(action, NavigateAction):
        log.debug("replay_navigate", url=action.url)
        page.goto(action.url, wait_until=action.wait_for)

    elif isinstance(action, FillAction):
        value = _resolve_variables(action.value, variables)
        log.debug("replay_fill", selector=action.selector)
        page.fill(action.selector, value)

    elif isinstance(action, ClickAction):
        log.debug("replay_click", selector=action.selector)
        if action.wait_for == "navigation":
            with page.expect_navigation():
                page.click(action.selector)
        else:
            page.click(action.selector)
            if action.wait_for:
                page.wait_for_load_state(action.wait_for)

    elif isinstance(action, WaitForSelectorAction):
        log.debug("replay_wait_selector", selector=action.selector)
        page.wait_for_selector(action.selector, timeout=action.timeout)

    elif isinstance(action, PauseAction):
        log.info("replay_pause", message=action.message)
        # In automated replay: wait for the resume selector to appear
        page.wait_for_selector(action.resume_on_selector, timeout=action.timeout)

    elif isinstance(action, ConditionalAction):
        element = page.query_selector(action.if_selector)
        if element is not None:
            log.debug("conditional_branch_taken", if_selector=action.if_selector)
            for sub_action in action.then:
                _execute_action(page, sub_action, variables, slow_mo_ms)
        else:
            log.debug("conditional_branch_skipped", if_selector=action.if_selector)


def _validate_success(page: Any, checks: list[SuccessCheck]) -> bool:
    """Return True if all success checks pass."""
    for check in checks:
        if check.type == "url_not_contains":
            for pattern in (check.patterns or []):
                if pattern in page.url:
                    log.warning("success_check_failed", type=check.type, pattern=pattern)
                    return False

        elif check.type == "cookie_exists":
            cookies = {c["name"] for c in page.context.cookies()}
            for name in (check.names or []):
                if name not in cookies:
                    log.warning("success_check_failed", type=check.type, name=name)
                    return False

        elif check.type == "dom_element_exists":
            if check.selector and not page.query_selector(check.selector):
                log.warning("success_check_failed", type=check.type, selector=check.selector)
                return False

    return True


class SessionReplayer:
    """Replay a recorded login flow against a live Playwright page."""

    def __init__(
        self,
        template: SessionTemplateData,
        variables: dict[str, str] | None = None,
    ) -> None:
        self.template = template
        self.variables: dict[str, str] = variables or {}
        self.settings: ReplaySettings = template.replay_settings

    def replay(self, page: Any) -> bool:
        """
        Execute the full recorded action sequence against *page*.

        Returns True on success, False when success validation fails.
        Raises ReplayError after all retries are exhausted.
        """
        last_exc: Exception | None = None

        for attempt in range(1, self.settings.max_retries + 1):
            try:
                log.info(
                    "replay_attempt",
                    attempt=attempt,
                    max=self.settings.max_retries,
                    target=self.template.target_url,
                )
                for action in self.template.actions:
                    _execute_action(
                        page, action, self.variables, self.settings.slow_mo_ms
                    )

                ok = _validate_success(page, self.template.success_validation)
                if ok:
                    log.info("replay_success", attempt=attempt)
                    return True

                log.warning("replay_validation_failed", attempt=attempt)

            except Exception as exc:
                last_exc = exc
                log.warning("replay_error", attempt=attempt, error=str(exc))

            if attempt < self.settings.max_retries:
                time.sleep(self.settings.retry_delay_seconds)

        raise ReplayError(
            f"Session replay failed after {self.settings.max_retries} attempts. "
            f"Last error: {last_exc}"
        )
