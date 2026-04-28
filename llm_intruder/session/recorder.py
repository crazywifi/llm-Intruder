"""Session recorder — opens a visible browser and captures the login flow.

The operator logs in manually while the recorder intercepts network
requests and DOM events.  On close, it writes a session_template.yaml
ready for automated replay.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from llm_intruder.session.models import (
    NavigateAction,
    SessionArtifacts,
    SessionTemplate,
    SessionTemplateData,
)
from llm_intruder.session.store import save_template

log = structlog.get_logger()


class SessionRecorder:
    """
    Opens a headed Chromium window and records operator interactions.

    Usage::

        recorder = SessionRecorder(target_url="https://app.example.com",
                                   output_path="session_template.yaml")
        recorder.record()
    """

    def __init__(self, target_url: str, output_path: str | Path) -> None:
        self.target_url = target_url
        self.output_path = Path(output_path)
        self._recorded_requests: list[dict[str, Any]] = []
        self._print = print
        self._input = input

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_io(self, print_fn=None, input_fn=None) -> None:
        """Override stdout/stdin handlers (e.g. dashboard-bridged IO)."""
        if print_fn is not None:
            self._print = print_fn
        if input_fn is not None:
            self._input = input_fn

    def record(self) -> SessionTemplate:
        """
        Launch a headed browser, navigate to *target_url*, and wait for the
        operator to complete the login flow.  Closes when the operator presses
        Enter in the terminal or closes the browser.

        Returns the saved SessionTemplate.
        """
        from playwright.sync_api import sync_playwright  # deferred import

        log.info("recorder_start", target=self.target_url)
        self._print(
            f"\n[LLM-Intruder] Recording session for: {self.target_url}\n"
            "  1. Complete your login in the browser that just opened.\n"
            "  2. Confirm you can see the main application UI.\n"
            "  3. Press ENTER once login is complete to save the session template.\n"
        )

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False, slow_mo=50)
            context = browser.new_context(
                record_har_path=str(self.output_path.with_suffix(".har")),
            )
            page = context.new_page()

            # Intercept responses to capture auth signals
            page.on("response", self._on_response)

            # Use domcontentloaded instead of networkidle — SPAs with
            # WebSockets (Meraki, Salesforce, Slack, …) never go idle and
            # would hang at goto forever.
            try:
                page.goto(self.target_url, wait_until="domcontentloaded", timeout=45_000)
            except Exception as _nav_err:
                self._print(f"[LLM-Intruder] WARN: initial navigation slow: {_nav_err}")
                self._print("[LLM-Intruder] Continuing — the page may still be loading.")

            # Block until operator signals done
            try:
                self._input(
                    "Press ENTER once your login is complete and you can see the main app UI."
                )
            except EOFError:
                pass  # non-interactive env

            template = self._build_template(page, context)

            # CRITICAL: save a Playwright storage_state.json alongside the
            # YAML. This is the actual cookie + localStorage + sessionStorage
            # payload the Intruder needs to skip re-login. The YAML alone only
            # contains cookie NAMES (no values) so it can't restore auth.
            storage_state_path = self.output_path.with_name("storage_state.json")
            try:
                context.storage_state(path=str(storage_state_path))
                log.info("recorder_storage_state_saved", path=str(storage_state_path))
                self._print(f"[LLM-Intruder] Auth state saved → {storage_state_path}")
            except Exception as _ss_err:
                log.warning("recorder_storage_state_failed", error=str(_ss_err))
                self._print(f"[LLM-Intruder] WARNING: Failed to save storage_state: {_ss_err}")

            context.close()
            browser.close()

        save_template(template, self.output_path)
        log.info("recorder_saved", path=str(self.output_path))
        self._print(f"\n[LLM-Intruder] Session template saved → {self.output_path}\n")
        return template

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _on_response(self, response: Any) -> None:
        try:
            self._recorded_requests.append(
                {"url": response.url, "status": response.status}
            )
        except Exception:
            pass

    def _build_template(self, page: Any, context: Any) -> SessionTemplate:
        """Build a SessionTemplate from the current page/context state."""
        cookies_raw = context.cookies()
        cookie_artifacts = [
            {"name": c["name"], "domain": c.get("domain", "")}
            for c in cookies_raw
        ]

        data = SessionTemplateData(
            name=f"recorded_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}",
            recorded_at=datetime.now(UTC),
            target_url=self.target_url,
            actions=[
                NavigateAction(type="navigate", url=self.target_url),
            ],
            session_artifacts=SessionArtifacts.model_validate(
                {"cookies": cookie_artifacts, "local_storage": []}
            ),
        )
        return SessionTemplate(session_template=data)
