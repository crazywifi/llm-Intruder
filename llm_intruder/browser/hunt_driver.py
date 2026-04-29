"""BrowserHuntDriver — wraps BrowserDriver + Playwright lifecycle for Hunt Mode.

Problem
-------
BrowserDriver.send_payload(page, payload) requires a Playwright *page* object.
HuntRunner (and ConversationSession) call driver.send_payload(payload) with only
one argument — the same interface as ApiDriver.

Solution
--------
BrowserHuntDriver keeps a persistent Playwright browser session open for the
entire duration of the hunt, then delegates every send_payload(payload) call to
the underlying BrowserDriver by passing its own managed page.

This means:
  - Browser launches ONCE at hunt start (not once per trial)
  - Every trial reuses the same browser tab / page
  - HuntRunner, ConversationSession, PAIR loop all work unchanged
  - Multi-turn conversations work correctly — each turn is a real separate
    message sent in the same browser session (conversation history kept by
    the target app's own session cookie)

Usage
-----
    with BrowserHuntDriver(adapter=site_cfg, headless=True) as driver:
        runner = HuntRunner(config=hunt_config, driver=driver, ...)
        runner.run()
"""
from __future__ import annotations

import structlog

from llm_intruder.browser.driver import BrowserDriver
from llm_intruder.browser.models import CapturedResponse, SiteAdapterConfig

log = structlog.get_logger()


class BrowserHuntDriver:
    """
    Persistent-browser wrapper that presents the same interface as ApiDriver.

    Parameters
    ----------
    adapter:
        Loaded :class:`~llm_intruder.browser.models.SiteAdapterConfig`.
    variables:
        ``${VAR}`` substitution table.
    headless:
        Launch browser headless (True) or show the window (False).
        Headless is faster; non-headless is useful for debugging.
    """

    def __init__(
        self,
        adapter: SiteAdapterConfig,
        variables: dict[str, str] | None = None,
        headless: bool = True,
    ) -> None:
        self._adapter   = adapter
        self._variables = variables or {}
        self._headless  = headless
        self._driver    = BrowserDriver(adapter=adapter, variables=variables)

        # Playwright handles — set when start() is called
        self._pw_ctx  = None
        self._browser = None
        self._context = None
        self._page    = None

        log.info(
            "browser_hunt_driver_init",
            url=adapter.target_url,
            headless=headless,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch Playwright, open browser, and navigate to the target URL.

        Called automatically when used as a context manager.
        """
        from playwright.sync_api import sync_playwright

        log.info("browser_hunt_driver_start", url=self._adapter.target_url)
        # Use .start() — sync_playwright() returns a context manager whose
        # __enter__ yields a Playwright instance that does NOT have __exit__.
        # Playwright exposes .start()/.stop() for non-CM usage.
        self._pw_ctx  = sync_playwright().start()
        self._browser = self._pw_ctx.chromium.launch(headless=self._headless)
        context_kwargs: dict = {}
        proxy_url = getattr(self._adapter, 'proxy_url', None)
        if proxy_url:
            context_kwargs["proxy"] = {"server": proxy_url}
            log.info("browser_hunt_driver_proxy", proxy=proxy_url)
        self._context = self._browser.new_context(**context_kwargs)
        self._page    = self._context.new_page()

        # Navigate to target and wait for chat UI to be ready
        self._driver.wait_and_navigate(self._page)
        log.info("browser_hunt_driver_ready", url=self._adapter.target_url)

    def stop(self) -> None:
        """Close browser and clean up Playwright resources."""
        log.info("browser_hunt_driver_stop")
        try:
            if self._browser:
                self._browser.close()
        except Exception as exc:
            log.warning("browser_hunt_driver_close_error", error=str(exc))
        try:
            if self._pw_ctx:
                self._pw_ctx.stop()
        except Exception as exc:
            log.warning("browser_hunt_driver_playwright_exit_error", error=str(exc))
        self._browser = None
        self._context = None
        self._page    = None

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "BrowserHuntDriver":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    # ── Public API (same interface as ApiDriver) ──────────────────────────────

    def send_payload(self, payload: str) -> CapturedResponse:
        """
        Send *payload* through the browser and return a :class:`CapturedResponse`.

        This is the only method HuntRunner and ConversationSession call.
        Signature is identical to ``ApiDriver.send_payload(payload)``.

        For multi-turn hunts: each call is a real separate message in the same
        browser tab, so the target app's conversation history is preserved
        naturally via its own session cookie — no manual context-building needed
        for apps that maintain server-side conversation state.

        Parameters
        ----------
        payload:
            The attack payload text to type into the chat input.

        Returns
        -------
        CapturedResponse
            Contains response text, hashes, and capture metadata.

        Raises
        ------
        RuntimeError
            If called before :meth:`start` (i.e. browser not initialised).
        """
        if self._page is None:
            raise RuntimeError(
                "BrowserHuntDriver is not started. "
                "Use 'with BrowserHuntDriver(...) as driver:' or call driver.start() first."
            )

        log.info(
            "browser_hunt_driver_send",
            chars=len(payload),
            url=self._adapter.target_url,
        )
        return self._driver.send_payload(self._page, payload)

    # ── Convenience helpers ───────────────────────────────────────────────────

    def reload_page(self) -> None:
        """
        Reload the target page — useful when the app's conversation gets stuck
        or you want to reset server-side session state between trials.
        """
        if self._page:
            log.info("browser_hunt_driver_reload")
            self._page.reload(wait_until="domcontentloaded")
            self._driver._wait_for_ready(self._page)

    @property
    def target_url(self) -> str:
        """The target URL this driver is pointed at."""
        return self._adapter.target_url

    @property
    def is_running(self) -> bool:
        """True if the browser is currently open and ready."""
        return self._page is not None
