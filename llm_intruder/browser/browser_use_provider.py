"""Optional integration with `browser-use` — AI browser agent for complex UIs.

browser-use (https://github.com/browser-use/browser-use, 33k+ stars) is an
open-source library that uses LLM + Playwright to auto-navigate any website.
It can handle:
  - Shadow DOM elements
  - Multi-step interactions (click launcher → wait → type → send)
  - CAPTCHAs (with vision models)
  - Dynamic sites that break CSS selectors

Install:
    pip install browser-use

Usage in LLM-Intruder:
    redteam browser-test --url https://www.pvrcinemas.com/ --llm-provider browser-use --llm-api-key sk-...

How it works:
  1. browser-use opens a real Chrome browser
  2. LLM (GPT-4o / Claude / Ollama) analyses the page screenshot + DOM
  3. LLM decides which elements to click/type (auto-navigates to chat input)
  4. We capture the detected selectors from browser-use's action log
  5. Those selectors feed into our normal BrowserDriver replay loop

This module wraps browser-use as a "detection provider" — it replaces the
heuristic/LLM element detection step but uses the same replay infrastructure.

NOTE: browser-use is OPTIONAL. If not installed, this module gracefully
degrades and suggests `pip install browser-use`.
"""
from __future__ import annotations

import structlog

log = structlog.get_logger()


def check_browser_use_available() -> bool:
    """Check if browser-use is installed."""
    try:
        import browser_use  # noqa: F401
        return True
    except ImportError:
        return False


def detect_with_browser_use(
    target_url: str,
    task_description: str = "Find the chat input field and send button on this page",
    llm_api_key: str | None = None,
    llm_model: str | None = None,
    llm_base_url: str | None = None,
) -> dict:
    """Use browser-use AI agent to detect chat UI elements.

    Parameters
    ----------
    target_url : URL to navigate to
    task_description : What to tell the LLM agent to do
    llm_api_key : API key for the LLM (OpenAI/Anthropic)
    llm_model : Model name (e.g., "gpt-4o", "claude-sonnet-4-20250514")
    llm_base_url : Base URL for local LLMs

    Returns
    -------
    dict with keys: input_selector, submit_selector, submit_method, confidence
    """
    try:
        from browser_use import Agent
        from langchain_openai import ChatOpenAI
    except ImportError:
        raise ImportError(
            "browser-use is not installed.\n"
            "Install it with: pip install browser-use langchain-openai\n"
            "See: https://github.com/browser-use/browser-use"
        )

    import asyncio

    model = llm_model or "gpt-4o"
    api_key = llm_api_key or ""

    # Configure the LLM
    llm_kwargs = {"model": model, "api_key": api_key}
    if llm_base_url:
        llm_kwargs["base_url"] = llm_base_url

    llm = ChatOpenAI(**llm_kwargs)

    task = f"""Navigate to {target_url} and find the chat interface.

Your goals:
1. If there's a chat launcher button (floating icon, "Chat with us", etc.), click it to open the chat widget
2. Find the text input field where users type messages
3. Find the send/submit button (or determine if Enter key is used to send)
4. Type "Hello" into the input field (DO NOT send it)
5. Report back the CSS selectors or descriptions of:
   - The input field (textarea, input, or contenteditable div)
   - The send button (or "Enter key" if no visible button)
   - The response/output area where the bot's reply appears

Format your final answer as:
INPUT: [description and CSS selector of input field]
SUBMIT: [description and CSS selector of send button, or "ENTER_KEY"]
RESPONSE: [description and CSS selector of response area]
"""

    result = {"input_selector": "", "submit_selector": "", "submit_method": "enter",
              "confidence": 0.0, "raw_output": ""}

    async def _run_agent():
        agent = Agent(
            task=task,
            llm=llm,
        )
        agent_result = await agent.run()
        return agent_result

    try:
        loop = asyncio.new_event_loop()
        agent_output = loop.run_until_complete(_run_agent())
        loop.close()

        # Parse the agent's output to extract selectors
        output_text = str(agent_output)
        result["raw_output"] = output_text

        # Try to extract structured info from the output
        for line in output_text.split("\n"):
            line_upper = line.strip().upper()
            if line_upper.startswith("INPUT:"):
                result["input_selector"] = line.split(":", 1)[1].strip()
                result["confidence"] = max(result["confidence"], 0.7)
            elif line_upper.startswith("SUBMIT:"):
                submit_val = line.split(":", 1)[1].strip()
                if "enter" in submit_val.lower() or "enter_key" in submit_val.lower():
                    result["submit_method"] = "enter"
                else:
                    result["submit_selector"] = submit_val
                    result["submit_method"] = "click"
                result["confidence"] = max(result["confidence"], 0.7)
            elif line_upper.startswith("RESPONSE:"):
                result["response_selector"] = line.split(":", 1)[1].strip()

        log.info("browser_use_detection_complete",
                 input=result["input_selector"][:50],
                 submit=result["submit_method"],
                 confidence=result["confidence"])

    except Exception as exc:
        log.warning("browser_use_detection_failed", error=str(exc)[:200])
        result["error"] = str(exc)

    return result


# ── Other recommended tools ─────────────────────────────────────────────────
#
# Tool          Install                   Best for
# ───────────── ───────────────────────── ─────────────────────────────────────
# browser-use   pip install browser-use   Auto-navigate any site using LLM +
# (33k+ stars)                            Playwright. Works with local Ollama.
#                                         Easiest to wire in as alt provider.
#
# Skyvern       docker compose up         LLM + computer vision, handles
#                                         CAPTCHAs, self-hosted API.
#
# Playwright    already installed          playwright codegen <url> — records
# codegen                                 to Python code with locators that
#                                         auto-pierce shadow DOM.
#
# See: https://github.com/browser-use/browser-use
# See: https://github.com/skyvern-ai/skyvern
