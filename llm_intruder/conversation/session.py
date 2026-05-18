"""Multi-turn conversation session — maintains real conversation state across HTTP turns.

Unlike the existing splitting mutator (which concatenates both turns into one message),
this class sends REAL sequential HTTP requests, maintaining conversation history.
Each turn's response is stored and used to build the next turn's context.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional

import structlog

log = structlog.get_logger()

# How many previous turns to include in context window
_DEFAULT_CONTEXT_TURNS = 3


@dataclass
class ConversationTurn:
    """A single turn in a multi-turn conversation."""
    turn_num: int
    payload_sent: str
    response_received: str
    response_type: str          # ResponseType.value string
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class ConversationSession:
    """
    Manages a stateful multi-turn attack conversation.

    Sends real sequential HTTP requests, accumulating history so that
    each turn can include context from prior exchanges.

    Parameters
    ----------
    driver:
        An :class:`~llm_intruder.api.driver.ApiDriver` (or browser driver)
        that exposes ``send_payload(payload: str) -> CapturedResponse``.
    max_turns:
        Maximum number of turns before the session is considered exhausted.
    goal:
        Optional plain-English goal string used in success detection.
    """

    def __init__(
        self,
        driver,
        max_turns: int = 8,
        goal: str = "",
    ) -> None:
        self.driver = driver
        self.max_turns = max_turns
        self.goal = goal
        self.history: list[ConversationTurn] = []
        log.debug("conversation_session_init", max_turns=max_turns, goal_preview=goal[:60])

    # ── Public API ────────────────────────────────────────────────────────────

    def send_turn(self, payload: str) -> tuple[str, ConversationTurn]:
        """
        Send one turn and record it in history.

        Parameters
        ----------
        payload:
            The raw payload text to send (already mutated/planned).

        Returns
        -------
        tuple[str, ConversationTurn]
            ``(response_text, turn_record)``
        """
        turn_num = len(self.history) + 1
        log.debug(
            "conversation_send_turn",
            turn=turn_num,
            payload_preview=payload[:80],
        )

        captured = self.driver.send_payload(payload)
        response_text = captured.text

        turn = ConversationTurn(
            turn_num=turn_num,
            payload_sent=payload,
            response_received=response_text,
            response_type="unknown",       # caller updates after classification
        )
        self.history.append(turn)

        log.debug(
            "conversation_turn_received",
            turn=turn_num,
            response_preview=response_text[:120],
        )
        return response_text, turn

    def build_context_payload(self, new_payload: str) -> str:
        """
        Prepend recent conversation history to *new_payload*.

        Includes up to the last ``_DEFAULT_CONTEXT_TURNS`` turns so the
        target model sees enough context without exceeding token limits.

        Parameters
        ----------
        new_payload:
            The next turn's probe text (without history).

        Returns
        -------
        str
            Combined payload including history and the new probe.
        """
        recent = self.history[-_DEFAULT_CONTEXT_TURNS:]
        if not recent:
            return new_payload

        lines: list[str] = ["Previous exchange:"]
        for turn in recent:
            lines.append(f"You: {turn.payload_sent}")
            # Truncate long responses to avoid overwhelming the context
            resp_preview = turn.response_received[:400]
            if len(turn.response_received) > 400:
                resp_preview += "..."
            lines.append(f"Assistant: {resp_preview}")

        lines.append(f"\nNow: {new_payload}")
        return "\n".join(lines)

    def reset(self) -> None:
        """Clear conversation history (start fresh)."""
        log.debug("conversation_session_reset", previous_turns=len(self.history))
        self.history.clear()

    def is_successful(self, goal_keyword: str = "") -> bool:
        """
        Return True if any turn's response contains the goal keyword.

        Uses self.goal as fallback if *goal_keyword* is empty.
        """
        keyword = goal_keyword or self.goal
        if not keyword:
            return False
        kw_lower = keyword.lower()
        return any(
            kw_lower in turn.response_received.lower()
            for turn in self.history
        )

    def summary(self) -> str:
        """Multi-line human-readable summary of all turns."""
        if not self.history:
            return "(No turns recorded)"

        lines: list[str] = [
            f"Conversation session — {len(self.history)} turn(s), goal: {self.goal or 'unset'}",
            "-" * 60,
        ]
        for turn in self.history:
            ts = turn.timestamp.strftime("%H:%M:%S")
            lines.append(
                f"[{ts}] Turn {turn.turn_num} ({turn.response_type})"
            )
            lines.append(f"  → SENT    : {turn.payload_sent[:120]}")
            resp_preview = turn.response_received[:200].replace("\n", " ")
            lines.append(f"  ← RECEIVED: {resp_preview}")
        lines.append("-" * 60)
        return "\n".join(lines)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def turn_count(self) -> int:
        """Number of turns completed so far."""
        return len(self.history)

    @property
    def is_exhausted(self) -> bool:
        """True when we've hit max_turns."""
        return len(self.history) >= self.max_turns

    @property
    def last_response(self) -> Optional[str]:
        """Text of the most recent response, or None if no turns yet."""
        if not self.history:
            return None
        return self.history[-1].response_received
