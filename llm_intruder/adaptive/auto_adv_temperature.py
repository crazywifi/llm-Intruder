"""AutoAdv Adaptive Temperature Scheduler.

Dynamic temperature control tied to attack success/failure outcomes.
Based on ZeroLeaks AutoAdv implementation (2024) which itself draws from
the "Adaptive Temperature Scheduling for LLM Red-Teaming" pattern.

Algorithm
---------
initial_temp  = 0.9
min_temp      = 0.3    (exploitation mode)
max_temp      = 1.0    (exploration mode)

Per trial outcome:
  SUCCESS      → temp -= decay_step       (exploit what's working → less noise)
  PARTIAL_LEAK → temp -= decay_step * 0.5 (partial success → slight exploitation)
  REFUSAL      → temp += explore_step     (vary more to find new path)
  PLATEAU      → temp += plateau_boost    (3+ consecutive failures → aggressive diversify)
  RESET        → temp = initial_temp      (5+ consecutive failures or burn detected)

Temperature is passed to:
  - AttackerLLM.refine_payload_async() when mode is PAIR/FULL
  - TombRaider step generation
  - Any API adapter that accepts temperature in its request body

The temperature is exposed as a simple float property so any component can
read and inject it without coupling to this class internals.
"""
from __future__ import annotations

import structlog

from llm_intruder.adaptive.response_classifier import ResponseType

log = structlog.get_logger()


class AutoAdvTemperature:
    """Manages attack generation temperature with outcome-driven scheduling.

    Parameters
    ----------
    initial:     Starting temperature (default 0.9)
    min_temp:    Lower bound — exploitation floor (default 0.3)
    max_temp:    Upper bound — exploration ceiling (default 1.0)
    decay_step:  Decrease on success (default 0.1)
    explore_step:Increase on failure (default 0.05)
    plateau_boost:Extra boost after plateau (default 0.15)
    plateau_threshold: Consecutive failures before plateau trigger (default 3)
    reset_threshold:   Consecutive failures before full reset (default 5)
    """

    def __init__(
        self,
        initial: float = 0.9,
        min_temp: float = 0.3,
        max_temp: float = 1.0,
        decay_step: float = 0.10,
        explore_step: float = 0.05,
        plateau_boost: float = 0.15,
        plateau_threshold: int = 3,
        reset_threshold: int = 5,
    ) -> None:
        self._initial           = initial
        self._current           = initial
        self._min               = min_temp
        self._max               = max_temp
        self._decay_step        = decay_step
        self._explore_step      = explore_step
        self._plateau_boost     = plateau_boost
        self._plateau_threshold = plateau_threshold
        self._reset_threshold   = reset_threshold

        self._consecutive_failures: int = 0
        self._total_adjustments: int = 0
        self._history: list[tuple[ResponseType, float]] = []

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def current(self) -> float:
        """Current temperature value (read-only)."""
        return self._current

    @property
    def consecutive_failures(self) -> int:
        return self._consecutive_failures

    def record(self, response_type: ResponseType) -> None:
        """Update temperature based on the observed response type."""
        prev = self._current

        if response_type == ResponseType.SUCCESS:
            # Exploit: reduce randomness
            self._current = max(self._min, self._current - self._decay_step)
            self._consecutive_failures = 0

        elif response_type == ResponseType.PARTIAL_LEAK:
            # Partial success: slight exploitation
            self._current = max(self._min, self._current - self._decay_step * 0.5)
            self._consecutive_failures = 0

        elif response_type in (ResponseType.HARD_REFUSAL, ResponseType.SOFT_REFUSAL,
                                ResponseType.OFF_TOPIC, ResponseType.UNCLEAR):
            self._consecutive_failures += 1

            if self._consecutive_failures >= self._reset_threshold:
                # Full reset
                self._current = self._initial
                self._consecutive_failures = 0
                log.info(
                    "autoadv_temp_reset",
                    reason="consecutive_failures_exceeded",
                    threshold=self._reset_threshold,
                )
            elif self._consecutive_failures >= self._plateau_threshold:
                # Plateau boost — aggressive exploration
                self._current = min(self._max, self._current + self._plateau_boost)
                log.debug(
                    "autoadv_plateau_detected",
                    consecutive_failures=self._consecutive_failures,
                    temp=f"{self._current:.2f}",
                )
            else:
                # Normal exploration step
                self._current = min(self._max, self._current + self._explore_step)

        self._history.append((response_type, self._current))
        self._total_adjustments += 1

        if abs(prev - self._current) > 0.01:
            log.debug(
                "autoadv_temp_adjusted",
                response_type=response_type.value,
                prev=f"{prev:.2f}",
                current=f"{self._current:.2f}",
            )

    def force_reset(self, reason: str = "manual") -> None:
        """Force a full temperature reset (e.g. on burn detection)."""
        self._current = self._initial
        self._consecutive_failures = 0
        log.info("autoadv_temp_reset", reason=reason, restored_to=self._initial)

    def should_reset(self) -> bool:
        """True if the scheduler recommends starting a fresh context."""
        return self._consecutive_failures >= self._reset_threshold

    def summary(self) -> str:
        """One-line summary for CLI/log display."""
        return (
            f"temp={self._current:.2f}  "
            f"consec_failures={self._consecutive_failures}  "
            f"total_adjustments={self._total_adjustments}"
        )

    def history(self) -> list[tuple[str, float]]:
        """Return full history as (response_type_value, temp_after) pairs."""
        return [(rt.value, t) for rt, t in self._history]
