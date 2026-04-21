from __future__ import annotations

import pytest

from llm_intruder.config.models import EngagementConfig
from llm_intruder.core.auth_guard import check_authorisation
from llm_intruder.exceptions import AuthorisationError


def _make_config(authorised: bool) -> EngagementConfig:
    return EngagementConfig(
        engagement_id="ENG-TEST",
        authorisation_confirmed=authorised,
        scope=["https://example.internal"],
        strategy_weights={},
    )


def test_check_authorisation_passes_when_true() -> None:
    config = _make_config(True)
    check_authorisation(config)  # must not raise


def test_check_authorisation_raises_when_false() -> None:
    config = _make_config(False)
    with pytest.raises(AuthorisationError):
        check_authorisation(config)


def test_authorisation_error_message_is_informative() -> None:
    config = _make_config(False)
    with pytest.raises(AuthorisationError, match="authorisation_confirmed"):
        check_authorisation(config)
