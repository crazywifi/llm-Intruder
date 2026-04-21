from __future__ import annotations

import click

from llm_intruder.config.models import EngagementConfig
from llm_intruder.exceptions import AuthorisationError

# Placeholder engagement IDs that indicate a config file was never properly
# filled out with a real engagement identifier.
_PLACEHOLDER_IDS = {"example", "engagement", "test", "demo", "placeholder", ""}


def check_authorisation(config: EngagementConfig) -> None:
    """Hard exit guard — raises AuthorisationError if authorisation_confirmed is False.

    Also validates that engagement_id is a non-empty, non-placeholder value so
    that operators cannot accidentally run tests under a default/template config.
    """
    if not config.authorisation_confirmed:
        raise AuthorisationError(
            "authorisation_confirmed is not True in the engagement config. "
            "You must hold explicit written authorisation before running any tests. "
            "Aborting."
        )

    # Validate engagement_id is meaningful
    eid = (config.engagement_id or "").strip().lower()
    if eid in _PLACEHOLDER_IDS:
        raise AuthorisationError(
            f"engagement_id '{config.engagement_id}' appears to be a default "
            "placeholder. Set a unique, descriptive engagement_id in your "
            "engagement config before running tests."
        )

    # Warning: authorisation is self-declaration, not a technical control
    click.echo(
        click.style(
            "WARNING: Authorisation check passed (self-declaration). "
            "LLM-Intruder does not verify written authorisation independently. "
            "Ensure you hold explicit written permission from the asset owner "
            "before proceeding.",
            fg="yellow",
        )
    )
