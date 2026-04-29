class SentinelAIError(Exception):
    """Base exception for LLM-Intruder."""


class AuthorisationError(SentinelAIError):
    """Raised when authorisation_confirmed is not set to true in engagement config."""


class ScopeViolationError(SentinelAIError):
    """Raised when a target URL is outside the declared scope."""


class ConfigurationError(SentinelAIError):
    """Raised when a config file is missing or malformed."""
