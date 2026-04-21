from __future__ import annotations

from urllib.parse import urlparse

from llm_intruder.config.models import EngagementConfig
from llm_intruder.exceptions import ScopeViolationError


def _strip_port(host: str) -> str:
    """Strip port number from a host string, handling IPv6 addresses.

    IPv6 addresses look like ``[::1]`` or ``[::1]:8080``.
    Regular hosts look like ``example.com`` or ``example.com:8080``.
    """
    # IPv6: strip surrounding brackets and any trailing port
    if host.startswith("["):
        bracket_end = host.find("]")
        if bracket_end != -1:
            return host[1:bracket_end]
        return host
    # Regular host: strip trailing :port
    if ":" in host:
        return host.rsplit(":", 1)[0]
    return host


def _scope_entry_scheme(entry: str) -> str | None:
    """Return the explicit scheme from *entry*, or None if entry is a bare domain.

    ``https://target.com`` → ``"https"``
    ``target.com``          → ``None``  (no scheme restriction)
    ``*.target.com``        → ``None``  (no scheme restriction)
    """
    parsed = urlparse(entry)
    if parsed.scheme in ("http", "https", "ws", "wss"):
        return parsed.scheme
    return None


def _normalise_host(entry: str) -> str:
    """Extract the host/domain from a scope entry or bare domain string."""
    parsed = urlparse(entry)
    # urlparse needs a scheme to populate netloc correctly
    if not parsed.scheme:
        parsed = urlparse(f"https://{entry}")
    return _strip_port(parsed.netloc.lower())


def _hosts_match(target_host: str, scope_host: str) -> bool:
    """Return True if *target_host* is covered by *scope_host*.

    Rules:
    - Exact match always passes.
    - Wildcard only if *scope_host* explicitly starts with ``*.``:
      ``*.example.com`` matches ``sub.example.com`` but NOT
      ``evil.sub.example.com`` (only one label deep).
    - No implicit subdomain matching when scope_host has no ``*.`` prefix.
    - The ``url.startswith(entry)`` path-prefix fallback is intentionally
      removed as it allows ``https://target.com.evil.com`` to match
      ``https://target.com``.
    """
    if target_host == scope_host:
        return True
    if scope_host.startswith("*."):
        # Wildcard: allow exactly one subdomain label
        parent = scope_host[2:]  # strip "*."
        # target must be exactly "<one-label>.<parent>"
        if target_host.endswith(f".{parent}"):
            subdomain_part = target_host[: -(len(parent) + 1)]
            # Ensure there is no further dot (only one label deep)
            if "." not in subdomain_part:
                return True
    return False


def check_scope(url: str, config: EngagementConfig) -> None:
    """Raise ScopeViolationError if *url* is not covered by any scope entry.

    Scheme enforcement: if a scope entry explicitly specifies a scheme
    (e.g. ``https://target.com``), the target URL must use the same scheme.
    Bare-domain scope entries (e.g. ``target.com``) allow any scheme.
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"https://{url}")
    target_host = _strip_port(parsed.netloc.lower())
    target_scheme = parsed.scheme.lower()

    for entry in config.scope:
        scope_scheme = _scope_entry_scheme(entry)
        scope_host = _normalise_host(entry)
        if not _hosts_match(target_host, scope_host):
            continue
        # Host matches — also require scheme match if scope entry specified one
        if scope_scheme is not None and scope_scheme != target_scheme:
            continue
        return

    raise ScopeViolationError(
        f"Target '{url}' is not in the declared scope: {config.scope}"
    )


def validate_scope_urls(config: EngagementConfig) -> None:
    """Validate that every scope entry is a parseable URL or domain."""
    for entry in config.scope:
        host = _normalise_host(entry)
        if not host:
            raise ScopeViolationError(f"Invalid scope entry (cannot parse host): '{entry}'")
