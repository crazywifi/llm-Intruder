"""Provider registry — auto-discovery of local LLM servers — Phase 13."""
from __future__ import annotations

import httpx
import structlog

log = structlog.get_logger()


def discover_local_providers() -> list[dict]:
    """Probe localhost for running LLM servers.

    Returns a list of dicts with keys:
      name, base_url, models, provider_class_hint
    """
    found: list[dict] = []

    # ── Ollama ────────────────────────────────────────────────────────────
    try:
        resp = httpx.get("http://localhost:11434/api/tags", timeout=2.0)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            found.append({
                "name": "Ollama",
                "base_url": "http://localhost:11434",
                "models": models,
                "provider": "ollama",
                "flag": "--provider ollama",
                "note": "Free, open-source. Recommended for most users.",
            })
    except Exception:
        pass

    # ── LM Studio ─────────────────────────────────────────────────────────
    try:
        resp = httpx.get("http://localhost:1234/v1/models", timeout=2.0)
        if resp.status_code == 200:
            models = [m["id"] for m in resp.json().get("data", [])]
            found.append({
                "name": "LM Studio",
                "base_url": "http://localhost:1234",
                "models": models,
                "provider": "lmstudio",
                "flag": "--provider lmstudio",
                "note": "GUI-based local LLM runner. OpenAI-compatible.",
            })
    except Exception:
        pass

    return found


def print_discovery_report() -> None:
    """Print a human-readable discovery report to stdout."""
    import click
    found = discover_local_providers()

    click.echo("\n  Local LLM servers detected:")
    if not found:
        click.echo("    None found. Is Ollama or LM Studio running?")
        click.echo("    - Ollama  : https://ollama.com  (free)")
        click.echo("    - LM Studio: https://lmstudio.ai (free)")
    else:
        for p in found:
            click.echo(f"\n    [{p['name']}]  {p['base_url']}")
            click.echo(f"      Note    : {p['note']}")
            click.echo(f"      Use flag: {p['flag']}")
            if p["models"]:
                for m in p["models"][:5]:
                    click.echo(f"      Model   : {m}")
                if len(p["models"]) > 5:
                    click.echo(f"      ... and {len(p['models'])-5} more")
            else:
                click.echo("      Models  : (none loaded)")

    click.echo("\n  Cloud providers (API key required):")
    click.echo("    Claude  : --provider claude  --api-key sk-ant-... "
               "(console.anthropic.com)")
    click.echo("    OpenAI  : --provider openai  --api-key sk-...     "
               "(platform.openai.com)")
    click.echo("    Gemini  : --provider gemini  --api-key AIza...    "
               "(aistudio.google.com)")
