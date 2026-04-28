"""Payload catalogue loader and optional internet fetcher — Phase 13.

Two modes:
  1. LOCAL (default) — loads the curated YAML files from payloads/catalogue/
  2. FETCH  (--fetch) — additionally downloads payloads from configured URLs
     and merges them into the active library.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterator

import yaml

CATALOGUE_DIR = Path(__file__).parent / "catalogue"

# ── URLs to fetch additional payloads from ───────────────────────────────────
# These are publicly available security research / red-team payload libraries.
FETCH_SOURCES: list[dict] = [
    {
        "url": "https://crazywifi.github.io/Redteam_LLM_Injection_payloads/Redteam_LLM_Injection_payloads.html",
        "category": "direct_injection",
        "parser": "html_li",
    },
    {
        "url": "https://crazywifi.github.io/Redteam_LLM_Injection_payloads/Financial&Banking_LLM_Prompt_injection_Test_Library.html",
        "category": "financial_domain",
        "parser": "html_li",
    },
    {
        "url": "https://crazywifi.github.io/Redteam_LLM_Injection_payloads/Enterprise&Corporate_LLM_Prompt_injection_Test_Library.html",
        "category": "enterprise_domain",
        "parser": "html_li",
    },
    {
        "url": "https://crazywifi.github.io/Redteam_LLM_Injection_payloads/Medical&Healthcare_LLM_Prompt_injection_Test_Library.html",
        "category": "medical_domain",
        "parser": "html_li",
    },
    {
        "url": "https://raw.githubusercontent.com/elder-plinius/L1B3RT4S/main/GOOGLE.txt",
        "category": "roleplay_jailbreak",
        "parser": "plain_lines",
    },
    {
        "url": "https://raw.githubusercontent.com/elder-plinius/L1B3RT4S/main/OPENAI.txt",
        "category": "roleplay_jailbreak",
        "parser": "plain_lines",
    },
    {
        "url": "https://raw.githubusercontent.com/rubend18/ChatGPT-Jailbreak-Prompts/main/Jailbreaks.csv",
        "category": "persona_hijack",
        "parser": "csv_jailbreak",
    },
    {
        "url": "https://raw.githubusercontent.com/elder-plinius/L1B3RT4S/main/ANTHROPIC.txt",
        "category": "roleplay_jailbreak",
        "parser": "plain_lines",
    },
    {
        "url": "https://raw.githubusercontent.com/elder-plinius/L1B3RT4S/main/META.txt",
        "category": "roleplay_jailbreak",
        "parser": "plain_lines",
    },
]


# ── Local catalogue loader ────────────────────────────────────────────────────

def load_catalogue(
    categories: list[str] | None = None,
    catalogue_dir: Path = CATALOGUE_DIR,
) -> list[dict]:
    """Load all payloads from the local YAML catalogue.

    Parameters
    ----------
    categories:
        Filter to these category names. ``None`` = load all.
    catalogue_dir:
        Override the catalogue directory (mainly for tests).

    Returns
    -------
    list[dict]
        List of payload dicts with keys: id, text, category, tags.
    """
    payloads: list[dict] = []
    for yaml_file in sorted(catalogue_dir.glob("*.yaml")):
        try:
            with yaml_file.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        if not data or "payloads" not in data:
            continue
        cat = data.get("category", yaml_file.stem)
        if categories is not None and cat not in categories:
            continue
        for idx, p in enumerate(data["payloads"]):
            # Auto-generate an id if the payload dict doesn't have one.
            # Format: <stem>-<index>-<hash6>  e.g. "cipher_jailbreak-3-a1b2c3"
            pid = p.get("id") or (
                f"{yaml_file.stem}-{idx}-"
                + hashlib.md5(
                    str(p.get("text", "")).encode("utf-8", errors="replace")
                ).hexdigest()[:6]
            )
            # Also carry through optional strategy / mutator hints from the YAML
            entry: dict = {
                "id": pid,
                "text": p.get("text", ""),
                "category": cat,
                "tags": p.get("tags", []),
                "source": "catalogue",
            }
            if "strategy" in data:
                entry.setdefault("strategy", data["strategy"])
            if "strategy" in p:
                entry["strategy"] = p["strategy"]
            if "mutator" in p:
                entry["mutator"] = p["mutator"]
            payloads.append(entry)
    return payloads


def catalogue_to_payloads_yaml(
    payloads: list[dict],
    output_path: Path,
    max_per_category: int | None = None,
) -> Path:
    """Write a standard ``payloads.yaml`` from catalogue payload dicts."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if max_per_category is not None:
        from collections import defaultdict
        counts: dict[str, int] = defaultdict(int)
        filtered = []
        for p in payloads:
            cat = p["category"]
            if counts[cat] < max_per_category:
                filtered.append(p)
                counts[cat] += 1
        payloads = filtered

    out = {
        "payloads": [
            {
                "id": p["id"],
                "strategy": p.get("strategy") or p.get("category", "direct_injection"),
                "text": p["text"],
                "tags": p.get("tags", []),
            }
            for p in payloads
        ]
    }
    with output_path.open("w", encoding="utf-8") as f:
        yaml.dump(out, f, allow_unicode=True, sort_keys=False, width=120)
    return output_path


# ── Internet fetcher ──────────────────────────────────────────────────────────

def fetch_payloads_from_url(source: dict, timeout: float = 15.0) -> list[dict]:
    """Fetch payloads from a single URL source.

    Returns a list of payload dicts (same format as :func:`load_catalogue`).
    Returns an empty list on any network or parse error.
    """
    try:
        import httpx
        resp = httpx.get(source["url"], timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text
    except Exception as exc:
        return []

    parser = source.get("parser", "plain_lines")
    category = source.get("category", "fetched")
    raw_texts: list[str] = []

    if parser == "html_li":
        # Extract text from <li>...</li> tags
        raw_texts = re.findall(r"<li[^>]*>(.*?)</li>", text, re.S | re.I)
        raw_texts = [_strip_html(t).strip() for t in raw_texts]
    elif parser == "csv_jailbreak":
        # Parse CSV with jailbreak prompts (header row + prompt column)
        import csv
        import io
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        # Find the column with the longest text (likely the prompt column)
        for row in reader:
            if row:
                # Take the cell with the most text as the payload
                longest = max(row, key=len) if row else ""
                if longest and len(longest) >= 15:
                    raw_texts.append(longest.strip())
    elif parser == "plain_lines":
        raw_texts = [ln.strip() for ln in text.splitlines()]

    payloads = []
    for raw in raw_texts:
        if not raw or len(raw) < 15:
            continue
        pid = "fetch-" + hashlib.sha256(raw.encode()).hexdigest()[:8]
        payloads.append({
            "id": pid,
            "text": raw,
            "category": category,
            "tags": ["fetched"],
            "source": source["url"],
        })
    return payloads


def fetch_all_sources(
    sources: list[dict] | None = None,
    timeout: float = 15.0,
) -> list[dict]:
    """Fetch from all configured sources and return combined payload list."""
    all_payloads: list[dict] = []
    for src in (sources or FETCH_SOURCES):
        fetched = fetch_payloads_from_url(src, timeout=timeout)
        all_payloads.extend(fetched)
    return all_payloads


# ── HTML strip helper ─────────────────────────────────────────────────────────

def _strip_html(text: str) -> str:
    """Remove HTML tags and decode common entities."""
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    return re.sub(r"\s+", " ", text).strip()


# ── Catalogue sync (new catalogues + dedup-merge into existing ones) ─────────

def _normalise_text(text: str) -> str:
    """Whitespace/case-normalised form used for duplicate detection."""
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def _safe_category_name(raw: str) -> str:
    """Slugify a category name so it is safe to use as a file stem."""
    if not raw:
        return "fetched"
    slug = re.sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_")
    return slug or "fetched"


def _next_id_for_stem(stem: str, existing_ids: set[str], text: str) -> str:
    """Generate a stable id of the form ``<short>-<hash6>`` matching the
    curated catalogue's style.  Falls back to numeric if hash collides.
    """
    # short prefix = first letter of each word in the stem, up to 3 chars
    parts = [p for p in stem.split("_") if p]
    short = "".join(p[0] for p in parts)[:3] or stem[:3]
    h = hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:6]
    candidate = f"{short}-{h}"
    if candidate not in existing_ids:
        return candidate
    # hash collision — append numeric suffix
    i = 2
    while f"{candidate}-{i}" in existing_ids:
        i += 1
    return f"{candidate}-{i}"


def sync_catalogue_from_sources(
    sources: list[dict] | None = None,
    catalogue_dir: Path = CATALOGUE_DIR,
    timeout: float = 15.0,
    create_new_categories: bool = True,
) -> dict:
    """Fetch internet payloads and merge them into the local catalogue folder.

    Behaviour:
      * For every fetched payload, normalise its text and check whether it
        already exists in the target category YAML file.  If yes, skip it.
      * If the target category file exists, append new payloads to it while
        preserving the existing ``category`` / ``description`` / order of
        entries.
      * If the target category does NOT exist and ``create_new_categories``
        is True, create a new YAML file under ``catalogue/`` using the same
        schema (``category``, ``description``, ``payloads[]``).
      * Deduplicate within the fetched batch too — if two sources return the
        same text, it is inserted once.

    Returns a report dict::

        {
          "categories":   {"direct_injection": {"added": 12, "skipped": 48, "existed": True}, ...},
          "new_categories":  ["some_new_slug", ...],
          "total_added":     N,
          "total_skipped":   M,
          "sources_ok":      k,
          "sources_failed":  f,
        }
    """
    catalogue_dir = Path(catalogue_dir)
    catalogue_dir.mkdir(parents=True, exist_ok=True)

    # 1. Fetch everything
    sources_ok = 0
    sources_failed = 0
    all_fetched: list[dict] = []
    for src in (sources or FETCH_SOURCES):
        try:
            got = fetch_payloads_from_url(src, timeout=timeout)
            if got:
                sources_ok += 1
                all_fetched.extend(got)
            else:
                # fetch_payloads_from_url swallows errors → returns []
                sources_failed += 1
        except Exception:
            sources_failed += 1

    # 2. Group fetched payloads by category, dedupe inside the batch
    by_cat: dict[str, list[dict]] = {}
    intra_batch_seen: set[tuple[str, str]] = set()
    for p in all_fetched:
        cat = _safe_category_name(p.get("category") or "fetched")
        norm = _normalise_text(p.get("text", ""))
        if not norm:
            continue
        key = (cat, norm)
        if key in intra_batch_seen:
            continue
        intra_batch_seen.add(key)
        by_cat.setdefault(cat, []).append(p)

    report = {
        "categories":      {},
        "new_categories":  [],
        "total_added":     0,
        "total_skipped":   0,
        "sources_ok":      sources_ok,
        "sources_failed":  sources_failed,
    }

    # 3. Per-category merge back into catalogue/<cat>.yaml
    for cat, incoming in by_cat.items():
        file_path = catalogue_dir / f"{cat}.yaml"
        existed = file_path.exists()

        if existed:
            try:
                with file_path.open(encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            except Exception:
                data = {}
        else:
            if not create_new_categories:
                report["categories"][cat] = {"added": 0, "skipped": len(incoming), "existed": False, "created": False}
                report["total_skipped"] += len(incoming)
                continue
            data = {
                "category": cat,
                "description": f"Auto-fetched payloads for category '{cat}'.",
                "payloads": [],
            }
            report["new_categories"].append(cat)

        if not isinstance(data, dict):
            data = {"category": cat, "payloads": []}
        data.setdefault("category", cat)
        data.setdefault("payloads", [])
        if not isinstance(data["payloads"], list):
            data["payloads"] = []

        # Build dedup set from existing payloads
        existing_norms: set[str] = set()
        existing_ids: set[str] = set()
        for p in data["payloads"]:
            if not isinstance(p, dict):
                continue
            existing_norms.add(_normalise_text(p.get("text", "")))
            pid = p.get("id")
            if pid:
                existing_ids.add(str(pid))

        added = 0
        skipped = 0
        for p in incoming:
            norm = _normalise_text(p.get("text", ""))
            if not norm or norm in existing_norms:
                skipped += 1
                continue
            new_id = _next_id_for_stem(cat, existing_ids, p.get("text", ""))
            existing_ids.add(new_id)
            existing_norms.add(norm)

            entry = {
                "id":   new_id,
                "text": p["text"],
                "tags": sorted(set((p.get("tags") or []) + ["fetched"])),
            }
            # Optional provenance — only kept on fetched payloads
            if p.get("source"):
                entry["source"] = p["source"]
            data["payloads"].append(entry)
            added += 1

        # 4. Write the merged file back if anything changed or we created new
        if added > 0 or not existed:
            # Ensure key order: category, description, payloads (matching
            # the curated style)
            ordered: dict = {}
            for k in ("category", "description"):
                if k in data:
                    ordered[k] = data[k]
            ordered["payloads"] = data["payloads"]
            for k, v in data.items():
                if k not in ordered:
                    ordered[k] = v
            with file_path.open("w", encoding="utf-8") as f:
                yaml.dump(
                    ordered, f,
                    allow_unicode=True,
                    sort_keys=False,
                    width=120,
                    default_flow_style=False,
                )

        report["categories"][cat] = {
            "added":   added,
            "skipped": skipped,
            "existed": existed,
            "created": (not existed),
        }
        report["total_added"]   += added
        report["total_skipped"] += skipped

    return report
