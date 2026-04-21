"""Adversarial image payload generation for multi-modal RAG testing.

Generates PNG images (when Pillow is available) or base64-encoded text
fallback files. All methods embed an adversarial text string that a
vision-language model or OCR-backed RAG pipeline may extract and execute.
"""
from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path

from llm_intruder.rag import PILLOW_AVAILABLE
from llm_intruder.rag.models import ImageMethod, ImagePayloadSpec

# Default image geometry
_IMG_W = 400
_IMG_H = 200
_BG_COLOR = (240, 240, 240)    # light grey
_FG_COLOR = (20, 20, 20)       # near-black
_INVIS_COLOR = (240, 240, 240)  # same as bg — invisible to human eye

_CARRIER_TEXT = "Q4 2024 Financial Report — Confidential"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Pillow-dependent builders ─────────────────────────────────────────────────

def _build_text_overlay(adversarial: str) -> tuple[bytes, str]:
    """Draw adversarial text in readable black on a grey background."""
    from PIL import Image, ImageDraw  # imported inside guard

    img = Image.new("RGB", (_IMG_W, _IMG_H), color=_BG_COLOR)
    draw = ImageDraw.Draw(img)
    # Benign carrier text at top in muted colour
    draw.text((10, 10), _CARRIER_TEXT, fill=(130, 130, 130))
    # Adversarial text in dark colour — visible and OCR-readable
    draw.text((10, 60), adversarial[:160], fill=_FG_COLOR)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue(), "probe_text_overlay.png"


def _build_metadata_embed(adversarial: str) -> tuple[bytes, str]:
    """Embed adversarial text in PNG tEXt metadata chunk.

    The image itself shows only benign carrier text; the adversarial
    instruction is stored in the 'Comment' and 'Description' metadata
    fields that some OCR-backed RAG pipelines ingest.
    """
    from PIL import Image, ImageDraw
    from PIL.PngImagePlugin import PngInfo

    img = Image.new("RGB", (_IMG_W, _IMG_H), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), _CARRIER_TEXT, fill=(80, 80, 80))

    pnginfo = PngInfo()
    pnginfo.add_text("Comment", adversarial)
    pnginfo.add_text("Description", adversarial)
    pnginfo.add_text("parameters", adversarial)  # read by some SD-era pipelines

    buf = io.BytesIO()
    img.save(buf, format="PNG", pnginfo=pnginfo)
    return buf.getvalue(), "probe_metadata_embed.png"


# ── Fallback builder (always available) ──────────────────────────────────────

def _build_base64_fallback(adversarial: str) -> tuple[str, str]:
    """Encode the adversarial text as base64 and write a .txt file.

    This is always produced regardless of Pillow availability, so the
    pipeline always generates at least one image payload variant.
    """
    encoded = base64.b64encode(adversarial.encode("utf-8")).decode("ascii")
    content = (
        "[RAG Image Payload — base64 encoded]\n"
        f"Carrier: {_CARRIER_TEXT}\n\n"
        f"data:text/plain;base64,{encoded}\n\n"
        f"# Decode:\n"
        f"# python3 -c \"import base64; "
        f'print(base64.b64decode(\'{encoded}\').decode())\"\n'
    )
    return content, "probe_base64_fallback.txt"


# ── Public generator class ────────────────────────────────────────────────────

class ImagePayloadGenerator:
    """Generate adversarial image payloads for multi-modal RAG testing."""

    def __init__(self, adversarial_text: str) -> None:
        self.adversarial_text = adversarial_text

    def generate(self, method: ImageMethod) -> ImagePayloadSpec:
        """Generate a single image payload spec (does not write to disk)."""
        if method == "base64_fallback":
            content_str, filename = _build_base64_fallback(self.adversarial_text)
            raw = content_str.encode("utf-8")
            return ImagePayloadSpec(
                method="base64_fallback",
                adversarial_text=self.adversarial_text,
                filename=filename,
                content_bytes=None,
                base64_content=content_str,
                byte_size=len(raw),
                sha256_hash=_sha256_bytes(raw),
            )
        if not PILLOW_AVAILABLE:
            raise RuntimeError(
                f"Cannot generate method='{method}': Pillow is not installed. "
                "Use method='base64_fallback' or install Pillow."
            )
        if method == "text_overlay":
            data, filename = _build_text_overlay(self.adversarial_text)
        elif method == "metadata_embed":
            data, filename = _build_metadata_embed(self.adversarial_text)
        else:
            raise ValueError(f"Unknown image method: {method!r}")

        return ImagePayloadSpec(
            method=method,
            adversarial_text=self.adversarial_text,
            filename=filename,
            content_bytes=data,
            base64_content=None,
            byte_size=len(data),
            sha256_hash=_sha256_bytes(data),
        )

    def generate_all(self) -> list[ImagePayloadSpec]:
        """Return one spec per available method.

        Always includes ``base64_fallback``. Adds ``text_overlay`` and
        ``metadata_embed`` when Pillow is installed.
        """
        specs: list[ImagePayloadSpec] = []
        if PILLOW_AVAILABLE:
            specs.append(self.generate("text_overlay"))
            specs.append(self.generate("metadata_embed"))
        specs.append(self.generate("base64_fallback"))
        return specs


# ── Disk writer ───────────────────────────────────────────────────────────────

def save_all(specs: list[ImagePayloadSpec], output_dir: Path) -> list[Path]:
    """Write each spec to ``output_dir / spec.filename``.

    PNG specs are written as binary; base64_fallback specs are written as UTF-8 text.
    Returns the list of paths written.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for spec in specs:
        path = output_dir / spec.filename
        if spec.content_bytes is not None:
            path.write_bytes(spec.content_bytes)
        else:
            path.write_text(spec.base64_content or "", encoding="utf-8")
        written.append(path)
    return written
