"""RagRunner — orchestrates all Phase 9 RAG and multi-modal test generation.

Coordinates document/image payload generation and optional live probe execution
via the existing ApiDriver infrastructure. Every live probe is SHA-256 audit
logged (ground rule: every target touch must be logged).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from llm_intruder.rag.boundary_tester import BoundaryTester
from llm_intruder.rag.citation_checker import CitationChecker
from llm_intruder.rag.cross_tenant import CrossTenantProber
from llm_intruder.rag.document_payload import DocumentPayloadGenerator
from llm_intruder.rag.document_payload import save_all as save_docs
from llm_intruder.rag.image_payload import ImagePayloadGenerator
from llm_intruder.rag.image_payload import save_all as save_images
from llm_intruder.rag.models import (
    BoundaryProbeResult,
    CitationCheckResult,
    CrossTenantProbeResult,
    DocumentPayloadSpec,
    ImagePayloadSpec,
    RagTestSummary,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session
    from llm_intruder.api.driver import ApiDriver
    from llm_intruder.profiles.models import TargetProfile

log = structlog.get_logger()


def _sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class RagRunner:
    """Orchestrate RAG boundary, citation, and cross-tenant tests.

    Parameters
    ----------
    engagement_id:
        Engagement identifier for audit log entries.
    profile:
        Loaded :class:`~llm_intruder.profiles.models.TargetProfile`.
    adversarial_text:
        Core adversarial instruction embedded in all payload variants.
    output_dir:
        Directory for payload files and ``rag_summary.json``.
    driver:
        Optional :class:`~llm_intruder.api.driver.ApiDriver` for live probes.
        Required when ``run_live_probes=True``.
    db_session:
        SQLAlchemy session for audit log writes.
        Required when *driver* is not ``None`` (ground rule: all live probes
        must be audit logged).
    operator:
        Operator string written to audit log entries.

    Raises
    ------
    ValueError
        If *driver* is provided without *db_session*.
    """

    def __init__(
        self,
        engagement_id: str,
        profile: "TargetProfile",
        adversarial_text: str,
        output_dir: Path | str,
        driver: "ApiDriver | None" = None,
        db_session: "Session | None" = None,
        operator: str = "rag_runner",
    ) -> None:
        if driver is not None and db_session is None:
            raise ValueError(
                "db_session is required when driver is provided. "
                "All live probes must be audit logged (ground rule)."
            )
        self.engagement_id = engagement_id
        self.profile = profile
        self.adversarial_text = adversarial_text
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._driver = driver
        self._session = db_session
        self._operator = operator

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(
        self,
        run_live_probes: bool = False,
        boundary_pattern_types: list[str] | None = None,
        cross_tenant_template_names: list[str] | None = None,
        known_sources: list[str] | None = None,
        current_tenant: str = "TENANT_A",
        target_tenant: str = "TENANT_B",
        control_callback=None,
        progress_callback=None,
    ) -> RagTestSummary:
        """Generate payloads and optionally run live probes.

        Parameters
        ----------
        run_live_probes:
            Send probes to the target via the driver. Requires *driver* and
            *db_session* to have been set at construction time.
        boundary_pattern_types:
            Filter boundary probe catalogue by pattern type.
            ``None`` = all types.
        cross_tenant_template_names:
            Filter cross-tenant templates by name. ``None`` = all templates.
        known_sources:
            Verified source identifiers for citation integrity checking.
        current_tenant / target_tenant:
            Tenant IDs used in cross-tenant probe text generation.
        """
        live = run_live_probes and self._driver is not None

        # control_callback() may return one of:
        #   None / "continue"  → keep going
        #   "pause"            → block here until callback returns something else
        #   "skip"             → end probe loop early, still write summary
        #   "stop"             → raise RuntimeError("Run stopped by user")
        # progress_callback(done, total, phase, last_id) is fired after each probe.
        def _check_control() -> str | None:
            if control_callback is None:
                return None
            import time as _time
            while True:
                action = control_callback() or "continue"
                if action != "pause":
                    return action
                _time.sleep(0.5)

        # ── Audit: start ───────────────────────────────────────────────────────
        self._audit("rag_test_start", payload="", response="", details={
            "run_live_probes": live,
            "output_dir": str(self.output_dir),
            "adversarial_text_hash": _sha256_str(self.adversarial_text),
            "profile_domain": self.profile.domain,
        })

        # ── 1. Generate document payloads ─────────────────────────────────────
        doc_gen = DocumentPayloadGenerator(self.adversarial_text)
        doc_specs: list[DocumentPayloadSpec] = doc_gen.generate_all()
        save_docs(doc_specs, self.output_dir / "document_payloads")
        log.info("rag_doc_payloads_generated", count=len(doc_specs))

        # ── 2. Generate image payloads ────────────────────────────────────────
        img_gen = ImagePayloadGenerator(self.adversarial_text)
        img_specs: list[ImagePayloadSpec] = img_gen.generate_all()
        save_images(img_specs, self.output_dir / "image_payloads")
        log.info("rag_img_payloads_generated", count=len(img_specs))

        # ── 3. Build probe lists ──────────────────────────────────────────────
        boundary_tester = BoundaryTester(self.adversarial_text, self.profile.domain)
        boundary_probes = boundary_tester.build_probes(boundary_pattern_types)

        cross_prober = CrossTenantProber(
            self.adversarial_text, current_tenant, target_tenant
        )
        ct_probes = cross_prober.build_probes(cross_tenant_template_names)

        citation_checker = CitationChecker(known_sources)

        # ── 4. Execute (live or offline) ──────────────────────────────────────
        boundary_results: list[BoundaryProbeResult] = []
        citation_results: list[CitationCheckResult] = []
        ct_results: list[CrossTenantProbeResult] = []
        live_count = 0
        skipped = False
        total_probes = len(boundary_probes) + len(ct_probes)
        done = 0

        for probe_id, name, payload in boundary_probes:
            action = _check_control()
            if action == "stop":
                raise RuntimeError("Run stopped by user")
            if action == "skip":
                skipped = True
                break
            if live:
                response = self._send_and_log(payload, "rag_boundary_probe", probe_id, {
                    "pattern_name": name,
                })
                live_count += 1
            else:
                response = ""
            result = boundary_tester.analyse_response(probe_id, name, payload, response)
            boundary_results.append(result)
            if response:
                cit = citation_checker.check(probe_id, response)
                citation_results.append(cit)
            done += 1
            if progress_callback:
                try:
                    progress_callback(done, total_probes, "boundary", probe_id)
                except Exception:
                    pass

        if not skipped:
            for probe_id, name, payload in ct_probes:
                action = _check_control()
                if action == "stop":
                    raise RuntimeError("Run stopped by user")
                if action == "skip":
                    break
                if live:
                    response = self._send_and_log(payload, "rag_cross_tenant_probe", probe_id, {
                        "template_name": name,
                        "target_tenant": target_tenant,
                    })
                    live_count += 1
                else:
                    response = ""
                result = cross_prober.analyse_response(probe_id, name, payload, response)
                ct_results.append(result)
                done += 1
                if progress_callback:
                    try:
                        progress_callback(done, total_probes, "cross_tenant", probe_id)
                    except Exception:
                        pass

        # ── 5. Assemble summary ───────────────────────────────────────────────
        boundary_breaches = sum(1 for r in boundary_results if r.leaked)
        ct_successes = sum(1 for r in ct_results if r.access_likely)
        citation_failures = sum(
            1 for r in citation_results
            if r.hallucinated_count + r.unverifiable_count > 0
        )
        findings = boundary_breaches + ct_successes + citation_failures

        summary = RagTestSummary(
            engagement_id=self.engagement_id,
            profile_path=str(getattr(self.profile, "_source_path", "")),
            adversarial_text=self.adversarial_text,
            output_dir=str(self.output_dir),
            document_payloads=doc_specs,
            image_payloads=img_specs,
            boundary_results=boundary_results,
            citation_results=citation_results,
            cross_tenant_results=ct_results,
            live_probes_run=live_count,
            findings_count=findings,
            completed_at=datetime.now(timezone.utc),
        )

        # ── 6. Write JSON output ──────────────────────────────────────────────
        summary_path = self.output_dir / "rag_summary.json"
        summary_path.write_text(
            summary.model_dump_json(indent=2),
            encoding="utf-8",
        )
        log.info("rag_summary_written", path=str(summary_path))

        # ── Audit: complete ───────────────────────────────────────────────────
        self._audit("rag_test_complete", payload="", response="", details={
            "findings_count": findings,
            "live_probes_run": live_count,
            "boundary_breaches": boundary_breaches,
            "cross_tenant_successes": ct_successes,
        })

        return summary

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _send_and_log(
        self,
        payload_text: str,
        event_type: str,
        probe_id: str,
        extra_details: dict,
    ) -> str:
        """Send payload via driver, write audit entry, return response text.

        On any driver exception: logs the error, returns ``"[ERROR: ...]"``.
        """
        from llm_intruder.core.audit_log import write_audit_entry

        try:
            result = self._driver.send_payload(payload_text)
            response_text = result.text or ""
        except Exception as exc:
            log.warning("rag_probe_error", probe_id=probe_id, error=str(exc))
            response_text = f"[ERROR: {exc}]"
            write_audit_entry(
                self._session,
                engagement_id=self.engagement_id,
                event_type=f"{event_type}_error",
                operator=self._operator,
                payload=payload_text,
                response=response_text,
                details={"probe_id": probe_id, "error": str(exc), **extra_details},
            )
            return response_text

        write_audit_entry(
            self._session,
            engagement_id=self.engagement_id,
            event_type=event_type,
            operator=self._operator,
            payload=payload_text,
            response=response_text,
            details={"probe_id": probe_id, **extra_details},
        )
        return response_text

    def _audit(self, event_type: str, payload: str, response: str, details: dict) -> None:
        """Write an audit entry if a session is available."""
        if self._session is None:
            return
        from llm_intruder.core.audit_log import write_audit_entry
        write_audit_entry(
            self._session,
            engagement_id=self.engagement_id,
            event_type=event_type,
            operator=self._operator,
            payload=payload,
            response=response,
            details=details,
        )
