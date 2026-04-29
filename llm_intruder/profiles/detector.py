"""RAG and Agent heuristic detectors.

These detectors analyse a :class:`TargetProfile` (and optionally probe
responses) to determine whether the target application uses a RAG pipeline
or an agent architecture.  They are intentionally lightweight — their job
is to surface signals for the operator, not to be definitive.

Detection approach
------------------
RAG signals:
  * ``application_type == "rag"``
  * ``rag_config.enabled is True``
  * Response text contains citations, source references, or document links
  * Response latency pattern suggests retrieval step (not modelled here)
  * System prompt hints mention "knowledge base", "retrieval", "documents"

Agent signals:
  * ``application_type == "agent"``
  * ``agent_config.enabled is True``
  * Response text shows tool call syntax (function calls, JSON actions)
  * System prompt hints mention tool names or "you have access to"
  * Response contains "I will search", "using the tool", "Action:", "Observation:"
"""
from __future__ import annotations

import re

from llm_intruder.profiles.models import (
    AgentDetectionResult,
    RAGDetectionResult,
    TargetProfile,
)

# ── RAG signal patterns ────────────────────────────────────────────────────────

_RAG_TEXT_PATTERNS: list[tuple[str, str]] = [
    (r"\bsource[s]?\b.{0,20}\[", "citation brackets detected"),
    (r"\baccording to (the |my )?(document|knowledge base|retrieved)", "retrieval reference"),
    (r"\[(doc|page|source|ref)\s*\d+\]", "numbered source reference"),
    (r"\bknowledge base\b", "knowledge base mention"),
    (r"\bbased on (the |my )?retrieved", "retrieval acknowledgement"),
    (r"\bfrom (the |my )?(document|corpus|knowledge)", "corpus reference"),
    (r"https?://\S+\.(pdf|docx|txt|csv)", "document URL"),
    (r"\bcontext window\b", "context window mention"),
]

_RAG_HINT_PATTERNS: list[tuple[str, str]] = [
    (r"retrieval.augmented", "RAG architecture in system prompt"),
    (r"knowledge\s*base", "knowledge base reference in system prompt"),
    (r"vector\s*(db|store|database)", "vector store in system prompt"),
    (r"document(s)?\s*(upload|search|retriev)", "document retrieval capability"),
    (r"semantic\s*search", "semantic search reference"),
]

# ── Agent signal patterns ──────────────────────────────────────────────────────

_AGENT_TEXT_PATTERNS: list[tuple[str, str]] = [
    (r"^Action\s*:", "ReAct Action prefix"),
    (r"^Observation\s*:", "ReAct Observation prefix"),
    (r"^Thought\s*:", "ReAct Thought prefix"),
    (r'"action"\s*:\s*"', "JSON action field"),
    (r'"tool"\s*:\s*"', "JSON tool field"),
    (r'\bI will (use|call|invoke|run)\b.{0,40}\btool\b', "tool invocation language"),
    (r'\busing (the )?\w+ tool\b', "tool usage reference"),
    (r'\bfunction call\b', "function call mention"),
    (r'\btool_call\b', "tool_call keyword"),
    (r'\bweb[_\s]?search\b', "web search tool"),
    (r'\bcode[_\s]?execution\b', "code execution tool"),
]

_AGENT_HINT_PATTERNS: list[tuple[str, str]] = [
    (r"you have access to (the following )?tool", "tool access in system prompt"),
    (r"available tools?\s*:", "tool listing in system prompt"),
    (r"function calling", "function calling capability"),
    (r"tool[_\s]use", "tool use reference"),
    (r"agent\b", "agent role in system prompt"),
]


def _scan_patterns(
    text: str,
    patterns: list[tuple[str, str]],
    flags: int = re.IGNORECASE | re.MULTILINE,
) -> list[str]:
    """Return description strings for all matching patterns."""
    hits = []
    for pattern, description in patterns:
        if re.search(pattern, text, flags):
            hits.append(description)
    return hits


def detect_rag(
    profile: TargetProfile,
    sample_responses: list[str] | None = None,
) -> RAGDetectionResult:
    """Heuristically detect whether the target uses a RAG pipeline.

    Parameters
    ----------
    profile:
        The loaded target profile.
    sample_responses:
        Optional list of actual model responses to scan for RAG signals.

    Returns
    -------
    RAGDetectionResult
    """
    signals: list[str] = []
    confidence = 0.0

    # Config-level certainty
    if profile.application_type == "rag":
        signals.append("application_type is 'rag'")
        confidence += 0.60
    if profile.rag_config.enabled:
        signals.append("rag_config.enabled is True")
        confidence += 0.30

    # System prompt hints
    for hint in profile.known_system_prompt_hints:
        hits = _scan_patterns(hint, _RAG_HINT_PATTERNS)
        signals.extend(hits)
        confidence += len(hits) * 0.05

    # Response text scanning
    if sample_responses:
        for resp in sample_responses:
            hits = _scan_patterns(resp, _RAG_TEXT_PATTERNS)
            signals.extend(hits)
            confidence += len(hits) * 0.08

    confidence = min(round(confidence, 3), 1.0)
    rag_likely = confidence >= 0.3

    recommended: list[str] = []
    if rag_likely:
        recommended = [
            "indirect_prompt_injection via document upload",
            "knowledge_base_poisoning via crafted document",
            "cross_context_leakage via tenant boundary probe",
        ]

    return RAGDetectionResult(
        rag_likely=rag_likely,
        confidence=confidence,
        signals=list(dict.fromkeys(signals)),  # deduplicate preserving order
        recommended_tests=recommended,
    )


def detect_agent(
    profile: TargetProfile,
    sample_responses: list[str] | None = None,
) -> AgentDetectionResult:
    """Heuristically detect whether the target uses an agent architecture.

    Parameters
    ----------
    profile:
        The loaded target profile.
    sample_responses:
        Optional list of actual model responses to scan for agent signals.

    Returns
    -------
    AgentDetectionResult
    """
    signals: list[str] = []
    detected_tools: list[str] = []
    confidence = 0.0

    # Config-level certainty
    if profile.application_type == "agent":
        signals.append("application_type is 'agent'")
        confidence += 0.60
    if profile.agent_config.enabled:
        signals.append("agent_config.enabled is True")
        confidence += 0.30
        for tool in profile.agent_config.available_tools:
            detected_tools.append(tool.name)
            if tool.risk_level in ("high", "critical"):
                signals.append(f"high-risk tool declared: {tool.name}")
                confidence += 0.05

    # System prompt hints
    for hint in profile.known_system_prompt_hints:
        hits = _scan_patterns(hint, _AGENT_HINT_PATTERNS)
        signals.extend(hits)
        confidence += len(hits) * 0.07

        # Extract tool names from hints
        tool_matches = re.findall(
            r'\b(web_search|code_execution|file_access|browser|calculator|email|calendar)\b',
            hint,
            re.IGNORECASE,
        )
        detected_tools.extend(tool_matches)

    # Response text scanning
    if sample_responses:
        for resp in sample_responses:
            hits = _scan_patterns(resp, _AGENT_TEXT_PATTERNS)
            signals.extend(hits)
            confidence += len(hits) * 0.08

    confidence = min(round(confidence, 3), 1.0)
    agent_likely = confidence >= 0.3

    recommended: list[str] = []
    if agent_likely:
        recommended = ["tool_abuse via direct tool invocation"]
        if any(t in detected_tools for t in ("code_execution", "file_access")):
            recommended.append("privilege_escalation via high-risk tool chain")
        recommended.append("agent_goal_hijacking via injected objective")

    return AgentDetectionResult(
        agent_likely=agent_likely,
        confidence=confidence,
        signals=list(dict.fromkeys(signals)),
        detected_tools=list(dict.fromkeys(detected_tools)),
        recommended_tests=recommended,
    )
