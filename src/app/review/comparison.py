"""Compare baseline and candidate evaluator decisions for the same connection queries.

Comparison is semantic: it uses evaluator verdicts, never policy text or rule order.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Sequence, Tuple

from app.model.evaluator import Decision, Evaluator, Verdict
from app.model.topology import ConnectionQuery, Pod, Protocol


class ReviewError(ValueError):
    """Raised for inconsistent comparison inputs (duplicate tuples, mismatched topologies)."""


class Change(str, Enum):
    NEWLY_ALLOWED = "NEWLY_ALLOWED"
    NEWLY_BLOCKED = "NEWLY_BLOCKED"
    UNCHANGED = "UNCHANGED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ConnectionComparison:
    tuple_id: str
    query: ConnectionQuery
    source: str  # "namespace/name"
    destination: str
    protocol: Protocol
    port: int
    baseline: Verdict
    candidate: Verdict
    change: Change
    baseline_decision: Decision  # keeps the full explanation trace
    candidate_decision: Decision


@dataclass(frozen=True)
class Approval:
    """Approval of one exact change: tuple plus before/after verdicts."""
    tuple_id: str
    baseline: Verdict
    candidate: Verdict


def pod_id(pod: Pod) -> str:
    return f"{pod.namespace}/{pod.name}"


def tuple_id(query: ConnectionQuery) -> str:
    """Stable ID from logical source/destination identity, protocol and numeric port."""
    key = f"{pod_id(query.source)}|{pod_id(query.destination)}|{query.protocol.value}|{query.port}"
    return "t-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def classify(baseline: Verdict, candidate: Verdict) -> Change:
    if baseline is Verdict.UNKNOWN or candidate is Verdict.UNKNOWN:
        return Change.UNKNOWN
    if baseline is candidate:
        return Change.UNCHANGED
    if baseline is Verdict.DENY:  # candidate is Allow
        return Change.NEWLY_ALLOWED
    return Change.NEWLY_BLOCKED  # Allow -> Deny


def compare_revisions(
    baseline: Evaluator, candidate: Evaluator, queries: Iterable[ConnectionQuery]
) -> Tuple[ConnectionComparison, ...]:
    """Evaluate every query under both revisions and classify the change."""
    if baseline.topology != candidate.topology:
        raise ReviewError("baseline and candidate must use the same topology")

    seen: Dict[str, ConnectionQuery] = {}
    results = []
    for q in queries:
        tid = tuple_id(q)
        if tid in seen:
            raise ReviewError(
                f"duplicate connection tuple {tid} "
                f"({pod_id(q.source)} -> {pod_id(q.destination)} {q.protocol.value}/{q.port})"
            )
        seen[tid] = q
        b, c = baseline.evaluate(q), candidate.evaluate(q)
        results.append(
            ConnectionComparison(
                tuple_id=tid,
                query=q,
                source=pod_id(q.source),
                destination=pod_id(q.destination),
                protocol=q.protocol,
                port=q.port,
                baseline=b.verdict,
                candidate=c.verdict,
                change=classify(b.verdict, c.verdict),
                baseline_decision=b,
                candidate_decision=c,
            )
        )
    return tuple(results)


def unapproved_changes(
    comparisons: Sequence[ConnectionComparison], approvals: Iterable[Approval]
) -> Tuple[ConnectionComparison, ...]:
    """Changed connections (newly allowed/blocked) lacking an exact approval.

    Approvals only clear this review gate; they say nothing about intents.
    """
    approved = {(a.tuple_id, a.baseline, a.candidate) for a in approvals}
    changed = (Change.NEWLY_ALLOWED, Change.NEWLY_BLOCKED)
    return tuple(
        c for c in comparisons
        if c.change in changed and (c.tuple_id, c.baseline, c.candidate) not in approved
    )