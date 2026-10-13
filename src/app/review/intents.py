"""Application-intent checking (must_allow / must_deny) over compared connections."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from app.model.evaluator import NS_NAME_LABEL, Verdict
from app.model.selectors import LabelSelector, SelectorError, matches, parse_selector
from app.model.topology import Pod, Protocol, Topology
from app.review.comparison import ConnectionComparison


class IntentError(ValueError):
    """Raised for malformed or duplicate intent definitions."""


class Expectation(str, Enum):
    MUST_ALLOW = "must_allow"
    MUST_DENY = "must_deny"


class IntentStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"  # no definite violation, but some decision is Unknown
    INVALID = "INVALID"  # zero-match or conflicting intent; never passes


def _empty_selector() -> LabelSelector:
    return parse_selector({})


@dataclass(frozen=True)
class EndpointSelector:
    """Pod + namespace selector. Empty selectors match everything (missing = all namespaces)."""
    pod: LabelSelector = field(default_factory=_empty_selector)
    namespace: LabelSelector = field(default_factory=_empty_selector)


@dataclass(frozen=True)
class Intent:
    id: str
    source: EndpointSelector
    destination: EndpointSelector
    protocol: Protocol
    port: int
    expectation: Expectation

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise IntentError("intent id must be a non-empty string")
        if not isinstance(self.protocol, Protocol):
            raise IntentError(f"{self.id}: protocol must be a Protocol")
        if not isinstance(self.expectation, Expectation):
            raise IntentError(f"{self.id}: expectation must be an Expectation")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise IntentError(f"{self.id}: port must be an integer in 1..65535, got {self.port!r}")


@dataclass(frozen=True)
class RevisionOutcome:
    status: IntentStatus
    violations: Tuple[str, ...] = ()  # tuple IDs definitely violating the intent
    unknown: Tuple[str, ...] = ()  # tuple IDs with Unknown decisions


@dataclass(frozen=True)
class IntentResult:
    intent_id: str
    expectation: Expectation
    matched_count: int
    matched_tuples: Tuple[str, ...]
    baseline: RevisionOutcome
    candidate: RevisionOutcome
    problems: Tuple[str, ...]  # "zero-match", "conflict"
    conflicting_tuples: Tuple[str, ...]
    existing_violations: Tuple[str, ...]  # violated already in the baseline
    new_violations: Tuple[str, ...]  # violated in candidate, not in baseline
    fixed_violations: Tuple[str, ...]  # violated in baseline, not in candidate

    @property
    def valid(self) -> bool:
        return not self.problems

    @property
    def candidate_passes(self) -> bool:
        return self.candidate.status is IntentStatus.PASS


# ---------------------------------------------------------------- parsing
def _parse_endpoint(raw: Any, where: str) -> EndpointSelector:
    if not isinstance(raw, Mapping):
        raise IntentError(f"{where}: must be a mapping, got {raw!r}")
    unknown = set(raw) - {"podSelector", "namespaceSelector"}
    if unknown:
        raise IntentError(f"{where}: unknown fields {sorted(map(str, unknown))}")
    try:
        return EndpointSelector(
            pod=parse_selector(raw.get("podSelector", {})),
            namespace=parse_selector(raw.get("namespaceSelector", {})),
        )
    except SelectorError as exc:
        raise IntentError(f"{where}: {exc}") from exc


def parse_intent(raw: Any) -> Intent:
    """Validate an intent mapping: id, source, destination, protocol, port, expect."""
    if not isinstance(raw, Mapping):
        raise IntentError(f"intent must be a mapping, got {raw!r}")
    required = {"id", "source", "destination", "protocol", "port", "expect"}
    unknown = set(raw) - required
    if unknown:
        raise IntentError(f"intent: unknown fields {sorted(map(str, unknown))}")
    missing = required - set(raw)
    if missing:
        raise IntentError(f"intent: missing fields {sorted(missing)}")
    iid = raw["id"]
    try:
        protocol = Protocol(raw["protocol"])
    except ValueError:
        raise IntentError(f"{iid}: invalid protocol {raw['protocol']!r}") from None
    try:
        expectation = Expectation(raw["expect"])
    except ValueError:
        raise IntentError(f"{iid}: expect must be 'must_allow' or 'must_deny', got {raw['expect']!r}") from None
    return Intent(
        id=iid,
        source=_parse_endpoint(raw["source"], f"{iid}.source"),
        destination=_parse_endpoint(raw["destination"], f"{iid}.destination"),
        protocol=protocol,
        port=raw["port"],
        expectation=expectation,
    )


# ---------------------------------------------------------------- matching / checking
def _endpoint_matches(sel: EndpointSelector, pod: Pod, topology: Topology) -> bool:
    ns = topology.namespaces.get(pod.namespace)
    ns_labels = {**(ns.labels if ns else {}), NS_NAME_LABEL: pod.namespace}
    return matches(sel.namespace, ns_labels) and matches(sel.pod, pod.labels)


def _intent_matches(intent: Intent, c: ConnectionComparison, topology: Topology) -> bool:
    return (
        c.protocol is intent.protocol
        and c.port == intent.port
        and _endpoint_matches(intent.source, c.query.source, topology)
        and _endpoint_matches(intent.destination, c.query.destination, topology)
    )


def _outcome(expectation: Expectation, pairs: Sequence[Tuple[str, Verdict]]) -> RevisionOutcome:
    bad = Verdict.DENY if expectation is Expectation.MUST_ALLOW else Verdict.ALLOW
    violations = tuple(sorted(t for t, v in pairs if v is bad))
    unknown = tuple(sorted(t for t, v in pairs if v is Verdict.UNKNOWN))
    if violations:
        status = IntentStatus.FAIL  # a definite violation outranks Unknown
    elif unknown:
        status = IntentStatus.UNKNOWN
    else:
        status = IntentStatus.PASS
    return RevisionOutcome(status, violations, unknown)


def _build_result(intent: Intent, matched: Sequence[ConnectionComparison], conflicts: set) -> IntentResult:
    ids = tuple(c.tuple_id for c in matched)
    conflicting = tuple(sorted(set(ids) & conflicts))
    problems: List[str] = []
    if not matched:
        problems.append("zero-match")
    if conflicting:
        problems.append("conflict")

    base = _outcome(intent.expectation, [(c.tuple_id, c.baseline) for c in matched])
    cand = _outcome(intent.expectation, [(c.tuple_id, c.candidate) for c in matched])
    if problems:
        base = replace(base, status=IntentStatus.INVALID)
        cand = replace(cand, status=IntentStatus.INVALID)

    base_set, cand_set = set(base.violations), set(cand.violations)
    return IntentResult(
        intent_id=intent.id,
        expectation=intent.expectation,
        matched_count=len(matched),
        matched_tuples=ids,
        baseline=base,
        candidate=cand,
        problems=tuple(problems),
        conflicting_tuples=conflicting,
        existing_violations=base.violations,
        new_violations=tuple(t for t in cand.violations if t not in base_set),
        fixed_violations=tuple(t for t in base.violations if t not in cand_set),
    )


def check_intents(
    intents: Iterable[Intent], comparisons: Sequence[ConnectionComparison], topology: Topology
) -> Tuple[IntentResult, ...]:
    """Expand each intent over the compared queries and check both revisions."""
    intents = list(intents)
    seen = set()
    for i in intents:
        if i.id in seen:
            raise IntentError(f"duplicate intent id: {i.id}")
        seen.add(i.id)

    matched: Dict[str, List[ConnectionComparison]] = {
        i.id: [c for c in comparisons if _intent_matches(i, c, topology)] for i in intents
    }
    allow_ids = {c.tuple_id for i in intents if i.expectation is Expectation.MUST_ALLOW for c in matched[i.id]}
    deny_ids = {c.tuple_id for i in intents if i.expectation is Expectation.MUST_DENY for c in matched[i.id]}
    conflicts = allow_ids & deny_ids
    return tuple(_build_result(i, matched[i.id], conflicts) for i in intents)


def candidate_acceptable(results: Sequence[IntentResult], unapproved: Sequence[ConnectionComparison]) -> bool:
    """True only if no unapproved changes remain AND every intent passes for the candidate.

    Approvals only shrink `unapproved`; they can never turn a failed, unknown or invalid
    intent into a pass. No intents at all is not a pass.
    """
    return bool(results) and not unapproved and all(r.candidate_passes for r in results)