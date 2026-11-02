"""Static NetworkPolicy evaluator (networking.k8s.io/v1 subset).

Pure Python; independent of FastAPI/UI. Decisions are three-valued:
  * Deny    - at least one direction is isolated and definitely has no allowing rule.
  * Allow   - both directions are unisolated or definitely allowed by some rule.
  * Unknown - unsupported/ambiguous input could change the answer (and nothing is a definite Deny).
Invalid policy documents raise PolicyError.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, List, Mapping, Optional, Tuple, Union

from app.model.selectors import LabelSelector, SelectorError, matches, parse_selector
from app.model.topology import ConnectionQuery, Pod, Protocol, Topology, ExternalEndpoint

API_VERSION = "networking.k8s.io/v1"
KIND = "NetworkPolicy"
NS_NAME_LABEL = "kubernetes.io/metadata.name"
INGRESS, EGRESS = "Ingress", "Egress"


class PolicyError(ValueError):
    """Raised for malformed or invalid NetworkPolicy input."""


class Verdict(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"
    UNKNOWN = "Unknown"


# ---------------------------------------------------------------- parsed policy
@dataclass(frozen=True)
class PortSpec:
    protocol: Protocol
    port: Union[int, str, None] = None  # number, container-port name, or None (any port)
    end_port: Optional[int] = None


@dataclass(frozen=True)
class Peer:
    pod_selector: Optional[LabelSelector] = None
    namespace_selector: Optional[LabelSelector] = None
    ip_block: Optional[str] = None  # Pod IP/NAT semantics remain unknown
    exceptions: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    peers: Tuple[Peer, ...] = ()  # empty = all peers
    ports: Tuple[PortSpec, ...] = ()  # empty = all ports


@dataclass(frozen=True)
class NetworkPolicy:
    namespace: str
    name: str
    pod_selector: LabelSelector
    policy_types: Tuple[str, ...]
    ingress: Tuple[Rule, ...]
    egress: Tuple[Rule, ...]

    @property
    def id(self) -> str:
        return f"{self.namespace}/{self.name}"


# ---------------------------------------------------------------- parsing
def _map(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{where}: must be a mapping, got {value!r}")
    return value


def _opt_list(value: Any, where: str) -> list:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise PolicyError(f"{where}: must be a list, got {value!r}")
    return list(value)


def _check_keys(obj: Mapping[str, Any], allowed: set, where: str) -> None:
    unknown = set(obj) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown fields {sorted(map(str, unknown))}")


def _selector(raw: Any, where: str) -> LabelSelector:
    try:
        return parse_selector(raw)
    except SelectorError as exc:
        raise PolicyError(f"{where}: {exc}") from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_numeric_port(value: Any, where: str) -> int:
    if not _is_int(value) or not 1 <= value <= 65535:
        raise PolicyError(f"{where}: must be an integer in 1..65535, got {value!r}")
    return value


def _valid_port_name(name: str) -> bool:  # IANA_SVC_NAME
    return (
        0 < len(name) <= 15
        and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) is not None
        and re.search(r"[a-z]", name) is not None
    )


def _parse_port(raw: Any, where: str) -> PortSpec:
    m = _map(raw, where)
    _check_keys(m, {"protocol", "port", "endPort"}, where)
    proto_raw = m.get("protocol")
    if proto_raw is None:
        protocol = Protocol.TCP  # API default
    else:
        try:
            protocol = Protocol(proto_raw)
        except ValueError:
            raise PolicyError(f"{where}.protocol: must be TCP, UDP or SCTP, got {proto_raw!r}") from None
    port, end = m.get("port"), m.get("endPort")
    if port is not None:
        if isinstance(port, str):
            if not _valid_port_name(port):
                raise PolicyError(f"{where}.port: invalid port name {port!r}")
        else:
            _check_numeric_port(port, f"{where}.port")
    if end is not None:
        if not _is_int(port):
            raise PolicyError(f"{where}.endPort: requires a numeric port (not absent or named)")
        _check_numeric_port(end, f"{where}.endPort")
        if end < port:
            raise PolicyError(f"{where}.endPort: must be >= port ({port})")
    return PortSpec(protocol, port, end)


def _parse_ip_block(raw: Any, where: str) -> str:
    m = _map(raw, where)
    _check_keys(m, {"cidr", "except"}, where)
    cidr = m.get("cidr")
    if not isinstance(cidr, str):
        raise PolicyError(f"{where}.cidr: required string")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise PolicyError(f"{where}.cidr: {exc}") from exc
    for i, exc_raw in enumerate(_opt_list(m.get("except"), f"{where}.except")):
        try:
            sub = ipaddress.ip_network(exc_raw, strict=False)
        except (ValueError, TypeError) as exc:
            raise PolicyError(f"{where}.except[{i}]: {exc}") from exc
        if sub.version != net.version or not sub.subnet_of(net):
            raise PolicyError(f"{where}.except[{i}]: {exc_raw!r} is outside {cidr}")
    return cidr


def _parse_peer(raw: Any, where: str) -> Peer:
    m = _map(raw, where)
    _check_keys(m, {"podSelector", "namespaceSelector", "ipBlock"}, where)
    if not m:
        raise PolicyError(f"{where}: peer must specify podSelector, namespaceSelector or ipBlock")
    if "ipBlock" in m and ("podSelector" in m or "namespaceSelector" in m):
        raise PolicyError(f"{where}: ipBlock cannot be combined with selectors")
    return Peer(
        pod_selector=_selector(m["podSelector"], f"{where}.podSelector") if "podSelector" in m else None,
        namespace_selector=(
            _selector(m["namespaceSelector"], f"{where}.namespaceSelector")
            if "namespaceSelector" in m
            else None
        ),
        exceptions=tuple(m.get("ipBlock", {}).get("except", [])),
        ip_block=_parse_ip_block(m["ipBlock"], f"{where}.ipBlock") if "ipBlock" in m else None,
    )


def _parse_rule(raw: Any, direction: str, where: str) -> Rule:
    m = _map(raw, where)
    peer_key = "from" if direction == INGRESS else "to"
    _check_keys(m, {peer_key, "ports"}, where)
    peers = tuple(
        _parse_peer(p, f"{where}.{peer_key}[{i}]") for i, p in enumerate(_opt_list(m.get(peer_key), where))
    )
    ports = tuple(
        _parse_port(p, f"{where}.ports[{i}]") for i, p in enumerate(_opt_list(m.get("ports"), where))
    )
    return Rule(peers, ports)


def parse_policy(doc: Any) -> NetworkPolicy:
    """Validate one networking.k8s.io/v1 NetworkPolicy document."""
    m = _map(doc, "policy")
    meta = _map(m.get("metadata"), "metadata")
    name, ns = meta.get("name"), meta.get("namespace")
    if not isinstance(name, str) or not name or not isinstance(ns, str) or not ns:
        raise PolicyError("metadata.name and metadata.namespace must be non-empty strings")
    where = f"{ns}/{name}"
    spec = _map(m.get("spec"), f"{where}.spec")
    _check_keys(spec, {"podSelector", "policyTypes", "ingress", "egress"}, f"{where}.spec")
    if "podSelector" not in spec:
        raise PolicyError(f"{where}.spec.podSelector: required (use {{}} to select all Pods)")
    pod_selector = _selector(spec["podSelector"], f"{where}.spec.podSelector")

    ingress = tuple(
        _parse_rule(r, INGRESS, f"{where}.ingress[{i}]")
        for i, r in enumerate(_opt_list(spec.get("ingress"), where))
    )
    egress = tuple(
        _parse_rule(r, EGRESS, f"{where}.egress[{i}]")
        for i, r in enumerate(_opt_list(spec.get("egress"), where))
    )

    types_raw = _opt_list(spec.get("policyTypes"), f"{where}.spec.policyTypes")
    if types_raw:
        if any(t not in (INGRESS, EGRESS) for t in types_raw) or len(set(types_raw)) != len(types_raw):
            raise PolicyError(f"{where}.spec.policyTypes: must be unique values from Ingress/Egress")
        types = tuple(types_raw)
    else:  # API default: Ingress always; Egress only if egress rules exist
        types = (INGRESS, EGRESS) if egress else (INGRESS,)
    return NetworkPolicy(ns, name, pod_selector, types, ingress, egress)


# ---------------------------------------------------------------- results / trace
@dataclass(frozen=True)
class RuleMatch:
    policy: str
    rule_index: int
    certain: bool  # False: rule might match, but a peer (ipBlock) cannot be resolved


@dataclass(frozen=True)
class DirectionResult:
    direction: str
    endpoint: str  # Pod whose policies were evaluated
    isolated: bool
    verdict: Verdict
    reason: str  # unisolated | rule-match | no-rule-match | unresolved-peer
    selecting_policies: Tuple[str, ...] = ()
    matched_rules: Tuple[RuleMatch, ...] = ()


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    egress: Optional[DirectionResult] = None
    ingress: Optional[DirectionResult] = None


# ---------------------------------------------------------------- evaluation
def _any3(results: Iterable[Optional[bool]]) -> Optional[bool]:
    results = list(results)
    if True in results:
        return True
    return None if None in results else False


def _and3(a: Optional[bool], b: Optional[bool]) -> Optional[bool]:
    if a is False or b is False:
        return False
    return None if (a is None or b is None) else True


def _pod_id(pod: Pod) -> str:
    return f"{pod.namespace}/{pod.name}"


class Evaluator:
    def __init__(self, topology: Topology, policies: Iterable[Mapping[str, Any]]):
        self.topology = topology
        self.policies: List[NetworkPolicy] = []
        self.unsupported: List[str] = []
        self._selection_cache = {}
        seen = set()
        for doc in policies:
            d = _map(doc, "policy")
            api, kind = d.get("apiVersion"), d.get("kind")
            if not isinstance(api, str) or not isinstance(kind, str):
                raise PolicyError("policy: apiVersion and kind are required strings")
            if (api, kind) != (API_VERSION, KIND):
                self.unsupported.append(f"{api}/{kind}")  # could influence any query
                continue
            pol = parse_policy(d)
            if pol.namespace not in topology.namespaces:
                raise PolicyError(f"{pol.id}: namespace {pol.namespace!r} is not in the topology")
            if pol.id in seen:
                raise PolicyError(f"duplicate policy identity: {pol.id}")
            seen.add(pol.id)
            self.policies.append(pol)

    def evaluate(self, q: ConnectionQuery) -> Decision:
        if self.unsupported:
            return Decision(Verdict.UNKNOWN, "unsupported-resource")
        src = q.source if isinstance(q.source, ExternalEndpoint) else self.topology.pods.get(q.source.key)
        dst = (
            q.destination
            if isinstance(q.destination, ExternalEndpoint)
            else self.topology.pods.get(q.destination.key)
        )
        if src is None or dst is None:
            return Decision(Verdict.UNKNOWN, "pod-not-in-topology")
        if getattr(src, "unsupported", False) or getattr(dst, "unsupported", False):
            return Decision(Verdict.UNKNOWN, "host-network-unsupported")
        if isinstance(src, ExternalEndpoint) and isinstance(dst, ExternalEndpoint):
            return Decision(Verdict.UNKNOWN, "external-to-external-unsupported")
        if isinstance(src, ExternalEndpoint):
            i = self._direction(INGRESS, dst, src, dst, q)
            return Decision(i.verdict, "pod-side-ingress-only", ingress=i)
        if isinstance(dst, ExternalEndpoint):
            e = self._direction(EGRESS, src, dst, dst, q)
            return Decision(e.verdict, "pod-side-egress-only", egress=e)
        if src.key == dst.key:
            return Decision(Verdict.UNKNOWN, "self-traffic-unsupported")

        egress = self._direction(EGRESS, src, dst, dst, q)
        ingress = self._direction(INGRESS, dst, src, dst, q)
        e, i = egress.verdict, ingress.verdict
        if e is Verdict.DENY and i is Verdict.DENY:
            verdict, reason = Verdict.DENY, "egress-and-ingress-denied"
        elif e is Verdict.DENY:
            verdict, reason = Verdict.DENY, "egress-denied"
        elif i is Verdict.DENY:
            verdict, reason = Verdict.DENY, "ingress-denied"
        elif e is Verdict.ALLOW and i is Verdict.ALLOW:
            verdict, reason = Verdict.ALLOW, "allowed"
        else:
            verdict, reason = Verdict.UNKNOWN, "unresolved-peer"
        return Decision(verdict, reason, egress, ingress)

    # endpoint: Pod whose policies apply; peer: the other end; dest: destination Pod (port resolution)
    def _direction(
        self, direction: str, endpoint: Pod, peer: Pod, dest: Pod, q: ConnectionQuery
    ) -> DirectionResult:
        cache_key = (direction, endpoint.key)
        selecting = self._selection_cache.get(cache_key)
        if selecting is None:
            selecting = [
                p
                for p in self.policies
                if p.namespace == endpoint.namespace
                and direction in p.policy_types
                and matches(p.pod_selector, endpoint.labels)
            ]
            self._selection_cache[cache_key] = selecting
        eid = _pod_id(endpoint)
        if not selecting:
            return DirectionResult(direction, eid, False, Verdict.ALLOW, "unisolated")

        matched: List[RuleMatch] = []
        for pol in selecting:
            rules = pol.ingress if direction == INGRESS else pol.egress
            for idx, rule in enumerate(rules):
                result = self._rule_result(pol, rule, peer, dest, q)
                if result is not False:
                    matched.append(RuleMatch(pol.id, idx, result is True))

        ids = tuple(p.id for p in selecting)
        if any(m.certain for m in matched):
            verdict, reason = Verdict.ALLOW, "rule-match"
        elif matched:
            verdict, reason = Verdict.UNKNOWN, "unresolved-peer"
        else:
            verdict, reason = Verdict.DENY, "no-rule-match"
        return DirectionResult(direction, eid, True, verdict, reason, ids, tuple(matched))

    def _rule_result(
        self, pol: NetworkPolicy, rule: Rule, peer: Pod, dest: Pod, q: ConnectionQuery
    ) -> Optional[bool]:
        peer_r = _any3(self._peer_result(pol, p, peer) for p in rule.peers) if rule.peers else True
        port_r = _any3(self._port_result(p, dest, q) for p in rule.ports) if rule.ports else True
        return _and3(peer_r, port_r)

    def _peer_result(self, pol: NetworkPolicy, peer: Peer, pod: Pod) -> Optional[bool]:
        if peer.ip_block is not None:
            if isinstance(pod, ExternalEndpoint):
                ip = ipaddress.ip_address(pod.ip)
                net = ipaddress.ip_network(peer.ip_block, strict=False)
                return ip in net and not any(
                    ip in ipaddress.ip_network(x, strict=False) for x in peer.exceptions
                )
            return None  # Pod IPs are not modelled; cannot decide
        if isinstance(pod, ExternalEndpoint):
            return False
        if peer.namespace_selector is not None:
            ns = self.topology.namespaces[pod.namespace]
            ns_labels = {**ns.labels, NS_NAME_LABEL: ns.name}
            if not matches(peer.namespace_selector, ns_labels):
                return False
        elif pod.namespace != pol.namespace:  # pod-only peer: policy's own namespace
            return False
        if peer.pod_selector is not None and not matches(peer.pod_selector, pod.labels):
            return False
        return True

    @staticmethod
    def _port_result(spec: PortSpec, dest: Pod, q: ConnectionQuery) -> Optional[bool]:
        if spec.protocol != q.protocol:
            return False
        if spec.port is None:
            return True
        if isinstance(spec.port, str):  # named: resolve at destination Pod
            if isinstance(dest, ExternalEndpoint):
                return None
            return any(
                cp.name == spec.port and cp.protocol == spec.protocol and cp.port == q.port
                for cp in dest.ports
            )
        if spec.end_port is None:
            return q.port == spec.port
        return spec.port <= q.port <= spec.end_port
