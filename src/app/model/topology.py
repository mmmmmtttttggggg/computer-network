"""Simple typed topology model: namespaces, Pods, ports, and connection queries."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    SCTP = "SCTP"


def _check_port(port: int, what: str) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"{what} must be an integer in 1..65535, got {port!r}")


@dataclass(frozen=True)
class Namespace:
    name: str
    labels: Dict[str, str] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Namespace name must be non-empty")


@dataclass(frozen=True)
class ContainerPort:
    port: int
    protocol: Protocol = Protocol.TCP  # Kubernetes default
    name: Optional[str] = None

    def __post_init__(self) -> None:
        _check_port(self.port, "container port")


@dataclass(frozen=True)
class Pod:
    name: str
    namespace: str
    labels: Dict[str, str] = field(default_factory=dict, hash=False)
    ports: Tuple[ContainerPort, ...] = ()
    unsupported: bool = False

    def __post_init__(self) -> None:
        if not self.name or not self.namespace:
            raise ValueError("Pod name and namespace must be non-empty")

    @property
    def key(self) -> Tuple[str, str]:
        return (self.namespace, self.name)


@dataclass(frozen=True)
class ConnectionQuery:
    source: Pod
    destination: Pod
    protocol: Protocol
    port: int  # numeric destination port

    def __post_init__(self) -> None:
        _check_port(self.port, "destination port")


@dataclass
class Topology:
    namespaces: Dict[str, Namespace] = field(default_factory=dict)
    pods: Dict[Tuple[str, str], Pod] = field(default_factory=dict)

    def add_namespace(self, ns: Namespace) -> None:
        if ns.name in self.namespaces:
            raise ValueError(f"duplicate namespace: {ns.name}")
        self.namespaces[ns.name] = ns

    def add_pod(self, pod: Pod) -> None:
        if pod.namespace not in self.namespaces:
            raise ValueError(f"Pod {pod.name!r} references unknown namespace {pod.namespace!r}")
        if pod.key in self.pods:
            raise ValueError(f"duplicate Pod: {pod.namespace}/{pod.name}")
        self.pods[pod.key] = pod

    def get_pod(self, namespace: str, name: str) -> Pod:
        try:
            return self.pods[(namespace, name)]
        except KeyError:
            raise KeyError(f"unknown Pod: {namespace}/{name}") from None

    def pods_in_namespace(self, namespace: str) -> Tuple[Pod, ...]:
        return tuple(p for p in self.pods.values() if p.namespace == namespace)


@dataclass(frozen=True)
class ExternalEndpoint:
    """Declared external IP. Only the Pod-side policy direction is modelled."""

    ip: str

    @property
    def namespace(self):
        return "@external"

    @property
    def name(self):
        return self.ip

    @property
    def key(self):
        return (self.namespace, self.ip)

    @property
    def ports(self):
        return ()

    @property
    def labels(self):
        return {}
