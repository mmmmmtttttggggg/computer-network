"""Bounded, strict project ingestion. Imported workloads are data, never executed."""

from __future__ import annotations
import copy
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any
import yaml
from app.model.topology import (
    Namespace,
    Pod,
    ContainerPort,
    Protocol,
    ConnectionQuery,
    Topology,
    ExternalEndpoint,
)
from app.model.evaluator import Evaluator
from app.review.intents import Intent, parse_intent, _endpoint_matches
from app.review.comparison import Approval
from app.model.evaluator import Verdict
from app.util import digest

MAX_INPUT = 5 * 1024 * 1024
MAX_QUERIES = 17400
MAX_PODS = 30
MAX_POLICIES = 100
MAX_NAMESPACES = 5
MAX_NODES = 150000


class InputError(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise InputError("YAML aliases are not accepted; expand anchors explicitly")
        self._depth = getattr(self, "_depth", 0) + 1
        if self._depth > 60:
            raise InputError("YAML nesting exceeds 60 levels")
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _mapping(loader, node, deep=False):
    out = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise InputError(f"Line {key_node.start_mark.line + 1}: object keys must be strings")
        if key in out:
            raise InputError(f"Line {key_node.start_mark.line + 1}: duplicate key {key!r}")
        out[key] = loader.construct_object(value_node, deep=deep)
    return out


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _bounded(value, depth=0, counter=None):
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if depth > 60 or counter[0] > MAX_NODES:
        raise InputError("Input structure exceeds safety limits")
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            raise InputError("Object keys must be strings")
        for v in value.values():
            _bounded(v, depth + 1, counter)
    elif isinstance(value, list):
        for v in value:
            _bounded(v, depth + 1, counter)
    elif value is not None and not isinstance(value, (str, bool, int, float)):
        raise InputError("Input contains unsupported scalar values")


def load_text(text: str) -> Any:
    if not isinstance(text, str) or len(text.encode()) > MAX_INPUT:
        raise InputError("Input exceeds 5 MiB")
    try:
        docs = list(yaml.load_all(text, Loader=StrictLoader))
        docs = [d for d in docs if d is not None]
    except (yaml.YAMLError, RecursionError) as e:
        raise InputError(f"Invalid YAML/JSON: {e}") from None
    if len(docs) != 1:
        raise InputError(
            "Project file must contain one object; use multi-document YAML inside resource fields"
        )
    _bounded(docs[0])
    return docs[0]


def resources(raw: Any, where: str) -> list[dict]:
    if isinstance(raw, str):
        try:
            raw = [d for d in yaml.load_all(raw, Loader=StrictLoader) if d is not None]
        except yaml.YAMLError as e:
            raise InputError(f"{where}: {e}") from None
    if isinstance(raw, dict):
        raw = raw.get("items", []) if raw.get("kind") == "List" else [raw]
    if not isinstance(raw, list):
        raise InputError(f"{where}: expected resource list or YAML text")
    if any(not isinstance(d, dict) for d in raw):
        raise InputError(f"{where}: every resource must be an object")
    if len(raw) > 1000:
        raise InputError(f"{where}: too many resource documents")
    _bounded(raw)
    return copy.deepcopy(raw)


def name(value: Any, where: str, *, namespace=False):
    limit = 63 if namespace else 253
    if (
        not isinstance(value, str)
        or len(value) > limit
        or not re.fullmatch(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*", value)
    ):
        raise InputError(f"{where}: invalid Kubernetes name {value!r}")
    if namespace and "." in value:
        raise InputError(f"{where}: namespace names cannot contain dots")
    return value


def labels(value: Any, where: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
    ):
        raise InputError(f"{where}: labels must map strings to strings (quote numbers/booleans)")
    for k, v in value.items():
        parts = k.split("/")
        if len(parts) > 2:
            raise InputError(f"{where}: invalid label key {k!r}")
        key = parts[-1]
        if len(key) > 63 or not re.fullmatch(r"[a-zA-Z0-9](?:[-_.a-zA-Z0-9]*[a-zA-Z0-9])?", key):
            raise InputError(f"{where}: invalid label key {k!r}")
        if len(parts) == 2 and (
            len(parts[0]) > 253 or not re.fullmatch(r"[a-z0-9](?:[-.a-z0-9]*[a-z0-9])?", parts[0])
        ):
            raise InputError(f"{where}: invalid label prefix")
        if len(v) > 63 or (v and not re.fullmatch(r"[a-zA-Z0-9](?:[-_.a-zA-Z0-9]*[a-zA-Z0-9])?", v)):
            raise InputError(f"{where}: invalid label value {v!r}")
    return dict(value)


@dataclass
class Project:
    raw: dict
    topology: Topology
    baseline: list[dict]
    candidate: list[dict]
    intents: list[Intent]
    queries: list[ConnectionQuery]
    approvals: list[Approval]
    warnings: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    workload_meta: dict = field(default_factory=dict)

    @property
    def fingerprint(self):
        return digest(self.raw)


def _parse_project(raw: Any) -> Project:
    if isinstance(raw, str):
        raw = load_text(raw)
    if not isinstance(raw, dict):
        raise InputError("Project must be an object")
    _bounded(raw)
    try:
        size = len(json.dumps(raw, allow_nan=False).encode())
    except (TypeError, ValueError, RecursionError):
        raise InputError("Project must contain finite JSON-compatible data") from None
    if size > MAX_INPUT:
        raise InputError("Input exceeds 5 MiB")
    allowed = {
        "schemaVersion",
        "name",
        "description",
        "topology",
        "baseline",
        "candidate",
        "intents",
        "queries",
        "ports",
        "approvals",
        "threatModel",
    }
    if set(raw) - allowed:
        raise InputError(f"Unknown project fields: {sorted(set(raw) - allowed)}")
    if type(raw.get("schemaVersion", 1)) is not int or raw.get("schemaVersion", 1) != 1:
        raise InputError("schemaVersion must be 1")
    if not isinstance(raw.get("name", "Untitled review"), str) or len(raw.get("name", "")) > 200:
        raise InputError("name must be a string up to 200 characters")
    if not isinstance(raw.get("description", ""), str) or len(raw.get("description", "")) > 4000:
        raise InputError("description must be a string up to 4000 characters")
    for key in ["topology", "baseline", "candidate", "intents"]:
        if key not in raw:
            raise InputError(f"Missing required field: {key}")
    top = Topology()
    warnings = []
    excluded = []
    meta = {}
    docs = resources(raw["topology"], "topology")
    for doc in docs:
        if doc.get("kind") == "Namespace":
            if doc.get("apiVersion") != "v1":
                raise InputError("Namespace requires apiVersion v1")
            m = doc.get("metadata", {})
            ns = name(m.get("name"), "Namespace.name", namespace=True)
            labs = labels(m.get("labels", {}), f"{ns}.labels")
            if "kubernetes.io/metadata.name" in labs and labs["kubernetes.io/metadata.name"] != ns:
                raise InputError("Namespace name label does not match its name")
            top.add_namespace(Namespace(ns, labs))
    for doc in docs:
        kind = doc.get("kind")
        m = doc.get("metadata", {})
        if not isinstance(m, dict):
            raise InputError("Resource metadata must be an object")
        if kind not in ["Pod", "Deployment", "Namespace"]:
            excluded.append(str(kind))
            continue
        if kind == "Namespace":
            continue
        if doc.get("apiVersion") != ("v1" if kind == "Pod" else "apps/v1"):
            raise InputError(f"{kind}: invalid apiVersion")
        ns = name(m.get("namespace"), f"{kind}.metadata.namespace", namespace=True)
        pn = name(m.get("name"), f"{kind}.metadata.name")
        spec = doc.get("spec", {})
        if not isinstance(spec, dict):
            raise InputError(f"{ns}/{pn}: spec must be an object")
        if kind == "Deployment":
            template = spec.get("template", {})
            m = template.get("metadata", {})
            spec = template.get("spec", {})
            warnings.append(
                f"{ns}/{pn}: Deployment template represents one logical endpoint, not running replicas"
            )
        containers = spec.get("containers", [])
        if not isinstance(containers, list) or not containers:
            raise InputError(f"{ns}/{pn}: at least one container is required")
        ports = []
        names = set()
        for c in containers:
            if not isinstance(c, dict):
                raise InputError(f"{ns}/{pn}: invalid container")
            for cp in c.get("ports", []):
                port = ContainerPort(
                    cp.get("containerPort"), Protocol(cp.get("protocol", "TCP")), cp.get("name")
                )
                if port.name:
                    from app.model.evaluator import _valid_port_name

                    if not _valid_port_name(port.name) or port.name in names:
                        raise InputError(f"{ns}/{pn}: invalid/ambiguous named port {port.name!r}")
                    names.add(port.name)
                ports.append(port)
        annotations = m.get("annotations", {})
        meta[f"{ns}/{pn}"] = {
            "origin": kind,
            "hostNetwork": bool(spec.get("hostNetwork", False)),
            "serviceAccount": spec.get("serviceAccountName", "default"),
            "tokenAutomount": spec.get("automountServiceAccountToken", True),
            "role": annotations.get("netscope.io/role", "workload")
            if isinstance(annotations, dict)
            else "workload",
        }
        top.add_pod(
            Pod(
                pn,
                ns,
                labels(m.get("labels", {}), f"{ns}/{pn}.labels"),
                tuple(ports),
                unsupported=bool(spec.get("hostNetwork", False)),
            )
        )
    if not top.pods:
        raise InputError("Topology must include at least one Pod or Deployment template")
    if len(top.pods) > MAX_PODS or len(top.namespaces) > MAX_NAMESPACES:
        raise InputError("Reference limits: 30 endpoints and 5 namespaces")
    base = resources(raw["baseline"], "baseline")
    cand = resources(raw["candidate"], "candidate")
    for phase, policies in [("baseline", base), ("candidate", cand)]:
        if len(policies) > MAX_POLICIES:
            raise InputError(f"{phase}: at most 100 policies")
        for d in policies:
            if d.get("kind") == "NetworkPolicy" and d.get("apiVersion") == "networking.k8s.io/v1":
                md = d.get("metadata", {})
                name(md.get("name"), f"{phase}.metadata.name")
                name(md.get("namespace"), f"{phase}.metadata.namespace", namespace=True)
                spec = d.get("spec", {})
                if spec.get("ingress") and spec.get("policyTypes") == ["Egress"]:
                    raise InputError(f"{phase}: ingress rules require Ingress policyType")
                if spec.get("egress") and spec.get("policyTypes") == ["Ingress"]:
                    raise InputError(f"{phase}: egress rules require Egress policyType")

        def validate_selectors(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key in ["podSelector", "namespaceSelector"] and isinstance(value, dict):
                        labels(value.get("matchLabels", {}), f"{phase}.{key}.matchLabels")
                        for expr in value.get("matchExpressions", []) or []:
                            if isinstance(expr, dict):
                                labels({expr.get("key"): ""}, f"{phase}.{key}.expression")
                                for v in expr.get("values", []) or []:
                                    labels({"value": v}, f"{phase}.{key}.expression.values")
                    validate_selectors(value)
            elif isinstance(obj, list):
                for value in obj:
                    validate_selectors(value)

        for doc in policies:
            if doc.get("kind") == "NetworkPolicy":
                validate_selectors(doc.get("spec", {}))
        Evaluator(top, policies)
    if not isinstance(raw["intents"], list):
        raise InputError("intents must be a list")
    intents = [parse_intent(i) for i in raw["intents"]]
    if len({i.id for i in intents}) != len(intents):
        raise InputError("Duplicate intent ID")
    if not intents:
        warnings.append("No application intents supplied; review cannot certify required behaviour")
    queries = {}

    def endpoint(value):
        if not isinstance(value, str):
            raise InputError("Endpoint must be namespace/name or external:IP")
        if value.startswith("external:"):
            ip = str(ipaddress.ip_address(value[9:]))
            return ExternalEndpoint(ip)
        if value.count("/") != 1:
            raise InputError(f"Endpoint must be namespace/name: {value!r}")
        ns, pn = value.split("/")
        return top.get_pod(ns, pn)

    def add(src, dst, proto, port):
        q = ConnectionQuery(src, dst, Protocol(proto), port)
        queries[(src.key, dst.key, q.protocol.value, port)] = q
        if len(queries) > MAX_QUERIES:
            raise InputError("Query scope exceeds 17,400; provide a smaller explicit query list")

    if "queries" in raw:
        if not isinstance(raw["queries"], list):
            raise InputError("queries must be a list")
        for q in raw["queries"]:
            if set(q) - {"source", "destination", "protocol", "port"}:
                raise InputError("Unknown query field")
            add(endpoint(q["source"]), endpoint(q["destination"]), q.get("protocol", "TCP"), q["port"])
    else:
        portset = {(p.protocol.value, p.port) for pod in top.pods.values() for p in pod.ports}
        for p in raw.get("ports", []):
            portset.add((p.get("protocol", "TCP"), p["port"]))
        portset |= {(i.protocol.value, i.port) for i in intents}
        for src in top.pods.values():
            for dst in top.pods.values():
                if src.key != dst.key:
                    for proto, port in sorted(portset):
                        add(src, dst, proto, port)
    # Intent coverage is mandatory even if an explicit query list omits it.
    for i in intents:
        for src in top.pods.values():
            for dst in top.pods.values():
                if (
                    src.key != dst.key
                    and _endpoint_matches(i.source, src, top)
                    and _endpoint_matches(i.destination, dst, top)
                ):
                    add(src, dst, i.protocol, i.port)
    if not queries:
        raise InputError("Query set is empty; declare ports, intents, or explicit queries")
    if len({(q.protocol, q.port) for q in queries.values()}) > 20:
        raise InputError("At most 20 protocol/port combinations per run")
    approvals = []
    for a in raw.get("approvals", []):
        if set(a) != {"tuple_id", "baseline", "candidate"}:
            raise InputError("Approval requires exact tuple_id, baseline and candidate")
        approvals.append(Approval(a["tuple_id"], Verdict(a["baseline"]), Verdict(a["candidate"])))
    threat = raw.get("threatModel", {})
    if not isinstance(threat, dict) or set(threat) - {"entrypoints", "pivots", "assets", "description"}:
        raise InputError("Invalid threatModel fields")
    for k in ["entrypoints", "pivots", "assets"]:
        entries = threat.get(k, [])
        if not isinstance(entries, list) or len(entries) > 30:
            raise InputError(f"threatModel.{k} must be a list of endpoint IDs")
        if any(not isinstance(v, str) for v in entries) or len(set(entries)) != len(entries):
            raise InputError(f"threatModel.{k} requires unique endpoint IDs")
        for v in entries:
            ep = endpoint(v)
            if isinstance(ep, ExternalEndpoint):
                raise InputError("Threat model endpoints must be Pods/templates")
    # Persist only model-relevant workload data. Imported application commands,
    # environment values, mounts and container images are never retained in a
    # saved project or replay bundle. Labels must remain because they affect policy.
    sanitized = []
    for doc in docs:
        if doc.get("kind") == "Secret":
            raise InputError("Secret objects are not accepted or stored")
        if doc.get("kind") not in ["Namespace", "Pod", "Deployment"]:
            continue
        clean = copy.deepcopy(doc)
        md = clean.get("metadata", {})
        clean["metadata"] = {k: md[k] for k in ["name", "namespace", "labels", "uid"] if k in md}
        if doc.get("kind") != "Namespace":
            spec = clean["spec"]
            if doc["kind"] == "Deployment":
                template = spec["template"]
                tm = template.get("metadata", {})
                template["metadata"] = {k: tm[k] for k in ["labels"] if k in tm}
                if tm.get("annotations", {}).get("netscope.io/role"):
                    template["metadata"]["annotations"] = {
                        "netscope.io/role": tm["annotations"]["netscope.io/role"]
                    }
                target = template["spec"]
            else:
                target = spec
                if md.get("annotations", {}).get("netscope.io/role"):
                    clean["metadata"]["annotations"] = {
                        "netscope.io/role": md["annotations"]["netscope.io/role"]
                    }
            safe_spec = {
                k: target[k]
                for k in ["hostNetwork", "automountServiceAccountToken", "serviceAccountName"]
                if k in target
            }
            safe_spec["containers"] = [
                {"name": c.get("name", "app"), "image": "data-only/not-executed", "ports": c.get("ports", [])}
                for c in target["containers"]
            ]
            if doc["kind"] == "Deployment":
                template["spec"] = safe_spec
                clean["spec"] = {k: spec[k] for k in ["replicas", "selector", "template"] if k in spec}
            else:
                clean["spec"] = safe_spec
        sanitized.append(clean)
    canonical = copy.deepcopy(raw)
    canonical["topology"] = sanitized
    canonical["baseline"] = base
    canonical["candidate"] = cand
    for policies in [base, cand]:
        for pol in policies:
            if pol.get("kind") == "Secret":
                raise InputError("Secret objects are not accepted or stored")
            md = pol.get("metadata", {})
            pol["metadata"] = {k: md[k] for k in ["name", "namespace", "labels"] if k in md}
    return Project(
        canonical,
        top,
        base,
        cand,
        intents,
        [queries[k] for k in sorted(queries)],
        approvals,
        warnings,
        excluded,
        meta,
    )


def parse_project(raw: Any) -> Project:
    """Public ingestion boundary: malformed data always yields an input error."""
    try:
        return _parse_project(raw)
    except InputError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise InputError(f"Invalid project: {exc}") from None
