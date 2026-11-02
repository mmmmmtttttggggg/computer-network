"""Explicitly authorized real-cluster runner. No simulated evidence is emitted.

Requires a separately created disposable kind cluster and explicit context /
server allowlist. Transport is kubectl argv, never shell interpolation.
"""

from __future__ import annotations
import copy
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from urllib.parse import urlsplit
from concurrent.futures import ThreadPoolExecutor
from app.ingest.project import parse_project
from app.service import review_project, utcnow, VERSION
from app.runtime.fixture import PROGRAM
from app.runtime.verdicts import classify_observation
from app.runtime.evidence import summarize_coverage
from app.util import digest

OWN = "netscope.io/run-id"
CONTROL_NS = "netscope-controls"
# This image is only an explicit local development default. Supply a digest in
# NETSCOPE_FIXTURE_IMAGE for release evidence; the runner records resolved imageIDs.
DEFAULT_IMAGE = "python:3.12.8-alpine3.21"


class RuntimeErrorSafe(ValueError):
    pass


class Kubectl:
    def __init__(self, context):
        if not shutil.which("kubectl"):
            raise RuntimeErrorSafe(
                "kubectl is unavailable. Static review works; real runtime is not verified."
            )
        self.context = context

    def call(self, args, body=None, timeout=30):
        cmd = ["kubectl", "--context", self.context, "--request-timeout=20s", *args]
        try:
            r = subprocess.run(
                cmd,
                input=None if body is None else json.dumps(body),
                text=True,
                capture_output=True,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise RuntimeErrorSafe(f"Kubernetes request failed: {type(e).__name__}") from None
        if r.returncode:
            raise RuntimeErrorSafe((r.stderr or r.stdout or "Kubernetes operation failed")[-1200:])
        return r.stdout

    def get(self, kind, namespace=None, name=None):
        args = ["get", kind]
        if name:
            args.append(name)
        if namespace:
            args += ["-n", namespace]
        return json.loads(self.call(args + ["-o", "json"]))

    def create(self, obj):
        return self.call(["create", "-f", "-"], obj)

    def config(self):
        return json.loads(self.call(["config", "view", "--minify", "-o", "json"]))


def runtime_preflight(raw, context, allowed_contexts):
    p = parse_project(raw)
    r = review_project(p)
    if context not in allowed_contexts:
        raise RuntimeErrorSafe(
            "Context is not in NETSCOPE_ALLOWED_CONTEXTS. Only a disposable test cluster may be allowlisted."
        )
    if any(n["origin"] != "Pod" or n["hostNetwork"] for n in r["nodes"]):
        raise RuntimeErrorSafe(
            "Initial live runner requires Pod snapshots without host networking; Deployment templates remain static-only."
        )
    if not r["plan"]["complete_supported"]:
        raise RuntimeErrorSafe(
            "Plan is empty, exceeds 300 tuples/phase, or includes unsupported/Unknown tuples; live coverage is incomplete."
        )
    for n in p.topology.namespaces:
        if n in ["default", "kube-system", "kube-public", "kube-node-lease", CONTROL_NS] or n.startswith(
            "kube-"
        ):
            raise RuntimeErrorSafe(f"Reserved namespace cannot be used: {n}")
    for row in r["plan"]["tuples"]:
        if row["port"] < 1024:
            raise RuntimeErrorSafe(
                "Trusted non-root fixtures currently support ports 1024..65535 only. This plan is not live-verifiable."
            )
    return p, r


def run_live(raw, context, allowed_contexts, *, cancel=None, progress=None, transport=None):
    cancel = cancel or threading.Event()
    progress = progress or (lambda x: None)
    p, report = runtime_preflight(raw, context, allowed_contexts)
    k = transport or Kubectl(context)
    rid = uuid.uuid4().hex[:24]
    result = {
        "run_id": rid,
        "tool_version": VERSION,
        "hashes": report["hashes"],
        "context": context,
        "input_hash": p.fingerprint,
        "plan_hash": report["plan"]["hash"],
        "started_at": utcnow(),
        "state": "RUNNING",
        "exit_code": 2,
        "observations": [],
        "events": [],
        "runtime_status": "INCOMPLETE",
        "leftovers": [],
        "mutations": [],
        "environment": {},
    }
    deadline = [None]
    namespace_uids = {}
    created = []
    policy_names = []
    pod_info = {}
    image = os.environ.get("NETSCOPE_FIXTURE_IMAGE", DEFAULT_IMAGE)
    control_protocols = sorted({"TCP"} | {row["protocol"] for row in report["plan"]["tuples"]})

    def event(message):
        result["coverage"] = summarize_coverage(report, result)
        result["events"].append({"at": utcnow(), "message": message})
        progress(copy.deepcopy(result))

    def stop():
        if deadline[0] is not None and time.monotonic() > deadline[0]:
            raise RuntimeErrorSafe("Live test budget exceeded (10 minutes after fixture readiness)")
        if cancel.is_set():
            raise RuntimeErrorSafe("Cancelled; unfinished work remains incomplete")

    def wait(seconds):
        if cancel.wait(seconds):
            stop()

    def owned(obj):
        return obj.get("metadata", {}).get("annotations", {}).get(OWN) == rid

    def create(obj):
        stop()
        obj = copy.deepcopy(obj)
        obj.setdefault("metadata", {}).setdefault("annotations", {})[OWN] = rid
        change = {
            "action": "create",
            "kind": obj["kind"],
            "namespace": obj["metadata"].get("namespace"),
            "name": obj["metadata"]["name"],
            "state": "REQUESTED",
        }
        result["mutations"].append(change)
        progress(copy.deepcopy(result))
        k.create(obj)
        created.append((obj["kind"], obj["metadata"].get("namespace"), obj["metadata"]["name"]))
        if obj["kind"] == "Namespace":
            uid = k.get("namespace", name=obj["metadata"]["name"])["metadata"]["uid"]
            namespace_uids[obj["metadata"]["name"]] = uid
            change["uid"] = uid
        change["state"] = "CREATED"
        progress(copy.deepcopy(result))

    def pod(namespace, name, ports, labels=None):
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"namespace": namespace, "name": name, "labels": labels or {}},
            "spec": {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001},
                "containers": [
                    {
                        "name": "fixture",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "-c", PROGRAM, "serve", json.dumps(ports)],
                        "ports": [{"containerPort": v, "protocol": proto} for v, proto in ports],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "requests": {"cpu": "10m", "memory": "20Mi"},
                            "limits": {"cpu": "250m", "memory": "64Mi"},
                        },
                    }
                ],
            },
        }

    def exec_probe(source, dest, port, proto):
        ns, pn = source.split("/")
        token = uuid.uuid4().hex
        at = utcnow()
        t = time.perf_counter()
        try:
            output = k.call(
                ["exec", "-n", ns, pn, "--", "python", "-c", PROGRAM, "probe", dest, str(port), proto, token],
                timeout=10,
            )
            data = json.loads(output.strip().splitlines()[-1])
            if data.get("outcome") not in ["success", "unreachable"]:
                data = {"outcome": "error", "error": "Invalid probe reply"}
        except Exception as e:
            data = {"outcome": "error", "error": str(e)[:500]}
        return {**data, "at": at, "duration_ms": round((time.perf_counter() - t) * 1000, 2)}

    def controls():
        # Dedicated controls test that the CNI enforces a known restriction. Pod
        # health is checked separately through API exec, not inferred from denies.
        records = {}
        for protocol in control_protocols:
            a = exec_probe(f"{CONTROL_NS}/source", pod_info[f"{CONTROL_NS}/allowed"]["ip"], 19090, protocol)
            d = exec_probe(f"{CONTROL_NS}/source", pod_info[f"{CONTROL_NS}/blocked"]["ip"], 19090, protocol)
            records[protocol] = {"allow": a, "deny": d}
        healthy = all(
            v["allow"]["outcome"] == "success" and v["deny"]["outcome"] == "unreachable"
            for v in records.values()
        )
        return healthy, {**records["TCP"], "by_protocol": records}

    def snapshot():
        state = {}
        for key, info in pod_info.items():
            ns, pn = key.split("/")
            obj = k.get("pod", ns, pn)
            state[key] = {
                "uid": obj["metadata"]["uid"],
                "ip": obj.get("status", {}).get("podIP"),
                "labels": obj["metadata"].get("labels", {}),
                "phase": obj.get("status", {}).get("phase"),
                "node": obj.get("spec", {}).get("nodeName"),
                "images": [x.get("imageID") for x in obj.get("status", {}).get("containerStatuses", [])],
            }
        return state

    try:
        stop()
        cfg = k.config()
        server = cfg["clusters"][0]["cluster"]["server"]
        url = urlsplit(server)
        if url.username or url.password or url.query or url.fragment:
            raise RuntimeErrorSafe("Credential-bearing or ambiguous API server URL is not accepted")
        result["environment"] = {
            "server": server,
            "kubernetes": json.loads(k.call(["version", "-o", "json"])).get("serverVersion"),
            "fixture_image_requested": image,
            "cni": "not auto-detected; record lab/versions.json with the exported run",
        }
        daemonsets = json.loads(k.call(["get", "daemonsets", "-A", "-o", "json"]))
        cni_images = [
            {
                "namespace": d["metadata"].get("namespace"),
                "name": d["metadata"]["name"],
                "images": [
                    c["image"]
                    for c in d.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
                ],
            }
            for d in daemonsets.get("items", [])
            if any(x in d["metadata"]["name"].lower() for x in ["calico", "cilium", "antrea"])
        ]
        if not cni_images:
            raise RuntimeErrorSafe(
                "No supported CNI DaemonSet identity found; environment version cannot be recorded"
            )
        result["environment"]["cni"] = cni_images
        # Explicit server binding prevents a context name from silently targeting a
        # different cluster. Allowlist must bind context -> exact server URL.
        expected = allowed_contexts[context] if isinstance(allowed_contexts, dict) else None
        if not expected or server != expected:
            raise RuntimeErrorSafe("Cluster server does not match the explicit context/server allowlist")
        existing = {x["metadata"]["name"] for x in k.get("namespaces")["items"]}
        if any(n in existing for n in [*p.topology.namespaces, CONTROL_NS]):
            raise RuntimeErrorSafe(
                "Test namespaces already exist. Refusing to adopt or mutate them; clean the previous lab first."
            )
        event("Cluster identity verified; creating owned test namespaces")
        for ns in p.topology.namespaces.values():
            create(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": ns.name, "labels": dict(ns.labels)},
                }
            )
        create({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": CONTROL_NS}})
        for endpoint in p.topology.pods.values():
            ports = {
                (cp.port, cp.protocol.value) for cp in endpoint.ports if cp.protocol.value in ["TCP", "UDP"]
            }
            ports |= {
                (row["port"], row["protocol"])
                for row in report["plan"]["tuples"]
                if row["destination"] == f"{endpoint.namespace}/{endpoint.name}"
            }
            obj = pod(endpoint.namespace, endpoint.name, sorted(ports), dict(endpoint.labels))
            for port in obj["spec"]["containers"][0]["ports"]:
                matches = [
                    cp.name
                    for cp in endpoint.ports
                    if cp.port == port["containerPort"] and cp.protocol.value == port["protocol"] and cp.name
                ]
                if matches:
                    port["name"] = matches[0]
            create(obj)
        for n in ["source", "allowed", "blocked"]:
            create(pod(CONTROL_NS, n, [(19090, protocol) for protocol in control_protocols], {"test": n}))
        for kind, ns, n in list(created):
            if kind == "Pod":
                stop()
                k.call(["wait", "--for=condition=Ready", "pod/" + n, "-n", ns, "--timeout=90s"], timeout=100)
                obj = k.get("pod", ns, n)
                pod_info[f"{ns}/{n}"] = {
                    "uid": obj["metadata"]["uid"],
                    "ip": obj["status"]["podIP"],
                    "node": obj.get("spec", {}).get("nodeName"),
                }
        # Verify unrestricted reachability for every planned tuple before policy
        # restrictions, so a dead listener cannot masquerade as a successful deny.
        result["fixtures_ready_at"] = utcnow()
        deadline[0] = time.monotonic() + 600
        event("Checking unrestricted listeners and network controls")
        for row in report["plan"]["tuples"]:
            stop()
            obs = exec_probe(row["source"], pod_info[row["destination"]]["ip"], row["port"], row["protocol"])
            if obs["outcome"] != "success":
                raise RuntimeErrorSafe("Unrestricted health check failed for " + row["tuple_id"])
        create(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"namespace": CONTROL_NS, "name": "known-deny"},
                "spec": {
                    "podSelector": {"matchLabels": {"test": "blocked"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [],
                },
            }
        )
        wait(10)
        healthy, control = controls()
        result["preflight_controls"] = control
        if not healthy:
            raise RuntimeErrorSafe("Known allow/deny controls failed; enforcement is not verified")
        reference = snapshot()
        if any(
            reference[key]["uid"] != info["uid"] or reference[key]["ip"] != info["ip"]
            for key, info in pod_info.items()
        ):
            raise RuntimeErrorSafe("Fixture identity changed before the reference snapshot")
        result["environment"]["pods"] = reference
        for phase, policies in [("baseline", p.baseline), ("candidate", p.candidate)]:
            stop()
            event("Applying " + phase + " policy set")
            for ns, n in policy_names:
                obj = k.get("networkpolicy", ns, n)
                if not owned(obj):
                    raise RuntimeErrorSafe("Policy ownership changed")
                k.call(
                    [
                        "delete",
                        "--raw",
                        f"/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{n}",
                        "-f",
                        "-",
                    ],
                    {
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "preconditions": {"uid": obj["metadata"]["uid"]},
                    },
                )
            policy_names = []
            for pol in policies:
                create(pol)
                policy_names.append((pol["metadata"]["namespace"], pol["metadata"]["name"]))
            applied = {}
            for pol in policies:
                md = pol["metadata"]
                read = k.get("networkpolicy", md["namespace"], md["name"])
                if not owned(read):
                    raise RuntimeErrorSafe("Applied policy not owned")
                # Model API defaults before comparing desired and observed semantics.
                from app.model.evaluator import parse_policy

                if parse_policy(read) != parse_policy(pol):
                    raise RuntimeErrorSafe("Policy read-back differs from requested input")
                applied[md["namespace"] + "/" + md["name"]] = digest(read["spec"])

            def drifted():
                if snapshot() != reference:
                    return True
                for ns in p.topology.namespaces:
                    live = k.get("networkpolicies", ns)["items"]
                    expected = {k_: v for k_, v in applied.items() if k_.startswith(ns + "/")}
                    actual = {ns + "/" + d["metadata"]["name"]: digest(d["spec"]) for d in live}
                    if actual != expected:
                        return True
                    nsobj = k.get("namespace", name=ns)
                    if nsobj["metadata"]["uid"] != namespace_uids[ns]:
                        return True
                    target = {**p.topology.namespaces[ns].labels, "kubernetes.io/metadata.name": ns}
                    if nsobj["metadata"].get("labels", {}) != target:
                        return True
                return False

            wait(10)
            healthy, ctrl_before = controls()
            if not healthy or drifted():
                raise RuntimeErrorSafe("Controls or input identity changed before probes")

            def probe_row(row):
                attempts = []
                for i in range(3):
                    if cancel.is_set():
                        break
                    attempts.append(
                        exec_probe(
                            row["source"], pod_info[row["destination"]]["ip"], row["port"], row["protocol"]
                        )
                    )
                    if i < 2:
                        wait(1)
                return {
                    "tuple_id": row["tuple_id"],
                    "phase": phase,
                    "model": row[phase],
                    "source_uid": pod_info[row["source"]]["uid"],
                    "destination_uid": pod_info[row["destination"]]["uid"],
                    "source_node": pod_info[row["source"]].get("node"),
                    "destination_node": pod_info[row["destination"]].get("node"),
                    "attempts": attempts,
                }

            # Batches permit control/drift checks between bounded parallel work.
            plan = report["plan"]["tuples"]
            for offset in range(0, len(plan), 10):
                stop()
                with ThreadPoolExecutor(max_workers=10) as pool:
                    batch = list(pool.map(probe_row, plan[offset : offset + 10]))
                healthy, ctrl_after = controls()
                drift = drifted()
                for obs in batch:
                    obs.update(
                        classify_observation(
                            obs["model"], obs["attempts"], controls_healthy=healthy, drift=drift
                        )
                    )
                    obs["controls"] = {"before": ctrl_before, "after": ctrl_after}
                    obs["drift"] = drift
                    result["observations"].append(obs)
                event(f"{phase}: {min(offset + 10, len(plan))}/{len(plan)} tuples tested")
                ctrl_before = ctrl_after
                if not healthy or drift:
                    raise RuntimeErrorSafe(
                        "Controls failed or drift detected; affected batch is inconclusive"
                    )
        complete = (
            report["exit_code"] != 2
            and all(o["complete"] for o in result["observations"])
            and len(result["observations"]) == 2 * len(report["plan"]["tuples"])
        )
        mismatch = any(o["mismatch"] for o in result["observations"])
        result["exit_code"] = (
            2 if not complete else (1 if mismatch or report["exit_code"] == 1 else report["exit_code"])
        )
        result["state"] = "COMPLETE" if complete else "INCOMPLETE"
        result["runtime_status"] = "VERIFIED_ON_SCOPE" if complete else "INCOMPLETE"
    except Exception as e:
        result["error"] = str(e)[:2000]
        result["state"] = "CANCELLED" if cancel.is_set() else "INCOMPLETE"
        result["exit_code"] = 2
        event("Stopped: " + result["error"])
    finally:
        # Namespaces are exclusively created for this run. UID and ownership must
        # still agree before deletion, so no unrelated namespace can be removed.
        for kind, ns, n in reversed(created):
            if kind != "Namespace":
                continue
            try:
                obj = k.get("namespace", name=n)
                if not owned(obj) or obj["metadata"]["uid"] != namespace_uids[n]:
                    raise RuntimeErrorSafe("ownership or namespace identity changed")
                uid = obj["metadata"]["uid"]
                k.call(
                    ["delete", "--raw", f"/api/v1/namespaces/{n}", "-f", "-"],
                    {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": uid}},
                )
                k.call(["wait", "--for=delete", "namespace/" + n, "--timeout=45s"], timeout=50)
            except Exception as e:
                result["leftovers"].append({"namespace": n, "reason": str(e)[:300]})
        confirmed_names = {n for kind, ns, n in created if kind == "Namespace"}
        for change in result["mutations"]:
            if change["kind"] == "Namespace" and change["name"] not in confirmed_names:
                result["leftovers"].append(
                    {
                        "namespace": change["name"],
                        "reason": "Creation result uncertain; inspect this namespace for the recorded run annotation before cleanup.",
                    }
                )
        if result["leftovers"]:
            result["exit_code"] = 2
            result["state"] = "INCOMPLETE"
            result["runtime_status"] = "INCOMPLETE"
        result["finished_at"] = utcnow()
        result["coverage"] = summarize_coverage(report, result)
        progress(copy.deepcopy(result))
    return result
