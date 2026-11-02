"""Scripted-adapter tests verify orchestration, not actual CNI enforcement."""

import copy
import json
import socket
import subprocess
import sys
import time
from app.runtime.runner import run_live, RuntimeErrorSafe
from app.runtime.fixture import PROGRAM
import pytest


class NoDelay:
    def __init__(self):
        self.flag = False

    def is_set(self):
        return self.flag

    def wait(self, seconds):
        return self.flag

    def set(self):
        self.flag = True


def tiny_project():
    def pod(n):
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": n, "namespace": "test-app", "labels": {"app": n}},
            "spec": {
                "containers": [{"name": "x", "image": "never-run", "ports": [{"containerPort": 19091}]}]
            },
        }

    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"namespace": "test-app", "name": "isolate-destination"},
        "spec": {
            "podSelector": {"matchLabels": {"app": "destination"}},
            "policyTypes": ["Ingress"],
            "ingress": [],
        },
    }
    endpoint = lambda n: {"podSelector": {"matchLabels": {"app": n}}}
    return {
        "schemaVersion": 1,
        "name": "runner test",
        "topology": [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "test-app"}},
            pod("source"),
            pod("destination"),
        ],
        "baseline": [policy],
        "candidate": [copy.deepcopy(policy)],
        "intents": [
            {
                "id": "deny",
                "source": endpoint("source"),
                "destination": endpoint("destination"),
                "port": 19091,
                "protocol": "TCP",
                "expect": "must_deny",
            }
        ],
    }


class ScriptedCluster:
    def __init__(self, *, enforce=True, drift=False, cleanup_error=False, existing=False):
        self.objects = {}
        self.calls = []
        self.enforce = enforce
        self.drift = drift
        self.cleanup_error = cleanup_error
        self.existing = existing
        self.ip = 2
        self.probes = 0

    def config(self):
        return {"clusters": [{"cluster": {"server": "https://127.0.0.1:6443"}}]}

    def create(self, obj):
        obj = copy.deepcopy(obj)
        m = obj["metadata"]
        key = (obj["kind"], m.get("namespace"), m["name"])
        m["uid"] = "uid-" + str(len(self.objects))
        self.objects[key] = obj
        if obj["kind"] == "Namespace":
            m.setdefault("labels", {})["kubernetes.io/metadata.name"] = m["name"]
        if obj["kind"] == "Pod":
            obj["status"] = {
                "podIP": f"10.0.0.{self.ip}",
                "phase": "Running",
                "containerStatuses": [{"imageID": "fixture@sha256:test"}],
            }
            self.ip += 1

    def get(self, kind, namespace=None, name=None):
        aliases = {
            "namespaces": "Namespace",
            "namespace": "Namespace",
            "pod": "Pod",
            "networkpolicy": "NetworkPolicy",
            "networkpolicies": "NetworkPolicy",
        }
        k = aliases[kind]
        if name:
            obj = copy.deepcopy(self.objects[(k, namespace, name)])
            if self.drift and k == "Pod" and name == "source" and self.probes >= 3:
                obj["metadata"]["uid"] = "replaced-uid"
            return obj
        items = [
            copy.deepcopy(v)
            for (kd, ns, n), v in self.objects.items()
            if kd == k and (namespace is None or namespace == ns)
        ]
        if self.existing and k == "Namespace":
            items.append({"metadata": {"name": "test-app"}})
        return {"items": items}

    def call(self, args, body=None, timeout=30):
        self.calls.append((args, body))
        if args[:2] == ["get", "daemonsets"]:
            return json.dumps(
                {
                    "items": [
                        {
                            "metadata": {"namespace": "kube-system", "name": "calico-node"},
                            "spec": {
                                "template": {"spec": {"containers": [{"image": "scripted-cni-not-real"}]}}
                            },
                        }
                    ]
                }
            )
        if args[0] == "version":
            return json.dumps({"serverVersion": {"gitVersion": "scripted-adapter-not-a-real-cluster"}})
        if args[0] == "wait":
            return "condition met"
        if args[0] == "delete":
            path = args[2]
            if path.startswith("/api/v1/namespaces/"):
                if self.cleanup_error:
                    raise RuntimeErrorSafe("scripted cleanup failure")
                n = path.split("/")[-1]
                obj = self.objects[("Namespace", None, n)]
                assert body["preconditions"]["uid"] == obj["metadata"]["uid"]
                self.objects = {
                    k: v for k, v in self.objects.items() if k[1] != n and k != ("Namespace", None, n)
                }
            else:
                parts = path.split("/")
                ns = parts[-3]
                n = parts[-1]
                obj = self.objects[("NetworkPolicy", ns, n)]
                assert body["preconditions"]["uid"] == obj["metadata"]["uid"]
                del self.objects[("NetworkPolicy", ns, n)]
            return "{}"
        if args[0] == "exec":
            dest = args[-4]
            self.probes += 1
            target = next(
                p for (kd, ns, n), p in self.objects.items() if kd == "Pod" and p["status"]["podIP"] == dest
            )
            md = target["metadata"]
            blocked = md["name"] == "blocked" and self.enforce
            if (
                md["name"] == "destination"
                and ("NetworkPolicy", "test-app", "isolate-destination") in self.objects
            ):
                blocked = True
            return json.dumps(
                {"outcome": "unreachable" if blocked else "success", "response_matched": not blocked}
            )
        raise AssertionError(args)


def test_runner_complete_flow_and_owned_cleanup():
    fake = ScriptedCluster()
    r = run_live(
        tiny_project(), "kind-lab", {"kind-lab": "https://127.0.0.1:6443"}, cancel=NoDelay(), transport=fake
    )
    assert r["runtime_status"] == "VERIFIED_ON_SCOPE", r
    assert r["exit_code"] == 0 and len(r["observations"]) == 2
    assert all(o["verdict"] == "OBSERVED_UNREACHABLE" for o in r["observations"])
    assert not r["leftovers"] and not fake.objects
    assert all(body["preconditions"]["uid"] for args, body in fake.calls if args[0] == "delete")


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("no-enforcement", "controls failed"),
        ("existing", "already exist"),
        ("wrong-server", "server does not match"),
        ("drift", "identity changed"),
    ],
)
def test_runner_refuses_unsafe_or_untrustworthy_conditions(mode, expected):
    fake = ScriptedCluster(
        enforce=mode != "no-enforcement", existing=mode == "existing", drift=mode == "drift"
    )
    allowed = {"kind-lab": "wrong"} if mode == "wrong-server" else {"kind-lab": "https://127.0.0.1:6443"}
    r = run_live(tiny_project(), "kind-lab", allowed, cancel=NoDelay(), transport=fake)
    assert r["exit_code"] == 2 and expected in r["error"], r
    assert r["runtime_status"] == "INCOMPLETE"


def test_cleanup_failure_overrides_complete_result():
    r = run_live(
        tiny_project(),
        "kind-lab",
        {"kind-lab": "https://127.0.0.1:6443"},
        cancel=NoDelay(),
        transport=ScriptedCluster(cleanup_error=True),
    )
    assert r["exit_code"] == 2 and r["leftovers"] and r["state"] == "INCOMPLETE"


def test_cancel_preserves_incomplete_status():
    cancel = NoDelay()
    cancel.set()
    fake = ScriptedCluster()
    r = run_live(
        tiny_project(), "kind-lab", {"kind-lab": "https://127.0.0.1:6443"}, cancel=cancel, transport=fake
    )
    assert r["state"] == "CANCELLED" and r["exit_code"] == 2 and not fake.objects


@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
def test_trusted_fixture_roundtrip_is_a_real_socket_test(protocol):
    # This validates the probe program on loopback, not Kubernetes policy enforcement.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = subprocess.Popen([sys.executable, "-c", PROGRAM, "serve", json.dumps([[port, protocol]])])
    try:
        result = None
        for _ in range(25):
            reply = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    PROGRAM,
                    "probe",
                    "127.0.0.1",
                    str(port),
                    protocol,
                    "unique-test-token",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            result = json.loads(reply.stdout)
            if result["outcome"] == "success":
                break
            time.sleep(0.03)
        assert result["outcome"] == "success" and result["response_matched"]
    finally:
        server.terminate()
        server.wait(timeout=5)


def test_completed_probes_cannot_certify_an_incomplete_parent_review():
    raw = tiny_project()
    raw["intents"] = []
    raw["candidate"][0]["spec"]["ingress"] = [{}]
    result = run_live(
        raw, "kind-lab", {"kind-lab": "https://127.0.0.1:6443"}, cancel=NoDelay(), transport=ScriptedCluster()
    )
    assert result["exit_code"] == 2 and result["state"] == "INCOMPLETE"
    assert result["runtime_status"] == "INCOMPLETE"
