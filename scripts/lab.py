"""Create/remove a dedicated local kind lab. Never targets an arbitrary cluster.

This bootstrap requires Docker, kind, kubectl and internet access. It has not
been integration-tested in the artifact-building environment (no Docker).
"""

from __future__ import annotations
import argparse
import json
import shutil
import subprocess
from pathlib import Path

NAME = "netscope-lab"
ADMIN = "kind-" + NAME
CONTEXT = "netscope-lab-runner"
NODE = "kindest/node:v1.35.8@sha256:07b2536e30b803ed61d1677a79df6115f798ce64c80f9e22f6ed45afd09323c0"
CALICO = "v3.33.0"
FIXTURE = "python:3.12.8-alpine3.21"
LAB_HOME = Path.home() / ".netscope"
STATE = LAB_HOME / "lab.json"
CONFIG = LAB_HOME / "lab-kubeconfig.json"


def call(args, body=None, timeout=300):
    r = subprocess.run(
        args,
        input=None if body is None else json.dumps(body),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if r.returncode:
        raise RuntimeError((r.stderr or r.stdout)[-2500:])
    return r.stdout


def kube(args, body=None):
    return call(["kubectl", "--context", ADMIN, *args], body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["up", "down", "status"])
    args = parser.parse_args()
    for binary in ["docker", "kind", "kubectl"]:
        if not shutil.which(binary):
            raise SystemExit(f"{binary} is required. See docs/LIVE_LAB.md.")
    if args.action == "status":
        print(STATE.read_text() if STATE.exists() else "No NetScope lab state.")
        return
    if args.action == "down":
        if not STATE.exists():
            raise SystemExit("No owned lab record; refusing automatic cluster deletion.")
        state = json.loads(STATE.read_text())
        if state.get("cluster") != NAME or state.get("owner") != "netscope-bootstrap-v1":
            raise SystemExit("Lab ownership record does not match.")
        call(["kind", "delete", "cluster", "--name", NAME])
        STATE.unlink(missing_ok=True)
        CONFIG.unlink(missing_ok=True)
        print("Owned lab removed.")
        return
    existing = call(["kind", "get", "clusters"]).splitlines()
    if NAME in existing:
        raise SystemExit(
            "netscope-lab already exists; refusing to adopt it. Use status/down for a recorded owned lab."
        )
    cfg = {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "nodes": [{"role": "control-plane"}, {"role": "worker"}, {"role": "worker"}],
        "networking": {
            "disableDefaultCNI": True,
            "podSubnet": "192.168.0.0/16",
            "apiServerAddress": "127.0.0.1",
        },
    }
    LAB_HOME.mkdir(parents=True, exist_ok=True)
    print("Creating dedicated kind cluster with a digest-pinned node image…", flush=True)
    call(["kind", "create", "cluster", "--name", NAME, "--image", NODE, "--config", "-"], cfg, timeout=600)
    state = {
        "owner": "netscope-bootstrap-v1",
        "cluster": NAME,
        "node_image": NODE,
        "calico_version": CALICO,
        "runtime_integration_validated": False,
    }
    STATE.write_text(json.dumps(state, indent=2))
    STATE.chmod(0o600)
    print("Installing versioned Calico manifest in the dedicated lab…", flush=True)
    kube(
        [
            "create",
            "-f",
            f"https://raw.githubusercontent.com/projectcalico/calico/{CALICO}/manifests/calico.yaml",
        ]
    )
    kube(["rollout", "status", "daemonset/calico-node", "-n", "kube-system", "--timeout=240s"])
    kube(["wait", "--for=condition=Ready", "nodes", "--all", "--timeout=180s"])
    print("Preparing the trusted fixture image…", flush=True)
    call(["docker", "pull", FIXTURE])
    repo_digests = json.loads(
        call(["docker", "image", "inspect", FIXTURE, "--format", "{{json .RepoDigests}}"])
    )
    if not repo_digests:
        raise RuntimeError("Could not resolve fixture image digest")
    fixture = repo_digests[0]
    call(["kind", "load", "docker-image", FIXTURE, "--name", NAME])
    # Dedicated runner identity: no Secret reads, no workload exec outside the
    # explicit runtime guard, no CNI or RBAC writes. Namespace permission remains
    # cluster-wide because imported names are dynamic; this is a disposable lab.
    resources = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "netscope-system"}},
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"name": "runner", "namespace": "netscope-system"},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "netscope-runner"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["namespaces"],
                    "verbs": ["get", "list", "watch", "create", "delete"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods"],
                    "verbs": ["get", "list", "watch", "create", "delete"],
                },
                {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create", "get"]},
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resources": ["networkpolicies"],
                    "verbs": ["get", "list", "watch", "create", "delete"],
                },
                {"apiGroups": ["apps"], "resources": ["daemonsets"], "verbs": ["get", "list"]},
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "netscope-runner"},
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "netscope-runner",
            },
            "subjects": [{"kind": "ServiceAccount", "name": "runner", "namespace": "netscope-system"}],
        },
    ]
    for resource in resources:
        kube(["create", "-f", "-"], resource)
    token = kube(["create", "token", "runner", "-n", "netscope-system", "--duration=8h"]).strip()
    original = json.loads(kube(["config", "view", "--minify", "--raw", "-o", "json"]))
    cluster = original["clusters"][0]["cluster"]
    server = cluster["server"]
    private = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "netscope", "cluster": cluster}],
        "users": [{"name": "runner", "user": {"token": token}}],
        "contexts": [{"name": CONTEXT, "context": {"cluster": "netscope", "user": "runner"}}],
        "current-context": CONTEXT,
    }
    CONFIG.write_text(json.dumps(private))
    CONFIG.chmod(0o600)
    state.update(
        {
            "contexts": {CONTEXT: server},
            "kubeconfig": str(CONFIG),
            "fixture_image": fixture,
            "token_note": "Requested 8 hours; the API server may shorten this. Recreate/refresh the lab when expired.",
        }
    )
    STATE.write_text(json.dumps(state, indent=2))
    STATE.chmod(0o600)
    print("Lab configured. Start the application with: python scripts/start.py --lab")
    print("This is setup, not verification evidence. Run a review and the confirmed live plan.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
        raise SystemExit(
            f"Lab setup stopped: {e}\nAn owned partial lab can be removed with python scripts/lab.py down"
        )
