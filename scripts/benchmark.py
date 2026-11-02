"""Measured finite-scope benchmark; does not invent runtime measurements."""

from __future__ import annotations
import copy
import gc
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from importlib.resources import files

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from app.service import review_project
from app.analysis.reducer import reduce_project
from app.analysis.experiments import repair_project, run_mutations


def workload():
    namespaces = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": f"team-{n}"}} for n in range(5)
    ]
    pods = []
    for i in range(30):
        pods.append(
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": f"pod-{i}",
                    "namespace": f"team-{i % 5}",
                    "labels": {"app": f"pod-{i}", "tier": "service"},
                },
                "spec": {
                    "containers": [
                        {
                            "name": "fixture",
                            "image": "data-only",
                            "ports": [{"containerPort": 8000 + p} for p in range(20)],
                        }
                    ]
                },
            }
        )
    policies = []
    for i in range(100):
        policies.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"namespace": f"team-{i % 5}", "name": f"policy-{i}"},
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress"],
                    "ingress": [{"from": [{"namespaceSelector": {}}], "ports": [{"port": 8000 + i % 20}]}],
                },
            }
        )
    intent = {
        "id": "reference-allow",
        "source": {"podSelector": {"matchLabels": {"app": "pod-0"}}},
        "destination": {"podSelector": {"matchLabels": {"app": "pod-1"}}},
        "protocol": "TCP",
        "port": 8000,
        "expect": "must_allow",
    }
    return {
        "schemaVersion": 1,
        "name": "30-endpoint reference",
        "topology": namespaces + pods,
        "baseline": policies,
        "candidate": copy.deepcopy(policies),
        "intents": [intent],
    }


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "artifacts/benchmark.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    raw = workload()
    r = review_project(raw)
    assert r["stats"]["queries"] == 17400
    samples = []
    for _ in range(20):
        del r
        gc.collect()
        t = time.perf_counter()
        r = review_project(raw)
        samples.append(round((time.perf_counter() - t) * 1000, 2))
    assert r["stats"]["queries"] == 17400
    metrics = {
        "tool_version": r["tool_version"],
        "method": "20 warm runs of parsing + full two-revision review + traces + intent + report construction. No HTTP serialization/browser/Kubernetes timing.",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "reference": {
            "endpoints": 30,
            "namespaces": 5,
            "policies_per_revision": 100,
            "port_combinations": 20,
            "queries_per_revision": 17400,
        },
        "samples_ms": samples,
        "median_ms": round(statistics.median(samples), 2),
        "max_ms": max(samples),
        "runs_under_5_seconds": sum(s <= 5000 for s in samples),
        "runtime_verified": False,
    }
    try:
        import resource

        metrics["process_peak_rss_mib"] = round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            / (1024 if sys.platform != "darwin" else 1024**2),
            2,
        )
    except ImportError:
        pass
    examples = {
        f.name[:-5]: json.loads(f.read_text())
        for f in files("app").joinpath("resources/examples").iterdir()
        if f.name.endswith(".json")
    }
    checkout = examples["checkout-regression"]
    report = review_project(checkout)
    tid = next(x["tuple_id"] for x in report["rows"] if x["change"] == "NEWLY_BLOCKED")
    reduced = reduce_project(checkout, tid)
    metrics["demonstration_reduction"] = {
        k: v for k, v in reduced.items() if k not in ["project", "signature", "kept", "removed"]
    }
    metrics["repair_proposals"] = {
        n: len(repair_project(examples[n])["solutions"])
        for n in ["checkout-regression", "agent-escape", "selector-trap"]
    }
    mutations = run_mutations(examples["clean-baseline"])
    metrics["intent_sensitivity"] = {k: v for k, v in mutations.items() if k != "mutations"}
    out.write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
