"""Optional differential check against independently implemented NCA 2.1.0.

Install the oracle in a separate venv; it is not a NetScope runtime dependency.
  python -m venv .oracle-venv
  .oracle-venv/bin/pip install network-config-analyzer==2.1.0
  python scripts/oracle_check.py --nca .oracle-venv/bin/nca

Only ordinary Pod-to-Pod Kubernetes NetworkPolicy fixtures are compared.
Unsupported oracle output fails closed rather than becoming an Allow or Deny.
"""

from __future__ import annotations
import argparse
import copy
import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from importlib.resources import files

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import yaml  # noqa: E402
from app.service import review_project  # noqa: E402


def connection_matches(text, protocol, port):
    """Read the pinned oracle's ungrouped connection notation, not its policies."""
    if text == "All connections":
        return True
    if text == "No connections":
        return False
    cubes = re.findall(r"\{[^{}]+\}", text)
    if not cubes or ",".join(cubes) != text:
        raise ValueError(f"Unsupported NCA connection notation: {text}")
    matched = False
    for cube in cubes:
        match = re.fullmatch(
            r"\{(?:protocols:([A-Z0-9,]+)(?:,dst_ports:([0-9,-]+))?|dst_ports:([0-9,-]+))\}", cube
        )
        if not match:
            raise ValueError(f"Unsupported NCA connection cube: {cube}")
        protocols, first_ports, only_ports = match.groups()
        ports = first_ports or only_ports
        port_match = ports is None
        if ports:
            for interval in ports.split(","):
                bounds = [int(n) for n in interval.split("-")]
                if len(bounds) not in (1, 2) or bounds[0] > bounds[-1]:
                    raise ValueError(f"Invalid NCA port interval: {interval}")
                port_match |= bounds[0] <= port <= bounds[-1]
        matched |= (protocols is None or protocol in protocols.split(",")) and port_match
    return matched


def oracle_map(text, endpoints):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(\S+) => (\S+) : (.+)", line)
        if not match:
            raise ValueError(f"Unsupported NCA output line: {line}")
        source, destination, connections = match.groups()
        # External-IP summaries are outside this Pod-to-Pod comparison.
        if source not in endpoints or destination not in endpoints:
            continue
        # Validate syntax even if no selected query exercises this pair.
        connection_matches(connections, "TCP", 1)
        # The oracle may emit separate TCP/UDP lines for the same endpoint pair.
        result.setdefault((source, destination), []).append(connections)
    return result


def generated_cases(seed=303, count=24):
    rng = random.Random(seed)
    topology = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {"team": ns}}}
        for ns in ["apps", "data"]
    ]
    for ns in ["apps", "data"]:
        for role in ["a", "b"]:
            topology.append(
                {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": role, "namespace": ns, "labels": {"app": role}},
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "data-only/not-executed",
                                "ports": [
                                    {
                                        "name": "web",
                                        "containerPort": 8080 if role == "a" else 8081,
                                        "protocol": "TCP",
                                    },
                                    {"name": "dns", "containerPort": 5353, "protocol": "UDP"},
                                ],
                            }
                        ]
                    },
                }
            )
    selectors = [
        {},
        {"matchLabels": {"app": "a"}},
        {"matchExpressions": [{"key": "app", "operator": "In", "values": ["a", "b"]}]},
        {"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["a"]}]},
        {"matchExpressions": [{"key": "app", "operator": "Exists"}]},
        {"matchExpressions": [{"key": "absent", "operator": "DoesNotExist"}]},
    ]
    ports = [
        {"protocol": protocol, "port": port}
        for protocol, port in [
            ("TCP", 8079),
            ("TCP", 8080),
            ("TCP", 8081),
            ("TCP", 8082),
            ("UDP", 5353),
            ("UDP", 8080),
        ]
    ]
    for index in range(count):
        phases = []
        for _ in range(2):
            policies = []
            for ix in range(rng.randrange(0, 9)):
                directions = rng.choice([["Ingress"], ["Egress"], ["Ingress", "Egress"]])
                spec = {"podSelector": copy.deepcopy(rng.choice(selectors)), "policyTypes": directions}
                for direction in directions:
                    rules = []
                    for _ in range(rng.randrange(0, 3)):
                        rule = {}
                        peers = [
                            {"namespaceSelector": {}},
                            {"podSelector": copy.deepcopy(rng.choice(selectors))},
                            {"namespaceSelector": {"matchLabels": {"team": rng.choice(["apps", "data"])}}},
                            {"namespaceSelector": {}, "podSelector": copy.deepcopy(rng.choice(selectors))},
                        ]
                        if rng.choice([True, False]):
                            rule["from" if direction == "Ingress" else "to"] = rng.sample(
                                peers, rng.randrange(0, 4)
                            )
                        if rng.choice([True, False]):
                            rule["ports"] = [
                                copy.deepcopy(
                                    rng.choice(
                                        [
                                            {"port": 8080},
                                            {"protocol": "UDP", "port": 5353},
                                            {"port": "web"},
                                            {"port": 8080, "endPort": 8081},
                                            {},
                                        ]
                                    )
                                )
                                for _ in range(rng.randrange(0, 3))
                            ]
                        rules.append(rule)
                    spec[direction.lower()] = rules
                policies.append(
                    {
                        "apiVersion": "networking.k8s.io/v1",
                        "kind": "NetworkPolicy",
                        "metadata": {"name": f"p-{ix}", "namespace": rng.choice(["apps", "data"])},
                        "spec": spec,
                    }
                )
            phases.append(policies)
        yield {
            "schemaVersion": 1,
            "name": f"seed-{seed}-{index:02}",
            "topology": copy.deepcopy(topology),
            "baseline": phases[0],
            "candidate": phases[1],
            "ports": copy.deepcopy(ports),
            "intents": [],
        }


def run(nca, output, seed, count, projects=None):
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").unlink(missing_ok=True)
    version = subprocess.run([nca, "--version"], capture_output=True, text=True, timeout=15, check=True)
    oracle_version = (version.stdout + version.stderr).strip()
    if "2.1.0" not in oracle_version:
        raise ValueError(f"This harness requires pinned NCA 2.1.0, got {oracle_version}")
    examples = [
        json.loads(files("app.resources.examples").joinpath(name + ".json").read_text())
        for name in ["agent-escape", "checkout-regression", "selector-trap", "clean-baseline"]
    ]
    cases = projects if projects is not None else examples + list(generated_cases(seed, count))
    results, disagreements = [], []
    for index, project in enumerate(cases):
        case_dir = output / f"case-{index:02}"
        case_dir.mkdir(exist_ok=True)
        project_text = json.dumps(project, indent=2) + "\n"
        (case_dir / "project.json").write_text(project_text)
        report = review_project(project)
        endpoints = {node["id"] for node in report["nodes"]}
        comparisons, allowed, denied = 0, 0, 0
        for phase in ["baseline", "candidate"]:
            manifest = case_dir / f"{phase}.yaml"
            manifest.write_text(yaml.safe_dump_all(project["topology"] + project[phase]))
            oracle_path = case_dir / f"{phase}.oracle.txt"
            cmd = [
                nca,
                "--connectivity",
                "-r",
                str(manifest.resolve()),
                "--output_format",
                "txt_no_fw_rules",
                "--output_endpoints",
                "pods",
                "--file_out",
                "PLACEHOLDER",
            ]
            # NCA appends to output files. A private fresh temporary path avoids
            # stale output even when the retained evidence directory is reused.
            with tempfile.TemporaryDirectory(prefix="netscope-oracle-") as temporary:
                fresh_output = Path(temporary) / "connections.txt"
                cmd[-1] = str(fresh_output)
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                oracle_text = fresh_output.read_text() if fresh_output.exists() else None
            (case_dir / f"{phase}.log.txt").write_text(proc.stdout + proc.stderr)
            if proc.returncode != 0 or oracle_text is None:
                raise RuntimeError(f"NCA failed for case {index}/{phase}; inspect {case_dir}")
            oracle_path.write_text(oracle_text)
            oracle = oracle_map(oracle_text, endpoints)
            for row in report["rows"]:
                if row[phase] == "Unknown":
                    raise ValueError("Shared-subset fixtures must not contain Unknown decisions")
                actual = (
                    "Allow"
                    if any(
                        connection_matches(text, row["protocol"], row["port"])
                        for text in oracle.get((row["source"], row["destination"]), ["No connections"])
                    )
                    else "Deny"
                )
                comparisons += 1
                allowed += actual == "Allow"
                denied += actual == "Deny"
                if actual != row[phase]:
                    disagreements.append(
                        {
                            "case": index,
                            "phase": phase,
                            "source": row["source"],
                            "destination": row["destination"],
                            "protocol": row["protocol"],
                            "port": row["port"],
                            "netscope": row[phase],
                            "oracle": actual,
                        }
                    )
        results.append(
            {
                "case": index,
                "name": project["name"],
                "comparisons": comparisons,
                "oracle_allow": allowed,
                "oracle_deny": denied,
                "project_sha256": hashlib.sha256(project_text.encode()).hexdigest(),
            }
        )
    summary = {
        "oracle": "network-config-analyzer",
        "oracle_version": oracle_version,
        "netscope_version": report["tool_version"],
        "seed": seed,
        "generated_cases": count if projects is None else 0,
        "cases": len(results),
        "comparisons": sum(r["comparisons"] for r in results),
        "disagreement_count": len(disagreements),
        "disagreements": disagreements,
        "results": results,
        "scope": (
            "Four shipped examples plus seeded four-Pod/two-namespace fixtures; "
            if projects is None
            else "Explicit JSON project fixture(s); "
        )
        + "both revisions, declared query scope. Selectors, additive rules, directional isolation, named ports, and endPort ranges. No external-IP, hostNetwork, vendor policy, or real-CNI claim. Agreement on these finite fixtures is not universal correctness or certification.",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nca", required=True)
    parser.add_argument("--output", type=Path, default=Path("artifacts/oracle"))
    parser.add_argument("--seed", type=int, default=303)
    parser.add_argument("--generated-cases", type=int, default=24)
    parser.add_argument(
        "--project", type=Path, help="Compare one explicit JSON fixture instead of the default suite"
    )
    args = parser.parse_args()
    if not 1 <= args.generated_cases <= 100:
        parser.error("--generated-cases must be 1..100")
    projects = [json.loads(args.project.read_text())] if args.project else None
    summary = run(args.nca, args.output, args.seed, args.generated_cases, projects)
    print(json.dumps({k: v for k, v in summary.items() if k not in ["results", "disagreements"]}, indent=2))
    sys.exit(1 if summary["disagreement_count"] else 0)
