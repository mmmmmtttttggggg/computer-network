"""Generate small explicit, inspectable demo inputs (no expected results from the engine)."""

from pathlib import Path
import copy, json

OUT = Path(__file__).resolve().parents[1] / "src/app/resources/examples"
OUT.mkdir(parents=True, exist_ok=True)


def ns(n):
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": n, "labels": {"team": n}}}


def pod(n, namespace, port, role="workload", tier="service"):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": n,
            "namespace": namespace,
            "labels": {"app": n, "tier": tier},
            "annotations": {"netscope.io/role": role},
        },
        "spec": {
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "app",
                    "image": "data-only/not-executed",
                    "ports": [
                        {
                            "containerPort": port,
                            "name": ("db" if n == "database" else "http"),
                            "protocol": "TCP",
                        }
                    ],
                }
            ],
        },
    }


def peer(n, namespace="apps"):
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
        "podSelector": {"matchLabels": {"app": n}},
    }


def rule(peers, port, d="ingress"):
    return {("from" if d == "ingress" else "to"): peers, "ports": [{"protocol": "TCP", "port": port}]}


def policy(n, target, namespace="apps", ingress=None, egress=None):
    spec = {"podSelector": {"matchLabels": {"app": target}}, "policyTypes": []}
    for k, v in [("ingress", ingress), ("egress", egress)]:
        if v is not None:
            spec[k] = v
            spec["policyTypes"].append(k.title())
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": n, "namespace": namespace},
        "spec": spec,
    }


def intent(i, s, d, port, expect="must_allow"):
    sn, sp = s.split("/")
    dn, dp = d.split("/")
    return {
        "id": i,
        "source": {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": sn}},
            "podSelector": {"matchLabels": {"app": sp}},
        },
        "destination": {
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": dn}},
            "podSelector": {"matchLabels": {"app": dp}},
        },
        "protocol": "TCP",
        "port": port,
        "expect": expect,
    }


common = [
    ns("apps"),
    ns("data"),
    ns("ops"),
    pod("frontend", "apps", 8080),
    pod("payments", "apps", 8080),
    pod("analytics", "apps", 8082),
    pod("agent", "apps", 8090, "agent"),
    pod("tool-gateway", "apps", 8081, "tool"),
    pod("database", "data", 5432, "asset", "backend"),
    pod("metrics", "ops", 9090),
]
base = [
    policy("db-ingress", "database", "data", ingress=[rule([peer("payments"), peer("tool-gateway")], 5432)]),
    policy("agent-egress", "agent", egress=[rule([peer("tool-gateway")], 8081, "egress")]),
    policy("gateway-egress", "tool-gateway", egress=[rule([peer("metrics", "ops")], 9090, "egress")]),
    policy("gateway-ingress", "tool-gateway", ingress=[rule([peer("agent")], 8081)]),
]
for n in range(6):
    base.append(policy(f"unrelated-metrics-{n}", "metrics", "ops", ingress=[rule([peer("frontend")], 9090)]))
ints = [
    intent("frontend-to-payments", "apps/frontend", "apps/payments", 8080),
    intent("payments-to-database", "apps/payments", "data/database", 5432),
    intent("analytics-isolated", "apps/analytics", "data/database", 5432, "must_deny"),
    intent("agent-only-via-tool", "apps/agent", "apps/tool-gateway", 8081),
    intent("agent-no-direct-db", "apps/agent", "data/database", 5432, "must_deny"),
]
cand = copy.deepcopy(base)
cand[2]["spec"]["egress"].append(
    rule([{"namespaceSelector": {}, "podSelector": {"matchLabels": {"tier": "backend"}}}], 5432, "egress")
)
agent = {
    "schemaVersion": 1,
    "name": "The indirect escape",
    "description": "Direct agent isolation still passes. One gateway egress edit creates a conditional two-hop path to the database. Can you spot it before merging?",
    "topology": common,
    "baseline": base,
    "candidate": cand,
    "intents": ints,
    "threatModel": {
        "entrypoints": ["apps/agent"],
        "pivots": ["apps/tool-gateway"],
        "assets": ["data/database"],
        "description": "Assume the agent is compromised and the gateway can relay requests. No application exploit is inferred.",
    },
}
(OUT / "agent-escape.json").write_text(json.dumps(agent, indent=2))
parallel = copy.deepcopy(agent)
parallel["name"] = "The parallel relay"
parallel["description"] = (
    "Two gateways can relay the same traffic. Removing one relay assumption leaves another path; inspect the alternative before claiming containment."
)
gateway_copy = copy.deepcopy(next(p for p in parallel["topology"] if p["metadata"]["name"] == "tool-gateway"))
gateway_copy["metadata"]["name"] = "tool-gateway-2"
parallel["topology"].append(gateway_copy)
parallel["threatModel"]["pivots"].append("apps/tool-gateway-2")
(OUT / "parallel-relay.json").write_text(json.dumps(parallel, indent=2))
checkout = copy.deepcopy(agent)
checkout["name"] = "The database switch"
checkout["description"] = (
    "A peer selector swap blocks payments and opens analytics. Reduce this regression into a tiny replayable bundle."
)
checkout["candidate"] = copy.deepcopy(base)
checkout["candidate"][0]["spec"]["ingress"] = [rule([peer("analytics")], 5432)]
checkout["threatModel"] = {}
(OUT / "checkout-regression.json").write_text(json.dumps(checkout, indent=2))
fixed = copy.deepcopy(agent)
fixed["name"] = "A clean baseline"
fixed["description"] = (
    "All application intents pass; baseline and candidate are identical. A good starting point for the fault-injection lab."
)
fixed["candidate"] = copy.deepcopy(base)
(OUT / "clean-baseline.json").write_text(json.dumps(fixed, indent=2))
trap = copy.deepcopy(fixed)
trap["name"] = "The AND / OR trap"
trap["description"] = (
    "Two selectors inside one peer mean AND. Split them into two peers and namespace access becomes much wider."
)
trap["candidate"][0]["spec"]["ingress"][0]["from"] = [
    {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "apps"}}},
    {"podSelector": {"matchLabels": {"app": "payments"}}},
]
(OUT / "selector-trap.json").write_text(json.dumps(trap, indent=2))
unknown = copy.deepcopy(fixed)
unknown["name"] = "An honest Unknown"
unknown["description"] = (
    "A vendor policy can influence access. The model refuses a complete pass instead of pretending it understands that policy."
)
unknown["candidate"].append(
    {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": "vendor-policy", "namespace": "apps"},
        "spec": {},
    }
)
(OUT / "unsupported-policy.json").write_text(json.dumps(unknown, indent=2))

deleted = copy.deepcopy(fixed)
deleted["name"] = "The last policy disappears"
deleted["description"] = (
    "Deleting the final agent egress policy removes isolation. Existing intents still pass, while previously restricted connections open."
)
deleted["candidate"] = [p for p in deleted["candidate"] if p["metadata"]["name"] != "agent-egress"]
(OUT / "last-policy-deleted.json").write_text(json.dumps(deleted, indent=2))

# Live-ready version of the independently reduced selector disagreement.
cross = json.loads((OUT.parents[3] / "artifacts/oracle/disagreement/minimal-project.json").read_text())
cross["name"] = "The cross-namespace check"
cross["description"] = (
    "A two-Pod DoesNotExist selector case where independent static analyzers disagree. NetScope predicts Allow; use recorded CNI observations to investigate."
)
cross["intents"] = [intent("cross-namespace-allowed", "data/b", "apps/b", 8080)]
cross["threatModel"] = {}
(OUT / "cross-namespace-check.json").write_text(json.dumps(cross, indent=2))
