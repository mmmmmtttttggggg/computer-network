import pytest

from app.model.evaluator import Evaluator, PolicyError, Verdict
from app.model.topology import ConnectionQuery, ContainerPort, Namespace, Pod, Protocol, Topology

API = "networking.k8s.io/v1"
TCP, UDP, SCTP = Protocol.TCP, Protocol.UDP, Protocol.SCTP
ALLOW, DENY, UNKNOWN = Verdict.ALLOW, Verdict.DENY, Verdict.UNKNOWN


def make_topology():
    t = Topology()
    t.add_namespace(Namespace("prod", {"team": "pay"}))
    t.add_namespace(Namespace("ops", {"team": "ops"}))
    t.add_pod(Pod("frontend", "prod", {"app": "frontend"}))
    t.add_pod(Pod("payments", "prod", {"app": "payments"}, (ContainerPort(8080, TCP, "http"),)))
    t.add_pod(Pod("database", "prod", {"app": "database"}, (ContainerPort(5432, TCP, "db"),)))
    t.add_pod(
        Pod(
            "cache",
            "prod",
            {"app": "cache"},
            (ContainerPort(5433, TCP, "db"), ContainerPort(5353, UDP, "dns")),
        )
    )
    t.add_pod(Pod("analytics", "ops", {"app": "analytics"}))
    return t


TOPO = make_topology()
PODS = {p.name: p for p in TOPO.pods.values()}


def policy(name, ns, pod_selector, *, ingress=None, egress=None, types=None):
    spec = {"podSelector": pod_selector}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    if types is not None:
        spec["policyTypes"] = types
    return {
        "apiVersion": API,
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": ns},
        "spec": spec,
    }


def decide(policies, src, dst, proto=TCP, port=5432):
    return Evaluator(TOPO, policies).evaluate(ConnectionQuery(PODS[src], PODS[dst], proto, port))


def sel(app):
    return {"matchLabels": {"app": app}}


def from_app(app):
    return [{"from": [{"podSelector": sel(app)}]}]


# ---------------------------------------------------------------- isolation
def test_no_policies_allows_everything():
    d = decide([], "frontend", "database")
    assert d.verdict is ALLOW and d.reason == "allowed"
    assert d.egress.isolated is False and d.ingress.isolated is False


def test_policy_in_other_namespace_does_not_isolate():
    p = policy("deny", "ops", {}, ingress=[])  # selects only ops Pods
    assert decide([p], "frontend", "database").verdict is ALLOW


def test_ingress_only_isolation():
    p = policy("db-deny", "prod", sel("database"), ingress=[])
    d = decide([p], "frontend", "database")
    assert d.verdict is DENY and d.reason == "ingress-denied"
    assert d.egress.isolated is False and d.ingress.isolated is True
    assert decide([p], "database", "frontend").verdict is ALLOW  # egress unrestricted


def test_egress_only_isolation():
    p = policy("pay-egress", "prod", sel("payments"), egress=[], types=["Egress"])
    d = decide([p], "payments", "database")
    assert d.verdict is DENY and d.reason == "egress-denied"
    assert decide([p], "database", "payments").verdict is ALLOW  # ingress unrestricted


def test_default_policy_types_empty_egress_list_is_not_egress_isolation():
    p = policy("pay", "prod", sel("payments"), egress=[])  # API default: Ingress only
    assert decide([p], "payments", "database").verdict is ALLOW


def test_default_policy_types_nonempty_egress_isolates_egress():
    p = policy("pay", "prod", sel("payments"), egress=[{"to": [{"podSelector": sel("frontend")}]}])
    assert decide([p], "payments", "database").verdict is DENY
    assert decide([p], "payments", "frontend").verdict is ALLOW


def test_both_directions_isolated():
    p = policy("db-lock", "prod", sel("database"), types=["Ingress", "Egress"])
    out = decide([p], "database", "payments")
    assert out.verdict is DENY and out.reason == "egress-denied"
    assert decide([p], "payments", "database").reason == "ingress-denied"
    both = [policy("pay-lock", "prod", sel("payments"), types=["Ingress", "Egress"]), p]
    d = decide(both, "database", "payments")
    assert d.verdict is DENY and d.reason == "egress-and-ingress-denied"


def test_empty_rule_allows_all_and_empty_lists_impose_no_restriction():
    p = policy("open", "prod", sel("database"), ingress=[{}])
    assert decide([p], "analytics", "database", TCP, 1).verdict is ALLOW
    p2 = policy("open2", "prod", sel("database"), ingress=[{"from": [], "ports": []}])
    assert decide([p2], "analytics", "database", UDP, 9).verdict is ALLOW


# ---------------------------------------------------------------- additive / combined
def test_rules_from_multiple_policies_are_additive():
    p1 = policy("a", "prod", sel("database"), ingress=from_app("frontend"))
    p2 = policy("b", "prod", sel("database"), ingress=from_app("payments"))
    assert decide([p1, p2], "frontend", "database").verdict is ALLOW
    d = decide([p1, p2], "payments", "database")
    assert d.verdict is ALLOW
    assert d.ingress.selecting_policies == ("prod/a", "prod/b")
    assert [(m.policy, m.rule_index, m.certain) for m in d.ingress.matched_rules] == [("prod/b", 0, True)]
    assert decide([p1, p2], "cache", "database").verdict is DENY


def test_allowed_ingress_but_denied_egress():
    ing = policy("db-in", "prod", sel("database"), ingress=from_app("payments"))
    egr = policy("pay-out", "prod", sel("payments"), egress=[], types=["Egress"])
    d = decide([ing, egr], "payments", "database")
    assert d.verdict is DENY and d.reason == "egress-denied"
    assert d.ingress.verdict is ALLOW and d.egress.verdict is DENY
    fixed = policy(
        "pay-out",
        "prod",
        sel("payments"),
        egress=[{"to": [{"podSelector": sel("database")}]}],
        types=["Egress"],
    )
    assert decide([ing, fixed], "payments", "database").verdict is ALLOW


# ---------------------------------------------------------------- selectors
def test_pod_only_peer_is_limited_to_policy_namespace():
    p = policy("db-in", "prod", sel("database"), ingress=from_app("analytics"))
    assert decide([p], "analytics", "database").verdict is DENY  # analytics lives in ops


def test_namespace_selector_alone_selects_all_pods_in_matching_namespaces():
    p = policy(
        "db-in",
        "prod",
        sel("database"),
        ingress=[{"from": [{"namespaceSelector": {"matchLabels": {"team": "ops"}}}]}],
    )
    assert decide([p], "analytics", "database").verdict is ALLOW
    assert decide([p], "frontend", "database").verdict is DENY  # prod team=pay


def test_namespace_and_pod_selector_in_one_peer_are_anded():
    ns_sel = {"matchLabels": {"team": "ops"}}
    good = policy(
        "g",
        "prod",
        sel("database"),
        ingress=[{"from": [{"namespaceSelector": ns_sel, "podSelector": sel("analytics")}]}],
    )
    bad = policy(
        "b",
        "prod",
        sel("database"),
        ingress=[{"from": [{"namespaceSelector": ns_sel, "podSelector": sel("frontend")}]}],
    )
    assert decide([good], "analytics", "database").verdict is ALLOW
    assert decide([bad], "analytics", "database").verdict is DENY


def test_separate_peers_are_ored():
    p = policy(
        "or",
        "prod",
        sel("database"),
        ingress=[
            {
                "from": [
                    {"namespaceSelector": {"matchLabels": {"team": "ops"}}},
                    {"podSelector": sel("payments")},
                ]
            }
        ],
    )
    assert decide([p], "analytics", "database").verdict is ALLOW
    assert decide([p], "payments", "database").verdict is ALLOW
    assert decide([p], "frontend", "database").verdict is DENY


def test_empty_namespace_selector_selects_all_namespaces():
    p = policy("all-ns", "prod", sel("database"), ingress=[{"from": [{"namespaceSelector": {}}]}])
    assert decide([p], "analytics", "database").verdict is ALLOW
    assert decide([p], "frontend", "database").verdict is ALLOW


def test_automatic_namespace_name_label():
    p = policy(
        "by-name",
        "prod",
        sel("database"),
        ingress=[{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ops"}}}]}],
    )
    assert decide([p], "analytics", "database").verdict is ALLOW
    assert decide([p], "frontend", "database").verdict is DENY


def test_match_expressions_in_policy_selector():
    p = policy(
        "expr",
        "prod",
        {"matchExpressions": [{"key": "app", "operator": "In", "values": ["database", "cache"]}]},
        ingress=[],
    )
    assert decide([p], "frontend", "database").verdict is DENY
    assert decide([p], "frontend", "cache").verdict is DENY
    assert decide([p], "database", "frontend").verdict is ALLOW


# ---------------------------------------------------------------- ports / protocols
def rule_ports(ports):
    return [{"from": [{"podSelector": sel("frontend")}], "ports": ports}]


def test_numeric_port():
    p = policy("n", "prod", sel("database"), ingress=rule_ports([{"protocol": "TCP", "port": 5432}]))
    assert decide([p], "frontend", "database", TCP, 5432).verdict is ALLOW
    assert decide([p], "frontend", "database", TCP, 5433).verdict is DENY


def test_named_port_resolves_at_destination():
    p = policy("named", "prod", {"matchLabels": {}}, ingress=rule_ports([{"port": "db"}]))
    assert decide([p], "frontend", "database", TCP, 5432).verdict is ALLOW  # db=5432 on database
    assert decide([p], "frontend", "database", TCP, 5433).verdict is DENY
    assert decide([p], "frontend", "cache", TCP, 5433).verdict is ALLOW  # db=5433 on cache
    assert decide([p], "frontend", "cache", TCP, 5432).verdict is DENY


def test_named_port_absent_or_wrong_protocol_does_not_match():
    missing = policy("m", "prod", sel("database"), ingress=rule_ports([{"port": "metrics"}]))
    assert decide([missing], "frontend", "database", TCP, 5432).verdict is DENY
    dns_tcp = policy("d", "prod", sel("cache"), ingress=rule_ports([{"protocol": "TCP", "port": "dns"}]))
    assert decide([dns_tcp], "frontend", "cache", TCP, 5353).verdict is DENY  # dns is UDP
    dns_udp = policy("d2", "prod", sel("cache"), ingress=rule_ports([{"protocol": "UDP", "port": "dns"}]))
    assert decide([dns_udp], "frontend", "cache", UDP, 5353).verdict is ALLOW


def test_named_port_in_egress_resolves_at_destination():
    p = policy(
        "eg",
        "prod",
        sel("frontend"),
        types=["Egress"],
        egress=[{"to": [{"podSelector": sel("cache")}], "ports": [{"port": "db"}]}],
    )
    assert decide([p], "frontend", "cache", TCP, 5433).verdict is ALLOW
    assert decide([p], "frontend", "cache", TCP, 5432).verdict is DENY


@pytest.mark.parametrize(
    "rule_proto,query_proto,expected",
    [
        (None, TCP, ALLOW),  # protocol defaults to TCP
        (None, UDP, DENY),
        ("TCP", UDP, DENY),
        ("UDP", UDP, ALLOW),
        ("UDP", TCP, DENY),
        ("SCTP", SCTP, ALLOW),
        ("SCTP", TCP, DENY),
    ],
)
def test_protocol_matching(rule_proto, query_proto, expected):
    entry = {"port": 9000}
    if rule_proto:
        entry["protocol"] = rule_proto
    p = policy("proto", "prod", sel("database"), ingress=rule_ports([entry]))
    assert decide([p], "frontend", "database", query_proto, 9000).verdict is expected


@pytest.mark.parametrize(
    "port,expected",
    [
        (7999, DENY),
        (8000, ALLOW),
        (8001, ALLOW),
        (8002, ALLOW),
        (8003, DENY),
    ],
)
def test_port_range_boundaries_are_inclusive(port, expected):
    p = policy("range", "prod", sel("database"), ingress=rule_ports([{"port": 8000, "endPort": 8002}]))
    assert decide([p], "frontend", "database", TCP, port).verdict is expected


def test_end_port_equal_to_port_is_single_port():
    p = policy("one", "prod", sel("database"), ingress=rule_ports([{"port": 8000, "endPort": 8000}]))
    assert decide([p], "frontend", "database", TCP, 8000).verdict is ALLOW
    assert decide([p], "frontend", "database", TCP, 8001).verdict is DENY


def test_port_omitted_matches_all_ports_of_protocol_only():
    p = policy("any", "prod", sel("database"), ingress=rule_ports([{"protocol": "UDP"}]))
    assert decide([p], "frontend", "database", UDP, 1).verdict is ALLOW
    assert decide([p], "frontend", "database", TCP, 1).verdict is DENY


# ---------------------------------------------------------------- invalid input
BAD = {"apiVersion": API, "kind": "NetworkPolicy"}


def doc(spec, name="p", ns="prod"):
    return {**BAD, "metadata": {"name": name, "namespace": ns}, "spec": spec}


@pytest.mark.parametrize(
    "bad",
    [
        "not a mapping",
        {"apiVersion": API},  # missing kind
        {**BAD, "metadata": {"namespace": "prod"}, "spec": {"podSelector": {}}},  # missing name
        {**BAD, "metadata": {"name": "p"}, "spec": {"podSelector": {}}},  # missing namespace
        doc({}),  # missing podSelector
        doc({"podSelector": None}),
        doc({"podSelector": {"matchLabels": {"a": 1}}}),  # malformed selector
        doc({"podSelector": {}, "bogus": 1}),  # unknown spec field
        doc({"podSelector": {}, "policyTypes": ["Sideways"]}),
        doc({"podSelector": {}, "policyTypes": ["Ingress", "Ingress"]}),
        doc({"podSelector": {}, "ingress": [{"from": [{}]}]}),  # empty peer
        doc({"podSelector": {}, "ingress": [{"bogus": []}]}),
        doc(
            {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}, "podSelector": {}}]}],
            }
        ),  # ipBlock + selector
        doc(
            {
                "podSelector": {},
                "ingress": [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8", "except": ["192.168.0.0/16"]}}]}],
            }
        ),
        doc({"podSelector": {}, "ingress": [{"from": [{"ipBlock": {"cidr": "not-a-cidr"}}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": 70000}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": 0}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": True}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": "Bad_Name"}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"protocol": "ICMP", "port": 80}]}]}),
        doc({"podSelector": {}, "ingress": [{"ports": [{"protocol": "tcp", "port": 80}]}]}),  # case-sensitive
        doc({"podSelector": {}, "ingress": [{"ports": [{"endPort": 90}]}]}),  # no port
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": "db", "endPort": 90}]}]}),  # named endPort
        doc({"podSelector": {}, "ingress": [{"ports": [{"port": 90, "endPort": 80}]}]}),  # end < port
    ],
)
def test_invalid_policy_raises(bad):
    with pytest.raises(PolicyError):
        Evaluator(TOPO, [bad])


def test_duplicate_policy_identity_rejected():
    with pytest.raises(PolicyError):
        Evaluator(TOPO, [doc({"podSelector": {}}), doc({"podSelector": {}})])


def test_policy_in_unknown_namespace_rejected():
    with pytest.raises(PolicyError):
        Evaluator(TOPO, [doc({"podSelector": {}}, ns="missing")])


# ---------------------------------------------------------------- unknown results
def test_unsupported_resource_kind_makes_every_query_unknown():
    anp = {
        "apiVersion": "policy.networking.k8s.io/v1alpha1",
        "kind": "AdminNetworkPolicy",
        "metadata": {"name": "x"},
        "spec": {},
    }
    d = decide([anp], "frontend", "database")
    assert d.verdict is UNKNOWN and d.reason == "unsupported-resource"


def test_ip_block_peer_cannot_be_resolved_for_pods():
    p = policy(
        "ip",
        "prod",
        sel("database"),
        ingress=[{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"port": 5432}]}],
    )
    d = decide([p], "frontend", "database", TCP, 5432)
    assert d.verdict is UNKNOWN and d.reason == "unresolved-peer"
    assert d.ingress.matched_rules[0].certain is False


def test_ip_block_with_nonmatching_port_is_definite_deny():
    p = policy(
        "ip",
        "prod",
        sel("database"),
        ingress=[{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}], "ports": [{"port": 5432}]}],
    )
    assert decide([p], "frontend", "database", TCP, 9999).verdict is DENY


def test_definite_allow_rule_overrides_unresolved_ip_block():
    p = policy(
        "mix",
        "prod",
        sel("database"),
        ingress=[{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}, {"podSelector": sel("frontend")}]}],
    )
    assert decide([p], "frontend", "database").verdict is ALLOW


def test_definite_deny_in_other_direction_beats_unknown():
    ip = policy("ip", "prod", sel("database"), ingress=[{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}])
    egr = policy("eg", "prod", sel("frontend"), egress=[], types=["Egress"])
    assert decide([ip, egr], "frontend", "database").verdict is DENY


def test_pod_not_in_topology_is_unknown():
    ghost = Pod("ghost", "prod", {"app": "ghost"})
    ev = Evaluator(TOPO, [])
    d = ev.evaluate(ConnectionQuery(ghost, PODS["database"], TCP, 5432))
    assert d.verdict is UNKNOWN and d.reason == "pod-not-in-topology"


def test_self_traffic_is_unknown():
    d = decide([], "database", "database")
    assert d.verdict is UNKNOWN and d.reason == "self-traffic-unsupported"
