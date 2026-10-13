import hashlib

import pytest

from app.model.evaluator import Evaluator, Verdict
from app.model.topology import ConnectionQuery, Namespace, Pod, Protocol, Topology
from app.review.comparison import (
    Approval, Change, ReviewError, compare_revisions, tuple_id, unapproved_changes,
)
from app.review.intents import (
    IntentError, IntentStatus, candidate_acceptable, check_intents, parse_intent,
)

API = "networking.k8s.io/v1"
TCP, UDP = Protocol.TCP, Protocol.UDP
ALLOW, DENY, UNKNOWN = Verdict.ALLOW, Verdict.DENY, Verdict.UNKNOWN


# ---------------------------------------------------------------- fixtures
def make_topology():
    t = Topology()
    t.add_namespace(Namespace("prod", {"team": "pay"}))
    t.add_namespace(Namespace("ops", {"team": "ops"}))
    t.add_pod(Pod("frontend", "prod", {"app": "frontend"}))
    t.add_pod(Pod("payments", "prod", {"app": "payments"}))
    t.add_pod(Pod("database", "prod", {"app": "database"}))
    t.add_pod(Pod("analytics", "ops", {"app": "analytics"}))
    return t


TOPO = make_topology()
PODS = {p.name: p for p in TOPO.pods.values()}
NS_OF = {p.name: p.namespace for p in TOPO.pods.values()}


def app(name):
    return {"matchLabels": {"app": name}}


def policy(name, selector, ingress=None, ns="prod"):
    spec = {"podSelector": selector}
    if ingress is not None:
        spec["ingress"] = ingress
    return {"apiVersion": API, "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": ns}, "spec": spec}


FROM_FRONTEND = [{"podSelector": app("frontend")}]
FROM_PAYMENTS = [{"podSelector": app("payments")}]
FROM_ANALYTICS = [{"namespaceSelector": {"matchLabels": {"team": "ops"}}, "podSelector": app("analytics")}]


def db_in(name, peers, port=5432):
    return policy(name, app("database"), [{"from": peers, "ports": [{"protocol": "TCP", "port": port}]}])


PAY_IN = policy("pay-in", app("payments"), [{"from": FROM_FRONTEND, "ports": [{"protocol": "TCP", "port": 8080}]}])
BASE = [db_in("db-in", FROM_PAYMENTS), PAY_IN]
CAND = [db_in("db-in", FROM_ANALYTICS), PAY_IN]  # the accidental swap


def ev(policies):
    return Evaluator(TOPO, list(policies))


def q(src, dst, proto=TCP, port=5432):
    return ConnectionQuery(PODS[src], PODS[dst], proto, port)


def tid(src, dst, proto="TCP", port=5432):
    """Independent re-derivation of the documented tuple-ID format."""
    key = f"{NS_OF[src]}/{src}|{NS_OF[dst]}/{dst}|{proto}|{port}"
    return "t-" + hashlib.sha256(key.encode()).hexdigest()[:16]


SCENARIO_QUERIES = [q("frontend", "payments", TCP, 8080), q("payments", "database"), q("analytics", "database")]


def scenario():
    return compare_revisions(ev(BASE), ev(CAND), SCENARIO_QUERIES)


def by_id(comparisons):
    return {c.tuple_id: c for c in comparisons}


def raw_intent(**over):
    d = {"id": "i1", "source": {"podSelector": app("payments")},
         "destination": {"podSelector": app("database")},
         "protocol": "TCP", "port": 5432, "expect": "must_allow"}
    d.update(over)
    return d


def result_for(results, intent_id):
    return next(r for r in results if r.intent_id == intent_id)


# ---------------------------------------------------------------- comparison (1-6, 12)
def test_newly_allowed():
    c = by_id(scenario())[tid("analytics", "database")]
    assert (c.baseline, c.candidate, c.change) == (DENY, ALLOW, Change.NEWLY_ALLOWED)


def test_newly_blocked():
    c = by_id(scenario())[tid("payments", "database")]
    assert (c.baseline, c.candidate, c.change) == (ALLOW, DENY, Change.NEWLY_BLOCKED)
    assert c.baseline_decision.reason == "allowed"
    assert c.candidate_decision.reason == "ingress-denied"  # explanations retained
    assert c.candidate_decision.ingress.selecting_policies == ("prod/db-in",)


def test_unchanged_frontend_to_payments():
    c = by_id(scenario())[tid("frontend", "payments", "TCP", 8080)]
    assert (c.baseline, c.candidate, c.change) == (ALLOW, ALLOW, Change.UNCHANGED)
    assert (c.source, c.destination, c.protocol, c.port) == ("prod/frontend", "prod/payments", TCP, 8080)


@pytest.mark.parametrize("base,cand,expected", [
    ([], [], ALLOW),                                         # allow -> allow
    ([db_in("db-in", FROM_PAYMENTS)], [db_in("x", FROM_PAYMENTS)], DENY),  # deny -> deny (analytics)
])
def test_unchanged_both_known(base, cand, expected):
    (c,) = compare_revisions(ev(base), ev(cand), [q("analytics", "database")])
    assert c.change is Change.UNCHANGED and c.baseline is expected and c.candidate is expected


IP_ONLY = policy("ip", app("database"), [{"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}])
ANP = {"apiVersion": "policy.networking.k8s.io/v1alpha1", "kind": "AdminNetworkPolicy",
       "metadata": {"name": "x"}, "spec": {}}


@pytest.mark.parametrize("base,cand,b_exp,c_exp", [
    ([], [IP_ONLY], ALLOW, UNKNOWN),
    ([ANP], [], UNKNOWN, ALLOW),
    ([IP_ONLY], [IP_ONLY], UNKNOWN, UNKNOWN),
])
def test_unknown_decisions(base, cand, b_exp, c_exp):
    (c,) = compare_revisions(ev(base), ev(cand), [q("frontend", "database")])
    assert (c.baseline, c.candidate, c.change) == (b_exp, c_exp, Change.UNKNOWN)


def test_tuple_ids_are_stable_and_distinct():
    a = compare_revisions(ev(BASE), ev(CAND), [q("payments", "database")])[0]
    b = compare_revisions(ev([]), ev([]), [q("payments", "database")])[0]
    assert a.tuple_id == b.tuple_id == tid("payments", "database")  # same across runs/revisions
    assert tuple_id(q("payments", "database")) == tid("payments", "database")
    others = {tid("database", "payments"), tid("payments", "database", "UDP"), tid("payments", "database", "TCP", 5433)}
    assert len(others | {a.tuple_id}) == 4
    assert tuple_id(q("payments", "database", UDP)) == tid("payments", "database", "UDP")
    relabelled = Pod("payments", "prod", {"other": "label"})
    assert tuple_id(ConnectionQuery(relabelled, PODS["database"], TCP, 5432)) == a.tuple_id


def test_duplicate_tuple_rejected():
    with pytest.raises(ReviewError, match="duplicate"):
        compare_revisions(ev([]), ev([]), [q("payments", "database"), q("payments", "database")])


def test_different_topologies_rejected():
    other = make_topology()
    other.add_pod(Pod("extra", "prod", {"app": "extra"}))
    with pytest.raises(ReviewError):
        compare_revisions(ev([]), Evaluator(other, []), [q("payments", "database")])


def test_equivalent_policies_produce_no_regression():
    rule_a = {"from": FROM_FRONTEND, "ports": [{"protocol": "TCP", "port": 5432}]}
    rule_b = {"from": FROM_PAYMENTS, "ports": [{"protocol": "TCP", "port": 5432}]}
    base = [policy("db-in", app("database"), [rule_a, rule_b])]
    reordered = [policy("db-in", app("database"), [rule_b, rule_a])]
    split = [policy("b", app("database"), [rule_b]), policy("a", app("database"), [rule_a])]
    merged_peers = [db_in("db-in", FROM_PAYMENTS + FROM_FRONTEND)]
    queries = [q("frontend", "database"), q("payments", "database"), q("analytics", "database")]
    for cand in (reordered, split, merged_peers):
        comps = compare_revisions(ev(base), ev(cand), queries)
        assert [c.change for c in comps] == [Change.UNCHANGED] * 3
        assert [c.candidate for c in comps] == [ALLOW, ALLOW, DENY]


# ---------------------------------------------------------------- intents (7-11)
def test_required_connection_unexpectedly_denied():
    intent = parse_intent(raw_intent(id="pay-db"))
    r = result_for(check_intents([intent], scenario(), TOPO), "pay-db")
    assert r.matched_count == 1
    assert r.baseline.status is IntentStatus.PASS
    assert r.candidate.status is IntentStatus.FAIL
    assert r.candidate.violations == (tid("payments", "database"),)
    assert r.new_violations == (tid("payments", "database"),) and r.existing_violations == ()


def test_forbidden_connection_unexpectedly_allowed():
    intent = parse_intent(raw_intent(id="no-analytics", source={"podSelector": app("analytics")}, expect="must_deny"))
    r = result_for(check_intents([intent], scenario(), TOPO), "no-analytics")
    assert r.baseline.status is IntentStatus.PASS
    assert r.candidate.status is IntentStatus.FAIL
    assert r.candidate.violations == (tid("analytics", "database"),)


def test_passing_intent_for_unchanged_connection():
    intent = parse_intent(raw_intent(id="fe-pay", source={"podSelector": app("frontend")},
                                     destination={"podSelector": app("payments")}, port=8080))
    r = check_intents([intent], scenario(), TOPO)[0]
    assert r.baseline.status is r.candidate.status is IntentStatus.PASS
    assert r.valid and r.candidate_passes


@pytest.mark.parametrize("over", [
    {"destination": {"podSelector": app("ghost")}},  # no such Pod
    {"port": 9999},                                   # no query on that port
    {"protocol": "UDP"},                              # no query with that protocol
])
def test_zero_match_intent_never_passes(over):
    intent = parse_intent(raw_intent(id="z", **over))
    r = check_intents([intent], scenario(), TOPO)[0]
    assert r.matched_count == 0 and r.problems == ("zero-match",)
    assert r.baseline.status is r.candidate.status is IntentStatus.INVALID
    assert not r.valid and not r.candidate_passes
    assert not candidate_acceptable([r], [])


def test_unknown_intent_outcomes():
    queries = [q("frontend", "database")]
    comps = compare_revisions(ev([]), ev([IP_ONLY]), queries)
    allow_i = parse_intent(raw_intent(id="allow", source={"podSelector": app("frontend")}))
    deny_i = parse_intent(raw_intent(id="deny", source={"podSelector": app("frontend")}, expect="must_deny"))
    ra = check_intents([allow_i], comps, TOPO)[0]  # separate calls: together they would conflict
    rd = check_intents([deny_i], comps, TOPO)[0]
    assert ra.baseline.status is IntentStatus.PASS
    assert ra.candidate.status is IntentStatus.UNKNOWN
    assert ra.candidate.unknown == (tid("frontend", "database"),) and ra.candidate.violations == ()
    assert rd.baseline.status is IntentStatus.FAIL  # baseline Allow violates must_deny
    assert rd.candidate.status is IntentStatus.UNKNOWN
    assert not candidate_acceptable([ra], [])  # Unknown can never pass


def test_definite_violation_outranks_unknown():
    front_locked = policy("front-lock", app("frontend"), [])  # isolates frontend ingress, no rules
    queries = [q("frontend", "database"), q("payments", "frontend")]
    comps = compare_revisions(ev([]), ev([IP_ONLY, front_locked]), queries)
    intent = parse_intent(raw_intent(
        id="any", source={},
        destination={"podSelector": {"matchExpressions": [
            {"key": "app", "operator": "In", "values": ["database", "frontend"]}]}}))
    r = check_intents([intent], comps, TOPO)[0]
    assert r.matched_count == 2
    assert r.baseline.status is IntentStatus.PASS
    assert r.candidate.status is IntentStatus.FAIL
    assert r.candidate.violations == (tid("payments", "frontend"),)
    assert r.candidate.unknown == (tid("frontend", "database"),)


def test_existing_versus_new_violations():
    # must_deny: nothing may reach the database on TCP/5432.
    base = [db_in("db-in", FROM_ANALYTICS)]   # analytics allowed (existing violation)
    cand = [db_in("db-in", FROM_FRONTEND)]    # frontend allowed (new), analytics fixed
    comps = compare_revisions(ev(base), ev(cand), [q("frontend", "database"), q("analytics", "database")])
    intent = parse_intent(raw_intent(id="locked", source={}, expect="must_deny"))
    r = check_intents([intent], comps, TOPO)[0]
    assert r.matched_count == 2
    assert r.existing_violations == (tid("analytics", "database"),)
    assert r.new_violations == (tid("frontend", "database"),)
    assert r.fixed_violations == (tid("analytics", "database"),)
    assert r.baseline.status is r.candidate.status is IntentStatus.FAIL


def test_preexisting_violation_that_persists_is_not_new():
    base = cand = [db_in("db-in", FROM_ANALYTICS)]
    comps = compare_revisions(ev(base), ev(cand), [q("analytics", "database")])
    r = check_intents([parse_intent(raw_intent(id="locked", source={}, expect="must_deny"))], comps, TOPO)[0]
    assert r.existing_violations == (tid("analytics", "database"),)
    assert r.new_violations == () and r.fixed_violations == ()


def test_conflicting_intents_are_invalid():
    comps = compare_revisions(ev([]), ev([]), [q("frontend", "database")])
    allow_i = parse_intent(raw_intent(id="a", source={"podSelector": app("frontend")}))
    deny_i = parse_intent(raw_intent(id="d", source={}, expect="must_deny"))
    res = check_intents([allow_i, deny_i], comps, TOPO)
    for r in res:
        assert r.problems == ("conflict",)
        assert r.conflicting_tuples == (tid("frontend", "database"),)
        assert r.candidate.status is IntentStatus.INVALID


def test_duplicate_intent_id_rejected():
    i = parse_intent(raw_intent(id="same"))
    with pytest.raises(IntentError, match="duplicate"):
        check_intents([i, i], scenario(), TOPO)


MISSING = object()


@pytest.mark.parametrize("bad", [
    "not a mapping",
    raw_intent(id=""),
    raw_intent(id=5),
    raw_intent(expect="maybe"),
    raw_intent(protocol="ICMP"),
    raw_intent(port=0),
    raw_intent(port=70000),
    raw_intent(port="5432"),
    raw_intent(port=True),
    raw_intent(source="payments"),
    raw_intent(source={"labels": {}}),
    raw_intent(source={"podSelector": {"matchLabels": {"a": 1}}}),
    raw_intent(bogus=1),
    {k: v for k, v in raw_intent().items() if k != "expect"},
    {k: v for k, v in raw_intent().items() if k != "source"},
])
def test_invalid_intent_definitions_rejected(bad):
    with pytest.raises(IntentError):
        parse_intent(bad)


# ---------------------------------------------------------------- approvals never override intents
def test_approval_clears_review_gate_but_not_intent_violation():
    comps = scenario()
    intent = parse_intent(raw_intent(id="pay-db"))
    results = check_intents([intent], comps, TOPO)
    approvals = [Approval(tid("payments", "database"), ALLOW, DENY),
                 Approval(tid("analytics", "database"), DENY, ALLOW)]
    assert unapproved_changes(comps, []) != ()
    assert unapproved_changes(comps, approvals) == ()
    assert not candidate_acceptable(results, unapproved_changes(comps, approvals))


def test_approval_must_match_exactly():
    comps = scenario()
    wrong = [Approval(tid("payments", "database"), ALLOW, UNKNOWN),   # wrong 'after' verdict
             Approval(tid("analytics", "database"), DENY, ALLOW)]
    remaining = unapproved_changes(comps, wrong)
    assert [c.tuple_id for c in remaining] == [tid("payments", "database")]


def test_acceptable_when_intents_pass_and_changes_approved():
    comps = compare_revisions(ev(BASE), ev(BASE), SCENARIO_QUERIES)
    intent = parse_intent(raw_intent(id="pay-db"))
    assert candidate_acceptable(check_intents([intent], comps, TOPO), unapproved_changes(comps, []))
    assert not candidate_acceptable([], [])  # no intents is not a pass