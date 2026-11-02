"""Metamorphic checks target real semantic risks, not implementation copies."""

import copy
import pytest
from hypothesis import given, strategies as st
from app.ingest.project import parse_project
from app.service import review_project
from app.model.selectors import matches
from app.model.evaluator import Evaluator


@given(
    st.dictionaries(st.sampled_from(["app", "team", "tier"]), st.sampled_from(["a", "b", "c"]), max_size=3)
)
def test_empty_selector_matches_all_labels(labels):
    assert matches({}, labels)


@given(st.sampled_from(["a", "b", "c"]), st.booleans())
def test_notin_absent_and_present_semantics(value, present):
    labels = {"app": value} if present else {}
    assert matches({"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["a"]}]}, labels) == (
        not present or value != "a"
    )


def test_order_invariance_and_duplicate_equivalent_policy(example):
    raw = example("checkout-regression")
    first = review_project(raw)
    raw["baseline"].reverse()
    raw["candidate"].reverse()
    raw["topology"].reverse()
    changed = review_project(raw)
    assert [(r["tuple_id"], r["baseline"], r["candidate"]) for r in first["rows"]] == [
        (r["tuple_id"], r["baseline"], r["candidate"]) for r in changed["rows"]
    ]
    dup = copy.deepcopy(raw["candidate"][0])
    dup["metadata"]["name"] = "equivalent-copy"
    raw["candidate"].append(dup)
    assert [(r["baseline"], r["candidate"]) for r in review_project(raw)["rows"]] == [
        (r["baseline"], r["candidate"]) for r in first["rows"]
    ]


def test_allow_addition_monotonic_when_isolation_unchanged(example):
    raw = example("clean-baseline")
    p = parse_project(raw)
    before = Evaluator(p.topology, p.candidate)
    extra = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "additional-allow", "namespace": "data"},
        "spec": {
            "podSelector": {"matchLabels": {"app": "database"}},
            "policyTypes": ["Ingress"],
            "ingress": [{}],
        },
    }
    after = Evaluator(p.topology, p.candidate + [extra])
    for q in p.queries:
        b, a = before.evaluate(q), after.evaluate(q)
        assert not (b.verdict.value == "Allow" and a.verdict.value == "Deny")


@pytest.mark.parametrize(
    "operator,key,extra_labels,expected",
    [
        ("Exists", "tier", {}, "Allow"),
        ("DoesNotExist", "absent", {}, "Allow"),
        ("DoesNotExist", "absent", {"absent": "present"}, "Deny"),
    ],
)
def test_cross_namespace_peer_presence_expressions(example, operator, key, extra_labels, expected):
    raw = example("clean-baseline")
    database = next(p for p in raw["topology"] if p["metadata"]["name"] == "database")
    database["metadata"]["labels"].update(extra_labels)
    policy = next(p for p in raw["candidate"] if p["metadata"]["name"] == "gateway-egress")
    policy["spec"]["egress"] = [
        {
            "to": [
                {
                    "namespaceSelector": {},
                    "podSelector": {"matchExpressions": [{"key": key, "operator": operator}]},
                }
            ],
            "ports": [{"port": 5432}],
        }
    ]
    row = next(
        r
        for r in review_project(raw)["rows"]
        if (r["source"], r["destination"], r["protocol"], r["port"])
        == ("apps/tool-gateway", "data/database", "TCP", 5432)
    )
    assert row["candidate"] == expected
