"""End-to-end cases with expectations derived from policy semantics."""

import copy
import pytest
from app.service import review_project
from app.analysis.coverage import verify_checks
from app.runtime.runner import runtime_preflight


def test_deleting_last_policy_opens_connections_even_when_intents_pass(example):
    r = review_project(example("last-policy-deleted"))
    assert r["stats"]["intent_pass"] == 5 and r["exit_code"] == 1
    changes = [q for q in r["rows"] if q["change"] == "NEWLY_ALLOWED"]
    assert len(changes) > 1 and all(q["source"] == "apps/agent" for q in changes)
    assert all(q["baseline_decision"]["egress"]["isolated"] for q in changes)
    assert all(q["candidate_decision"]["egress"]["isolated"] is False for q in changes)


def test_removing_one_overlapping_allow_policy_preserves_permission(example):
    raw = example()
    overlapping = copy.deepcopy(raw["baseline"][1])
    overlapping["metadata"]["name"] = "second-agent-egress"
    raw["baseline"].append(overlapping)
    r = review_project(raw)
    assert r["exit_code"] == 0 and all(q["change"] == "UNCHANGED" for q in r["rows"])


def test_reduced_oracle_case_has_an_explicit_intent_and_live_plan(example):
    raw = example("cross-namespace-check")
    r = review_project(raw)
    assert r["exit_code"] == 0 and r["stats"]["queries"] == 1
    assert r["rows"][0]["baseline"] == r["rows"][0]["candidate"] == "Allow"
    assert r["plan"]["tuples"][0]["source"] == "data/b"
    runtime_preflight(raw, "test", {"test": "https://127.0.0.1:6443"})


@pytest.mark.parametrize(
    "port,expected", [(8079, "Deny"), (8080, "Allow"), (8081, "Allow"), (8082, "Allow"), (8083, "Deny")]
)
def test_numeric_range_boundaries_through_exact_check_api(example, port, expected):
    raw = example()
    policy = raw["candidate"][1]
    policy["spec"]["egress"][0]["ports"] = [{"protocol": "TCP", "port": 8080, "endPort": 8082}]
    spec = {
        "schemaVersion": 1,
        "checks": [
            {
                "id": "range-boundary",
                "source": "apps/agent",
                "destination": "apps/tool-gateway",
                "protocol": "TCP",
                "port": port,
                "expect": "must_allow",
            }
        ],
    }
    # Remove gateway ingress so this case isolates the source range semantics.
    raw["candidate"] = [p for p in raw["candidate"] if p["metadata"]["name"] != "gateway-ingress"]
    r = verify_checks(raw, spec)
    assert r["checks"][0]["actual"] == expected
    assert r["exit_code"] == (0 if expected == "Allow" else 1)
