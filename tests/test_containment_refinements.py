import copy
from app.service import review_project


def test_single_pivot_sensitivity_rechecks_routes_without_changing_permissions(example):
    raw = example("agent-escape")
    report = review_project(raw)
    finding = report["threat"]["findings"][0]
    assert finding["assumption_checks"] == [
        {
            "pivot": "apps/tool-gateway",
            "asset_still_reachable": False,
            "alternative_hops": [],
        }
    ]
    assert all(p["declaration"] == "declared" for p in finding["port_evidence"])
    raw["threatModel"]["pivots"] = []
    changed = review_project(raw)
    assert changed["threat"]["findings"] == []
    assert report["rows"] == changed["rows"]


def test_alternative_gateway_prevents_false_critical_assumption(example):
    raw = example("agent-escape")
    gateway = copy.deepcopy(next(p for p in raw["topology"] if p["metadata"]["name"] == "tool-gateway"))
    gateway["metadata"]["name"] = "tool-gateway-2"
    raw["topology"].append(gateway)
    raw["threatModel"]["pivots"].append("apps/tool-gateway-2")
    finding = review_project(raw)["threat"]["findings"][0]
    check = finding["assumption_checks"][0]
    assert check["asset_still_reachable"]
    assert [h["destination"] for h in check["alternative_hops"]] == ["apps/tool-gateway-2", "data/database"]


def test_missing_port_declaration_does_not_silently_remove_permission_path(example):
    raw = example("agent-escape")
    db = next(p for p in raw["topology"] if p["metadata"]["name"] == "database")
    db["spec"]["containers"][0]["ports"] = []
    finding = review_project(raw)["threat"]["findings"][0]
    assert finding["port_evidence"][-1]["declaration"] == "not-declared"
    assert finding["port_evidence"][0]["declaration"] == "declared"


def test_direct_path_has_no_pivot_to_remove(example):
    raw = example("agent-escape")
    raw["threatModel"]["entrypoints"] = ["apps/tool-gateway"]
    finding = review_project(raw)["threat"]["findings"][0]
    assert finding["kind"] == "direct exposure"
    assert finding["assumption_checks"] == []


def test_alternative_path_outside_query_scope_is_not_assumed(example):
    raw = example("agent-escape")
    raw["queries"] = [
        {"source": "apps/agent", "destination": "apps/tool-gateway", "protocol": "TCP", "port": 8081},
        {"source": "apps/tool-gateway", "destination": "data/database", "protocol": "TCP", "port": 5432},
    ]
    finding = review_project(raw)["threat"]["findings"][0]
    assert not finding["assumption_checks"][0]["asset_still_reachable"]
    assert "not a universal" in review_project(raw)["threat"]["sensitivity_scope"]
