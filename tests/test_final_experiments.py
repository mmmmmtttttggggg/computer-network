import copy
import json
import pytest
from app.analysis.coverage import suggest_checks, verify_checks
from app.analysis.labels import label_experiment
from app.analysis.experiments import run_mutations
from app.ingest.project import InputError
from app.cli import main


def test_advisor_is_deterministic_and_keeps_reference_passing(example):
    raw = example()
    before = copy.deepcopy(raw)
    r = suggest_checks(raw)
    assert r["draft_count"] > 0 and r["reference_check"]["status"] == "PASS"
    assert r["specification"] == suggest_checks(raw)["specification"]
    assert raw == before
    assert r["training"]["caught_with_drafts"] > r["training"]["caught_before"]
    assert r["holdout"]["caught_with_drafts"] <= r["holdout"]["effective_faults"]


def test_advisor_holdout_never_used_for_selection(example, monkeypatch):
    import app.analysis.coverage as module

    real = module.run_mutations
    suite = real(example())
    from app.util import digest

    ordered = sorted(suite["mutations"], key=lambda m: digest(m["project"]["candidate"]))
    reference = suggest_checks(example())["specification"]
    # Adversarially replace every held-out decision: the selected checks must stay identical.
    for index, m in enumerate(ordered):
        if index % 4 == 0:
            m["candidate_decisions"] = {}
            m["caught_by_intents"] = True
    monkeypatch.setattr(module, "run_mutations", lambda *a, **k: suite)
    assert suggest_checks(example())["specification"] == reference


def test_drafts_catch_a_real_missed_fault(example):
    raw = example()
    checks = suggest_checks(raw)["specification"]
    missed = [
        m
        for m in run_mutations(raw)["mutations"]
        if not m["caught_by_intents"] and not m["equivalent_on_scope"]
    ]
    assert any(verify_checks(m["project"], checks)["exit_code"] == 1 for m in missed)


@pytest.mark.parametrize("scenario", ["checkout-regression", "unsupported-policy"])
def test_advisor_refuses_bad_reference(example, scenario):
    with pytest.raises(InputError):
        suggest_checks(example(scenario))


def test_budget_limited_suite_is_explicit(example):
    r = suggest_checks(example(), seconds=0)
    assert r["budget_limited"] and r["faults_generated"] == 0 and r["draft_count"] == 0


def one_check(**changes):
    c = {
        "id": "agent-no-db",
        "source": "apps/agent",
        "destination": "data/database",
        "protocol": "TCP",
        "port": 5432,
        "expect": "must_deny",
    }
    c.update(changes)
    return {"schemaVersion": 1, "checks": [c]}


def test_check_can_ask_outside_declared_port_scope(example):
    raw = example()
    before = copy.deepcopy(raw)
    r = verify_checks(raw, one_check(port=12345))
    assert r["status"] == "PASS" and r["checks"][0]["actual"] == "Deny"
    assert raw == before


def test_check_unknown_never_passes(example):
    r = verify_checks(example("unsupported-policy"), one_check())
    assert r["status"] == "INCOMPLETE" and r["exit_code"] == 2


@pytest.mark.parametrize(
    "change",
    [
        {"port": True},
        {"port": 0},
        {"source": "missing/pod"},
        {"protocol": "HTTP"},
        {"expect": "Unknown"},
        {"port": []},
    ],
)
def test_invalid_checks_are_rejected(example, change):
    with pytest.raises(InputError):
        verify_checks(example(), one_check(**change))


def test_duplicate_conflicting_checks_are_rejected(example):
    spec = one_check()
    second = {**spec["checks"][0], "id": "conflict", "expect": "must_allow"}
    spec["checks"].append(second)
    with pytest.raises(InputError):
        verify_checks(example(), spec)


def test_changed_reference_hash_is_informational_and_checks_still_execute(example):
    raw = example()
    spec = suggest_checks(raw)["specification"]
    raw["name"] += " new revision"
    r = verify_checks(raw, spec)
    assert not r["same_as_reference"] and r["status"] == "PASS"


def test_label_change_exposes_policy_selection_and_zero_matches(example):
    raw = example("agent-escape")
    before = copy.deepcopy(raw)
    r = label_experiment(raw, "apps/agent", {"app": "payments", "tier": "service"})
    assert raw == before
    assert r["targeting"]["egress"]["before"]["isolated"]
    assert r["targeting"]["egress"]["after"]["isolated"] is False
    assert not r["new_asset_paths"]  # The indirect asset pair was already exposed.
    assert r["shortened_asset_paths"][0]["after"]["hops"][0]["destination"] == "data/database"
    assert len(r["shortened_asset_paths"][0]["before"]["hops"]) == 2
    assert any(i["matched_count"] == 0 and i["candidate"]["status"] == "INVALID" for i in r["intents"])


def test_noop_labels_do_not_change_permissions(example):
    r = label_experiment(example(), "apps/agent", {"app": "agent", "tier": "service"})
    assert not r["changes"] and not r["new_asset_paths"]


def test_label_scope_does_not_attribute_newly_queried_edges_to_labels(example):
    raw = example("agent-escape")
    raw["queries"] = []
    raw["intents"] = [i for i in raw["intents"] if i["id"] != "agent-no-direct-db"]
    r = label_experiment(raw, "apps/agent", {"app": "payments", "tier": "service"})
    assert r["additional_intent_queries"] > 0
    assert not r["new_asset_paths"]  # Unqueried old edges cannot be treated as prior Deny.


@pytest.mark.parametrize(
    "endpoint,labels",
    [("bad/pod", {}), ("apps/agent", []), ("apps/agent", {"app": 3}), ("apps/agent", {"bad key": "value"})],
)
def test_bad_label_experiment_is_rejected(example, endpoint, labels):
    with pytest.raises(InputError):
        label_experiment(example(), endpoint, labels)


def test_cli_drafts_are_reusable(example, tmp_path):
    project = tmp_path / "project.json"
    output = tmp_path / "checks.json"
    project.write_text(json.dumps(example()))
    assert main(["suggest-checks", str(project), "--out", str(output)]) == 0
    assert main(["check", str(project), str(output)]) == 0
    project.write_text(json.dumps(example("unsupported-policy")))
    assert main(["check", str(project), str(output)]) == 2
