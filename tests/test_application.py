import copy
import io
import json
import zipfile
from app.service import review_project
from app.ingest.project import parse_project, load_text, InputError
from app.analysis.reducer import reduce_project, bundle_zip
from app.analysis.experiments import repair_project, run_mutations
from app.cli import replay, main
from app.store import RunStore, CapacityError
from app.runtime.runner import runtime_preflight, RuntimeErrorSafe
from app.runtime.verdicts import classify_observation
import pytest


@pytest.mark.parametrize(
    "name,status,opened,blocked,intents,paths",
    [
        ("clean-baseline", "PASS", 0, 0, 5, 0),
        ("agent-escape", "FAIL", 1, 0, 5, 1),
        ("parallel-relay", "FAIL", 2, 0, 5, 1),
        ("checkout-regression", "FAIL", 1, 1, 3, 0),
        ("selector-trap", "FAIL", 2, 0, 4, 0),
        ("unsupported-policy", "INCOMPLETE", 0, 0, 0, 0),
    ],
)
def test_reviewed_scenario_truth_tables(example, name, status, opened, blocked, intents, paths):
    r = review_project(example(name))
    assert r["status"] == status
    assert r["stats"]["NEWLY_ALLOWED"] == opened
    assert r["stats"]["NEWLY_BLOCKED"] == blocked
    assert r["stats"]["intent_pass"] == intents
    assert len(r["threat"]["findings"]) == paths
    assert r["runtime_status"] == "NOT_VERIFIED"


def test_indirect_path_requires_explicit_pivot(example):
    raw = example("agent-escape")
    r = review_project(raw)
    assert r["threat"]["findings"][0]["hops"] == [
        next(
            {k: row[k] for k in ["source", "destination", "protocol", "port", "tuple_id"]}
            for row in r["rows"]
            if row["source"] == s and row["destination"] == d and row["port"] == port
        )
        for s, d, port in [
            ("apps/agent", "apps/tool-gateway", 8081),
            ("apps/tool-gateway", "data/database", 5432),
        ]
    ]
    raw["threatModel"]["pivots"] = []
    assert review_project(raw)["threat"]["findings"] == []
    # Network decisions themselves must be unchanged when an assumption changes.
    assert review_project(raw)["rows"] == r["rows"]


def test_unknown_and_unqueried_edges_never_form_paths(example):
    raw = example("agent-escape")
    raw["queries"] = []
    raw["intents"] = [i for i in raw["intents"] if i["id"] != "payments-to-database"]
    assert review_project(raw)["threat"]["findings"] == []
    assert review_project(example("unsupported-policy"))["threat"]["findings"] == []


def test_explicit_queries_cannot_skip_intent_coverage(example):
    raw = example()
    raw["queries"] = []
    r = review_project(raw)
    assert len(r["rows"]) == 5
    assert all(i["matched_count"] == 1 for i in r["intents"])


def test_zero_match_intent_prevents_pass(example):
    raw = example()
    raw["intents"][0]["source"]["podSelector"]["matchLabels"]["app"] = "missing"
    r = review_project(raw)
    assert r["exit_code"] == 2
    assert "zero-match" in r["intents"][0]["problems"]


def test_approval_never_waives_failed_intent(example):
    raw = example("checkout-regression")
    r = review_project(raw)
    raw["approvals"] = [
        {k: row[k] for k in ["tuple_id", "baseline", "candidate"]}
        for row in r["rows"]
        if row["change"] != "UNCHANGED"
    ]
    r = review_project(raw)
    assert not r["unapproved"] and r["exit_code"] == 1


def test_approval_does_not_hide_containment_finding(example):
    raw = example("agent-escape")
    r = review_project(raw)
    raw["approvals"] = [
        {k: row[k] for k in ["tuple_id", "baseline", "candidate"]}
        for row in r["rows"]
        if row["change"] != "UNCHANGED"
    ]
    r = review_project(raw)
    assert r["exit_code"] == 0  # SRS gate is separate from the conditional threat study.
    assert len(r["threat"]["findings"]) == 1


def test_reducer_preserves_and_replays_with_fixed_topology(example):
    raw = example("checkout-regression")
    before = copy.deepcopy(raw)
    r = review_project(raw)
    tid = next(row["tuple_id"] for row in r["rows"] if row["change"] == "NEWLY_BLOCKED")
    result = reduce_project(raw, tid)
    assert result["policy_units_before"] == 10 and result["policy_units_after"] == 1
    assert result["status"] == "1-minimal"
    assert result["project"]["topology"] == raw["topology"]
    assert raw == before
    assert replay(result["project"], result)["preserved"]
    assert reduce_project(raw, tid)["kept"] == result["kept"]
    with zipfile.ZipFile(io.BytesIO(bundle_zip(result))) as z:
        assert set(z.namelist()) == {"project.yaml", "preservation.json", "README.txt"}
        p = load_text(z.read("project.yaml").decode())
        proof = json.loads(z.read("preservation.json"))
        assert replay(p, proof)["preserved"]
        p["candidate"] = p["baseline"]
        with pytest.raises(ValueError, match="signature|hash"):
            replay(p, proof)


def test_reduction_budget_does_not_claim_minimality(example):
    raw = example("checkout-regression")
    r = review_project(raw)
    tid = next(row["tuple_id"] for row in r["rows"] if row["change"] == "NEWLY_BLOCKED")
    result = reduce_project(raw, tid, max_calls=0)
    assert result["status"] == "budget-limited" and result["policy_units_after"] == 10


def test_reducer_rejects_unchanged_and_unknown(example):
    raw = example()
    tid = review_project(raw)["rows"][0]["tuple_id"]
    with pytest.raises(InputError):
        reduce_project(raw, tid)


@pytest.mark.parametrize("name", ["checkout-regression", "agent-escape", "selector-trap"])
def test_scoped_repair_rechecks_all_queries_and_intents(example, name):
    raw = example(name)
    r = repair_project(raw)
    assert r["solutions"]
    for proposal in r["solutions"]:
        report = review_project(proposal["project"])
        assert all(i["candidate"]["status"] == "PASS" for i in report["intents"])
        assert report["stats"]["UNKNOWN"] == 0
        assert all(not p["new"] for p in report["threat"]["findings"])
        assert len(report["rows"]) == 252
    assert raw == example(name)


def test_mutations_expose_intent_gaps_instead_of_claiming_accuracy(example):
    r = run_mutations(example())
    assert r["total"] > 10 and r["effective_on_scope"] > 0
    assert r["newly_caught"] > 0
    assert any(m["mutation"] == "AND → OR peer split" for m in r["mutations"])
    for m in r["mutations"]:
        assert m["caught_by_intents"] == bool(m["new_intent_failures"])


@pytest.mark.parametrize(
    "text", ["a: 1\na: 2", "a: &a [*a]", "!!python/object:foo {}", "---\na: 1\n---\nb: 2"]
)
def test_unsafe_or_ambiguous_yaml_rejected(text):
    with pytest.raises(InputError):
        load_text(text)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(unknownKey=1),
        lambda p: p.update(schemaVersion=True),
        lambda p: p["topology"][0]["metadata"].update(labels={"bad": True}),
        lambda p: p["topology"].append(copy.deepcopy(p["topology"][0])),
        lambda p: p["candidate"].append(copy.deepcopy(p["candidate"][0])),
        lambda p: p["candidate"][0]["spec"]["ingress"][0]["ports"][0].update(port=70000),
        lambda p: p["candidate"][0]["spec"].update(podSelector={"matchLabels": {"x": 1}}),
        lambda p: p.update(queries=[{"source": "bad", "destination": "data/database", "port": 80}]),
        lambda p: p.update(description="x" * 4001),
        lambda p: p.update(name="x" * 201),
    ],
)
def test_invalid_project_boundaries(example, mutate):
    raw = example()
    mutate(raw)
    with pytest.raises(ValueError):
        parse_project(raw)


def test_deployment_templates_are_explicit_and_live_ineligible(example):
    raw = example()
    obj = raw["topology"][3]
    raw["topology"][3] = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": obj["metadata"],
        "spec": {
            "replicas": 3,
            "template": {"metadata": {"labels": obj["metadata"]["labels"]}, "spec": obj["spec"]},
        },
    }
    r = review_project(raw)
    assert r["warnings"] and r["nodes"][0]["origin"] == "Deployment"
    with pytest.raises(RuntimeErrorSafe, match="Pod snapshots"):
        runtime_preflight(raw, "test", {"test": "x"})


def test_external_ip_cidr_exceptions_only_pod_side(example):
    raw = example()
    raw["queries"] = [
        {"source": "apps/agent", "destination": "external:192.0.2.10", "port": 443},
        {"source": "apps/agent", "destination": "external:192.0.2.200", "port": 443},
    ]
    policy = next(p for p in raw["candidate"] if p["metadata"]["name"] == "agent-egress")
    policy["spec"]["egress"] = [
        {
            "to": [{"ipBlock": {"cidr": "192.0.2.0/24", "except": ["192.0.2.128/25"]}}],
            "ports": [{"port": 443}],
        }
    ]
    r = review_project(raw)
    ext = {x["destination"]: x for x in r["rows"] if x["destination"].startswith("@external")}
    assert ext["@external/192.0.2.10"]["candidate"] == "Allow"
    assert ext["@external/192.0.2.200"]["candidate"] == "Deny"
    assert ext["@external/192.0.2.10"]["candidate_decision"]["ingress"] is None


def test_host_network_not_silently_modelled(example):
    raw = example()
    raw["topology"][3]["spec"]["hostNetwork"] = True
    assert review_project(raw)["exit_code"] == 2


def test_store_restart_capacity_and_path_traversal(example, tmp_path):
    store = RunStore(tmp_path)
    raw = example()
    report = review_project(raw)
    rid = store.save(raw, report)
    assert RunStore(tmp_path).get(rid)["report"] == report
    with pytest.raises(KeyError):
        store.get("../../upload")
    jid = store.job(rid)
    store.update_job(jid, "RUNNING", {"observations": [{"x": 1}]})
    recovered = RunStore(tmp_path)
    assert recovered.get_job(jid)["state"] == "INTERRUPTED"
    assert recovered.get_job(jid)["result"]["observations"] == [{"x": 1}]
    recovered.delete(rid)
    with pytest.raises(KeyError):
        recovered.get(rid)


@pytest.mark.parametrize(
    "model,outcomes,healthy,drift,expected,mismatch",
    [
        ("Allow", ["success"] * 3, True, False, "OBSERVED_AGREEMENT", False),
        ("Allow", ["unreachable"] * 3, True, False, "OBSERVED_UNREACHABLE", True),
        ("Deny", ["unreachable"] * 3, True, False, "OBSERVED_UNREACHABLE", False),
        ("Deny", ["unreachable", "success", "unreachable"], True, False, "UNEXPECTED_REACHABILITY", True),
        ("Allow", ["success", "unreachable", "success"], True, False, "INCONCLUSIVE", False),
        ("Deny", ["unreachable"] * 3, False, False, "INCONCLUSIVE", False),
        ("Deny", ["unreachable"] * 3, True, True, "INCONCLUSIVE", False),
        ("Deny", ["error"] * 3, True, False, "INCONCLUSIVE", False),
        ("Unknown", ["success"] * 3, True, False, "INCONCLUSIVE", False),
        ("Deny", ["unreachable"], True, False, "INCONCLUSIVE", False),
    ],
)
def test_conservative_runtime_verdicts(model, outcomes, healthy, drift, expected, mismatch):
    r = classify_observation(model, [{"outcome": o} for o in outcomes], controls_healthy=healthy, drift=drift)
    assert r["verdict"] == expected and r["mismatch"] == mismatch


def test_live_requires_explicit_allowlist(example):
    with pytest.raises(RuntimeErrorSafe, match="allowlisted"):
        runtime_preflight(example(), "arbitrary", {})


def test_cli_demo_and_exit_contract(example, tmp_path):
    path = tmp_path / "project.json"
    path.write_text(json.dumps(example("checkout-regression")))
    assert main(["review", str(path), "--out", str(tmp_path / "out")]) == 1
    assert (tmp_path / "out/report.html").is_file()
    path.write_text(json.dumps(example("unsupported-policy")))
    assert main(["review", str(path), "--out", str(tmp_path / "out")]) == 2
    path.write_text(json.dumps(example()))
    assert main(["review", str(path), "--out", str(tmp_path / "out")]) == 0


def test_imported_application_execution_details_are_not_retained(example):
    raw = example()
    pod = raw["topology"][3]
    pod["spec"]["containers"][0].update(
        image="private/app:secret-build",
        command=["sh", "-c", "do-not-execute"],
        env=[{"name": "TOKEN", "value": "sentinel-secret-value"}],
    )
    pod["spec"]["volumes"] = [{"name": "credentials", "secret": {"secretName": "sensitive"}}]
    p = parse_project(raw)
    saved = json.dumps(p.raw)
    assert "sentinel-secret-value" not in saved and "do-not-execute" not in saved
    assert "private/app" not in saved and "volumes" not in saved
    assert p.topology.pods[("apps", "frontend")].labels == pod["metadata"]["labels"]
    assert review_project(p)["status"] == "PASS"


def test_secret_objects_rejected_before_persistence(example):
    raw = example()
    raw["topology"].append(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "secret", "namespace": "apps"},
            "data": {"token": "sentinel"},
        }
    )
    with pytest.raises(InputError, match="Secret"):
        parse_project(raw)


def test_input_byte_limit_is_enforced_before_resource_expansion(example):
    raw = example()
    raw["baseline"] = " " * (5 * 1024 * 1024)
    with pytest.raises(InputError, match="5 MiB"):
        parse_project(raw)


def test_review_count_limit_requires_explicit_deletion(tmp_path):
    store = RunStore(tmp_path)
    report = {
        "name": "capacity fixture",
        "created_at": "2026-10-28T00:00:00+00:00",
        "status": "PASS",
        "input_hash": "test",
    }
    for _ in range(100):
        store.save({"fixture": True}, report)
    with pytest.raises(CapacityError, match="100 runs"):
        store.save({"fixture": True}, report)
    store.delete(store.list()[0]["id"])
    assert store.save({"fixture": True}, report)
