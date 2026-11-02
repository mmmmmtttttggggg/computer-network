from app.runtime.evidence import summarize_coverage
from app.service import review_project
from app.runtime.runner import run_live
from test_runtime import tiny_project, ScriptedCluster, NoDelay


def test_no_observations_never_imply_coverage():
    r = review_project(tiny_project())
    c = summarize_coverage(r, {})
    assert c["conclusive_both_revisions"] == c["attempted_connections"] == c["cross_node_conclusive"] == 0
    assert all(x["baseline"]["verdict"] == "NOT_TESTED" for x in c["matrix"])


def test_one_revision_and_unknown_node_never_imply_cross_node():
    r = review_project(tiny_project())
    tid = r["plan"]["tuples"][0]["tuple_id"]
    obs = {
        "tuple_id": tid,
        "phase": "baseline",
        "complete": True,
        "verdict": "OBSERVED_UNREACHABLE",
        "attempts": [],
    }
    c = summarize_coverage(r, {"observations": [obs]})
    assert c["attempted_connections"] == 1 and c["conclusive_both_revisions"] == 0
    c = summarize_coverage(r, {"observations": [obs, {**obs, "phase": "candidate"}]})
    assert c["unknown_placement_conclusive"] == 1 and c["cross_node_conclusive"] == 0


def test_scripted_node_placement_is_recorded_without_real_cni_claim():
    class Placed(ScriptedCluster):
        def create(self, obj):
            super().create(obj)
            if obj["kind"] == "Pod":
                key = ("Pod", obj["metadata"].get("namespace"), obj["metadata"]["name"])
                self.objects[key]["spec"]["nodeName"] = (
                    "worker-a" if obj["metadata"]["name"] == "source" else "worker-b"
                )

    r = run_live(
        tiny_project(), "test", {"test": "https://127.0.0.1:6443"}, transport=Placed(), cancel=NoDelay()
    )
    assert r["coverage"]["cross_node_conclusive"] == 1
    assert r["environment"]["pods"]["test-app/source"]["node"] == "worker-a"


def test_udp_plans_have_udp_enforcement_controls():
    raw = tiny_project()
    raw["intents"][0]["protocol"] = "UDP"
    for p in raw["topology"]:
        if p["kind"] == "Pod":
            p["spec"]["containers"][0]["ports"][0]["protocol"] = "UDP"
    r = run_live(
        raw, "test", {"test": "https://127.0.0.1:6443"}, transport=ScriptedCluster(), cancel=NoDelay()
    )
    assert "UDP" in r["preflight_controls"]["by_protocol"]
    assert r["coverage"]["protocols_observed"] == ["UDP"]
