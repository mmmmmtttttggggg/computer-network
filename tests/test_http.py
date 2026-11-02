import io
import zipfile
from fastapi.testclient import TestClient
import pytest
from app.web.server import create_app


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path)) as c:
        c.headers.update({"X-NetScope-Token": c.get("/api/config").json()["token"]})
        yield c


def test_dashboard_and_packaged_assets(client):
    assert client.get("/").status_code == 200
    for path in ["style.css", "app.js", "experiments-extra.js"]:
        r = client.get("/static/" + path)
        assert r.status_code == 200 and len(r.content) > 1000
    assert {e["id"] for e in client.get("/api/examples").json()} == {
        "agent-escape",
        "parallel-relay",
        "checkout-regression",
        "clean-baseline",
        "selector-trap",
        "unsupported-policy",
        "last-policy-deleted",
        "cross-namespace-check",
    }
    assert client.get("/api/examples/missing").status_code == 404


def test_missing_token_and_cross_origin_rejected(client, example):
    assert (
        client.post("/api/runs", json={"project": example()}, headers={"X-NetScope-Token": ""}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/runs", json={"project": example()}, headers={"Origin": "https://untrusted.example"}
        ).status_code
        == 403
    )


def test_http_review_exports_history_and_recovery(client, example, tmp_path):
    response = client.post("/api/runs", json={"project": example("agent-escape")})
    assert response.status_code == 200, response.text
    r = response.json()
    rid = r["id"]
    assert r["status"] == "FAIL" and r["stats"]["intent_pass"] == 5
    assert client.get("/api/runs/" + rid).json()["input_hash"] == r["input_hash"]
    assert client.get("/api/runs/" + rid + "/project").json() == example("agent-escape")
    assert client.get("/api/runs").json()[0]["id"] == rid
    exported = client.get("/api/runs/" + rid + "/report.json").json()
    assert exported["stats"] == r["stats"] and exported["rows"] == r["rows"]
    html = client.get("/api/runs/" + rid + "/report.html").text
    assert "Runtime NOT VERIFIED" in html and r["input_hash"] in html
    assert all(i["intent_id"] in html for i in r["intents"])
    with TestClient(create_app(tmp_path)) as restarted:
        assert restarted.get("/api/runs/" + rid).json()["input_hash"] == r["input_hash"]


def test_invalid_payload_is_422_not_500(client, example):
    for payload in [
        None,
        [],
        {"project": None},
        {"project": {"name": "missing"}},
        {"project": {**example(), "queries": [{}]}},
        {"project": {**example(), "topology": [None]}},
    ]:
        response = client.post("/api/runs", json=payload)
        assert response.status_code == 422, response.text
    raw = example()
    raw["topology"][0]["metadata"] = None
    assert client.post("/api/runs", json={"project": raw}).status_code == 422


def test_report_escapes_markup_and_queries_remain_data(client, example):
    raw = example()
    raw["name"] = "<img src=x onerror=alert(1)>"
    rid = client.post("/api/runs", json={"project": raw}).json()["id"]
    html = client.get("/api/runs/" + rid + "/report.html").text
    assert "<img src=x" not in html and "&lt;img src=x" in html
    assert client.get("/api/runs/" + rid).headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]


def test_http_experiments_bundle_and_no_original_mutation(client, example):
    original = client.post("/api/runs", json={"project": example("checkout-regression")}).json()
    rid = original["id"]
    tid = next(r["tuple_id"] for r in original["rows"] if r["change"] == "NEWLY_BLOCKED")
    reduced = client.post("/api/runs/" + rid + "/reduce", json={"tuple_id": tid})
    assert reduced.status_code == 200, reduced.text
    assert reduced.json()["policy_units_after"] == 1
    zipped = client.post("/api/runs/" + rid + "/bundle", json={"tuple_id": tid})
    assert zipped.status_code == 200 and zipped.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(zipped.content)) as z:
        assert z.testzip() is None
    repairs = client.post("/api/runs/" + rid + "/repair", json={}).json()
    assert repairs["solutions"][0]["exit_code"] == 0
    mutant = client.post("/api/runs/" + rid + "/mutate", json={})
    assert mutant.status_code == 200 and mutant.json()["total"] > 0
    assert client.get("/api/runs/" + rid + "/project").json() == example("checkout-regression")


def test_live_disabled_is_honest_and_requires_confirmation(client, example):
    rid = client.post("/api/runs", json={"project": example()}).json()["id"]
    response = client.post("/api/runs/" + rid + "/plan", json={"context": "kind-netscope-lab"})
    assert response.status_code == 422
    assert client.post("/api/runs/" + rid + "/verify", json={"context": "arbitrary"}).status_code == 422
    assert client.get("/api/jobs/" + "a" * 24).status_code == 404


def test_deletion_is_scoped(client, example):
    ids = [client.post("/api/runs", json={"project": example()}).json()["id"] for _ in range(2)]
    assert client.delete("/api/runs/" + ids[0]).status_code == 200
    assert client.get("/api/runs/" + ids[0]).status_code == 404
    assert client.get("/api/runs/" + ids[1]).status_code == 200


def test_disk_capacity_is_not_acknowledged_as_a_saved_review(client, example, monkeypatch):
    monkeypatch.setattr(client.app.state.store, "_size", lambda: 1024**3)
    r = client.post("/api/runs", json={"project": example()})
    assert r.status_code == 507 and not client.get("/api/runs").json()


def test_new_experiments_keep_saved_review_immutable(client, example):
    raw = example()
    original = client.post("/api/runs", json={"project": raw}).json()
    url = "/api/runs/" + original["id"]
    saved_before = client.get(url).json()
    response = client.post(url + "/checks/suggest")
    assert response.status_code == 200, response.text
    checks = response.json()["specification"]
    verified = client.post(url + "/checks/verify", json=checks)
    assert verified.status_code == 200 and verified.json()["status"] == "PASS"
    labels = client.post(url + "/labels", json={"endpoint": "apps/agent", "labels": {"app": "payments"}})
    assert labels.status_code == 200 and labels.json()["new_asset_paths"]
    assert client.get(url).json() == saved_before
    assert client.get(url + "/project").json() == raw
    assert len(client.get("/api/runs").json()) == 1
    assert client.post(url + "/labels", json={"endpoint": "missing/pod", "labels": {}}).status_code == 422
    assert client.post(url + "/checks/verify", json={}).status_code == 422
    for suffix in ["/checks/suggest", "/checks/verify", "/labels"]:
        assert client.post(url + suffix, json={}, headers={"X-NetScope-Token": ""}).status_code == 403
