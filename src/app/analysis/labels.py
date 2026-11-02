"""Immutable Pod-label counterfactuals, with explicit shared-query scope."""

from __future__ import annotations
import copy
from app.ingest.project import parse_project, InputError
from app.service import review_project
from app.analysis.coverage import query_from_row
from app.analysis.threat import analyze_threat


def label_experiment(raw, endpoint, labels):
    original = parse_project(raw)
    before = review_project(original)
    if not isinstance(endpoint, str) or endpoint not in original.workload_meta:
        raise InputError("Select a declared Pod endpoint")
    if original.workload_meta[endpoint]["origin"] != "Pod":
        raise InputError("Label experiments currently require explicit Pod snapshots")
    if not isinstance(labels, dict):
        raise InputError("Labels must be a JSON object")
    draft = copy.deepcopy(original.raw)
    target = next(
        p
        for p in draft["topology"]
        if p.get("kind") == "Pod"
        and p["metadata"].get("namespace", "default") + "/" + p["metadata"]["name"] == endpoint
    )
    previous = copy.deepcopy(target["metadata"].get("labels", {}))
    target["metadata"]["labels"] = copy.deepcopy(labels)
    draft["name"] = draft.get("name", "Review")[:170] + " · label experiment"
    draft["queries"] = [query_from_row(r) for r in before["rows"]]
    parsed = parse_project(draft)
    after = review_project(parsed)
    old = {r["tuple_id"]: r for r in before["rows"]}
    changes = []
    for row in after["rows"]:
        if row["tuple_id"] not in old:
            continue
        prior = old[row["tuple_id"]]["candidate"]
        if prior != row["candidate"]:
            changes.append(
                {
                    **query_from_row(row),
                    "tuple_id": row["tuple_id"],
                    "before": prior,
                    "after": row["candidate"],
                    "change": "UNKNOWN"
                    if "Unknown" in [prior, row["candidate"]]
                    else "NEWLY_ALLOWED"
                    if row["candidate"] == "Allow"
                    else "NEWLY_BLOCKED",
                }
            )

    def targeting(report, direction):
        field = "source" if direction == "egress" else "destination"
        decision = next(
            (
                r["candidate_decision"].get(direction)
                for r in report["rows"]
                if r[field] == endpoint and r["candidate_decision"].get(direction)
            ),
            None,
        )
        return (
            {"isolated": decision["isolated"], "policies": decision["selecting_policies"]}
            if decision
            else {"isolated": None, "policies": [], "note": "Direction absent from query coverage"}
        )

    shared_threat = analyze_threat(parsed, [r for r in after["rows"] if r["tuple_id"] in old])
    old_pairs = {(p["entrypoint"], p["asset"]) for p in before["threat"]["findings"]}
    prior_paths = {(p["entrypoint"], p["asset"]): p for p in before["threat"]["findings"]}
    shortened = []
    for path in shared_threat["findings"]:
        previous_path = prior_paths.get((path["entrypoint"], path["asset"]))
        if previous_path and len(path["hops"]) < len(previous_path["hops"]):
            shortened.append({"before": previous_path, "after": path})
    return {
        "endpoint": endpoint,
        "labels_before": previous,
        "labels_after": labels,
        "parent_input_hash": original.fingerprint,
        "input_hash": parsed.fingerprint,
        "project": parsed.raw,
        "changes": changes,
        "shared_queries": len(old),
        "additional_intent_queries": len(after["rows"]) - len(old),
        "targeting": {
            d: {"before": targeting(before, d), "after": targeting(after, d)} for d in ["egress", "ingress"]
        },
        "intents": after["intents"],
        "review_status": after["status"],
        "new_asset_paths": [
            p for p in shared_threat["findings"] if (p["entrypoint"], p["asset"]) not in old_pairs
        ],
        "shortened_asset_paths": shortened,
        "scope": "Compare reference-candidate behaviour with the label-edited candidate on identical connection tuples. Extra intent queries are reported separately. Each review keeps one shared topology for its own policy comparison.",
        "warning": "A configuration counterfactual, not proof an attacker can change labels. No RBAC/credential analysis or live deployment is performed. Zero-match intents remain invalid.",
    }
