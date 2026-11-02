"""Draft exact-connection regression checks from missed policy faults.

Assertions preserve a reviewed reference candidate's behaviour. They do not
infer security requirements. A deterministic holdout is never used in selection.
"""

from __future__ import annotations
import copy
from app.analysis.experiments import run_mutations
from app.ingest.project import parse_project, InputError
from app.service import review_project
from app.util import digest


def wire_endpoint(endpoint):
    return "external:" + endpoint.split("/", 1)[1] if endpoint.startswith("@external/") else endpoint


def query_from_row(row):
    return {
        "source": wire_endpoint(row["source"]),
        "destination": wire_endpoint(row["destination"]),
        "protocol": row["protocol"],
        "port": row["port"],
    }


def verify_checks(raw, specification):
    project = parse_project(raw)
    if (
        not isinstance(specification, dict)
        or type(specification.get("schemaVersion")) is not int
        or specification.get("schemaVersion") != 1
    ):
        raise InputError("Checks require schemaVersion 1")
    if set(specification) - {"schemaVersion", "reference_input_hash", "checks"}:
        raise InputError("Unknown checks-file fields")
    reference_hash = specification.get("reference_input_hash")
    if reference_hash is not None and (not isinstance(reference_hash, str) or len(reference_hash) != 64):
        raise InputError("Invalid checks reference hash")
    checks = specification.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 32:
        raise InputError("Supply 1..32 connection checks")
    ids, tuples, normalized = set(), set(), []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {
            "id",
            "source",
            "destination",
            "protocol",
            "port",
            "expect",
        }:
            raise InputError("Each check requires id, source, destination, protocol, port and expect")
        if (
            not isinstance(check["id"], str)
            or not check["id"].strip()
            or len(check["id"]) > 100
            or check["id"] in ids
        ):
            raise InputError("Check IDs must be non-empty and unique (up to 100 characters)")
        if check["expect"] not in ["must_allow", "must_deny"]:
            raise InputError("Check expect must be must_allow or must_deny")
        if not all(isinstance(check[k], str) for k in ["source", "destination", "protocol"]):
            raise InputError("Check endpoints and protocol must be strings")
        key = tuple(check[k] for k in ["source", "destination", "protocol", "port"])
        try:
            duplicate = key in tuples
        except TypeError:
            raise InputError("Check port must be a number") from None
        if duplicate:
            raise InputError("Duplicate connection check (including conflicting expectations)")
        tuples.add(key)
        ids.add(check["id"])
        normalized.append({k: check[k] for k in ["source", "destination", "protocol", "port"]})
    draft = copy.deepcopy(project.raw)
    draft["queries"] = normalized
    # Project ingestion validates endpoints/ports and expands mandatory intents.
    report = review_project(draft)
    rows = {
        (wire_endpoint(r["source"]), wire_endpoint(r["destination"]), r["protocol"], r["port"]): r
        for r in report["rows"]
    }
    results = []
    for check in checks:
        row = rows[tuple(check[k] for k in ["source", "destination", "protocol", "port"])]
        actual = row["candidate"]
        expected = "Allow" if check["expect"] == "must_allow" else "Deny"
        results.append(
            {
                **check,
                "tuple_id": row["tuple_id"],
                "actual": actual,
                "status": "Unknown" if actual == "Unknown" else "PASS" if actual == expected else "FAIL",
            }
        )
    code = (
        2
        if any(r["status"] == "Unknown" for r in results)
        else 1
        if any(r["status"] == "FAIL" for r in results)
        else 0
    )
    return {
        "status": ["PASS", "FAIL", "INCOMPLETE"][code],
        "exit_code": code,
        "checks": results,
        "input_hash": project.fingerprint,
        "reference_input_hash": reference_hash,
        "same_as_reference": reference_hash == project.fingerprint,
        "scope": "Exact connection checks against this candidate; this result does not certify the full SRS review gate or live enforcement.",
    }


def suggest_checks(raw, *, max_checks=12, seconds=10):
    if type(max_checks) is not int or not 1 <= max_checks <= 32:
        raise InputError("max_checks must be 1..32")
    project = parse_project(raw)
    reference = review_project(project)
    if (
        reference["stats"]["UNKNOWN"]
        or not reference["intents"]
        or any(i["candidate"]["status"] != "PASS" for i in reference["intents"])
    ):
        raise InputError(
            "Suggestions require known reference decisions and valid, passing candidate intents; start with A clean baseline"
        )
    suite = run_mutations(project.raw, seconds=seconds)
    ordered = sorted(suite["mutations"], key=lambda m: digest(m["project"]["candidate"]))
    for index, mutant in enumerate(ordered):
        mutant["experiment_id"] = "fault-" + digest(mutant["project"]["candidate"])[:12]
        mutant["partition"] = "holdout" if index % 4 == 0 else "training"
    originals = {r["tuple_id"]: r for r in reference["rows"]}
    missed = [
        m
        for m in ordered
        if m["partition"] == "training" and not m["equivalent_on_scope"] and not m["caught_by_intents"]
    ]
    coverage = {}
    for mutant in missed:
        for tid, verdict in mutant["candidate_decisions"].items():
            if tid in originals and verdict in ["Allow", "Deny"] and verdict != originals[tid]["candidate"]:
                coverage.setdefault(tid, set()).add(mutant["experiment_id"])
    remaining = {m["experiment_id"] for m in missed}
    selected, selected_tids = [], []
    while remaining and len(selected) < max_checks:
        ranked = sorted(coverage, key=lambda tid: (-len(coverage[tid] & remaining), tid))
        if not ranked or not coverage[ranked[0]] & remaining:
            break
        tid = ranked[0]
        selected_tids.append(tid)
        selected.append(
            {
                "id": f"draft-{len(selected) + 1}",
                **query_from_row(originals[tid]),
                "expect": "must_allow" if originals[tid]["candidate"] == "Allow" else "must_deny",
            }
        )
        remaining -= coverage[tid]

    def summary(partition):
        effective = [m for m in ordered if m["partition"] == partition and not m["equivalent_on_scope"]]

        def caught(m):
            return m["caught_by_intents"] or any(
                m["candidate_decisions"].get(tid, originals[tid]["candidate"]) in ["Allow", "Deny"]
                and m["candidate_decisions"].get(tid, originals[tid]["candidate"])
                != originals[tid]["candidate"]
                for tid in selected_tids
            )

        return {
            "effective_faults": len(effective),
            "caught_before": sum(m["caught_by_intents"] for m in effective),
            "caught_with_drafts": sum(caught(m) for m in effective),
        }

    specification = {"schemaVersion": 1, "reference_input_hash": project.fingerprint, "checks": selected}
    return {
        "reference_input_hash": project.fingerprint,
        "draft_count": len(selected),
        "specification": specification,
        "reference_check": verify_checks(project.raw, specification) if selected else None,
        "training": summary("training"),
        "holdout": summary("holdout"),
        "faults_generated": suite["total"],
        "budget_limited": suite["budget_limited"],
        "uncovered_training_faults": sorted(remaining),
        "method": "Deterministic fault split (every fourth sorted candidate hash held out); greedy connection-check selection using missed training faults only. No minimum-size or generalization guarantee.",
        "warning": "Review these drafts: they preserve reference candidate behaviour, not inferred security requirements. Holdout faults come from the same synthetic generator; coverage is not analyzer accuracy or independent validation.",
    }
