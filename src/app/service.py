"""The application boundary shared by CLI, HTTP, experiments and replay."""

from __future__ import annotations
import time
from collections import Counter
from datetime import datetime, timezone
from app.ingest.project import parse_project, Project
from app.model.evaluator import Evaluator
from app.review.comparison import compare_revisions, unapproved_changes
from app.review.intents import check_intents, IntentStatus
from app.analysis.threat import analyze_threat
from app.util import plain, digest

VERSION = "1.2.1"


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def review_project(project: Project | dict | str) -> dict:
    started = time.perf_counter()
    if not isinstance(project, Project):
        project = parse_project(project)
    comparisons = compare_revisions(
        Evaluator(project.topology, project.baseline),
        Evaluator(project.topology, project.candidate),
        project.queries,
    )
    intents = check_intents(project.intents, comparisons, project.topology)
    unapproved = unapproved_changes(comparisons, project.approvals)
    unknown = any(c.change.value == "UNKNOWN" for c in comparisons)
    incomplete = (
        unknown
        or not intents
        or any(not i.valid or i.baseline.unknown or i.candidate.unknown for i in intents)
    )
    violations = any(i.candidate.status == IntentStatus.FAIL for i in intents)
    exit_code = 2 if incomplete else (1 if violations or unapproved else 0)
    rows = []
    for c in comparisons:
        rows.append(
            {
                k: plain(getattr(c, k))
                for k in [
                    "tuple_id",
                    "source",
                    "destination",
                    "protocol",
                    "port",
                    "baseline",
                    "candidate",
                    "change",
                    "baseline_decision",
                    "candidate_decision",
                ]
            }
        )
    counts = dict(Counter(c.change.value for c in comparisons))
    for k in ["NEWLY_ALLOWED", "NEWLY_BLOCKED", "UNCHANGED", "UNKNOWN"]:
        counts.setdefault(k, 0)
    planids = sorted(
        {c.tuple_id for c in comparisons if c.change.value in ["NEWLY_ALLOWED", "NEWLY_BLOCKED"]}
        | {t for i in intents for t in i.matched_tuples}
    )
    rowmap = {r["tuple_id"]: r for r in rows}
    plan = [
        {
            "tuple_id": tid,
            "source": rowmap[tid]["source"],
            "destination": rowmap[tid]["destination"],
            "protocol": rowmap[tid]["protocol"],
            "port": rowmap[tid]["port"],
            "baseline": rowmap[tid]["baseline"],
            "candidate": rowmap[tid]["candidate"],
        }
        for tid in planids
    ]
    unsupported = [
        p["tuple_id"]
        for p in plan
        if p["port"] < 1024
        or p["protocol"] == "SCTP"
        or p["source"].startswith("@external/")
        or p["destination"].startswith("@external/")
        or any(p[x] == "Unknown" for x in ["baseline", "candidate"])
    ]
    if (
        len(plan) > 300
        or any(m["origin"] != "Pod" for m in project.workload_meta.values())
        or any(cp.port < 1024 for pod in project.topology.pods.values() for cp in pod.ports)
    ):
        unsupported.extend(p["tuple_id"] for p in plan)
    nodes = [
        {
            "id": f"{p.namespace}/{p.name}",
            "name": p.name,
            "namespace": p.namespace,
            "labels": dict(p.labels),
            "ports": plain(p.ports),
            **project.workload_meta.get(f"{p.namespace}/{p.name}", {}),
        }
        for p in project.topology.pods.values()
    ]
    posture = []
    for n in nodes:
        if (
            n["id"] in project.raw.get("threatModel", {}).get("entrypoints", [])
            and n.get("tokenAutomount") is not False
        ):
            posture.append(
                {
                    "endpoint": n["id"],
                    "code": "AGENT_TOKEN_DEFAULT",
                    "severity": "review",
                    "message": "Token automount is not explicitly disabled in the supplied Pod/template. Review service-account permissions; RBAC is not analyzed here.",
                }
            )
    threat = analyze_threat(project, rows)
    duration = round((time.perf_counter() - started) * 1000, 2)
    return {
        "schema_version": 1,
        "tool_version": VERSION,
        "created_at": utcnow(),
        "name": project.raw.get("name", "Untitled review"),
        "description": project.raw.get("description", ""),
        "input_hash": project.fingerprint,
        "hashes": {
            "baseline": digest(project.baseline),
            "candidate": digest(project.candidate),
            "topology": digest(project.raw["topology"]),
        },
        "mode": "static",
        "runtime_status": "NOT_VERIFIED",
        "exit_code": exit_code,
        "status": ["PASS", "FAIL", "INCOMPLETE"][exit_code],
        "gate_reasons": ([f"{len(unapproved)} unapproved semantic changes"] if unapproved else [])
        + (["Candidate intent violations"] if violations else [])
        + (["Unknown/invalid/missing intent or query coverage"] if incomplete else []),
        "stats": {
            "queries": len(rows),
            "endpoints": len(nodes),
            "policies_baseline": len(project.baseline),
            "policies_candidate": len(project.candidate),
            **counts,
            "intent_pass": sum(i.candidate.status == IntentStatus.PASS for i in intents),
            "intent_fail": sum(i.candidate.status == IntentStatus.FAIL for i in intents),
            "unapproved": len(unapproved),
            "duration_ms": duration,
        },
        "rows": rows,
        "intents": plain(intents),
        "unapproved": [c.tuple_id for c in unapproved],
        "nodes": nodes,
        "warnings": project.warnings,
        "excluded_resources": project.excluded,
        "threat": threat,
        "posture": posture,
        "plan": {
            "tuples": plan,
            "hash": digest(plan),
            "count_per_phase": len(plan),
            "unsupported": sorted(set(unsupported)),
            "complete_supported": bool(plan) and not unsupported,
            "attempts": 3,
            "timeout_seconds": 2,
            "gap_seconds": 1,
            "settle_seconds": 10,
            "max_concurrent": 10,
            "coverage_note": "All changed and intent tuples; no silent sampling.",
        },
    }
