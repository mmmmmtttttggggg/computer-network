"""Bounded, non-monotonic paired-policy reduction with preserved signatures."""

from __future__ import annotations
import copy
import io
import json
import time
import zipfile
import yaml
from app.ingest.project import parse_project, InputError
from app.model.evaluator import Evaluator, Verdict
from app.review.comparison import tuple_id
from app.review.intents import check_intents
from app.review.comparison import compare_revisions
from app.util import digest, plain


def identity(p):
    return p["metadata"]["namespace"] + "/" + p["metadata"]["name"]


def reduce_project(raw, witness, *, max_calls=2000, seconds=30):
    project = parse_project(raw)
    q = next((q for q in project.queries if tuple_id(q) == witness), None)
    if q is None:
        raise InputError("Witness tuple not found")
    if any(
        p.get("kind") != "NetworkPolicy" or p.get("apiVersion") != "networking.k8s.io/v1"
        for p in project.baseline + project.candidate
    ):
        raise InputError("Reducer requires fully supported policy resources")
    started = time.perf_counter()
    calls = 0
    removed = []
    units = sorted({identity(p) for p in project.baseline + project.candidate})
    kept = set(units)

    def signature(ids):
        b = Evaluator(project.topology, [p for p in project.baseline if identity(p) in ids])
        c = Evaluator(project.topology, [p for p in project.candidate if identity(p) in ids])
        result = compare_revisions(b, c, [q])[0]
        if result.baseline == Verdict.UNKNOWN or result.candidate == Verdict.UNKNOWN:
            return None
        flags = tuple(
            getattr(getattr(d, way), "isolated", None)
            for d in [result.baseline_decision, result.candidate_decision]
            for way in ["egress", "ingress"]
        )
        intent = check_intents(project.intents, [result], project.topology)
        violated = sorted(i.intent_id for i in intent if witness in i.candidate.violations)
        return (result.baseline.value, result.candidate.value, flags, tuple(violated))

    original = signature(kept)
    if original is None or original[0] == original[1]:
        raise InputError("Select a known changed connection for reduction")
    status = "1-minimal"
    reason = "No remaining paired policy can be individually removed while preserving this signature."
    while True:
        changed = False
        for u in sorted(kept):
            if calls >= max_calls or time.perf_counter() - started >= seconds:
                status = "budget-limited"
                reason = "Search bound reached; no minimality claim."
                break
            trial = kept - {u}
            calls += 1
            if signature(trial) == original:
                kept = trial
                removed.append(u)
                changed = True
                break
        if status == "budget-limited" or not changed:
            break
    reduced = copy.deepcopy(project.raw)
    reduced["baseline"] = [p for p in project.baseline if identity(p) in kept]
    reduced["candidate"] = [p for p in project.candidate if identity(p) in kept]
    reduced["queries"] = [
        {
            "source": f"{q.source.namespace}/{q.source.name}"
            if q.source.namespace != "@external"
            else "external:" + q.source.ip,
            "destination": f"{q.destination.namespace}/{q.destination.name}"
            if q.destination.namespace != "@external"
            else "external:" + q.destination.ip,
            "protocol": q.protocol.value,
            "port": q.port,
        }
    ]
    # Keep only matching intents. Their expansion can include additional tuples;
    # the preservation guarantee remains explicitly scoped to the chosen witness.
    relevant = {
        i.intent_id
        for i in check_intents(
            project.intents,
            compare_revisions(
                Evaluator(project.topology, project.baseline),
                Evaluator(project.topology, project.candidate),
                [q],
            ),
            project.topology,
        )
        if i.matched_count
    }
    reduced["intents"] = [i for i in raw["intents"] if i["id"] in relevant]
    reduced["approvals"] = []
    return {
        "witness": witness,
        "status": status,
        "reason": reason,
        "parent_input_hash": project.fingerprint,
        "signature": plain(original),
        "policy_units_before": len(units),
        "policy_units_after": len(kept),
        "reduction_percent": round(100 * (1 - len(kept) / len(units)), 1) if units else 0,
        "removed": removed,
        "kept": sorted(kept),
        "calls": calls,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "runtime_status": "NOT_VERIFIED",
        "scope": "Only the selected tuple signature is preserved. Topology is unchanged. This is not a unique-cause or global-minimum claim.",
        "project": reduced,
        "bundle_hash": digest(reduced),
    }


def bundle_zip(result):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("project.yaml", yaml.safe_dump(result["project"], sort_keys=False))
        z.writestr(
            "preservation.json", json.dumps({k: v for k, v in result.items() if k != "project"}, indent=2)
        )
        z.writestr(
            "README.txt",
            "NetScope model-preserved regression bundle\n\nInstall the NetScope release, then run:\n  netscope replay project.yaml preservation.json\n\nOptional real-cluster verification:\n  netscope verify project.yaml --context kind-netscope-lab --allow-live\n\nNo runtime evidence is embedded or implied. Fixed topology; selected-witness preservation only.\n",
        )
    return buf.getvalue()
