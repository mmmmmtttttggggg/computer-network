"""Counterfactual policy reverts and deterministic fault injection.

Repair proposals never deploy. Every proposal is re-evaluated on the whole
parent query scope; additive allow rules are never presented as deny rules.
"""

from __future__ import annotations
import copy
import itertools
import time
from app.ingest.project import parse_project, InputError
from app.analysis.reducer import identity
from app.service import review_project
from app.util import digest


def repair_project(raw, *, max_calls=64, seconds=10):
    project = parse_project(raw)
    base = {identity(p): p for p in project.baseline}
    cand = {identity(p): p for p in project.candidate}
    if any(p.get("kind") != "NetworkPolicy" for p in project.baseline + project.candidate):
        raise InputError("Repair experiments require standard NetworkPolicies")
    changed = sorted(k for k in base.keys() | cand.keys() if digest(base.get(k)) != digest(cand.get(k)))
    if len(changed) > 16:
        raise InputError("Repair search supports at most 16 changed policy identities")
    original = review_project(project)
    allowed_asset_pairs = {(p["entrypoint"], p["asset"]) for p in original["threat"]["baseline"]["paths"]}
    old_allowed = {r["tuple_id"] for r in original["rows"] if r["candidate"] == "Allow"}
    started = time.perf_counter()
    calls = 0
    solutions = []
    bounded = False
    for size in range(1, min(3, len(changed)) + 1):
        for reverted in itertools.combinations(changed, size):
            if calls >= max_calls or time.perf_counter() - started >= seconds:
                bounded = True
                break
            draft = copy.deepcopy(project.raw)
            policies = dict(cand)
            for k in reverted:
                if k in base:
                    policies[k] = base[k]
                else:
                    policies.pop(k, None)
            draft["candidate"] = [policies[k] for k in sorted(policies)]
            candidate = review_project(draft)
            calls += 1
            valid = bool(candidate["intents"]) and all(
                i["candidate"]["status"] == "PASS" for i in candidate["intents"]
            )
            known = candidate["stats"]["UNKNOWN"] == 0
            extra = [
                r["tuple_id"]
                for r in candidate["rows"]
                if r["candidate"] == "Allow" and r["tuple_id"] not in old_allowed
            ]
            no_new_asset_paths = all(
                (p["entrypoint"], p["asset"]) in allowed_asset_pairs for p in candidate["threat"]["findings"]
            )
            if valid and known and no_new_asset_paths:
                solutions.append(
                    {
                        "revert": list(reverted),
                        "changed_objects": size,
                        "status": candidate["status"],
                        "exit_code": candidate["exit_code"],
                        "remaining_unapproved": candidate["stats"]["unapproved"],
                        "newly_reachable_vs_original_candidate": extra,
                        "stats": candidate["stats"],
                        "project": draft,
                        "input_hash": candidate["input_hash"],
                        "scope": "All declared queries and intents re-evaluated; live runtime not verified.",
                    }
                )
                if len(solutions) >= 5:
                    break
        if bounded or solutions:
            break
    return {
        "status": "proposals-found" if solutions else "no-solution-within-bound",
        "calls": calls,
        "bounded": bounded,
        "changed_policies": changed,
        "solutions": solutions,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "constraints": [
            "All candidate intents pass",
            "No Unknown decisions",
            "No additional entrypoint/asset pairs beyond baseline under declared pivot assumptions",
        ],
        "method": "Smallest tested set of baseline policy reverts (up to 3 identities, 64 evaluations / 10 seconds). No automatic apply.",
        "warning": "Repair means candidate intents pass on declared scope, not universal safety. Review newly reachable paths and any remaining unapproved changes.",
    }


def mutations(raw):
    project = parse_project(raw)
    for index, p in enumerate(project.candidate):
        pid = identity(p) if p.get("kind") == "NetworkPolicy" else f"policy-{index}"
        if p.get("kind") != "NetworkPolicy":
            continue

        def modified(label, detail, edit):
            draft = copy.deepcopy(project.raw)
            draft["candidate"] = copy.deepcopy(project.candidate)
            edit(draft["candidate"][index])
            draft["name"] = f"{project.raw.get('name', 'Review')} · {label}"
            return label, pid, detail, draft

        for direction in ["ingress", "egress"]:
            if p["spec"].get(direction):
                yield modified(
                    f"Remove {direction} rules",
                    f"Delete allow rules while preserving isolation in {pid}",
                    lambda pol, d=direction: pol["spec"].__setitem__(d, []),
                )
                yield modified(
                    f"Unrestricted {direction}",
                    f"An empty allow rule opens this direction in {pid}",
                    lambda pol, d=direction: pol["spec"].__setitem__(d, [{}]),
                )
                for ri, r in enumerate(p["spec"][direction]):
                    peerkey = "from" if direction == "ingress" else "to"
                    for pi, peer in enumerate(r.get(peerkey, [])):
                        if "podSelector" in peer and "namespaceSelector" in peer:

                            def split(pol, d=direction, ri=ri, pi=pi, k=peerkey):
                                peers = pol["spec"][d][ri][k]
                                peer = peers.pop(pi)
                                peers.extend(
                                    [
                                        {"podSelector": peer["podSelector"]},
                                        {"namespaceSelector": peer["namespaceSelector"]},
                                    ]
                                )

                            yield modified(
                                "AND → OR peer split",
                                f"Split a combined namespace+Pod selector into two alternative peers in {pid}",
                                split,
                            )
                    for portidx, port in enumerate(r.get("ports", [])):
                        if type(port.get("port")) is int:

                            def wrong(pol, d=direction, ri=ri, ix=portidx):
                                spec = pol["spec"][d][ri]["ports"][ix]
                                spec["port"] = 1 if spec["port"] == 65535 else spec["port"] + 1
                                spec.pop("endPort", None)

                            yield modified(
                                "Wrong destination port",
                                f"Increment a numeric destination port in {pid}",
                                wrong,
                            )
        if p["spec"].get("podSelector"):
            yield modified(
                "Target selector typo",
                f"Target a non-existing label in {pid}",
                lambda pol: pol["spec"].__setitem__(
                    "podSelector", {"matchLabels": {"netscope-typo": "absent"}}
                ),
            )


def run_mutations(raw, *, limit=24, seconds=10):
    started = time.perf_counter()
    original = review_project(raw)
    rows = []
    seen = set()
    bounded = False
    for label, policy, detail, draft in mutations(raw):
        if time.perf_counter() - started >= seconds:
            bounded = True
            break
        key = digest(draft["candidate"])
        if key in seen:
            continue
        seen.add(key)
        result = review_project(draft)
        old = {r["tuple_id"]: r["candidate"] for r in original["rows"]}
        affected = [r["tuple_id"] for r in result["rows"] if old.get(r["tuple_id"]) != r["candidate"]]
        affected_set = set(affected)
        failing = [i["intent_id"] for i in result["intents"] if i["candidate"]["status"] != "PASS"]
        introduced = sorted(
            set(failing) - {i["intent_id"] for i in original["intents"] if i["candidate"]["status"] != "PASS"}
        )
        rows.append(
            {
                "mutation": label,
                "policy": policy,
                "detail": detail,
                "changed_tuples": len(affected),
                "affected": affected,
                "candidate_decisions": {
                    r["tuple_id"]: r["candidate"] for r in result["rows"] if r["tuple_id"] in affected_set
                },
                "candidate_intent_failures": failing,
                "new_intent_failures": introduced,
                "caught_by_intents": bool(introduced),
                "status": result["status"],
                "project": draft,
                "equivalent_on_scope": not affected,
            }
        )
        if len(rows) >= limit:
            break
    relevant = [r for r in rows if not r["equivalent_on_scope"]]
    return {
        "mutations": rows,
        "total": len(rows),
        "effective_on_scope": len(relevant),
        "newly_caught": sum(r["caught_by_intents"] for r in relevant),
        "budget_limited": bounded,
        "interpretation": "Intent sensitivity experiment, not correctness accuracy. Changes not covered by an intent can remain uncaught. Start from a passing project for meaningful new-failure detection.",
    }
