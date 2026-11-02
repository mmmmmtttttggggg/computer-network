"""Summarize actual recorded observations without upgrading missing coverage."""

from __future__ import annotations


def summarize_coverage(report, result):
    plan = report["plan"]["tuples"]
    known = {r["tuple_id"] for r in plan}
    observed = {
        (o["tuple_id"], o["phase"]): o
        for o in result.get("observations", [])
        if o.get("tuple_id") in known and o.get("phase") in ["baseline", "candidate"]
    }
    matrix = []
    for row in plan:
        phases = {}
        for phase in ["baseline", "candidate"]:
            obs = observed.get((row["tuple_id"], phase))
            phases[phase] = {
                "model": row[phase],
                "verdict": obs.get("verdict", "NOT_TESTED") if obs else "NOT_TESTED",
                "complete": bool(obs and obs.get("complete")),
                "mismatch": bool(obs and obs.get("mismatch")),
                "attempts": len(obs.get("attempts", [])) if obs else 0,
                "successful_attempts": sum(a.get("outcome") == "success" for a in obs.get("attempts", []))
                if obs
                else 0,
            }
        sample = (
            observed.get((row["tuple_id"], "candidate")) or observed.get((row["tuple_id"], "baseline")) or {}
        )
        source_node, destination_node = sample.get("source_node"), sample.get("destination_node")
        placement = (
            "unknown"
            if not source_node or not destination_node
            else "same-node"
            if source_node == destination_node
            else "cross-node"
        )
        matrix.append(
            {
                "tuple_id": row["tuple_id"],
                "source": row["source"],
                "destination": row["destination"],
                "protocol": row["protocol"],
                "port": row["port"],
                "source_node": source_node,
                "destination_node": destination_node,
                "placement": placement,
                **phases,
            }
        )
    complete_both = [r for r in matrix if r["baseline"]["complete"] and r["candidate"]["complete"]]
    return {
        "model_queries": report["stats"]["queries"],
        "planned_connections": len(plan),
        "attempted_connections": len({tid for tid, _ in observed}),
        "conclusive_both_revisions": len(complete_both),
        "cross_node_conclusive": sum(r["placement"] == "cross-node" for r in complete_both),
        "same_node_conclusive": sum(r["placement"] == "same-node" for r in complete_both),
        "unknown_placement_conclusive": sum(r["placement"] == "unknown" for r in complete_both),
        "protocols_observed": sorted(
            {
                r["protocol"]
                for r in matrix
                if (r["tuple_id"], "baseline") in observed or (r["tuple_id"], "candidate") in observed
            }
        ),
        "matrix": matrix,
        "note": "Only recorded changed/intent tuples are probed. Conclusive observations may disagree with the model. Node placement is observed, not forced; no cross-node coverage is claimed when it is absent or unknown. Inspect controls, errors, cleanup, and the overall job status.",
    }
