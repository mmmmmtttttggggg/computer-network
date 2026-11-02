"""Conditional reachability: a network edge is not proof of an exploit.

Only explicitly declared pivot workloads may relay/forward a path. All graph
edges must be known Allow within the declared query scope. No CVE inference.
"""

from __future__ import annotations
from collections import deque


def analyze_threat(project, rows):
    model = project.raw.get("threatModel", {})
    entries = model.get("entrypoints", [])
    pivots = set(model.get("pivots", []))
    assets = set(model.get("assets", []))

    def adjacency(phase):
        adj = {}
        for row in rows:
            if row[phase] == "Allow":
                adj.setdefault(row["source"], []).append(row)
        return {
            node: sorted(edges, key=lambda x: (x["destination"], x["protocol"], x["port"]))
            for node, edges in adj.items()
        }

    def revision(adj, allowed_pivots, starts=entries):
        paths = []
        radius = {}
        for start in starts:
            queue = deque([(start, [], {start})])
            seen = {start}
            reached = []
            while queue:
                node, path, visited = queue.popleft()
                if node != start and node not in allowed_pivots:
                    continue
                if len(path) >= 4:
                    continue
                for edge in adj.get(node, []):
                    target = edge["destination"]
                    if target in visited or target in seen:
                        continue
                    seen.add(target)
                    hops = path + [
                        {
                            "source": edge["source"],
                            "destination": target,
                            "protocol": edge["protocol"],
                            "port": edge["port"],
                            "tuple_id": edge["tuple_id"],
                        }
                    ]
                    reached.append(target)
                    if target in assets:
                        paths.append(
                            {
                                "entrypoint": start,
                                "asset": target,
                                "hops": hops,
                                "assumptions": [f"{start} is compromised"]
                                + [
                                    f"{h['destination']} can relay or be pivoted through (declared assumption)"
                                    for h in hops[:-1]
                                ],
                                "kind": "direct exposure" if len(hops) == 1 else "conditional pivot path",
                            }
                        )
                    queue.append((target, hops, visited | {target}))
            radius[start] = sorted(reached)
        return {"paths": paths, "radius": radius, "reachable_pairs": sum(len(v) for v in radius.values())}

    baseline_adj, candidate_adj = (adjacency("baseline"), adjacency("candidate")) if entries else ({}, {})
    b, c = revision(baseline_adj, pivots), revision(candidate_adj, pivots)
    old = {(p["entrypoint"], p["asset"]) for p in b["paths"]}
    findings = [{**p, "new": (p["entrypoint"], p["asset"]) not in old} for p in c["paths"]]
    # Re-run reachability after removing each assumption used by a witness.
    # Inspecting only the original path would incorrectly call a pivot critical
    # when a different permitted route still reaches the same sensitive asset.
    sensitivity_cache = {}
    for finding in findings:
        start = finding["entrypoint"]
        checks = []
        for pivot in sorted({h["destination"] for h in finding["hops"][:-1]}):
            key = (start, pivot)
            if key not in sensitivity_cache:
                sensitivity_cache[key] = {
                    p["asset"]: p for p in revision(candidate_adj, pivots - {pivot}, [start])["paths"]
                }
            alternate = sensitivity_cache[key].get(finding["asset"])
            checks.append(
                {
                    "pivot": pivot,
                    "asset_still_reachable": alternate is not None,
                    "alternative_hops": alternate["hops"] if alternate else [],
                }
            )
        finding["assumption_checks"] = checks
        finding["port_evidence"] = []
        for hop in finding["hops"]:
            pod = project.topology.pods.get(tuple(hop["destination"].split("/", 1)))
            declared = pod is not None and any(
                cp.port == hop["port"] and cp.protocol.value == hop["protocol"] for cp in pod.ports
            )
            finding["port_evidence"].append(
                {
                    "tuple_id": hop["tuple_id"],
                    "destination": hop["destination"],
                    "protocol": hop["protocol"],
                    "port": hop["port"],
                    "declaration": "declared" if declared else "not-declared",
                }
            )
    return {
        "enabled": bool(entries),
        "entrypoints": entries,
        "pivots": sorted(pivots),
        "assets": sorted(assets),
        "baseline": b,
        "candidate": c,
        "findings": findings,
        "scope": "Known Allow queries only; at most four hops; one shortest path per entrypoint/asset. Unqueried and Unknown edges are excluded, not proven blocked.",
        "sensitivity_scope": "Each witness pivot is removed separately and all candidate routes within the same four-hop query scope are searched again. This changes a relay assumption, not network permissions. No path found is not a universal isolation proof.",
        "listener_note": "Container ports are declarations, not evidence of a running listener. Missing declarations do not prove a port is closed. Policy-permitted edges are retained in either case.",
        "warning": "Conditional exposure under declared relay/compromise assumptions, not a vulnerability or exploit claim. NetworkPolicies do not enforce transitive application authorization.",
    }
