"""Standalone, escaped HTML report (no remote assets or scripts)."""

from __future__ import annotations
from html import escape as esc
import json


def html_report(report):
    stats = report["stats"]
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{esc(str(row[k]))}</td>"
            for k in ["source", "destination", "protocol", "port", "baseline", "candidate", "change"]
        )
        + "</tr>"
        for row in report["rows"]
    )
    intents = "".join(
        f"<tr><td>{esc(i['intent_id'])}</td><td>{esc(i['expectation'])}</td><td>{i['matched_count']}</td><td>{esc(i['baseline']['status'])}</td><td>{esc(i['candidate']['status'])}</td></tr>"
        for i in report["intents"]
    )
    paths = (
        "".join(
            f"<li>{esc(p['entrypoint'])} → {esc(p['asset'])}: {len(p['hops'])} hops; assumptions: {esc('; '.join(p['assumptions']))}"
            + "<ul>"
            + "".join(
                f"<li>Without {esc(c['pivot'])} as a relay: "
                + (
                    "an alternative scoped path still reaches this asset."
                    if c["asset_still_reachable"]
                    else "no path to this asset found within the same scope."
                )
                + "</li>"
                for c in p.get("assumption_checks", [])
            )
            + "</ul>"
            + "".join(
                f"<p>Destination port {esc(h['destination'])} {esc(h['protocol'])}/{h['port']}: {esc(h['declaration'])} in workload metadata; runtime listener unverified.</p>"
                for h in p.get("port_evidence", [])
            )
            + "</li>"
            for p in report["threat"]["findings"]
        )
        or "<li>No asset path found within declared query/pivot scope.</li>"
    )
    details = "".join(
        f"<details><summary>{esc(r['source'])} → {esc(r['destination'])} {r['protocol']}/{r['port']}</summary><pre>{esc(json.dumps({'baseline': r['baseline_decision'], 'candidate': r['candidate_decision']}, indent=2))}</pre></details>"
        for r in report["rows"]
        if r["change"] != "UNCHANGED"
    )
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>NetScope · {esc(report["name"])}</title><style>body{{max-width:1150px;margin:40px auto;padding:20px;font:15px/1.6 system-ui;color:#142238;background:#f4f7fa}}h1{{font-size:32px}}small,code{{color:#50667d}}table{{border-collapse:collapse;width:100%;background:white;font-size:13px;margin:15px 0 30px}}td,th{{padding:9px;text-align:left;border-bottom:1px solid #dce4ed}}.status{{padding:14px;border-left:4px solid #159f87;background:#e8f4f3}}pre{{overflow:auto;padding:16px;background:#e5ebf2}}details{{padding:10px;border-bottom:1px solid #ccc}}</style><header><small>NETSCOPE / POLICY INTELLIGENCE LAB</small><h1>{esc(report["name"])}</h1><p>{esc(report["description"])}</p></header><p class="status">Static {report["status"]} · Exit {report["exit_code"]} · Runtime NOT VERIFIED. Known model permission does not prove runtime access or application security.</p><p>{stats["queries"]} queries · {stats["NEWLY_ALLOWED"]} newly allowed · {stats["NEWLY_BLOCKED"]} newly blocked · {stats["UNKNOWN"]} Unknown · {stats["intent_pass"]} intents pass</p><p>Input SHA-256: <code>{report["input_hash"]}</code><br>Tool {report["tool_version"]} · {report["created_at"]}</p><h2>Application intent</h2><table><tr><th>ID</th><th>Expectation</th><th>Matches</th><th>Baseline</th><th>Candidate</th></tr>{intents}</table><h2>Conditional containment paths</h2><p>{esc(report["threat"]["warning"])}</p><ul>{paths}</ul><p>{esc(report["threat"]["scope"])}</p><h2>Connection review</h2><table><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Port</th><th>Baseline</th><th>Candidate</th><th>Change</th></tr>{rows}</table><h2>Changed-path evidence</h2>{details}<h2>Live test coverage</h2><p>{report["plan"]["count_per_phase"]} required tuples per phase. {esc(report["plan"]["coverage_note"])} Unsupported: {len(report["plan"]["unsupported"])}.</p><p>Warnings: {esc("; ".join(report["warnings"]) or "None")}. Excluded topology kinds: {esc(", ".join(report["excluded_resources"]) or "None")}.</p></html>"""
