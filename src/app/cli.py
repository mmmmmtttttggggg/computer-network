"""NetScope CLI: same analysis boundary as the web application."""

from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from importlib.resources import files
from app.ingest.project import load_text
from app.service import review_project, VERSION
from app.reporting import html_report
from app.analysis.reducer import reduce_project, bundle_zip
from app.analysis.experiments import repair_project, run_mutations
from app.analysis.coverage import suggest_checks, verify_checks
from app.analysis.labels import label_experiment
from app.runtime.runner import run_live


def read(path):
    return load_text(Path(path).read_text())


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def export(report, out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "report.json", report)
    (out / "report.html").write_text(html_report(report))


def replay(raw, preservation):
    r = review_project(raw)
    w = preservation["witness"]
    row = next((x for x in r["rows"] if x["tuple_id"] == w), None)
    if row is None:
        raise ValueError("Witness is absent from replay input")
    flags = [
        (row[phase + "_decision"].get(way) or {}).get("isolated")
        for phase in ["baseline", "candidate"]
        for way in ["egress", "ingress"]
    ]
    failed = sorted(i["intent_id"] for i in r["intents"] if w in i["candidate"]["violations"])
    signature = [row["baseline"], row["candidate"], flags, failed]
    if signature != preservation["signature"]:
        raise ValueError("Preservation signature differs; this is not a faithful static replay")
    if preservation.get("bundle_hash") != r["input_hash"]:
        raise ValueError("Bundle input hash differs")
    return {
        "preserved": True,
        "witness": w,
        "signature": signature,
        "runtime_status": "NOT_VERIFIED",
        "input_hash": r["input_hash"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netscope", description="Kubernetes NetworkPolicy digital twin and containment experiments"
    )
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="Launch the local dashboard")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--data-dir")
    review = sub.add_parser("review", help="Review a project (exit 0/1/2)")
    review.add_argument("project")
    review.add_argument("--out", default="artifacts/review")
    demo = sub.add_parser("demo", help="Export all inspectable scenarios")
    demo.add_argument("--out", default="artifacts/demo")
    reduce = sub.add_parser("reduce", help="Export model-preserved replay bundle")
    reduce.add_argument("project")
    reduce.add_argument("--tuple-id", required=True)
    reduce.add_argument("--out", default="artifacts/replay.zip")
    repair = sub.add_parser("repair", help="Find bounded, fully re-evaluated revert proposals")
    repair.add_argument("project")
    repair.add_argument("--out", default="artifacts/repair.json")
    mutate = sub.add_parser("mutate", help="Run controlled policy mutations")
    mutate.add_argument("project")
    mutate.add_argument("--out", default="artifacts/mutations.json")
    advisor = sub.add_parser(
        "suggest-checks", help="Propose reference-behaviour checks from missed training faults"
    )
    advisor.add_argument("project")
    advisor.add_argument("--out", default="artifacts/draft-checks.json")
    checker = sub.add_parser("check", help="Evaluate exact candidate connection checks (exit 0/1/2)")
    checker.add_argument("project")
    checker.add_argument("checks")
    label = sub.add_parser("labels", help="Run an immutable Pod-label counterfactual")
    label.add_argument("project")
    label.add_argument("--endpoint", required=True)
    label.add_argument("--labels", required=True, help="Full replacement labels as a JSON object")
    label.add_argument("--out", default="artifacts/label-experiment.json")
    rep = sub.add_parser("replay", help="Verify a replay bundle signature")
    rep.add_argument("project")
    rep.add_argument("preservation")
    verify = sub.add_parser("verify", help="Explicit real-cluster verification")
    verify.add_argument("project")
    verify.add_argument("--context", required=True)
    verify.add_argument("--allow-live", action="store_true")
    verify.add_argument("--out", default="artifacts/live.json")
    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            if args.data_dir:
                os.environ["NETSCOPE_DATA"] = args.data_dir
            import uvicorn

            uvicorn.run("app.web.server:app_factory", factory=True, host="127.0.0.1", port=args.port)
            return 0
        if args.command == "demo":
            summaries = []
            for f in sorted(files("app").joinpath("resources/examples").iterdir(), key=lambda x: x.name):
                if not f.name.endswith(".json"):
                    continue
                raw = json.loads(f.read_text())
                r = review_project(raw)
                out = Path(args.out) / f.name[:-5]
                export(r, out)
                write_json(out / "project.json", raw)
                summaries.append(
                    {
                        "scenario": f.name[:-5],
                        "status": r["status"],
                        "exit_code": r["exit_code"],
                        "stats": r["stats"],
                        "conditional_asset_paths": len(r["threat"]["findings"]),
                    }
                )
            write_json(Path(args.out) / "summary.json", summaries)
            print(json.dumps(summaries, indent=2))
            print(f"Exported to {Path(args.out).resolve()}. Launch: netscope serve")
            return 0
        raw = read(args.project)
        if args.command == "review":
            r = review_project(raw)
            export(r, args.out)
            print(
                json.dumps(
                    {
                        "status": r["status"],
                        "exit_code": r["exit_code"],
                        "stats": r["stats"],
                        "gate_reasons": r["gate_reasons"],
                        "runtime_status": r["runtime_status"],
                    },
                    indent=2,
                )
            )
            return r["exit_code"]
        if args.command == "reduce":
            r = reduce_project(raw, args.tuple_id)
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(bundle_zip(r))
            print(json.dumps({k: v for k, v in r.items() if k != "project"}, indent=2))
            return 0
        if args.command == "repair":
            r = repair_project(raw)
            write_json(args.out, r)
            print(f"{len(r['solutions'])} proposals → {args.out}")
            return 0
        if args.command == "mutate":
            r = run_mutations(raw)
            write_json(args.out, r)
            print(json.dumps({k: v for k, v in r.items() if k != "mutations"}, indent=2))
            return 0
        if args.command == "suggest-checks":
            r = suggest_checks(raw)
            if not r["draft_count"]:
                print("No additional supported check was found within this fault scope.")
                return 0
            write_json(args.out, r["specification"])
            write_json(Path(args.out).with_suffix(".evaluation.json"), r)
            print(
                json.dumps(
                    {
                        "draft_count": r["draft_count"],
                        "training": r["training"],
                        "holdout": r["holdout"],
                        "warning": r["warning"],
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "check":
            r = verify_checks(raw, read(args.checks))
            print(json.dumps(r, indent=2))
            return r["exit_code"]
        if args.command == "labels":
            r = label_experiment(raw, args.endpoint, json.loads(args.labels))
            write_json(args.out, r)
            print(
                json.dumps(
                    {
                        "endpoint": r["endpoint"],
                        "changed_connections": len(r["changes"]),
                        "new_asset_paths": len(r["new_asset_paths"]),
                        "shortened_asset_paths": len(r["shortened_asset_paths"]),
                        "warning": r["warning"],
                    },
                    indent=2,
                )
            )
            return 0
        if args.command == "replay":
            print(json.dumps(replay(raw, read(args.preservation)), indent=2))
            return 0
        if args.command == "verify":
            if not args.allow_live:
                raise ValueError("Review the disposable lab plan, then explicitly pass --allow-live")
            allowed = json.loads(os.environ.get("NETSCOPE_ALLOWED_CONTEXTS", "{}"))
            if not isinstance(allowed, dict):
                raise ValueError("Allowlist must bind context names to exact API server URLs")
            r = run_live(raw, args.context, allowed)
            write_json(args.out, r)
            print(
                json.dumps(
                    {
                        "state": r["state"],
                        "exit_code": r["exit_code"],
                        "error": r.get("error"),
                        "runtime_status": r["runtime_status"],
                    },
                    indent=2,
                )
            )
            return r["exit_code"]
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as exc:
        print(f"NetScope: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
