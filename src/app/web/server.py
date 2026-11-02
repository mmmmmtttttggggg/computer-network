"""Local HTTP application. All views call the same tested application boundary."""

from __future__ import annotations
from contextlib import asynccontextmanager
import json
import os
import secrets
import threading
from pathlib import Path
from importlib.resources import files
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from app.ingest.project import parse_project, load_text, MAX_INPUT
from app.service import review_project, VERSION
from app.store import RunStore, CapacityError
from app.analysis.reducer import reduce_project, bundle_zip
from app.analysis.experiments import repair_project, run_mutations
from app.analysis.coverage import suggest_checks, verify_checks
from app.analysis.labels import label_experiment
from app.runtime.runner import run_live, runtime_preflight
from app.reporting import html_report


def create_app(data_dir=None):
    token = secrets.token_urlsafe(32)
    store = RunStore(data_dir or os.environ.get("NETSCOPE_DATA", str(Path.home() / ".netscope")))
    live_lock = threading.Lock()
    cancels = {}

    def allowlist():
        try:
            value = json.loads(os.environ.get("NETSCOPE_ALLOWED_CONTEXTS", "{}"))
            return (
                value
                if isinstance(value, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
                else {}
            )
        except ValueError:
            return {}

    @asynccontextmanager
    async def lifespan(app):
        yield
        for event in list(cancels.values()):
            event.set()

    api = FastAPI(title="NetScope", version=VERSION, lifespan=lifespan)
    api.state.store = store
    api.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @api.middleware("http")
    async def protect(request, call_next):
        if request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            if not secrets.compare_digest(request.headers.get("x-netscope-token", ""), token):
                return JSONResponse({"detail": "Missing local session token"}, status_code=403)
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Cross-origin write rejected"}, status_code=403)
            length = request.headers.get("content-length")
            if length and not length.isdecimal():
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
            if length and int(length) > MAX_INPUT:
                return JSONResponse({"detail": "Input exceeds 5 MiB"}, status_code=413)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > MAX_INPUT:
                    return JSONResponse({"detail": "Input exceeds 5 MiB"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    @api.exception_handler(CapacityError)
    async def quota(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=507)

    @api.exception_handler(OSError)
    async def storage_error(request, exc):
        return JSONResponse(
            {"detail": "Local storage operation failed; the operation was not acknowledged as successful."},
            status_code=507,
        )

    @api.exception_handler(ValueError)
    async def bad(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @api.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": "Run, query, or endpoint not found: " + str(exc)}, status_code=404)

    @api.exception_handler(TypeError)
    async def invalid(request, exc):
        return JSONResponse({"detail": "Invalid input structure: " + str(exc)}, status_code=422)

    @api.exception_handler(AttributeError)
    async def invalid_attr(request, exc):
        return JSONResponse({"detail": "Invalid input structure: " + str(exc)}, status_code=422)

    def read(rid):
        return store.get(rid)

    @api.get("/", response_class=HTMLResponse)
    def home():
        return (Path(__file__).parent / "static/index.html").read_text()

    @api.get("/api/config")
    def config():
        return {
            "token": token,
            "version": VERSION,
            "contexts": list(allowlist()),
            "live_available": bool(allowlist()),
            "limits": {"input_mib": 5, "queries": 17400, "live_tuples": 300},
        }

    @api.get("/api/examples")
    def examples():
        out = []
        for f in sorted(files("app").joinpath("resources/examples").iterdir(), key=lambda p: p.name):
            if f.name.endswith(".json"):
                raw = json.loads(f.read_text())
                out.append({"id": f.name[:-5], "name": raw["name"], "description": raw["description"]})
        return out

    @api.get("/api/examples/{eid}")
    def example(eid: str):
        if not eid.replace("-", "").isalnum():
            raise HTTPException(404)
        f = files("app").joinpath("resources/examples", eid + ".json")
        if not f.is_file():
            raise HTTPException(404)
        return json.loads(f.read_text())

    @api.post("/api/runs")
    def run(payload: dict):
        raw = payload.get("project", payload)
        if isinstance(raw, str):
            raw = load_text(raw)
        project = parse_project(raw)
        report = review_project(project)
        rid = store.save(project.raw, report)
        return {"id": rid, **report}

    @api.get("/api/runs")
    def history():
        return store.list()

    @api.get("/api/runs/{rid}")
    def get(rid: str):
        return {"id": rid, **read(rid)["report"], "jobs": store.jobs(rid)}

    @api.get("/api/runs/{rid}/project")
    def project(rid: str):
        return read(rid)["project"]

    @api.delete("/api/runs/{rid}")
    def delete(rid: str):
        store.delete(rid)
        return {"deleted": rid}

    @api.get("/api/runs/{rid}/report.json")
    def export_json(rid: str):
        return Response(
            json.dumps({"id": rid, **read(rid)["report"]}, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="netscope-report.json"'},
        )

    @api.get("/api/runs/{rid}/report.html")
    def export_html(rid: str):
        return Response(
            html_report(read(rid)["report"]),
            media_type="text/html",
            headers={"Content-Disposition": 'attachment; filename="netscope-report.html"'},
        )

    @api.post("/api/runs/{rid}/reduce")
    def reduce(rid: str, payload: dict):
        return reduce_project(read(rid)["project"], payload.get("tuple_id"))

    @api.post("/api/runs/{rid}/bundle")
    def bundle(rid: str, payload: dict):
        result = reduce_project(read(rid)["project"], payload.get("tuple_id"))
        return Response(
            bundle_zip(result),
            media_type="application/zip",
            headers={"Content-Disposition": 'attachment; filename="netscope-replay.zip"'},
        )

    @api.post("/api/runs/{rid}/repair")
    def repair(rid: str):
        return repair_project(read(rid)["project"])

    @api.post("/api/runs/{rid}/mutate")
    def mutate(rid: str):
        return run_mutations(read(rid)["project"])

    @api.post("/api/runs/{rid}/checks/suggest")
    def suggestions(rid: str):
        return suggest_checks(read(rid)["project"])

    @api.post("/api/runs/{rid}/checks/verify")
    def checks(rid: str, payload: dict):
        return verify_checks(read(rid)["project"], payload)

    @api.post("/api/runs/{rid}/labels")
    def labels(rid: str, payload: dict):
        return label_experiment(read(rid)["project"], payload.get("endpoint"), payload.get("labels"))

    @api.post("/api/runs/{rid}/plan")
    def plan(rid: str, payload: dict):
        raw = read(rid)["project"]
        ctx = payload.get("context", "")
        p, r = runtime_preflight(raw, ctx, allowlist())
        return {
            "context": ctx,
            "server": allowlist()[ctx],
            "plan": r["plan"],
            "input_hash": p.fingerprint,
            "mutations": [
                "Create exclusive test namespaces and trusted fixture Pods",
                "Apply both complete policy revisions",
                "Probe all changed/intent tuples",
                "Delete only owned namespaces",
            ],
            "warning": "Explicit local disposable cluster only. No imported images/commands are executed.",
        }

    @api.post("/api/runs/{rid}/verify")
    def verify(rid: str, payload: dict):
        saved = read(rid)
        context = payload.get("context", "")
        _, report = runtime_preflight(saved["project"], context, allowlist())
        if (
            payload.get("plan_hash") != report["plan"]["hash"]
            or payload.get("confirm") != "RUN DISPOSABLE LAB"
        ):
            raise HTTPException(409, "Confirm the exact plan hash and type RUN DISPOSABLE LAB")
        if not live_lock.acquire(blocking=False):
            raise HTTPException(409, "Another live job owns the cluster lock")
        try:
            jid = store.job(rid)
        except Exception:
            live_lock.release()
            raise
        cancel = threading.Event()
        cancels[jid] = cancel

        def worker():
            try:
                store.update_job(jid, "RUNNING", {"events": []})
                result = run_live(
                    saved["project"],
                    context,
                    allowlist(),
                    cancel=cancel,
                    progress=lambda r: store.update_job(jid, "RUNNING", r),
                )
                store.update_job(jid, result["state"], result)
            except Exception as e:
                store.update_job(
                    jid, "INCOMPLETE", {"error": str(e), "exit_code": 2, "runtime_status": "INCOMPLETE"}
                )
            finally:
                cancels.pop(jid, None)
                live_lock.release()

        threading.Thread(target=worker, daemon=True).start()
        return {"job_id": jid, "state": "QUEUED"}

    @api.get("/api/jobs/{jid}")
    def job(jid: str):
        return store.get_job(jid)

    @api.post("/api/jobs/{jid}/cancel")
    def cancel(jid: str):
        job = store.get_job(jid)
        if jid in cancels:
            cancels[jid].set()
        return {"job_id": jid, "state": job["state"], "cancel_requested": jid in cancels}

    api.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
    return api


def app_factory():
    return create_app()
