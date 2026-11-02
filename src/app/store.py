"""Local durable run/evidence store with transactional references and disk limits."""

from __future__ import annotations
import json
import os
import re
import sqlite3
import threading
import uuid
from pathlib import Path
from app.service import utcnow


class CapacityError(ValueError):
    pass


class RunStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.db = self.path / "runs.sqlite3"
        self.lock = threading.RLock()
        with self.connect() as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, name TEXT, created TEXT, status TEXT, input_hash TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, run_id TEXT, state TEXT, created TEXT, result TEXT)"
            )
            c.execute("UPDATE jobs SET state='INTERRUPTED' WHERE state IN ('QUEUED','RUNNING')")

    def connect(self):
        c = sqlite3.connect(self.db, timeout=30)
        c.row_factory = sqlite3.Row
        return c

    def _valid(self, rid):
        if not re.fullmatch(r"[a-f0-9]{24}", rid):
            raise KeyError(rid)
        return self.path / rid

    def _size(self):
        return sum(p.stat().st_size for p in self.path.rglob("*") if p.is_file())

    def save(self, project, report):
        payload = json.dumps(
            {"project": project, "report": report}, ensure_ascii=False, allow_nan=False
        ).encode()
        with self.lock, self.connect() as c:
            if (
                c.execute("SELECT count(*) FROM runs").fetchone()[0] >= 100
                or self._size() + len(payload) > 1024**3
            ):
                raise CapacityError(
                    "Report capacity exceeded (100 runs / 1 GiB). Explicitly remove old runs first."
                )
            rid = uuid.uuid4().hex[:24]
            target = self._valid(rid)
            target.mkdir()
            tmp = target / "run.tmp"
            with tmp.open("wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, target / "run.json")
            c.execute(
                "INSERT INTO runs VALUES (?,?,?,?,?)",
                (rid, report["name"], report["created_at"], report["status"], report["input_hash"]),
            )
        return rid

    def get(self, rid):
        target = self._valid(rid)
        with self.connect() as c:
            if c.execute("SELECT id FROM runs WHERE id=?", (rid,)).fetchone() is None:
                raise KeyError(rid)
        return json.loads((target / "run.json").read_text())

    def list(self):
        with self.connect() as c:
            return [dict(x) for x in c.execute("SELECT * FROM runs ORDER BY created DESC LIMIT 100")]

    def delete(self, rid):
        target = self._valid(rid)
        with self.lock, self.connect() as c:
            if c.execute(
                "SELECT 1 FROM jobs WHERE run_id=? AND state IN ('QUEUED','RUNNING')", (rid,)
            ).fetchone():
                raise CapacityError("Cannot delete a run while verification is active")
            if c.execute("DELETE FROM runs WHERE id=?", (rid,)).rowcount == 0:
                raise KeyError(rid)
            c.execute("DELETE FROM jobs WHERE run_id=?", (rid,))
            for p in target.iterdir():
                p.unlink()
            target.rmdir()

    def job(self, rid, state="QUEUED"):
        self.get(rid)
        jid = uuid.uuid4().hex[:24]
        with self.lock, self.connect() as c:
            c.execute("INSERT INTO jobs VALUES (?,?,?,?,?)", (jid, rid, state, utcnow(), "{}"))
        return jid

    def update_job(self, jid, state, result):
        data = json.dumps(result, allow_nan=False)
        if len(data.encode()) > 100 * 1024**2:
            raise CapacityError("Evidence exceeds 100 MiB per job")
        with self.lock, self.connect() as c:
            if self._size() + len(data.encode()) > 1024**3:
                raise CapacityError("Evidence storage quota exceeded")
            c.execute("UPDATE jobs SET state=?,result=? WHERE id=?", (state, data, jid))

    def get_job(self, jid):
        self._valid(jid)
        with self.connect() as c:
            row = c.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if row is None:
            raise KeyError(jid)
        r = dict(row)
        r["result"] = json.loads(r["result"])
        return r

    def jobs(self, rid):
        with self.connect() as c:
            return [
                dict(x)
                for x in c.execute(
                    "SELECT id,run_id,state,created FROM jobs WHERE run_id=? ORDER BY created DESC", (rid,)
                )
            ]
