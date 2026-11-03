"""Regression coverage for a source fixture overwhelmed by concurrent execs.

Scripted transports test orchestration only. The signal test uses a real local
process; none of these tests claim Kubernetes or CNI validation.
"""

from collections import Counter, defaultdict
import copy
import json
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

from app.runtime.fixture import PROGRAM
from app.runtime.runner import run_live, RuntimeErrorSafe
from app.service import review_project
from test_runtime import tiny_project, ScriptedCluster, NoDelay


def fanout_project(sources=1, ports=20):
    raw = tiny_project()
    raw["intents"] = []
    original = copy.deepcopy(raw["topology"][1])
    for i in range(sources):
        source = "source" if i == 0 else f"source-{i}"
        if i:
            pod = copy.deepcopy(original)
            pod["metadata"].update(name=source, labels={"app": source})
            raw["topology"].append(pod)
        for port in range(19091, 19091 + ports):
            raw["intents"].append(
                {
                    "id": f"deny-{i}-{port}",
                    "source": {"podSelector": {"matchLabels": {"app": source}}},
                    "destination": {"podSelector": {"matchLabels": {"app": "destination"}}},
                    "port": port,
                    "protocol": "TCP",
                    "expect": "must_deny",
                }
            )
    return raw


class LoadedCluster(ScriptedCluster):
    def __init__(self, *, cancel_during_batch=None, crash=False, on_batch_start=None):
        super().__init__()
        self.lock = threading.Lock()
        self.active = Counter()
        self.peaks = Counter()
        self.peak_total = 0
        self.total = 0
        self.executed = defaultdict(Counter)
        self.resources = []
        self.cancel_during_batch = cancel_during_batch
        self.crash = crash
        self.crashed = False
        self.on_batch_start = on_batch_start

    def create(self, obj):
        if obj["kind"] == "Pod":
            self.resources.append(copy.deepcopy(obj["spec"]["containers"][0]["resources"]))
        super().create(obj)

    def get(self, kind, namespace=None, name=None):
        obj = super().get(kind, namespace, name)
        if kind == "pod" and namespace == "test-app" and name == "source" and self.crashed:
            obj["status"]["phase"] = "Failed"
            obj["status"]["containerStatuses"][0].update(
                name="fixture",
                ready=False,
                restartCount=0,
                state={"terminated": {"reason": "OOMKilled", "exitCode": 137}},
            )
        return obj

    def call(self, args, body=None, timeout=30):
        if args[0] != "exec" or args[2] == "netscope-controls":
            return super().call(args, body, timeout)
        source = args[3] if args[2] == "test-app" else f"{args[2]}/{args[3]}"
        with self.lock:
            self.active[source] += 1
            self.total += 1
            self.peaks[source] = max(self.peaks[source], self.active[source])
            self.peak_total = max(self.peak_total, self.total)
            self.executed[source][int(args[-3])] += 1
            overloaded = self.active[source] > 2
            under_policy = ("NetworkPolicy", "test-app", "isolate-destination") in self.objects
            if under_policy and self.cancel_during_batch and self.active[source] == 2:
                self.cancel_during_batch.set()
            if under_policy and self.crash:
                self.crashed = True
            if under_policy and self.on_batch_start and self.active[source] == 2:
                self.on_batch_start()
        try:
            time.sleep(0.02)  # Let actual executor threads overlap.
            if overloaded or (under_policy and self.crash):
                raise RuntimeErrorSafe("command terminated with exit code 137")
            return super().call(args, body, timeout)
        finally:
            with self.lock:
                self.active[source] -= 1
                self.total -= 1


def run(raw, fake, cancel=None):
    return run_live(
        raw, "test", {"test": "https://127.0.0.1:6443"}, transport=fake, cancel=cancel or NoDelay()
    )


def test_source_fanout_is_bounded_without_sampling_queries():
    fake = LoadedCluster()
    raw = fanout_project()
    result = run(raw, fake)
    assert result["state"] == "COMPLETE", result.get("error")
    assert result["exit_code"] == 0
    assert fake.peaks["source"] == 2 and fake.total == 0
    assert len(result["observations"]) == 40
    assert all(o["complete"] and len(o["attempts"]) == 3 for o in result["observations"])
    assert result["coverage"]["conclusive_both_revisions"] == 20
    # Every port receives one unrestricted check and three attempts per phase.
    assert fake.executed["source"] == Counter({p: 7 for p in range(19091, 19111)})
    assert all(r["limits"]["memory"] == "128Mi" for r in fake.resources)
    assert result["environment"]["execution"]["max_parallel_probes_per_source"] == 2
    assert not result["leftovers"] and not fake.objects


def test_source_limits_still_allow_parallel_work_across_pods():
    fake = LoadedCluster()
    result = run(fanout_project(sources=3, ports=4), fake)
    assert result["state"] == "COMPLETE", result.get("error")
    assert 2 < fake.peak_total <= 10 and max(fake.peaks.values()) <= 2
    assert len(result["observations"]) == 24 and not fake.objects


def test_cancel_stops_waiters_and_drains_active_execs_before_cleanup():
    fake = LoadedCluster()
    cancel = NoDelay()
    fake.cancel_during_batch = cancel
    result = run(fanout_project(), fake, cancel)
    assert result["state"] == "CANCELLED" and result["exit_code"] == 2
    assert fake.total == 0 and fake.peaks["source"] <= 2
    assert not result["leftovers"] and not fake.objects


def test_budget_expiry_stops_queued_work_and_preserves_cleanup(monkeypatch):
    from app.runtime import runner

    offset = [0]
    clock = SimpleNamespace(monotonic=lambda: time.monotonic() + offset[0], perf_counter=time.perf_counter)
    monkeypatch.setattr(runner, "time", clock)
    fake = LoadedCluster(on_batch_start=lambda: offset.__setitem__(0, 601))
    result = run(fanout_project(), fake)
    assert result["state"] == "INCOMPLETE" and result["exit_code"] == 2
    assert "budget exceeded" in result["error"]
    assert fake.total == 0 and fake.peaks["source"] <= 2
    assert not result["leftovers"] and not fake.objects


def test_failed_fixture_keeps_termination_reason_and_never_certifies_denial():
    fake = LoadedCluster(crash=True)
    result = run(fanout_project(), fake)
    assert result["exit_code"] == 2 and result["runtime_status"] == "INCOMPLETE"
    assert all(o["verdict"] == "INCONCLUSIVE" and not o["complete"] for o in result["observations"])
    assert all(o["controls"]["after"]["allow"]["outcome"] == "success" for o in result["observations"])
    detail = result["drift_details"][0]["changes"]["test-app/source"]
    assert detail["expected"]["phase"] == "Running"
    assert detail["observed"]["phase"] == "Failed"
    assert detail["observed"]["containers"][0]["state"]["terminated"]["reason"] == "OOMKilled"
    assert not result["leftovers"] and not fake.objects


def test_cleanup_progress_precedes_final_result_and_keeps_cleanup_guards():
    updates = []
    result = run_live(
        tiny_project(),
        "test",
        {"test": "https://127.0.0.1:6443"},
        transport=ScriptedCluster(),
        cancel=NoDelay(),
        progress=updates.append,
    )
    assert any(x.get("stage") == "CLEANUP" for x in updates)
    assert updates[-1]["stage"] == "FINISHED" and result["exit_code"] == 0
    assert any("Removed owned namespace" in x["message"] for x in result["events"])
    failed = run(tiny_project(), ScriptedCluster(cleanup_error=True))
    assert failed["state"] == "INCOMPLETE" and failed["leftovers"]
    assert failed["events"][-1]["message"] == "Cleanup incomplete; inspect leftovers"


def test_actual_deletion_scenario_keeps_all_23_planned_connections(example):
    raw = example("last-policy-deleted")
    expected = review_project(raw)
    assert expected["plan"]["count_per_phase"] == 23
    fake = LoadedCluster()
    # The scripted adapter does not implement all example policies. Agreement
    # is not claimed; this regression checks scheduling and retained coverage.
    result = run(raw, fake)
    assert result["state"] == "COMPLETE", result.get("error")
    assert len(result["observations"]) == 46
    assert Counter(o["tuple_id"] for o in result["observations"]) == Counter(
        {row["tuple_id"]: 2 for row in expected["plan"]["tuples"]}
    )
    assert fake.peaks["apps/agent"] == 2 and max(fake.peaks.values()) <= 2


def test_fixture_handles_sigterm_with_a_clean_exit():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = subprocess.Popen([sys.executable, "-c", PROGRAM, "serve", json.dumps([[port, "TCP"]])])
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.01)
        else:
            raise AssertionError("fixture listener did not start")
        server.terminate()
        assert server.wait(timeout=2) == 0
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=2)
