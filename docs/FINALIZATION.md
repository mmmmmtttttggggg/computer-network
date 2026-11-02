# Your one-batch Mac checklist — NetScope 1.2

You already installed Homebrew, Python 3.12, kind, kubectl 1.35, and Docker Desktop. There is no need to reinstall them or use the other laptops. This is a working local application; real Kubernetes enforcement is the remaining environment-dependent validation step.

## 1. Use the new ZIP and launch once

Stop the old NetScope terminal with **Ctrl+C**. Extract the new ZIP into a fresh folder, such as `~/Downloads/NetScope-1.2/`. Keep the old folder as a backup; do not copy its `.venv` into the new folder. In Terminal, type `cd `, drag the new extracted `computer-network-main` folder into Terminal, and press Enter.

```bash
export PATH="/opt/homebrew/opt/kubernetes-cli@1.35/bin:$PATH:$HOME/.docker/bin:/Applications/Docker.app/Contents/Resources/bin"
python3.12 scripts/start.py
```

Open **http://127.0.0.1:8000**. The sidebar should say **v1.2.0**. Old reviews may reappear because history is stored outside the project. Select a scenario and click **Run review** to create a current report. Do not assume an old saved report has the new results. Leave this terminal running while using the dashboard.

## 2. Learn the useful demonstrations

| Scenario / action | Expected explanation |
|---|---|
| The indirect escape → Containment lab | Five direct intents pass; an explicitly assumed gateway relay creates an indirect database path. A network path is not an exploit. |
| The indirect escape → Experiments → Find scoped repair | Open the proposal as a new review; its whole scope and constraints are re-evaluated. Nothing deploys. |
| A clean baseline → Experiments → Suggest missing checks | Four draft checks; training detection 8/14 → 14/14, held-out 2/6 → 4/6. Verify on reference and download checks. These are synthetic faults, not analyzer accuracy. |
| The indirect escape → label experiment → apps/agent → Set app=payments → Analyze | Egress isolation disappears, 20 permissions change, an existing two-hop database path becomes direct, and unmatched agent intents stay INVALID. This assumes a label edit, not authority to perform it. |
| The last policy disappears | All five intents still pass, but policy deletion opens access. |
| The database switch → reducer | Two changed database connections; reduce a witness from ten paired policies to one and download its replay ZIP. |
| Connections → Ask about another connection | Query agent → database TCP/12345, expected Deny; download the exact assertion. It does not change the saved report's scope. |

Use `docs/DEMO_SCRIPT.md` for the original short presentation and `docs/EXPERIMENTS.md` for the additions. The code-reading order is README → `service.py` → `ingest/project.py` → `model/evaluator.py` → `review/` → `analysis/` → `web/server.py` → `runtime/runner.py`, all application modules under `src/app/`. Run a small example before studying the evaluator.

## 3. Run the real Kubernetes lab

Keep Docker Desktop open. Its Kubernetes option is not needed; the script creates a dedicated kind cluster with a policy-enforcing CNI. Close heavy apps if necessary; the lab expects roughly 8 GiB RAM available. Stop NetScope with Ctrl+C, then in the same project folder run:

```bash
docker version
kind --version
kubectl version --client
python3.12 scripts/lab.py up
python3.12 scripts/start.py --lab --skip-install
```

Docker must show both Client and Server. Cluster creation downloads images and installs Calico. If `netscope-lab` already exists, inspect `python3.12 scripts/lab.py status`; use `down` only for your recorded disposable lab, then `up` again. Old reserved namespaces must not be silently reused. If setup fails, keep the error output rather than changing random Kubernetes settings.

In the dashboard, run these sequentially:

1. **A clean baseline**: Run review → Evidence → select the available context → Preview plan → read the plan → type `RUN DISPOSABLE LAB` → start verification.
2. **The database switch**: repeat. Agreement with runtime can coexist with a FAIL review, because this candidate intentionally violates application requirements.
3. **The indirect escape**: repeat. Runtime checks individual network hops; the assumed application relay is still a separate assumption.
4. **The cross-namespace check**: repeat. This single connection investigates the retained independent-analyzer disagreement. Either observed outcome is evidence to inspect, not a result to edit away.

After each job, download its **evidence JSON**. Check the overall runtime status, model/observation matrix, protocol controls, conclusive coverage, errors, and cleanup leftovers. `NOT_TESTED`, missing revision observations, failed controls, or incomplete cleanup are not a successful verification. Cross-node coverage is counted from recorded node names; zero is not evidence of cross-node enforcement. Extra infrastructure is not required for the first presentation.

These jobs use trusted fixture Pods, not your application containers. They validate modeled network connectivity in the disposable lab, not application authorization, prompt-injection defenses, production safety, or a complete exploit chain. See `docs/LIVE_LAB.md` for exact scope and failure interpretation.

## 4. Keep the evidence and clean up

Keep the four downloaded live JSON files, a current HTML report, the draft-check JSON, label comparison JSON, and reduced replay ZIP. These support the main presentation claims. Send back any failed/incomplete job JSON plus its terminal error for diagnosis; do not relabel it as a pass.

Optional local developer check (the delivered release already includes its build-workspace test results): stop the server, then run:

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

When finished, stop NetScope and remove only its dedicated lab:

```bash
python3.12 scripts/lab.py down
```

For later static use, run `python3.12 scripts/start.py --skip-install`. For a later live session, recreate the lab so the short-lived runner credential is fresh. Do not commit or share `~/.netscope/lab-kubeconfig.json`.

The honest final claim is: **a working local NetworkPolicy analysis and experiment tool, with real-cluster evidence for the specific scenarios you actually ran.** Completing the lab checks makes that claim stronger; it does not make the tool production-certified.
