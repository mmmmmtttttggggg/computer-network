# NetScope — Kubernetes Policy Intelligence Lab

**Release: 1.2.0.** A local Kubernetes NetworkPolicy review and experiment tool.

| Status | Current evidence |
|---|---|
| Application, dashboard, CLI, static experiments | Implemented; release package checked outside its source folder. |
| Automated tests | 287 passing in the recorded build-workspace run. Run them on your machine using the commands below. |
| Browser workflows | Recorded Chromium checks at 1440, 1366, and 390 px, with no JavaScript page errors. |
| Actual Kubernetes / Calico enforcement | Runner implemented; **real-cluster verification remains pending**. Scripted worker tests are not CNI evidence. |
| GitHub Actions | Runs on every push: tests on Python 3.10 and 3.12, plus the browser workflow. Passing on `main`. |

The original final archive is available at **[releases/NetScope-1.2.zip](releases/NetScope-1.2.zip)**. The branch also contains the extracted project so its code and tests can be inspected directly. The archive preserves the release bytes; this branch README adds the GitHub handoff instructions.

**A working NetworkPolicy digital twin with agent-containment experiments, counterfactual repairs, and replayable regression cases.** Built on the supplied Python evaluator, selector, and review modules; the original 151 tests are retained.

The first demo is deliberately surprising: five direct connectivity intents pass, yet a gateway policy change creates an indirect agent-to-database path under an explicit relay assumption. Every hop has policy evidence. The application also compares ordinary policy changes, explains ingress/egress decisions, and measures where an intent suite misses injected mistakes.

## Run the application

Python 3.10+ is required; Python 3.12 on Linux was tested. No JavaScript build step, paid service, LLM API key, or cluster is needed for the main demo.

```bash
python3 scripts/start.py
```

Windows: `py scripts/start.py`. Open **http://127.0.0.1:8000**. The launcher creates `.venv`, installs `requirements.lock`, and installs the package. Subsequent launches can use `--skip-install`. Stop with Ctrl+C. Use `--port 8001` if necessary.

On a Mac with Python 3.12 installed, use `python3.12 scripts/start.py`. Confirm **v1.2.0** in the sidebar. Select a scenario and click **Run review**, since saved history can restore an older report. All commands in this README are run from the project root, where `pyproject.toml` and `scripts/` exist.

**Docker is only needed for live Kubernetes verification.** The Python dashboard and static analysis run directly on the host. `scripts/lab.py up` uses Docker through kind to create the dedicated Kubernetes cluster.

Manual setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install -e '.[dev]'
netscope serve
```

PowerShell activation: `.venv\Scripts\Activate.ps1`. The runtime dependency resolution is recorded for the tested Linux/Python 3.12 environment; pip may resolve additional platform-specific dependencies elsewhere.

## What is implemented

| Capability | What you can demonstrate |
|---|---|
| Policy review | Shared topology, baseline/candidate decisions, semantic deltas, exact change approvals, and independent application intent checks. |
| Explainable results | Click a connection for selecting policies, directional isolation, matching rules, endpoint labels, and destination port declarations. |
| Agent containment | Explicit entrypoints, pivots, sensitive assets, blast radius, witnessed paths, and single-pivot counterfactuals that search alternate routes. Port declarations are separated from listener evidence. |
| Scoped repair experiments | Search small sets of changed policy reverts. Re-evaluate all queries/intents and prevent new conditional asset pairs relative to baseline. Export proposals or inspect them as new runs. |
| Regression reduction | Remove paired policy identities while preserving a selected connection's before/after decisions, four isolation flags, and candidate intent violations. Export and replay the resulting bundle. |
| Fault injection | Deterministic selector, peer-composition, port, and allow-rule mistakes. Distinguish effective/equivalent mutations and new intent failures. |
| Suggested regression checks | Draft exact connection assertions from missed training faults; measure them on held-out synthetic faults; export reusable checks and verify them through the CLI. |
| Label counterfactuals | Replace one Pod's labels; explain changed policy selection/isolation, newly exposed or shorter asset paths, and intents that lose their matches. Open the result as a new immutable review. |
| Query composer | Ask about another candidate connection/port without changing the saved review; download a portable regression assertion. |
| Evidence and persistence | Local SQLite/file storage, immutable static reviews, hashes, JSON/standalone HTML exports, restart recovery, and explicit storage limits. |
| Controlled live testing | Opt-in disposable-cluster worker, exact context/server binding, trusted fixtures, health/enforcement controls, fresh TCP/UDP probes, drift checks, cancellation, and UID-guarded cleanup. Real CNI integration remains unverified in this build environment. |

## What the model means

A tuple is `(source, destination, protocol, numeric destination port)`. Pod-to-Pod traffic must satisfy **source egress AND destination ingress**. Policies are additive. An isolated direction needs an allow match; an unisolated direction is unrestricted by standard NetworkPolicy.

Supported static features include selector expressions, namespace boundaries, combined AND / separate OR peers, TCP/UDP/SCTP, named destination ports, inclusive numeric port ranges, and declared external IP CIDR exclusions. Unknown influencing policies, host-network/self traffic, and unresolved Pod/IP-block/NAT semantics cannot receive a complete pass. Deployment templates represent logical endpoints, not live replicas. Services are excluded from the core Pod-IP model.

The primary graph shows selected intent, changed, and containment paths (up to 24); the Connections table contains the full declared query set. The model's Allow means policy permission, not listener health, application authorization, or production safety.

Containment paths assume the entrypoint is compromised and only explicitly listed pivots can relay traffic. They use known Allow edges, are bounded to four hops, and show one shortest path per entrypoint/asset. No CVE, prompt-injection, RBAC exploit, or automatic compromise is inferred. Unqueried/Unknown edges are excluded from this graph and are not proved blocked. The SRS review gate and the conditional containment study are distinct; approving a delta never hides a containment finding or overrides failed intent.

## Inspectable demo scenarios

Examples live in `src/app/resources/examples/` and can be edited in Inputs.

- **The indirect escape**: one new gateway path; five candidate direct intents pass.
- **The parallel relay**: a second gateway keeps the asset reachable when one relay assumption is removed.
- **The database switch**: exactly two changed database paths and two candidate intent violations.
- **A clean baseline**: identical revisions; all five intents pass; good for mutation testing.
- **The AND / OR trap**: splitting a combined peer widens access.
- **An honest Unknown**: an influencing vendor policy blocks complete certification.
- **The last policy disappears**: deleting the final selecting policy opens connections while existing intents still pass.
- **The cross-namespace check**: a reduced independent-analyzer disagreement with an explicit intent and a one-connection live plan.

See **[START_HERE.md](START_HERE.md)** for the presentation sequence.

## CLI and reports

After installation:

```bash
netscope demo --out artifacts/demo
netscope review src/app/resources/examples/checkout-regression.json --out artifacts/review
netscope repair src/app/resources/examples/agent-escape.json --out artifacts/repair.json
netscope mutate src/app/resources/examples/clean-baseline.json --out artifacts/mutations.json
netscope suggest-checks src/app/resources/examples/clean-baseline.json --out artifacts/draft-checks.json
netscope check src/app/resources/examples/clean-baseline.json artifacts/draft-checks.json
netscope labels src/app/resources/examples/agent-escape.json --endpoint apps/agent --labels '{"app":"payments","tier":"service"}' --out artifacts/labels.json
```

`review` exits **0** for a complete static pass, **1** for a completed failure, **2** for invalid/error/incomplete results. Exit 2 takes precedence while known failures remain recorded. Static results always say runtime is not verified. `demo` exits 0 when its exports succeed even though some intentional scenarios fail their review gates.

`check` uses the same 0/1/2 convention for its exact candidate assertions; its pass is separate from the full review gate. Suggested assertions preserve a reviewed reference's behavior, so review their expected outcomes before adopting them. Their held-out faults use the same synthetic generator and do not establish analyzer accuracy or independent validation. See `docs/FINALIZATION.md` for the single Mac setup/validation checklist and `docs/EXPERIMENTS.md` for the new demonstrations.

For reduction, copy a changed `tuple_id` from the report:

```bash
netscope reduce project.json --tuple-id t-REPLACE_WITH_ACTUAL_ID --out artifacts/replay.zip
```

Unzip a bundle, then:

```bash
netscope replay project.yaml preservation.json
```

Replay verifies the exact selected static signature and bundle hash. It is not a live verification claim. A bounded search reports `budget-limited`; a completed deletion search reports `1-minimal`, never globally smallest or a unique root cause. Repair searches cover at most 16 changed policy identities, test subsets up to size three, and stop at 64 evaluations or ten seconds. Their proposals can still contain approved/unapproved review differences; inspect that gate and newly reachable paths before use.

## Engineering and validation

After the initial launch has created `.venv`, stop the server with Ctrl+C and run:

```bash
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
```

On Windows use `.venv\Scripts\Activate.ps1` for activation. The recorded release result is **287 passed**, with a test-client deprecation warning retained in the log. Tests cover policy semantics, validation, review gates, persistence, HTTP/CLI workflows, immutable experiments, reducer replay, and worker controls/failures. See [artifacts/test-results.txt](artifacts/test-results.txt) and [docs/VALIDATION.md](docs/VALIDATION.md).

Optional real-browser workflows:

```bash
python -m pip install -e '.[dev,browser]'
python -m playwright install chromium
python scripts/browser_smoke.py
```

Optional local performance measurement:

```bash
python scripts/benchmark.py artifacts/benchmark-local.json
```

The benchmark measures complete two-revision static review construction, including traces and intent, rather than a single query. The retained release 1.1 baseline is in `artifacts/benchmark.json`; write new measurements to a separate file. The evaluator/review modules are unchanged in 1.2, but those historical timings were not rerun for this release. Scripted Kubernetes-adapter tests check worker sequencing/failures only; actual loopback TCP/UDP tests exercise the trusted probe program. Neither is labelled as real CNI verification. The CI workflow repeats unit/integration, lint, demo export, and browser checks.

An optional independent check against **Network Config Analyzer 2.1.0** compares 5,472 decisions across 28 finite fixtures. One cross-namespace selector disagreement is retained with a reduced reproducer; this is not a perfect-conformance claim. See [docs/ORACLE_CHECK.md](docs/ORACLE_CHECK.md). The oracle has its own environment and is not required to launch NetScope.

The dashboard restores the last saved review after refresh. The **Examples** page lists every bundled scenario with what to look for and opens each one on the page where its result appears. It also holds a five-minute walkthrough; [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) has the longer script.

## Real-cluster verification

Prerequisites: Docker Desktop running, kind, kubectl, and roughly 8 GiB RAM available for the disposable lab. On macOS, the built-in Kubernetes option in Docker Desktop is not required. Stop any existing NetScope server before relaunching with lab access.

```bash
python3.12 scripts/lab.py up
python3.12 scripts/start.py --lab --skip-install
```

If using a different Python command, use that interpreter consistently. If Docker/kubectl are missing from the Mac terminal PATH, use the PATH command in [docs/FINALIZATION.md](docs/FINALIZATION.md). The first lab setup downloads images; it must finish successfully before starting live verification.

For each scenario below, select it and click **Run review**, then open **Evidence**, select the available lab context, preview the plan, type `RUN DISPOSABLE LAB`, and start verification. Wait for completion and download **Evidence JSON** before starting the next scenario.

| Order | Scenario | Purpose |
|---|---|---|
| 1 | A clean baseline | Compare known reference permissions against recorded baseline/candidate observations. |
| 2 | The database switch | Verify the intentionally broken/gained paths; a failed application review can coexist with runtime agreement. |
| 3 | The indirect escape | Verify individual permitted hops; the application's relay capability remains an explicit assumption. |
| 4 | The cross-namespace check | Investigate the retained independent-analyzer disagreement using an actual CNI. Preserve either observed outcome. |

Inspect the overall runtime status, protocol controls, per-connection matrix, observations for both revisions, and cleanup leftovers. `NOT_TESTED`, failed controls, incomplete observations, or leftovers do not count as successful verification. Node-placement counts report actual recorded same/cross/unknown node assignments; zero cross-node observations establish no cross-node result.

Keep all four JSON exports, including failed/incomplete jobs. A static FAIL in an intentionally regressing scenario is expected; runtime agreement does not waive violated application requirements. These tests use trusted fixtures, not application images, and do not prove application authorization or exploitability.

Stop the server with Ctrl+C and remove the dedicated lab when finished:

```bash
python3.12 scripts/lab.py down
```

See **[docs/LIVE_LAB.md](docs/LIVE_LAB.md)** for the versioned kind/Calico bootstrap, limited runner identity, exact server allowlist, and confirmation flow. No production cluster is targeted automatically. No application container images, commands, mounts, or environment values are executed by the runner.

The live release subset is IPv4 Pod snapshots, TCP/UDP, ports 1024–65535, at most 300 required tuples per phase. Deployment templates, external peers, SCTP/IPv6, low-port fixtures, and large live plans remain explicitly incomplete. Runtime evidence captures tool/Kubernetes/CNI identity, resolved fixture image IDs, Pod UIDs/IPs, hashes, timestamps, attempts, control outcomes, and cleanup leftovers.

## What remains to do

No additional feature work is required before the first validation pass. The priority is to collect evidence and fix specific failures rather than expand scope.

| Priority | Remaining task | Completion evidence |
|---|---|---|
| First local check | Run the automated suite and explore the main demonstrations on the target Mac. | Local test output and working review/experiment exports. |
| Before claiming live enforcement | Complete the four kind/Calico runs above. | Actual downloaded job JSON with controls, environment, both revisions, coverage, and cleanup results. |
| Before claiming cross-node verification | Obtain conclusive observations between Pods recorded on different nodes. | Nonzero cross-node coverage with actual node names; no inference from cluster size alone. |
| Before claiming full runtime acceptance | Validate cancellation, drift, control failure, and cleanup behavior against a real API server. | Saved real-cluster failure-path evidence; existing scripted tests alone are insufficient. |
| Repository check | Inspect the branch's GitHub Actions test and browser jobs after upload. | Successful workflow results, or concrete issues to fix. |
| Optional broader study | More representative topologies, multiple CNIs, and Safari/Firefox validation. | Separate measured results; these are not prerequisites for the first local demo. |

The proposed larger research study and live-replay target have not been completed. Production/multi-user hardening, RBAC analysis, CVE detection, and prompt-injection defenses are outside this release's claims. The contribution is the integrated, inspectable analysis/experiment workflow—not a claim that graph search or semantic comparison is a new algorithm.

For a single ordered Mac checklist, use **[docs/FINALIZATION.md](docs/FINALIZATION.md)**. For explanations and expected experiment outcomes, use **[docs/EXPERIMENTS.md](docs/EXPERIMENTS.md)**. The project should be described as a working local application, with real-cluster evidence only for runs actually completed.

## Project structure

```text
src/app/
  model/       Existing evaluator/selector/topology core, extended conservatively
  review/      Existing comparison, approval, and intent logic
  ingest/      Strict bounded YAML/JSON and normalized model snapshots
  analysis/    Conditional paths, reducer, repairs, fault injection
  runtime/     Trusted fixture program, conservative verdicts, kubectl adapter
  web/         FastAPI application and self-contained dashboard assets
  resources/   Eight inspectable project examples
  service.py   Shared application boundary
  store.py     Durable reviews and live-job state
  reporting.py Standalone escaped report
  cli.py       Same features through the command line
scripts/       Launch, browser checks, measured benchmark, dedicated lab setup
lab/           Lab configuration notes
artifacts/     Actual generated demo reports and benchmark evidence
```

## Scope, privacy, and research claims

Input limits are 5 MiB, 30 endpoints, 5 namespaces, 100 policies per revision, and 20 protocol/port combinations / 17,400 directed queries. Intent-matched tuples are added even when explicit queries omit them. Storage refuses new work above 100 reviews or 1 GiB instead of silently deleting evidence. The API listens on loopback by default, verifies local write tokens/origins, and escapes report content.

Imported workloads are normalized to model-relevant fields before persistence. Application images become a non-executable placeholder; commands, environment values, and mounts are not retained. Kubernetes Secret objects are rejected. Labels and policy configuration are required model data and can still be organizationally sensitive. Kubeconfig and service-account tokens stay outside this repository and are never included in run exports.

The engineering contribution is the integrated **change → conditional consequence → scoped repair → reduced reproduction** workflow and its inspectable evidence. The constituent ideas are established techniques; no patent or world-first novelty claim is made. Read **[docs/RESEARCH.md](docs/RESEARCH.md)**, **[docs/SRS_COVERAGE.md](docs/SRS_COVERAGE.md)**, and **[docs/VALIDATION.md](docs/VALIDATION.md)** for sources, exact coverage, and release limits.
