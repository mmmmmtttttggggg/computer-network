# NetScope

NetScope reviews a Kubernetes NetworkPolicy change before it is deployed. It compares the policies before and after the change, shows every connection that opens or closes, checks your expected rules (intents), and finds indirect paths a compromised workload could use to reach a sensitive service.

It runs entirely on your machine as a local web dashboard and a command-line tool. No cluster, cloud account or API key is needed.

## Requirements

- Python 3.10 or newer (3.12 recommended)
- Docker, kind and kubectl only for the optional live-cluster check

## Quick start

From the project folder:

```bash
python3 scripts/start.py
```

Open **http://127.0.0.1:8000**. On Windows use `py scripts/start.py`.

The launcher creates a virtual environment in `.venv`, installs the pinned dependencies and starts the server. Later starts can skip installation with `--skip-install`. Use `--port 8001` if port 8000 is busy. Stop the server with Ctrl+C.

### Manual installation

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.lock
pip install -e .
netscope serve
```

## Using the dashboard

1. Pick a scenario in the bar at the top of the page and click **Run review**.
2. Read the **Overview**: changed connections, passing intents, paths to sensitive assets and the overall result.
3. Click any connection to see the exact policies and rules that decided it.
4. Use **Experiments** to shrink a regression or search for a repair.

The **Guide** page in the dashboard explains every page and term, and **How this page works** in the top bar opens the relevant section. The **Examples** page has eight ready-made scenarios and a five-minute walkthrough.

To review your own policies, open **Inputs & history** and load a JSON or YAML project file. The format is described in [docs/PROJECT_FORMAT.md](docs/PROJECT_FORMAT.md), and the files in `src/app/resources/examples/` are complete templates.

## Features

| Page | What it does |
|---|---|
| Overview | Summary of the review, the main finding, a connectivity map and the list of changed connections. |
| Examples | Eight scenarios, each showing one idea, plus a guided walkthrough. |
| Connections | Every checked connection under both revisions, with search, filters and a rule-by-rule explanation of each decision. Lets you check a new connection and export it as a test. |
| Containment | Paths from an assumed-compromised workload (for example an AI agent) to sensitive assets through declared relays, up to four hops. Test whether a path depends on a relay. |
| Experiments | Shrink a regression to the fewest policies that reproduce it, search for small policy repairs, inject policy faults to measure your intents, draft missing checks and test label changes. |
| Evidence | Input fingerprint, analysis details and an optional plan for checking results on a disposable kind/Calico cluster. |
| Inputs & history | Edit or upload a project, and reopen or delete saved reviews. |
| Guide | In-app help for every page, the terms used and the command line. |

Every review is saved locally and can be exported as JSON or as a standalone HTML report.

## Command line

The same analysis is available from the terminal:

| Command | Purpose |
|---|---|
| `netscope serve` | Start the dashboard |
| `netscope review project.json` | Review a change and export the report |
| `netscope repair project.json` | Search for policy repairs |
| `netscope reduce project.json --tuple-id ID` | Shrink a regression to one connection and export a replay bundle |
| `netscope replay project.yaml preservation.json` | Verify a replay bundle |
| `netscope mutate project.json` | Inject policy faults |
| `netscope suggest-checks project.json` | Draft checks for faults the intents miss |
| `netscope check project.json checks.json` | Run exported checks |
| `netscope labels project.json --endpoint ns/pod --labels '{...}'` | Test a label change |
| `netscope demo --out artifacts/demo` | Export reports for all examples |

`review` and `check` exit with **0** for a pass, **1** for a failure and **2** when the result is incomplete, so they can be used in CI.

## Development

```bash
pip install -e '.[dev]'
pytest -q
ruff check src tests scripts
ruff format --check src tests scripts
```

Browser tests:

```bash
pip install -e '.[dev,browser]'
python -m playwright install chromium
python scripts/browser_smoke.py
```

GitHub Actions runs the tests on Python 3.10 and 3.12 and the browser tests on every push.

## Live-cluster check (optional)

NetScope's results come from a static model of NetworkPolicy. To compare them with real enforcement, start a disposable kind cluster with Calico and launch the dashboard with lab access:

```bash
python3 scripts/lab.py up
python3 scripts/start.py --lab --skip-install
python3 scripts/lab.py down        # when finished
```

Then open **Evidence** and follow the on-screen steps. Only the dedicated lab cluster is ever targeted. See [docs/LIVE_LAB.md](docs/LIVE_LAB.md) for details.

## Limits

- Allow means NetworkPolicy permits the traffic, not that a service is listening or that access is safe.
- Policies the model cannot read produce Unknown results, which are never counted as Deny.
- Inputs are limited to 30 workloads, 5 namespaces and 100 policies per revision.
- RBAC, application authentication and software vulnerabilities are out of scope.
- The dashboard listens on localhost by default. Kubernetes Secrets are rejected, and container commands and environment values are not stored.

## Project structure

```text
src/app/
  model/       NetworkPolicy evaluation and selectors
  review/      Revision comparison, approvals and intents
  ingest/      JSON/YAML loading and validation
  analysis/    Containment paths, reduction, repair, fault injection
  runtime/     Live-cluster verification
  web/         FastAPI server and dashboard
  resources/   Example projects
  cli.py       Command-line interface
scripts/       Launcher, browser tests, benchmark, lab setup
tests/         Test suite
docs/          Detailed documentation
```

## Documentation

- [docs/PROJECT_FORMAT.md](docs/PROJECT_FORMAT.md): input file format
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how the system is built
- [docs/EXPERIMENTS.md](docs/EXPERIMENTS.md): the experiments and their expected results
- [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md): a presentation script
- [docs/LIVE_LAB.md](docs/LIVE_LAB.md): live-cluster setup
- [docs/VALIDATION.md](docs/VALIDATION.md): test and validation results
