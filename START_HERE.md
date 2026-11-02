# Start here — NetScope 1.2

This is a working local application with a real analysis backend, browser interface, immutable saved reviews, CLI, exports, and executable experiments. The original evaluator/review modules and their 151 tests are retained. Python 3.12 is recommended. No paid API, Node.js, cloud account, or Kubernetes cluster is needed for the static demonstration.

## Launch

Extract the updated ZIP into a fresh folder. Stop the old server with Ctrl+C and open Terminal inside the new `computer-network-main` folder:

```bash
python3.12 scripts/start.py
```

Open **http://127.0.0.1:8000** and check **v1.2.0** in the sidebar. Select a scenario and click **Run review**; history may restore an older saved report. Later launches can add `--skip-install`. Other platforms can use Python 3.10+ (`python3` or Windows `py`).

## What to show

1. **The indirect escape:** direct intent checks pass, but a declared gateway-relay assumption exposes an indirect database path. Inspect every hop; test removing the assumption or opening a scoped repair as a new review.
2. **A clean baseline → Experiments → Suggest missing checks:** four draft assertions raise detection from 8/14 to 14/14 training faults and 2/6 to 4/6 held-out faults. Verify on reference, export JSON, and explain that synthetic fault coverage is not analyzer accuracy.
3. **The indirect escape → label counterfactual:** choose `apps/agent`, set `app=payments`, and analyze. Twenty permissions change and the two-hop database path becomes direct. Unmatched intents stay INVALID. The saved parent is unchanged.
4. **The database switch → reducer:** inspect the broken/gained paths, reduce a witness from ten paired policies to one, and download its replay ZIP.
5. **The last policy disappears:** deletion removes isolation while all five existing intents still pass. **Connections** also lets you ask an exact query beyond the saved port grid and export a reusable assertion.

Eight scenarios cover these cases, alternate relay routes, AND/OR selectors, unsupported-policy Unknown, and a small independent-analyzer disagreement. See `docs/EXPERIMENTS.md` for explanation and `docs/DEMO_SCRIPT.md` for a speaking outline.

## Your remaining work, in one batch

Follow **[docs/FINALIZATION.md](docs/FINALIZATION.md)**. It covers fresh installation, exploration, the dedicated kind/Calico lab on your Mac, four sequential evidence runs, exports, and cleanup. Your Homebrew/Python/kind/kubectl/Docker installations can be reused.

The controlled Kubernetes runner is implemented, including protocol controls, node-placement recording, a baseline/candidate observation matrix, drift checks, cancellation, and cleanup. **Real Kubernetes/CNI enforcement was not executed in the build environment.** Run the checklist to obtain actual evidence on your Mac. Scripted worker tests and loopback sockets are explicitly not presented as CNI verification.

Build-workspace tests, actual Chromium workflows, prior performance measurements, and the retained independent-analyzer disagreement are documented in `docs/VALIDATION.md`. This is a working local project with an explicit real-cluster validation boundary.
