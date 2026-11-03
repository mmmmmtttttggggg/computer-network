# Validation evidence — NetScope 1.2

Release checkpoint: 1 November 2026. This file records tests actually executed in the build workspace. It does not turn scripted or loopback checks into Kubernetes enforcement evidence.

## Local follow-up run — 3 November 2026

On macOS arm64 with Python 3.13.0, the full suite passed **287/287**, including the TCP/UDP loopback fixture checks after running outside the socket-restricted sandbox. Ruff lint and formatting checks also passed. One Starlette/httpx deprecation warning remains. The exact result and environment are recorded in `artifacts/local-validation-2026-11-03.json`. This is an additional local result; it does not replace the release's Python 3.12 run or verify browser workflows.

The disposable-cluster checks could not be run. Docker CLI, kind, kubectl, and Colima were installed, but the container engine is not running; approval to start the Colima VM was rejected. Python 3.12 is also unavailable. No real-cluster, cross-node, or real API-server cleanup evidence was generated.

## Retained release 1.1 performance baseline

- Environment: `Linux-6.18.55-x86_64-with-glibc2.39`; Python `3.12.14`. Shared/containerized resources can vary.
- Scope: 30 endpoints, 5 namespaces, 100 policies per revision, 20 protocol/port combinations, **17,400 directed queries per revision**.
- Method: one warm-up, then twenty complete reviews. Includes input parsing/normalization, both policy evaluations, traces, semantic comparison, intent, and report construction. Excludes HTTP serialization/browser/cluster startup.
- Median: **3.72 seconds**. Maximum: **5.11 seconds**.
- Runs under the five-second target: **19 / 20**. This measurement does not establish an always-under-five-second guarantee.
- Process peak RSS during the script: **149.55 MiB** (not an isolated allocation measurement; excludes browser and cluster).

These are retained release 1.1 measurements, not a new 1.2 timing run. The evaluator and review modules are unchanged; see `artifacts/core-continuity.json`. Raw samples and methodology are retained in `artifacts/benchmark.json`. An earlier run made while browser/oracle work was also scheduled is retained as `artifacts/benchmark-contended.json` (median 5.87 seconds, 9/20 under five). Shared resources vary; both runs are retained rather than hiding the slower result. These measurements establish performance on this environment only.

## Automated and browser checks

All **287 automated tests pass**. The exact final test result is in `artifacts/test-results.txt`; all original 151 tests are retained. Added tests cover ingestion, external CIDR exclusions, mandatory intent expansion, Unknown/approval precedence, conditional paths, repair constraints, reducer replay/budgets, HTML escaping, local write protection, persistence/capacity, worker failures/ownership, and the actual trusted TCP/UDP socket program.

`artifacts/browser-results.json` records a real Chromium run at **1440, 1366, and 390 px**. It exercised the conditional path/evidence drawer, a repair opened as a new passing review, real reduced-ZIP download, mutation results, keyboard row inspection, invalid-input feedback, and all six views without horizontal page overflow. No JavaScript page errors were observed. The 1.2 run additionally generated and verified draft checks, downloaded their JSON, opened a label-edited review with a shorter direct asset path, evaluated/exported an out-of-grid connection check, and rendered an explicitly missing-observation matrix. That matrix check is presentation-only, not a live job. Browser screenshots were used for internal QA and are not shipped.

The current browser run also exercised refresh without duplicate history, the presenter guide, single-pivot counterfactuals with unchanged policy decisions, and the parallel-relay path surviving removal of one assumption. Added semantic checks cover alternate routes, direct paths, missing destination-port declarations, and finite-scope sensitivity.

## Independent static comparison

The retained release 1.1 NCA 2.1.0 run compared **5,472 decisions across 28 fixtures**: 5,471 agree; one cross-namespace `DoesNotExist` peer-selector disagreement is retained. Deletion reduces it to two Pods and one policy. Raw evidence, a replay command, controls, specification-based interpretation, and limitations are in `artifacts/oracle/` and `docs/ORACLE_CHECK.md`. This is bounded differential evidence, not universal correctness, certification, or live enforcement.

Ruff lint and formatting gates pass. A Starlette/httpx test-client deprecation warning is visible in the retained test log; it does not affect the passing HTTP assertions. The CI configuration is supplied, but no remote GitHub Actions execution is claimed.

New 1.2 tests cover training/holdout separation (including adversarial replacement of held-out decisions), exact check validation/Unknown/duplicates, immutable label forks and shared-query scope, zero-match intents, API write protection, deletion/additive/range cases, missing runtime coverage, node-placement recording, and UDP control orchestration.

## Feature demonstrations

- **Agent escape:** one newly allowed tuple; all five candidate direct intents pass; one conditional two-hop asset path under a declared gateway-pivot assumption. Removing the pivot assumption removes that indirect path without changing any policy decisions.
- **Parallel relay:** two newly allowed tuples; five candidate intents pass; removing one witness pivot still leaves an alternate two-hop asset path. The sensitivity result does not falsely claim containment.
- **Checkout regression:** exactly one newly allowed and one newly blocked database tuple; exactly two candidate intent failures.
- **Reducer:** the checkout witness reduces from ten paired policy identities to one (90%). Its before/after decisions, isolation flags, and candidate intent violation are preserved and verified by static replay. Raw bundle/proof/replay result are in `artifacts/examples/`. This is one inspectable demonstration, not a broad independent benchmark.
- **Repair:** at least one fully re-evaluated scoped proposal is found for checkout, selector-trap, and agent-escape scenarios. No proposal auto-deploys.
- **Mutation sensitivity:** 24 unique injected edits, 20 effective on the declared scope, 10 introducing a new intent failure. The uncaught cases intentionally expose gaps in the intent suite; these figures are not analyzer accuracy.

- **Suggested checks:** four drafts; training detection 8/14 → 14/14, held-out detection 2/6 → 4/6. Held-out faults are excluded from selection but use the same synthetic generator. Two remain undetected; these figures are not analyzer accuracy. Raw result/checks are in `artifacts/examples/draft-checks*`.
- **Label experiments:** setting the agent label to payments changes 20 permissions. On the agent-escape candidate, an existing two-hop path becomes direct; on the clean baseline, the asset pair is newly exposed. Invalid unmatched intents remain visible. Full comparisons and summary are in `artifacts/examples/label-*.json` and `artifacts/feature-evaluation.json`.
- **Deletion and independent disagreement:** final egress-policy deletion opens 18 permissions while five intents pass. The new cross-namespace scenario adds an explicit intent to the historical reduced disagreement so its one-connection live plan is executable. No CNI result is prefilled.

## Not verified here

- Real Kubernetes/CNI enforcement, cross-node behaviour, cancellation/cleanup against a real API server, and 300-live-tuple timing. Docker, kind, and kubectl were unavailable.
- The dedicated kind/Calico bootstrap and Docker image build. The source follows versioned upstream setup and records limitations; no fabricated deployment result is included.
- Firefox/Safari and non-Linux Python runtime installation. The package declares Python 3.10+, has a CI matrix, and was run on Python 3.12 here.
- Independent NP-Guard/Cyclonus differential conformance certification, the proposed larger ten-topology research study, universal least privilege, or patent novelty.

The release's working core is the local static application plus reproducible experiments and reports. The real-cluster path remains an explicit, separately verifiable next gate.
