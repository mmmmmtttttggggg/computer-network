# Release 1.2.1: live runner resource fix

Bound probe execs to two per source Pod within the ten-worker global limit. Increase trusted fixture memory limits from 64 MiB to 128 MiB and CPU limits from 250m to 500m. Waiting work observes cancellation and the existing test budget; full planned query coverage is retained.

Record execution settings and concrete Pod, policy and namespace drift details. Handle fixture SIGTERM explicitly, publish namespace cleanup progress, and show pending exit codes during active work. Ownership/UID cleanup guards and conservative inconclusive verdicts remain in place. The current dashboard styling, Examples and Guide pages are preserved.

Add overload, cross-source parallelism, queued cancellation/deadline, failed-fixture, cleanup, full-plan and graceful-termination regression coverage, plus browser checks for active/cleanup/final job presentation. Real Kubernetes rerun evidence remains a separate gate.

# Release 1.2 finalization

Added regression-check suggestions with deterministic training/holdout separation, reference verification, reusable JSON assertions, CLI checking, and explicit synthetic-coverage limitations. Added a candidate query composer for exact tuples outside the saved port grid.

Added immutable Pod-label counterfactuals explaining policy selection, isolation, permission changes, new asset pairs, shorter existing asset paths, and zero-match intents. Added last-policy-deletion and live-ready cross-namespace disagreement scenarios.

Live evidence now records actual node assignments, protocol-specific UDP controls, and a per-connection baseline/candidate matrix with attempted/conclusive coverage. Missing observations never count as verified connections. Added automated/API/browser workflows, updated exports and wheel, and one Mac finalization checklist. Real Kubernetes/CNI execution remains pending on the user's machine.

# Release 1.1 refinements

Added per-witness relay-assumption sensitivity: remove one pivot, search all remaining routes in scope, and expose whether an alternate asset path survives. Counterfactual buttons open new immutable reviews. Destination-port declarations are reported separately from listener evidence. Standalone HTML includes these results.

Added the parallel-relay scenario, an on-screen presentation guide, a short speaking script, and saved-review restoration on refresh. Deleting the selected review switches to a valid saved review instead of leaving broken export links. Report timing now includes containment analysis; graphs are not built for inputs without entrypoints.

Added a separately installed NCA 2.1.0 oracle harness. It compared 5,472 decisions across 28 finite fixtures and retains one cross-namespace selector disagreement with reduced inputs and controls. No claim of full agreement or real-CNI verification is made. Extended browser and regression checks cover the new workflows.

Updated the wheel, examples, exports, source manifest, documentation, and measured validation evidence.

# Release 1.0 changes from the supplied prototype

The supplied ZIP contained a selector engine, topology model, NetworkPolicy evaluator, semantic comparison/approval/intent modules, and 151 tests. These modules were used as the starting point; they were not replaced with a disconnected demo.

Added the complete project-ingestion/application/CLI/HTTP/reporting path, local persistence, six-view presentation UI, external-IP exception evaluation, unsupported host-network handling, and a target-selection cache. Existing tests continue to validate the original core behaviour.

Added conditional agent-containment paths and blast-radius comparison, constrained policy-revert experiments, paired-policy reduction with a portable replay verifier, and a controlled mutation-sensitivity lab. Five input scenarios make these features reproducible and explainable.

Added a real-cluster adapter, trusted probe program, conservative observation verdicts, control-flow/failure tests, dedicated kind/Calico bootstrap, limited runner identity, exact server allowlisting, cancellation, mutation journaling, and UID-precondition cleanup. Real CNI integration is intentionally still labelled unverified until run on a Docker-enabled machine.

Added dependency resolution, packaging, one-command launch, CI configuration, source-format/lint gates, browser workflow checks, actual reference performance measurement, generated reports/replay examples, a presentation walkthrough, research references, and an explicit SRS coverage table.

The design's larger independent benchmark, cross-browser verification, and production hardening remain separate work; they are not represented as completed in release evidence.
