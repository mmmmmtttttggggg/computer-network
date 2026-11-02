# SRS / design coverage for release 1.1

The original documents remain design/requirements baselines. This table describes software evidence rather than silently changing those documents.

| Requirement | Release implementation | Evidence / remaining boundary |
|---|---|---|
| FR-01 Import/validate | Strict bounded YAML/JSON, resource lists, duplicate/schema/port/selector checks, excluded topology kinds, influencing unsupported policy → Unknown. | Input/HTTP tests. Namespace/Pod/Deployment subset; no general Kubernetes schema validator. Secret objects rejected; execution data stripped. |
| FR-02 Twin | Original core extended with external IP/CIDR exceptions, host-network Unknown, target-selection cache, stable tuple IDs. | Original tests plus reviewed scenarios/properties. Fixed finite scope; templates are logical endpoints. |
| FR-03 Compare | Known semantic changes and Unknown classification; exact tuple/direction approvals. | Comparison tests; equivalent reorder test. |
| FR-04 Intent | Both revisions, new/existing/fixed failures, conflict/zero-match/Unknown, mandatory expansion. | Intent and application tests. Candidate gate remains separate from conditional exposure findings. |
| FR-05 Explain | Both directional traces, selected policies/rules, labels, declared ports, raw policy source. | Browser evidence drawer and HTML/JSON exports. No unique-cause claim. |
| FR-06 Prepare live | Exact context/server allowlist, plan hash confirmation, exclusive/reserved namespace checks, trusted fixtures, controls. | Worker scripted-adapter tests; **real cluster integration unverified**. |
| FR-07 Probe both revisions | Full policy-set reconcile/read-back, same Pods, changed/intent plan, no sampling. | Trusted TCP/UDP program tested on actual loopback sockets. Real CNI tests outstanding; runtime subset below. |
| FR-08 Interpret | Agreement, unexpected reachability, observed unreachability, inconclusive errors/controls/drift. | Conservative verdict tests. No timeout-as-causation claim. |
| FR-09 Evidence | Normalized/revision/plan hashes, tool/Kubernetes/CNI identity, actual Pod UIDs/IPs, image IDs, attempts, timestamps. | Persistence and worker tests. CNI runtime identity collected when available; real evidence still must be generated. |
| FR-10 Inspect/export | Six-view dashboard, filtered table/map, explanations, JSON/HTML, local run history. | Automated browser/API/packaged-resource checks. Map selects up to 24 important paths; table holds full scope. |
| FR-11 Failure/cleanup | Partial live jobs, cancel, restart interruption, requested mutation log, ownership/UID-precondition cleanup, leftovers. | Scripted failures and restart tests. Hard-kill cleanup cannot be guaranteed; manual owned-lab inspection may be needed. |
| S-01–06 Semantics | Directional isolation, selector/peer composition, rule union, ports/defaults/ranges, external CIDR exceptions. | Existing and extended semantic suite. Pod/IP-block NAT and unsupported influencing constructs remain Unknown. |
| UI-01 / IF-01–02 | Inspectable project input, filters, progress/cancel, same CLI/service, versioned reports, exits 0/1/2. | Browser, HTTP, CLI tests; incomplete exit precedence. |
| AT-01–04, AT-07 | Static examples and semantic/intent/export tests implemented. | Reviewed scenario expectations and original tests. |
| AT-05, AT-06, AT-08 | Worker/control/error logic implemented and scripted-adapter tested. | **Full real Kubernetes/CNI acceptance pending**, including a fixed candidate, drift, failed controls, and cleanup on an actual cluster. |
| D-EXT-01 Reduction | Deterministic completed paired-identity search; witness signature; bundle; static replay; budget labels. | Ten→one policy identity on the supplied checkout demonstration. No global minimum or full-study claim. |

## Non-functional boundaries

- **Correctness:** original 151 tests retained, extended reviewed scenarios/metamorphic checks, and an independent 5,472-decision NCA comparison with one retained disagreement. See `ORACLE_CHECK.md`; no complete Kubernetes conformance or independent certification claim.
- **Responsiveness/memory:** see the actual 20-run reference measurement in `artifacts/benchmark.json`; thresholds are not guaranteed on arbitrary hardware. Browser interaction time has not been statistically benchmarked.
- **Live timing:** ten-minute job budget implemented after fixture readiness; 300-tuples/phase real-cluster performance is unmeasured.
- **Security:** local write token/Origin/Host checks; escaped outputs; no imported execution; limited lab identity. Production multi-user deployment is outside release scope. Image digest resolution happens in local lab setup.
- **Durability/capacity:** atomic snapshot files, transactional references, restart interruption, explicit 100-review/1-GiB quota. No automatic retention deletion; storage failure is not acknowledged as success.
- **Usability:** real Chromium tests at 1440/1366/390 px, keyboard connection inspection, status text. Firefox and Safari have not been validated here.
- **Reproducibility:** runtime dependency resolution, versioned lab setup, source examples, tests, exports, and measured benchmark. Lab images still require a first download; installed static features have no external-service dependency.

## Explicit release limitations

Live verification: IPv4 Pod snapshots / TCP / UDP / destination ports ≥1024 / ≤300 required tuples per phase. Templates, external peers, SCTP/IPv6, low-port fixtures, unsupported influencing resources, and larger plans cannot get complete live coverage.

Conditional containment is bounded reachability under user-declared relay/compromise assumptions, not exploitability. Repairs are bounded baseline reverts, not arbitrary deny-policy synthesis. Reduction preserves a selected witness only. The design's proposed ten-topology mutation/replay study and 90% live-replay target have **not** been completed; the shipped intent-sensitivity experiment is a smaller demonstration.
