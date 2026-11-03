# Five-minute presentation

Start with `python3 scripts/start.py`, open the dashboard, and select **The indirect escape**. Refresh restores the saved review; selecting a scenario and pressing Run review deliberately starts a new one.

| Time | Action | What to say |
|---|---|---|
| 0:00–0:45 | Overview: five passing direct intents, one new asset path. | “This reviews what a policy change permits. Direct checks can pass while an assumed application relay creates an indirect exposure.” |
| 0:45–1:45 | Containment lab: click the database hop, inspect ingress and egress. Open the single-relay counterfactual. | “Every edge has a policy trace. Removing the relay assumption removes this conditional path while leaving network decisions unchanged.” |
| 1:45–2:30 | Load **The parallel relay**; remove one relay assumption. | “The tool searches again. Another gateway still reaches the asset, so deleting the first visible explanation is insufficient.” |
| 2:30–3:30 | Load the agent example; Experiments → scoped repair → open proposal. | “These are small baseline reverts, checked against every declared query, intent, and baseline asset-pair constraint. They are proposals, never automatic deployments.” |
| 3:30–4:30 | Load **The database switch**; reduce a changed tuple and download the replay ZIP. | “Ten policy identities reduce to one while preserving this particular before/after decision and intent violation. The bundle can be replayed.” |
| 4:30–5:00 | Evidence → exports. | “Results include inputs, hashes, traces, assumptions, and test scope. Static permission and actual enforcement are separate claims.” |

For a shorter demo, show the first three rows and export the HTML report. For extra time, use the clean baseline's fault-injection lab: uncaught effective mutations reveal missing intents, not necessarily an analyzer defect.

## Likely questions

**What is distinctive?** The combined workflow: conditional agent/tool exposure, assumption sensitivity with alternate-route search, constrained repairs, and a compact replayable regression. Graph search and semantic diff themselves are established techniques.

**Is this a real exploit?** No. The entrypoint is assumed compromised and listed pivots are assumed capable of relaying. Authentication, credentials, RBAC escalation, prompt injection, and CVEs are outside this model.

**Why retain a path if a port is undeclared?** NetworkPolicy permission does not depend on declaring a numeric `containerPort`. A declaration also does not prove a listener is running. The evidence labels this distinction explicitly.

**How did you check correctness?** Existing semantic tests, additional properties/scenarios, browser workflows, and a separate NCA comparison. Of 5,472 finite comparisons, one cross-namespace selector disagreement is retained with a reduced reproducer and controls. This is not universal conformance.

**What remains?** Real Kubernetes/CNI adjudication and replay, broader representative studies, and cross-browser testing. The controlled runner is included, but no live-enforcement result is claimed from this environment.

## Optional release 1.2 extension (two minutes)

Show the clean baseline’s suggested checks: four drafts improve training and held-out fault detection, while two held-out faults still escape. Explain that expected behavior is reviewed reference behavior. Then run the agent label counterfactual: losing egress selection and gaining a trusted database peer match turns the two-hop path into a direct one. Agent intents become INVALID rather than silently passing. `docs/EXPERIMENTS.md` has the exact claims; `docs/LIVE_LAB.md` explains how to collect live evidence.
