# Controlled Kubernetes lab

**The static application is working without this setup. Real CNI verification was not executed in the artifact-building environment.** The worker's sequencing, ownership checks, failure paths, and actual loopback probe program have automated tests; a scripted adapter is not CNI evidence.

## Prerequisites and setup

Use a machine with Docker running, kind, kubectl, Python, roughly 4 CPU cores, 8 GiB RAM available, and 10 GiB free disk. Docker Desktop is suitable on macOS/Windows when configured with enough resources. The bootstrap creates only `netscope-lab`; it refuses to adopt an existing cluster with that name.

After installing the Python project:

```bash
python scripts/lab.py up
python scripts/start.py --lab --skip-install
```

`lab.py up` chooses a digest-pinned Kubernetes 1.35.8 kind node image and versioned Calico v3.33.0, disables kind's default CNI, and uses the official Calico manifest. These versions are selected from the upstream release/support documentation, not claimed as a locally integration-tested combination. Overrides require editing and reviewing the constants in `scripts/lab.py`.

The script resolves the trusted fixture image digest, preloads the image, creates a separate runner service account, and stores its limited kubeconfig **outside the project** at `~/.netscope/lab-kubeconfig.json` (mode 0600). Its token is requested for eight hours; server policy can shorten this. Lab state/configuration is in `~/.netscope/lab.json`, also outside the repository. Do not commit those files. The `--lab` launcher loads this configuration into the server's process environment.

The role permits only namespace/Pod/NetworkPolicy lifecycle, fixture exec, and read-only CNI DaemonSet discovery; it cannot read Secrets or modify RBAC/CNI resources. Namespace/Pod privileges remain cluster-wide because imported namespace names are dynamic. Therefore the credential is for this disposable cluster only, with additional application ownership guards—not a production permission model.

## Run a confirmed plan

1. Open the dashboard and choose a supported demo.
2. Open **Evidence** and select the allowlisted runner context.
3. Preview the exact plan: cluster/server identity, hashes, tuple count, and mutations.
4. Type `RUN DISPOSABLE LAB` and start it. This confirms the exact plan hash; a stale plan is rejected.
5. Watch the saved job events. Download the resulting evidence JSON, including failures and leftovers. Cancel via the UI when needed; unfinished work remains incomplete.

CLI use with manually configured allowlisting is also possible:

```bash
export KUBECONFIG="$HOME/.netscope/lab-kubeconfig.json"
# Copy the actual context/server mapping from your local lab.json; do not use a guessed port.
export NETSCOPE_ALLOWED_CONTEXTS='{"netscope-lab-runner":"https://127.0.0.1:ACTUAL_PORT"}'
export NETSCOPE_FIXTURE_IMAGE='python@sha256:ACTUAL_RESOLVED_DIGEST'
netscope verify src/app/resources/examples/checkout-regression.json \
  --context netscope-lab-runner --allow-live --out artifacts/live.json
```

The dashboard requires explicit confirmation even when the environment allowlist is configured. The runner's default development image is a fixed Python tag; use the bootstrap's resolved digest for reproducible evidence. The evidence records requested and resolved image identity.

## Evidence and coverage

Initial live coverage is IPv4 Pod snapshots, TCP/UDP, and ports 1024–65535, with all required changed/intent tuples up to 300 per phase. Templates, external peers, SCTP/IPv6, low-port fixtures, Unknown decisions, or excess coverage produce an explicit rejection/incomplete result rather than sampling.

The runner:

- Verifies the exact context/server pair and records Kubernetes/CNI identity.
- Refuses reserved or pre-existing test namespaces, including leftovers from another run.
- Creates trusted non-root, non-privileged fixtures with original labels/names, no service-account token mount, resource limits, and no host mounts.
- Checks unrestricted planned connectivity and known allow/deny controls before verification.
- Applies each entire revision, including deletions, confirms API read-back, waits ten seconds, then makes three fresh attempts with two-second timeouts and one-second gaps, at most ten concurrent attempts.
- Checks controls and Pod/namespace/policy drift around batches. UDP requires a nonce-matched reply.
- Runs allow/deny controls for every planned transport protocol (with TCP health controls retained), records node names, and shows a baseline/candidate observation matrix for the exact plan. Missing observations remain `NOT_TESTED`. Cross-node counts describe observed placement and may be zero.
- Saves requested mutations before execution and partial results on failure. Cleanup has ownership/UID preconditions and waits for deletion; leftovers prevent successful completion.

A completed runtime job is evidence only for its recorded scope/environment. Model/runtime agreement does not waive a failed application intent or an unapproved semantic change. Timeouts do not prove policy causation.

The ten-minute test budget begins after fixtures are ready. Cluster setup/image downloads are separate. Actual enforcement settling, the 300-tuple timing bound, cross-node behaviour, and CNI version compatibility still require measurements on your machine.

## Stop and remove

```bash
python scripts/lab.py status
python scripts/lab.py down
```

`down` checks the owned lab state before deleting that dedicated kind cluster. It never deletes an arbitrary current context. If setup fails, it retains its owned-state record so you can remove the partial lab. A hard process crash may leave run-owned namespaces; inspect their `netscope.io/run-id` annotations or recreate the dedicated lab. Do not silently resume stale evidence.
