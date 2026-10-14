# Kubernetes NetworkPolicy Digital Twin and Regression Tester

A Python-based tool for modeling Kubernetes NetworkPolicy behavior, comparing policy revisions, and detecting network connectivity regressions before deployment.

## 1. Overview

Kubernetes NetworkPolicies control communication between Pods through ingress and egress rules. Changes to these policies can unintentionally expose services or block legitimate communication.

The **Kubernetes NetworkPolicy Digital Twin and Regression Tester** aims to simulate policy behavior, compare a baseline configuration with a candidate configuration, and identify potentially unsafe changes before deployment.

The project follows a model-based approach: it evaluates connectivity using a representation of the Kubernetes environment and provides explicit `Allow`, `Deny`, or `Unknown` decisions. The planned runtime verification component will compare these predictions with observed connectivity in a disposable Kubernetes cluster.

## 2. Current Status

**Core policy evaluation and regression-review modules are implemented and tested.**

- Topology model for representing namespaces and Pods.
- Kubernetes label selector matching.
- NetworkPolicy evaluation for ingress and egress.
- Baseline-versus-candidate policy comparison.
- Connectivity intent validation using `must_allow` and `must_deny`.
- Approval checks and detection of existing and newly introduced violations.
- Unit test suite: **151 tests passing**.

Input ingestion, CLI integration, runtime verification, reporting, and the web interface remain planned work.

## 3. Key Features

### Implemented

- **Topology Modeling:** Represents the Pods, namespaces, and labels used during policy evaluation.
- **Selector Evaluation:** Supports label matching and selector expressions, including `In`, `NotIn`, `Exists`, and `DoesNotExist`.
- **Ingress and Egress Evaluation:** Models isolation and additive allow rules.
- **Protocol and Port Handling:** Supports TCP, UDP, SCTP, numeric ports, named ports, and port ranges within the implemented evaluator.
- **Three-Valued Decisions:** Uses `Allow`, `Deny`, and `Unknown` to avoid treating unresolved cases as definite results.
- **Regression Detection:** Identifies newly allowed, newly blocked, unchanged, and unknown connectivity decisions.
- **Intent Validation:** Checks whether required and forbidden connections satisfy their expected behavior.
- **Approval Validation:** Checks approvals against the relevant changes without allowing an approval to override an intent violation.

### Planned

- YAML input loading and validation.
- Command-line interface (CLI).
- Detailed policy explanations and provenance.
- JSON and HTML reports.
- Runtime connectivity testing in a disposable Kubernetes cluster.
- Comparison of simulated and observed network behavior.
- Persistent evidence and revision traceability.
- FastAPI-based web interface.
- Policy reduction while preserving a selected regression.
- Integration testing and final acceptance validation.

## 4. How It Works

The intended workflow is:

1. Load the topology, baseline policies, candidate policies, and connectivity intents.
2. Validate the input configurations.
3. Evaluate connectivity under the baseline policies.
4. Evaluate connectivity under the candidate policies.
5. Compare the two sets of decisions.
6. Check required and forbidden connections and identify violations.
7. Run runtime connectivity tests in a disposable Kubernetes environment.
8. Compare predicted and observed behavior.
9. Generate reports and retain evidence for review.

The input-loading, orchestration, runtime-testing, and reporting stages are part of the planned end-to-end workflow.

## 5. NetworkPolicy Evaluation Model

For a connection represented as:

`q = (source, destination, protocol, port)`

the evaluator determines whether communication is allowed, denied, or unknown.

When both Pods are covered by the relevant policy isolation rules, communication must be permitted by both directions:

`Allowed = Source Egress Allowed AND Destination Ingress Allowed`

If a direction is not isolated, it does not impose a NetworkPolicy restriction in that direction.

The evaluator uses `Unknown` when the available model cannot establish a reliable decision. For example, IP-block matching against Pods cannot always be resolved when the topology lacks the necessary IP information.

## 6. Regression Classification

The comparison module classifies changes between baseline and candidate revisions.

| Classification | Meaning |
|---|---|
| `NEWLY_ALLOWED` | A previously denied connection becomes allowed. |
| `NEWLY_BLOCKED` | A previously allowed connection becomes denied. |
| `UNCHANGED` | The known connectivity decision remains the same. |
| `UNKNOWN` | A reliable comparison cannot be established. |

A newly allowed connection may indicate an unintended exposure, while a newly blocked connection may indicate a service disruption. The significance of each change depends on the connectivity intents and review requirements.

## 7. Connectivity Intents

Intents express the expected behavior of network connections.

- `must_allow`: the specified connection must be permitted.
- `must_deny`: the specified connection must be blocked.

The review module checks these expectations, detects conflicting or invalid intents, and distinguishes existing violations from newly introduced violations.

Approvals are evaluated separately from intent compliance. Approving a change does not automatically make a failed connectivity requirement pass.

## 8. Project Structure

The current core implementation is organized as follows:

```text
computer-network/
├── src/
│   └── app/
│       ├── model/
│       │   ├── topology.py
│       │   ├── selectors.py
│       │   └── evaluator.py
│       └── review/
│           ├── comparison.py
│           └── intents.py
├── tests/
│   ├── test_selectors.py
│   ├── test_evaluator.py
│   └── test_review.py
├── pyproject.toml
└── README.md
```

The structure above documents the current core modules and tests. Additional directories and files will be introduced as the CLI, input handling, runtime testing, and reporting components are implemented.

## 9. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| pytest | Unit and integration testing |
| Kubernetes NetworkPolicy concepts | Policy semantics and connectivity modeling |
| FastAPI | Planned web application backend |
| SQLite | Planned evidence and result storage |
| kind and Calico | Planned disposable Kubernetes runtime-testing environment |

The runtime-testing environment and web application are planned components, not prerequisites for running the current unit tests.

## 10. Setup and Testing

### Prerequisites

- Python 3.12 or a compatible Python version.
- Git.
- A terminal such as PowerShell.

### Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd computer-network
```

Replace `<YOUR_REPOSITORY_URL>` with the repository's actual Git URL.

### Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Install the project

```powershell
python -m pip install -e .
```

If your development dependencies are configured as an optional extra in `pyproject.toml`, install that extra as well. Otherwise, install pytest if it is not already available.

### Run the test suite

```powershell
python -m pytest -v
```

To run individual test modules:

```powershell
python -m pytest tests/test_selectors.py -v
python -m pytest tests/test_evaluator.py -v
python -m pytest tests/test_review.py -v
```

**Current verified result:** 151 tests passed in the full test suite.

The test count reflects the current committed development checkpoint and may change as more functionality and tests are added.

## 11. Limitations

- The complete end-to-end workflow is not yet integrated.
- YAML ingestion and CLI orchestration remain to be implemented.
- Runtime behavior has not yet been verified by the planned Kubernetes probe component.
- Some policy constructs require information that is not yet represented in the topology model; these cases may return `Unknown`.
- Reports, persistent evidence, and the web interface are not yet complete.

The project should not be treated as a replacement for runtime enforcement or as proof of cluster security until the planned validation and runtime-testing components are implemented and tested.

## 12. Future Work

Development will proceed incrementally:

1. Implement YAML loading and validation.
2. Integrate the existing modules through a CLI.
3. Add policy explanations and structured reports.
4. Implement runtime connectivity probes in a disposable Kubernetes cluster.
5. Compare model predictions with observed behavior.
6. Add evidence storage and revision traceability.
7. Develop the FastAPI-based web interface and CI integration.
8. Implement policy reduction and complete integration and acceptance testing.

## 13. Project Goal

The goal is to provide a reproducible workflow for evaluating Kubernetes NetworkPolicy changes, detecting connectivity regressions, checking explicit network access requirements, and validating predicted behavior against actual network observations.

The final system aims to help developers identify unintended network exposure and service disruption before changes are accepted or deployed.
