**Zelyo is an autonomous AI security agent for Kubernetes that detects, correlates, and fixes misconfigurations — so your team doesn't have to.**

<p align="center">
  <img src="assets/logo.png" alt="Zelyo" width="180" />
</p>

<h1 align="center">Zelyo Operator</h1>

<p align="center">
  <strong>Autonomous AI Security Agent for Kubernetes</strong><br/>
  <sub>Others detect. Zelyo detects AND fixes. Scans misconfigurations across 7 security layers, correlates signals with AI, and auto-generates confidence-scored GitOps PRs.</sub>
</p>

<p align="center">
  <a href="https://github.com/zelyo-ai/zelyo-operator/actions/workflows/ci.yml"><img src="https://github.com/zelyo-ai/zelyo-operator/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/zelyo-ai/zelyo-operator/releases"><img src="https://img.shields.io/github/v/release/zelyo-ai/zelyo-operator?style=flat-square&color=00c9a7" alt="Release" /></a>
  <a href="https://goreportcard.com/report/github.com/zelyo-ai/zelyo-operator"><img src="https://goreportcard.com/badge/github.com/zelyo-ai/zelyo-operator" alt="Go Report Card" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License" /></a>
  <a href="https://artifacthub.io/packages/helm/zelyo-ai/zelyo-operator"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/zelyo-operator&style=flat-square" alt="Artifact Hub" /></a>
</p>

<p align="center">
  <a href="https://github.com/zelyo-ai/zelyo/actions/workflows/ci.yml"><img src="https://github.com/zelyo-ai/zelyo/actions/workflows/ci.yml/badge.svg" alt="CI status" /></a>
  <a href="https://codecov.io/gh/zelyo-ai/zelyo"><img src="https://img.shields.io/codecov/c/github/zelyo-ai/zelyo?style=flat-square" alt="Coverage" /></a>
  <a href="https://github.com/zelyo-ai/zelyo/stargazers"><img src="https://img.shields.io/github/stars/zelyo-ai/zelyo?style=flat-square" alt="Stars" /></a>
  <a href="https://github.com/zelyo-ai/zelyo/releases"><img src="https://img.shields.io/github/v/release/zelyo-ai/zelyo?style=flat-square" alt="Release" /></a>
  <a href="https://goreportcard.com/report/github.com/zelyo-ai/zelyo"><img src="https://goreportcard.com/badge/github.com/zelyo-ai/zelyo" alt="Go Report Card" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License" /></a>
  <a href="https://artifacthub.io/packages/helm/zelyo-ai/zelyo"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/zelyo&style=flat-square" alt="Artifact Hub" /></a>
  <a href="https://zelyo-ai.github.io/zelyo-operator/quickstart/">📖 Quick Start</a> &nbsp;·&nbsp;
  <a href="https://zelyo-ai.github.io/zelyo-operator/">📚 Documentation</a> &nbsp;·&nbsp;
  <a href="https://github.com/zelyo-ai/zelyo-operator/issues/new?template=bug_report.md">🐛 Report Bug</a> &nbsp;·&nbsp;
  <a href="https://github.com/zelyo-ai/zelyo-operator/issues/new?template=feature_request.md">✨ Request Feature</a>
</p>

---

## 🧠 What is Zelyo?

**Zelyo** is an **autonomous AI security agent for Kubernetes**. It doesn't just alert — it **detects**, **correlates**, and **fixes**, continuously protecting your production clusters while you sleep. Non-destructive by design. Production-safe by default. Every decision logged and auditable.

### Key Features
- 🔒 **Continuous Security Scanning**: 8 scanners across Identity, Posture, Runtime, Network, Workload, Data, and Compliance layers.
- 🧠 **AI-Powered Threat Correlation**: Connects signals across layers — overprivileged role + exposed service = attack chain.
- 🔧 **Automated Remediation**: Auto-generates code fixes as GitOps PRs with confidence scores. Every fix is a PR. Every decision is logged.
- 📋 **Compliance-Grade Evidence**: Maps findings to SOC 2, PCI-DSS, HIPAA, NIST 800-53, and CIS Benchmarks with audit trail.
- 🛡️ **Production-Safe by Default**: Read-only cluster access. Non-destructive by design.

## Use Cases

- 🔒 **Reduce alert-to-fix time**: From hours of SOC triage to minutes of automated detection, correlation, and remediation.
- 🤖 **Automate Tier-1 SOC triage**: Let Zelyo handle security posture violations so your team focuses on real threats.
- 🔧 **GitOps-native remediation**: Auto-generates production-ready YAML patches and opens PRs — no live-system changes.
- 🛡️ **Continuous compliance**: Never let a drifted permission, exposed secret, or vulnerable image go unaddressed.

That's Zelyo. All automated, all autonomous, all with **read-only cluster access**. Production-safe by default.

---

## ⚡ Key Capabilities

<table>
<tr>
<td width="50%">

### 🔒 Security Scanning
Continuously scans for RBAC issues, image CVEs, PodSecurity violations, secrets exposure, and network policy gaps.

### 🧠 Anomaly Detection
Builds σ-deviation baselines for pod restarts, resource usage, and error rates — detects anomalies without static thresholds.

### 🔄 Drift Detection
Compares live cluster state against your Git repo, identifying shadow resources and ClickOps changes.

### 💰 Cost Optimization
Detects idle workloads, recommends rightsizing, and assesses spot-instance readiness.

</td>
<td width="50%">

### 🛡️ Compliance Auditing
Maps scan findings to CIS Kubernetes Benchmark controls, generates audit-ready reports with evidence.

### 🔗 Incident Correlation
Groups related events within time windows into unified incidents for LLM diagnosis — no more alert fatigue.

### 🤖 Auto-Remediation
LLM generates structured JSON fix plans, validates them, and opens GitOps PRs with risk scores.

### 📢 On-Call Notifications
Routes alerts to Slack, Teams, PagerDuty, Telegram, WhatsApp, and webhooks with severity filtering and deduplication.

</td>
</tr>
</table>

---

## 🔁 The Agentic Pipeline: Detect → Correlate → Fix

Unlike traditional scanning tools that dump findings and walk away, Zelyo operates as a **closed-loop autonomous security agent**:

```mermaid
graph LR
    accTitle: Kubernetes security agent reconciliation loop diagram
    accDescr: The agentic pipeline showing how Zelyo detects, correlates, and fixes autonomously
    SP["SecurityPolicy<br/>Scanner"] -->|findings| C["Correlator<br/>Engine"]
    MP["MonitoringPolicy<br/>Observer"] -->|pod metrics| AD["Anomaly<br/>Detector"]
    AD -->|σ-deviations| C
    CS["ClusterScan<br/>Scheduler"] -->|findings| CF["Compliance<br/>Framework"]
    CF -->|CIS report| C
    C -->|incidents| RP["Remediation<br/>Policy"]
    RP -->|finding| RE["LLM<br/>Reasoner"]
    RE -->|JSON fix plan| GH["GitHub<br/>Engine"]
    GH -->|Pull Request| REPO["Your GitOps<br/>Repo"]
    REPO -->|merged| ARGO["ArgoCD/Flux"]
    ARGO -->|applied| K8S["Cluster"]
```

1. **Detect** — SecurityPolicy scans pods across 7 security layers, MonitoringPolicy watches for anomalies, ClusterScan evaluates compliance
2. **Correlate** — The correlator engine groups related signals within a 5-minute window into unified security findings (e.g., overprivileged role + exposed pod = lateral movement risk)
3. **Reason** — The LLM analyzes the finding with full context and generates a confidence-scored JSON fix plan
4. **Fix** — The remediation engine validates the plan, and the GitHub engine opens a production-safe PR with the fix
5. **Report** — Compliance-grade evidence, Kubernetes events, and Prometheus metrics flow to your dashboards

---

## 🎯 Dual Operating Modes

| Mode | When | Behavior |
|:---:|---|---|
| 🔍 **Audit Mode** *(default)* | No GitOps repo onboarded | Detects, correlates, and alerts — your always-on security scanner |
| 🛡️ **Protect Mode** | GitOps repo onboarded | Full autonomous remediation — your autonomous remediation agent |

---

## 🏗️ Architecture

```mermaid
graph TB
    accTitle: Kubernetes security agent architecture diagram
    accDescr: High-level system architecture of the Zelyo AI Security Agent
    subgraph "Kubernetes Cluster — Read-Only Access"
        Events[K8s Events]
        Logs[Pod Logs]
        Nodes[Node Conditions]
        Net[Network Telemetry]
        Metrics[Resource Metrics]
    end

    subgraph "Zelyo — AI Security Agent"
        subgraph "Observe"
            Watcher[Real-Time Watcher]
            Scanner[Security Scanner]
            CostEng[Cost Optimizer]
        end
        subgraph "Reason"
            AnomalyDet[Anomaly Detector<br/>σ-deviation baselines]
            Correlator[Incident Correlator<br/>time-window grouping]
            Compliance[Compliance Engine<br/>CIS/NIST/SOC2]
            DriftDet[Live Drift Detector<br/>cluster vs Git]
            LLM[LLM Reasoner<br/>structured JSON output]
        end
        subgraph "Act"
            Remediation[Remediation Engine<br/>risk-scored fix plans]
            GitOps[GitHub App Engine<br/>JWT auth, PR lifecycle]
            Notify[Notifier<br/>dedup + rate limit]
        end
    end

    subgraph "Integrations"
        GitRepo[Your GitOps Repo]
        Alerts[Slack · Teams · PagerDuty<br/>Telegram · WhatsApp]
        Prom[Prometheus · Grafana]
        ArgoFlux[ArgoCD / Flux]
    end

    Events & Logs & Nodes & Net & Metrics --> Watcher
    Watcher --> AnomalyDet & Scanner & CostEng
    Scanner --> DriftDet & Compliance
    AnomalyDet & Scanner & CostEng & DriftDet & Compliance --> Correlator
    Correlator --> LLM
    LLM --> Remediation
    Remediation -->|Protect Mode| GitOps
    Remediation -->|Audit Mode| Notify
    GitOps --> GitRepo
    GitRepo --> ArgoFlux
    Notify --> Alerts
    Watcher --> Prom
```

---

## Installation

*Dive right in using these exact copy-paste install commands.*

### Install via Helm (OCI)

```bash
# Add your LLM API key as a Kubernetes secret
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_OPENROUTER_API_KEY>

# Install cert-manager (takes ~1m)
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.20.0 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

# Wait for cert-manager to be ready before installing the operator
kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=120s

# Install Zelyo Operator from OCI registry
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set config.llm.apiKeySecret=zelyo-llm \
  --set webhook.certManager.enabled=true

# Verify the installation
kubectl get pods -n zelyo-system
```

## Quickstart

### Verify Image Signature

```bash
cosign verify ghcr.io/zelyo-ai/zelyo-operator:<tag> \
  --certificate-identity-regexp='.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

### Apply a Security Policy

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: enforce-non-root
  namespace: zelyo-system
spec:
  severity: critical
  match:
    namespaces: ["production", "staging"]
  rules:
    - type: container-security-context
      enforce: true
      autoRemediate: true
```

<details>
<summary><strong>🛡️ Onboard a GitOps Repository (Activate Protect Mode)</strong></summary>

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: my-infra-repo
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths:
    - "clusters/production/"
    - "clusters/staging/"
  provider: github
  authSecret: github-app-credentials
  syncStrategy: poll
```

</details>

<details>
<summary><strong>🤖 Enable Auto-Remediation</strong></summary>

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix-critical
  namespace: zelyo-system
spec:
  gitOpsRepository: my-infra-repo
  severityFilter: high        # Only fix high and critical findings
  dryRun: false               # Set to true to preview fixes without opening PRs
  maxConcurrentPRs: 3         # Limit blast radius
  autoMerge: false            # Require human approval
  prTemplate:
    titlePrefix: "[Zelyo]"
    labels: ["zelyo", "auto-remediation"]
    branchPrefix: "zelyo/fix-"
```

</details>

---

## 📦 CRD Reference

Zelyo Operator uses **9 Custom Resource Definitions** to declaratively configure every aspect of the AI Security Agent:

| CRD | Purpose |
|---|---|
| `ZelyoConfig` | Global configuration — LLM provider, API keys, feature flags |
| `SecurityPolicy` | Defines which security rules to scan for and which namespaces to target |
| `MonitoringPolicy` | Configures real-time monitoring — event filters, anomaly detection, alerts |
| `RemediationPolicy` | Controls auto-remediation — severity filter, dry-run, max PRs, GitOps target |
| `GitOpsRepository` | Onboards a Git repository for drift detection and PR submission |
| `ClusterScan` | Schedules cluster-wide security and compliance scans |
| `ScanReport` | Stores individual scan results (auto-created by ClusterScan) |
| `CostPolicy` | Configures cost optimization rules and thresholds |
| `NotificationChannel` | Configures alert delivery — Slack, Teams, PagerDuty, webhooks |

> 📚 See [CRD Reference](docs/crd-reference.md) for complete field documentation.

---

## 🧩 Internal Package Architecture

<details>
<summary><strong>Click to expand internal package map</strong></summary>

| Package | Role in the Security Pipeline |
|---|---|
| `internal/scanner` | 8 security scanners (RBAC, images, PodSecurity, secrets, network, supply chain) |
| `internal/anomaly` | Statistical baseline engine — σ-deviation anomaly detection with sliding windows |
| `internal/correlator` | Time-windowed event correlation — groups alerts into unified incidents |
| `internal/compliance` | Maps findings to CIS/NIST/SOC2 controls, generates audit-ready reports |
| `internal/drift` | Live drift detector — compares cluster state vs Git with recursive object diffing |
| `internal/remediation` | LLM-powered fix generation with structured JSON output and risk scoring |
| `internal/llm` | Multi-provider LLM client with circuit breaker, retry, and token budgeting |
| `internal/github` | GitHub App engine — JWT auth, installation tokens, PR lifecycle (stdlib only) |
| `internal/gitops` | GitOps engine interface + ArgoCD/Flux/Kustomize/Helm source discovery |
| `internal/notifier` | Multi-channel notifications with severity filtering, dedup, and rate limiting |
| `internal/monitor` | Real-time Kubernetes resource watcher with event dispatch |
| `internal/controller` | 7 Kubernetes controllers orchestrating the Detect → Correlate → Fix pipeline |

</details>

---

## 🛠️ Development

### Prerequisites

- Go 1.25+
- Docker
- kubectl
- [kind](https://kind.sigs.k8s.io/) or [minikube](https://minikube.sigs.k8s.io/)
- [Kubebuilder](https://kubebuilder.io/)
- Helm 3.x

### Setup

```bash
# Clone the repository
git clone https://github.com/zelyo-ai/zelyo-operator.git
cd zelyo-operator

# Install dependencies
make install

# Generate manifests & CRDs
make manifests generate

# Run locally against a kind cluster
make run

# Run tests (14 packages, 60+ test cases)
make test

# Lint
make lint
```

### Build

```bash
# Build the binary
make build

# Build the Docker image
make docker-build IMG=ghcr.io/zelyo-ai/zelyo-operator:dev

# Build and push
make docker-push IMG=ghcr.io/zelyo-ai/zelyo-operator:dev
```

---

## 📚 Documentation

| Document | Description |
|---|---|
| [Getting Started](docs/quickstart.md) | Step-by-step setup: clone, cluster, first policy, first scan |
| [Quick Start Recipes](docs/quickstart.md) | Copy-paste YAML recipes for common use cases |
| [Architecture](docs/architecture.md) | System design, controllers, scanner engine, data flow |
| [Security Scanners](docs/scanners.md) | All 8 scanners: what they check, severity levels, example policies |
| [CRD Reference](docs/crd-reference.md) | Complete field reference for all 9 CRDs (spec + status) |
| [Monitoring & Metrics](docs/metrics.md) | Prometheus metrics, PromQL queries, Grafana dashboards, alerting rules |
| [LLM Configuration](docs/llm-configuration.md) | Provider setup, token budgets, and cost optimization |
| [GitOps Onboarding](docs/gitops-onboarding.md) | How to connect your GitOps repositories for auto-remediation |
| [Integrations](docs/integrations.md) | Notification channel setup guides (Slack, Teams, PagerDuty, etc.) |
| [Compliance](docs/compliance.md) | Supported frameworks and custom rule authoring |
| [Supply Chain Security](docs/supply-chain-security.md) | Verifying image signatures, SBOMs, and provenance |

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on local setup, managing the PR lifecycle, and DCO sign-offs.

## 🔐 Security

To report a security vulnerability, please see [SECURITY.md](SECURITY.md).

## 📄 License

Zelyo Operator is licensed under the [Apache License 2.0](LICENSE).

---

<p align="center">
  <sub>Created with ❤️ by <a href="https://zelyo.ai">Zelyo AI</a></sub><br/>
  <sub>⭐ If Zelyo catches a misconfiguration before it reaches production, consider giving us a star!</sub>
</p>
