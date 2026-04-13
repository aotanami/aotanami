<p align="center">
  <img src="assets/logo.png" alt="Zelyo" width="180" />
</p>

<h1 align="center">Zelyo Operator</h1>

<p align="center">
  <strong>Open-Source CNAPP — Detect, Correlate, Fix</strong><br/>
  <sub>56 security scanners across Kubernetes and AWS cloud accounts. AI-powered correlation. Auto-generated GitOps PRs.</sub>
</p>

<p align="center">
  <a href="https://github.com/zelyo-ai/zelyo-operator/actions/workflows/ci.yml"><img src="https://github.com/zelyo-ai/zelyo-operator/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/zelyo-ai/zelyo-operator/releases"><img src="https://img.shields.io/github/v/release/zelyo-ai/zelyo-operator?style=flat-square&color=00c9a7" alt="Release" /></a>
  <a href="https://goreportcard.com/report/github.com/zelyo-ai/zelyo-operator"><img src="https://goreportcard.com/badge/github.com/zelyo-ai/zelyo-operator" alt="Go Report Card" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License" /></a>
  <a href="https://artifacthub.io/packages/helm/zelyo-ai/zelyo-operator"><img src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/zelyo-operator&style=flat-square" alt="Artifact Hub" /></a>
</p>

<p align="center">
  <a href="https://zelyo-ai.github.io/zelyo-operator/quickstart/">Quickstart</a> ·
  <a href="https://zelyo-ai.github.io/zelyo-operator/">Docs</a> ·
  <a href="https://github.com/zelyo-ai/zelyo-operator/issues/new?template=bug_report.md">Report Bug</a> ·
  <a href="https://github.com/zelyo-ai/zelyo-operator/issues/new?template=feature_request.md">Request Feature</a>
</p>

---

## What is Zelyo?

Zelyo is an open-source **Cloud-Native Application Protection Platform (CNAPP)** that runs as a Kubernetes operator. It continuously scans your Kubernetes workloads and cloud accounts, correlates findings with an LLM, and auto-generates code fixes as GitOps pull requests.

**What makes it different:** other tools detect. Zelyo detects AND fixes. Every remediation is a PR with a confidence score — human-reviewed, never applied directly.

### Capabilities

|                                   |                                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **56 Security Scanners**    | 8 Kubernetes (RBAC, images, PodSecurity, secrets, network, privilege escalation, security context, resource limits) + 48 cloud (CSPM, CIEM, Network, DSPM, Supply Chain, CI/CD) |
| **Multi-Cloud CNAPP**       | Onboard AWS accounts via `CloudAccountConfig` CRD with IRSA, Pod Identity, or static credentials                                                                              |
| **AI Correlation**          | LLM reasons over findings — overprivileged role + exposed service = attack chain                                                                                               |
| **GitOps Remediation**      | Auto-generates Kubernetes YAML patches and cloud IaC fixes (Terraform/CloudFormation), opens PRs                                                                                |
| **6 Compliance Frameworks** | CIS Kubernetes Benchmark, NIST 800-53, SOC 2, PCI-DSS, HIPAA, ISO 27001                                                                                                         |
| **Anomaly Detection**       | Builds statistical baselines for pod restarts, resource usage, and error rates                                                                                                  |
| **Drift Detection**         | Compares live cluster state against your Git repo                                                                                                                               |
| **Cost Optimization**       | Detects idle workloads, recommends rightsizing                                                                                                                                  |
| **Notifications**           | Slack, Teams, PagerDuty, Telegram, WhatsApp, webhooks, email                                                                                                                    |
| **Production-Safe**         | Read-only cluster access. Non-destructive by design.                                                                                                                            |

---

## The Pipeline: Detect → Correlate → Fix

```mermaid
graph LR
    SP["SecurityPolicy<br/>8 K8s Scanners"] -->|findings| C["Correlator<br/>Engine"]
    CAC["CloudAccountConfig<br/>48 Cloud Scanners"] -->|findings| CF["Compliance<br/>Framework"]
    MP["MonitoringPolicy<br/>Observer"] -->|pod metrics| AD["Anomaly<br/>Detector"]
    AD -->|deviations| C
    CS["ClusterScan<br/>Scheduler"] -->|findings| CF
    CF -->|compliance report| C
    C -->|incidents| RP["Remediation<br/>Policy"]
    RP -->|finding| RE["LLM<br/>Reasoner"]
    RE -->|JSON fix plan| GH["GitHub<br/>Engine"]
    GH -->|Pull Request| REPO["Your GitOps<br/>Repo"]
    REPO -->|merged| ARGO["ArgoCD / Flux"]
    ARGO -->|applied| K8S["Cluster"]
```

1. **Detect** — SecurityPolicy scans Kubernetes pods, CloudAccountConfig scans cloud accounts, MonitoringPolicy watches for anomalies, ClusterScan evaluates compliance
2. **Correlate** — Groups related signals within a time window into unified findings
3. **Fix** — LLM generates a confidence-scored JSON fix plan, remediation engine validates it, GitHub engine opens a PR

### Operating Modes

| Mode                          | Behavior                                                                                |
| ----------------------------- | --------------------------------------------------------------------------------------- |
| **Audit** *(default)* | Detects, correlates, and alerts. No automated changes.                                  |
| **Protect**             | Full pipeline. Opens GitOps PRs automatically when a `GitOpsRepository` is onboarded. |

---

## Installation

```bash
# 1. Install Zelyo Operator
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace

# 2. Add your LLM API key (operator auto-activates within seconds)
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_API_KEY>

# 3. Deploy default security policies
helm install zelyo-policies oci://ghcr.io/zelyo-ai/charts/zelyo-policies \
  --namespace zelyo-system

# 4. Verify
kubectl get pods -n zelyo-system
kubectl get securitypolicies,clusterscans,monitoringpolicies -n zelyo-system
```

Step 3 deploys the `zelyo-policies` chart with production-ready defaults: 3 tiered SecurityPolicies (production/staging/default), nightly + weekly ClusterScans, MonitoringPolicy with anomaly detection, and CIS compliance evaluation. Override the profile with `--set global.profile=strict` for regulated environments, or enable additional compliance frameworks with `--set compliance.presets.soc2=true`.

Webhook TLS uses self-signed certificates by default. To use cert-manager instead, add `--set webhook.certManager.enabled=true` and install cert-manager first.

Supported LLM providers: OpenRouter, OpenAI, Anthropic, Azure OpenAI, Ollama.

### Verify Image Signature

```bash
cosign verify ghcr.io/zelyo-ai/zelyo-operator:<tag> \
  --certificate-identity-regexp='.*' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

See the [Quickstart Guide](docs/quickstart.md) for a complete walkthrough including local cluster setup, all CRD recipes, and cloud account onboarding.

---

## Quick Examples

### Scan Kubernetes Workloads

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
    - name: security-context
      type: container-security-context
      enforce: true
    - name: pod-security
      type: pod-security
      enforce: true
```

### Scan an AWS Account

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-prod
  namespace: zelyo-system
spec:
  provider: aws
  accountID: "123456789012"
  regions: ["us-east-1", "us-west-2"]
  credentials:
    method: irsa
    roleARN: "arn:aws:iam::123456789012:role/ZelyoReadOnly"
  scanCategories: ["cspm", "ciem", "network", "dspm"]
  complianceFrameworks: ["soc2", "pci-dss"]
```

### Enable Auto-Remediation

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths: ["clusters/production/"]
  provider: github
  authSecret: github-creds
  enableDriftDetection: true
---
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix
  namespace: zelyo-system
spec:
  gitOpsRepository: infra-repo
  severityFilter: high
  dryRun: false
  maxConcurrentPRs: 3
  autoMerge: false
  prTemplate:
    titlePrefix: "[Zelyo Auto-Fix]"
    labels: ["security", "automated"]
    branchPrefix: "zelyo-operator/fix-"
```

---

## CRDs

Zelyo Operator uses **10 Custom Resource Definitions**:

| CRD                     | Purpose                                                                       |
| ----------------------- | ----------------------------------------------------------------------------- |
| `ZelyoConfig`         | Global config — LLM provider, API keys, operating mode, token budget         |
| `SecurityPolicy`      | Kubernetes workload security rules and namespace targeting                    |
| `CloudAccountConfig`  | Cloud account onboarding (AWS) for multi-cloud scanning                       |
| `ClusterScan`         | Scheduled cluster-wide scans with history retention                           |
| `ScanReport`          | Immutable scan results (auto-created by ClusterScan / CloudAccountConfig)     |
| `MonitoringPolicy`    | Real-time event monitoring and anomaly detection                              |
| `RemediationPolicy`   | Auto-remediation config — severity filter, dry-run, max PRs                  |
| `GitOpsRepository`    | Repository onboarding for drift detection and PR submission                   |
| `CostPolicy`          | Cost optimization — idle detection, rightsizing, budget alerts               |
| `NotificationChannel` | Alert routing — Slack, Teams, PagerDuty, Telegram, WhatsApp, webhooks, email |

See [CRD Reference](docs/crd-reference.md) for complete field documentation.

---

## Architecture

```mermaid
graph TB
    subgraph Kubernetes_Cluster
        Events["K8s Events"]
        Pods["Pod Workloads"]
        Metrics["Resource Metrics"]
    end

    subgraph Cloud_Accounts
        AWS["AWS APIs<br/>S3, EC2, IAM, RDS, ..."]
    end

    subgraph Observe
        Scanner["K8s Scanner<br/>8 rule types"]
        CloudScanner["Cloud Scanner<br/>48 checks"]
        Watcher["Real-Time Watcher"]
        CostEng["Cost Optimizer"]
    end
  
    subgraph Reason
        AnomalyDet["Anomaly Detector"]
        Correlator["Correlator Engine"]
        Compliance["Compliance Engine<br/>CIS · SOC2 · PCI-DSS · HIPAA"]
        DriftDet["Drift Detector"]
        LLM["LLM Reasoner"]
    end
  
    subgraph Act
        Remediation["Remediation Engine"]
        GitOps["GitHub Engine"]
        Notify["Notifier"]
    end

    subgraph Integrations
        GitRepo["Your GitOps Repo"]
        Alerts["Slack · Teams · PagerDuty"]
        Prom["Prometheus · Grafana"]
        ArgoFlux["ArgoCD / Flux"]
    end

    Events --> Watcher
    Events --> Scanner
    Pods --> Watcher
    Pods --> Scanner
    Metrics --> Watcher
    Metrics --> Scanner
    AWS --> CloudScanner
    Watcher --> AnomalyDet
    Scanner --> Compliance
    Scanner --> DriftDet
    CloudScanner --> Compliance
    CloudScanner --> DriftDet
    Scanner --> Correlator
    CloudScanner --> Correlator
    CostEng --> Correlator
    AnomalyDet --> Correlator
    DriftDet --> Correlator
    Compliance --> Correlator
    Correlator --> LLM
    LLM --> Remediation
    Remediation -->|Protect Mode| GitOps
    Remediation -->|Audit Mode| Notify
    GitOps --> GitRepo
    GitRepo --> ArgoFlux
    Notify --> Alerts
    Watcher --> Prom
```

<details>
<summary><strong>Internal Package Map</strong></summary>

| Package                   | Role                                                                                    |
| ------------------------- | --------------------------------------------------------------------------------------- |
| `internal/scanner`      | 8 Kubernetes security scanners + registry                                               |
| `internal/cloudscanner` | 48 cloud scanners (CSPM, CIEM, Network, DSPM, Supply Chain, CI/CD) + AWS client factory |
| `internal/anomaly`      | Statistical baseline engine with sliding-window deviation detection                     |
| `internal/correlator`   | Time-windowed event correlation                                                         |
| `internal/compliance`   | Maps findings to CIS/NIST/SOC2/PCI-DSS/HIPAA/ISO27001 controls                          |
| `internal/drift`        | Live drift detector — cluster state vs Git                                             |
| `internal/remediation`  | LLM-powered fix generation with structured JSON output                                  |
| `internal/llm`          | Multi-provider LLM client with circuit breaker and token budgeting                      |
| `internal/github`       | GitHub App engine — JWT auth, PR lifecycle                                             |
| `internal/gitops`       | GitOps engine interface + ArgoCD/Flux/Kustomize/Helm discovery                          |
| `internal/notifier`     | Multi-channel notifications with dedup and rate limiting                                |
| `internal/monitor`      | Real-time Kubernetes resource watcher                                                   |
| `internal/controller`   | 10 controllers orchestrating the Detect → Correlate → Fix pipeline                    |

</details>

---

## Development

### Prerequisites

- Go 1.26+
- Docker
- kubectl
- [k3d](https://k3d.io/) or [kind](https://kind.sigs.k8s.io/)
- Helm 3.x

### Build & Test

```bash
git clone https://github.com/zelyo-ai/zelyo-operator.git
cd zelyo-operator

make generate manifests   # Generate DeepCopy and CRD YAML
make build                # Build binary
make test                 # Run tests (15 packages)
make lint                 # golangci-lint with 30+ linters
make docker-build IMG=ghcr.io/zelyo-ai/zelyo-operator:dev
```

---

## Documentation

| Document                                            | Description                                            |
| --------------------------------------------------- | ------------------------------------------------------ |
| [Quickstart](docs/quickstart.md)                       | Local cluster setup, all CRD recipes, cloud onboarding |
| [Architecture](docs/architecture.md)                   | System design, controllers, data flow                  |
| [Scanners](docs/scanners.md)                           | All 56 scanners — what they check, severity levels    |
| [CRD Reference](docs/crd-reference.md)                 | Complete field reference for all 10 CRDs               |
| [Compliance](docs/compliance.md)                       | Supported frameworks and control mappings              |
| [Metrics](docs/metrics.md)                             | Prometheus metrics, PromQL queries, alerting rules     |
| [LLM Configuration](docs/llm-configuration.md)         | Provider setup and token budgets                       |
| [GitOps Onboarding](docs/gitops-onboarding.md)         | Repository connection for auto-remediation             |
| [Integrations](docs/integrations.md)                   | Notification channel setup (Slack, Teams, PagerDuty)   |
| [Supply Chain Security](docs/supply-chain-security.md) | Image signatures, SBOMs, provenance                    |

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built by <a href="https://zelyo.ai">Zelyo AI</a></sub>
</p>
