# Architecture

## Overview

Aotanami is your **Digital SRE and Security Engineer** — a Kubernetes Operator built with [Kubebuilder](https://kubebuilder.io/) that autonomously **observes**, **reasons about**, and **acts on** security and reliability issues in your production clusters. It runs as a single deployment, continuously protecting your workloads while you focus on building features.

## How It Works: Observe → Reason → Act

```
SecurityPolicy scans pods  →  Correlator groups signals  →  LLM diagnoses root cause  →  GitHub PR with fix
MonitoringPolicy watches  →  Anomaly detector fires     →  into a unified incident   →  or Slack/PagerDuty alert
ClusterScan evaluates CIS  →  Compliance framework maps  →                            →
```

1. **You declare intent** by creating CRDs like `SecurityPolicy`, `MonitoringPolicy`, or `ClusterScan`
2. **Aotanami observes** — scanning pods, watching restart rates, evaluating compliance
3. **The brain reasons** — anomaly detector builds baselines, correlator groups events into incidents, LLM generates structured JSON fix plans
4. **The engine acts** — remediation engine validates fixes, GitHub engine opens PRs, notifier routes alerts
5. **It never stops** — continuous reconciliation catches new violations, drift, and anomalies

## System Architecture

```mermaid
graph TB
    subgraph "Kubernetes Cluster — Read-Only Access"
        Pods[Running Pods]
        Secrets[K8s Secrets]
        NS[Namespaces]
        Events[K8s Events]
        Logs[Pod Logs & Metrics]
    end

    subgraph "Aotanami — The Digital SRE"
        subgraph "Observe (Controllers)"
            SecPolCtrl["SecurityPolicy<br/>pod scanning"]
            MonCtrl["MonitoringPolicy<br/>pod restart watch"]
            ScanCtrl["ClusterScan<br/>scheduled compliance"]
            CostCtrl["CostPolicy<br/>resource analysis"]
            GitCtrl["GitOpsRepository<br/>repo discovery"]
        end

        subgraph "Reason (The Brain)"
            AD["anomaly<br/>σ-deviation baselines"]
            CE["correlator<br/>incident grouping"]
            CF["compliance<br/>CIS/NIST/SOC2 mapping"]
            LD["drift<br/>cluster vs Git diffing"]
            LLM["llm<br/>structured JSON reasoning"]
        end

        subgraph "Act (Execution)"
            RE["remediation<br/>risk-scored fix plans"]
            GH["github<br/>JWT auth, PR lifecycle"]
            NF["notifier<br/>dedup + rate limit"]
        end
    end

    subgraph "External Integrations"
        GitHub["Your GitOps Repo"]
        Alerts["Slack · Teams · PagerDuty"]
        Prometheus["Prometheus · Grafana"]
        ArgoFlux["ArgoCD / Flux"]
    end

    Pods --> SecPolCtrl & ScanCtrl & CostCtrl
    Events & Logs --> MonCtrl
    Secrets --> GitCtrl

    SecPolCtrl -->|findings| CE
    MonCtrl -->|pod restarts| AD
    ScanCtrl -->|findings| CF
    AD -->|anomalies| CE
    CF -->|violations| CE
    CostCtrl -->|waste| CE
    LD -->|drift| CE

    CE -->|correlated incidents| LLM
    LLM -->|JSON fix plan| RE

    RE -->|Protect Mode| GH
    RE -->|Audit Mode| NF
    GH --> GitHub
    GitHub --> ArgoFlux
    NF --> Alerts
    SecPolCtrl & MonCtrl --> Prometheus
```

## The Digital SRE Brain (`internal/`)

The intelligence lives entirely within the `internal/` packages. These form the autonomous pipeline that converts raw Kubernetes telemetry into actionable GitOps Pull Requests.

### Observe Layer

| Package | What the Digital SRE Observes |
|---|---|
| `scanner` | 8 pluggable scanners — RBAC, container security, images, PodSecurity, secrets, network, privilege escalation, resource limits |
| `monitor` | Real-time Kubernetes resource watcher with event dispatch |
| `costoptimizer` | Resource utilization analysis — idle workloads, rightsizing, spot readiness |

### Reason Layer

| Package | How the Digital SRE Thinks |
|---|---|
| `anomaly` | Statistical baseline engine — σ-deviation detection with sliding windows (1000 data points per metric) |
| `correlator` | Time-windowed event grouping — merges security findings + anomalies + crashes into unified incidents |
| `compliance` | Maps findings to CIS Kubernetes Benchmark controls (15 controls) with evidence attachment |
| `drift` | Live drift detector — recursive object diffing across 9 resource types, shadow resource detection |
| `llm` | Multi-provider LLM client — OpenRouter, OpenAI, Anthropic, Azure, Ollama with circuit breaker + retry |

### Act Layer

| Package | How the Digital SRE Acts |
|---|---|
| `remediation` | LLM-powered fix generation — structured JSON output, risk scoring (0-100), blast radius protection |
| `github` | GitHub App engine — RS256 JWT auth, token caching, branch → commit → PR → label lifecycle (stdlib only) |
| `gitops` | GitOps interface + ArgoCD/Flux/Kustomize/Helm source discovery |
| `notifier` | Multi-channel delivery — Slack, Teams, PagerDuty, webhooks with severity filtering + deduplication |

## Controllers — The Digital SRE's Responsibilities

| Controller | Observe | Reason | Act |
|---|---|---|---|
| **SecurityPolicy** | Scans pods for violations | Feeds findings → correlator | — |
| **MonitoringPolicy** | Watches pod restart counts | Feeds → anomaly detector → correlator | — |
| **ClusterScan** | Runs scheduled scans | Evaluates CIS compliance | Creates ScanReport CRs, emits ComplianceViolation events |
| **RemediationPolicy** | — | Queries correlator for open incidents | LLM plan → validates → opens GitOps PR |
| **GitOpsRepository** | Discovers repo structure | — | Provides Git context for remediation |
| **CostPolicy** | Analyzes resource utilization | Identifies waste | — |
| **AotanamiConfig** | — | — | Configures global settings |

### Controller Lifecycle

Every controller follows the standard lifecycle pattern:

```mermaid
stateDiagram-v2
    [*] --> Pending: Resource created
    Pending --> Active: Validation passes
    Pending --> Error: Validation fails
    Pending --> Degraded: Partial validation
    Active --> Active: Periodic re-reconcile
    Error --> Active: Issue resolved
    Degraded --> Active: Issue resolved
    Active --> Error: Runtime failure
```

## Scanner Engine

The scanner engine is **pluggable** — each scanner registers by rule type, and controllers look them up from a shared registry.

```
SecurityPolicy.spec.rules[].type  →  Registry.Get(type)  →  scanner.Scan(pods)  →  []Finding
```

### Available Scanners

| Scanner | Rule Type | What It Checks |
|---|---|---|
| **Container Security Context** | `container-security-context` | runAsNonRoot, privileged, readOnlyRootFilesystem, allowPrivilegeEscalation |
| **Resource Limits** | `resource-limits` | Missing CPU/memory requests and limits |
| **Image Pinning** | `image-vulnerability` | `:latest` tags, missing digest pins |
| **Pod Security** | `pod-security` | hostNetwork, hostPID, hostIPC, hostPath, SYS_ADMIN, NET_RAW |
| **Privilege Escalation** | `privilege-escalation` | Root UID, auto-mounted tokens, unmasked /proc |
| **Secrets Exposure** | `secrets-exposure` | Hardcoded secrets in env vars, sensitive patterns |
| **Network Policy** | `network-policy` | Unlabeled pods, hostPort usage |
| **RBAC Audit** | `rbac-audit` | Default service account usage, admin-named SAs |

## Status Conditions

Every resource uses **Kubernetes-standard status conditions**:

| Condition | Meaning |
|---|---|
| `Ready` | Fully reconciled and operational |
| `SecretResolved` | Referenced K8s Secret is accessible |
| `ScanCompleted` | Security scan finished |
| `GitOpsConnected` | GitOps repository available |

## Prometheus Metrics

| Metric | Type | What It Tracks |
|---|---|---|
| `aotanami_controller_reconcile_total` | Counter | Reconcile operations per controller |
| `aotanami_controller_reconcile_duration_seconds` | Histogram | Reconcile latency |
| `aotanami_scanner_findings_total` | Counter | Findings by scanner and severity |
| `aotanami_scanner_resources_scanned_total` | Counter | Total resources scanned |
| `aotanami_policy_violations` | Gauge | Current violations per policy |
| `aotanami_clusterscan_completed_total` | Counter | Completed cluster scans |
| `aotanami_clusterscan_findings` | Gauge | Findings from last scan |
| `aotanami_cost_rightsizing_recommendations` | Gauge | Pending rightsizing recommendations |

## Security Model

- **Read-only cluster access**: Only `get`, `list`, `watch` verbs on cluster resources
- **No direct mutations**: All fixes delivered as GitOps PRs, never applied directly
- **API key isolation**: LLM keys in Kubernetes Secrets, never logged
- **Non-root container**: UID 65532, `scratch` image, read-only rootfs
- **Signed artifacts**: Cosign-signed images with SBOM attestations
- **Admission webhooks**: Validates SecurityPolicy resources before persistence

## Project Layout

```
aotanami/
├── api/v1alpha1/           # CRD type definitions (9 types + conditions)
├── cmd/main.go             # Entrypoint — wires controllers, brain, scanners
├── config/                 # Kustomize manifests (CRDs, RBAC, webhook, samples)
├── internal/
│   ├── controller/         # 7 controllers (Observe → Reason → Act)
│   ├── scanner/            # 8 security scanners + registry
│   ├── anomaly/            # σ-deviation baseline engine
│   ├── correlator/         # Time-windowed incident correlation
│   ├── compliance/         # CIS/NIST/SOC2 framework mapping
│   ├── drift/              # Live cluster-vs-Git drift detection
│   ├── remediation/        # LLM-powered fix generation + risk scoring
│   ├── llm/                # Multi-provider LLM client + circuit breaker
│   ├── github/             # GitHub App engine (stdlib only)
│   ├── gitops/             # GitOps interface + source discovery
│   ├── notifier/           # Multi-channel notifications
│   ├── monitor/            # Real-time resource watcher
│   ├── conditions/         # Status condition helpers
│   ├── metrics/            # Prometheus metrics
│   └── webhook/            # Admission webhook
├── charts/                 # Helm chart
├── test/                   # E2E tests
└── docs/                   # Documentation
```
