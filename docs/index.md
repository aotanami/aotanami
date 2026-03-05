---
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

![Aotanami](assets/logo.png){ width="120" }

# Aotanami

<p class="hero-subtitle">Your Digital SRE &amp; Security Engineer for Kubernetes</p>

<div class="badges">
  <a href="https://github.com/aotanami/aotanami/actions/workflows/ci.yml"><img src="https://github.com/aotanami/aotanami/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/aotanami/aotanami/releases"><img src="https://img.shields.io/github/v/release/aotanami/aotanami?style=flat-square" alt="Release"></a>
  <a href="https://goreportcard.com/report/github.com/aotanami/aotanami"><img src="https://goreportcard.com/badge/github.com/aotanami/aotanami" alt="Go Report Card"></a>
  <a href="https://github.com/aotanami/aotanami/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
</div>

<div class="hero-actions">
  <a href="getting-started/" class="primary-btn">🚀 Get Started</a>
  <a href="https://github.com/aotanami/aotanami" class="secondary-btn">⭐ View on GitHub</a>
</div>

</div>

---

## What is Aotanami?

Aotanami is your **Digital SRE and Security Engineer** — a self-hosted Kubernetes Operator powered by **Agentic AI** that does the job of a full-time site reliability and security engineer. It autonomously **observes** your cluster, **reasons** about security findings and anomalies using LLMs, and **acts** by opening GitOps PRs with production-ready fixes — all with **read-only cluster access**.

**Bring your own LLM API keys** (OpenRouter, OpenAI, Anthropic, Azure, Ollama) — optimized for minimal token usage.

---

## Key Features

<div class="feature-grid" markdown>

<div class="feature-card" markdown>
<div class="feature-icon">🔒</div>

### Security Scanning
RBAC audit, image vulnerabilities, PodSecurity violations, secrets exposure, and network policy gaps.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🛡️</div>

### Compliance
CIS Benchmarks, NSA/CISA hardening, PCI-DSS, SOC2, and HIPAA compliance mapping with automated checks.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🔗</div>

### Supply Chain Security
SBOM analysis, image signature verification (Cosign/Notary), and base image CVE tracking.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">⚡</div>

### Real-Time Monitoring
24/7 Kubernetes events, pod logs, node conditions, and network telemetry with anomaly detection.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🧠</div>

### Agentic AI Remediation
LLM-powered diagnosis with structured JSON fix plans, risk scoring, and production-ready GitOps PRs via GitHub App.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">💰</div>

### Cost Optimization
Resource rightsizing, idle workload detection, and spot-readiness assessment to reduce cloud spend.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🔄</div>

### Config Drift Detection
Compares live cluster state against your GitOps repo manifests and auto-generates reconciliation PRs.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🚨</div>

### Runtime Threat Detection
Suspicious exec detection, privilege escalation, filesystem anomalies, and lateral movement detection.
</div>

<div class="feature-card" markdown>
<div class="feature-icon">🌐</div>

### Multi-Cluster Federation
Aggregate views, cross-cluster correlation, and centralized policy management across all your clusters.
</div>

</div>

---

## Dual Operating Modes

| Mode | When | Behavior |
|---|---|---|
| **:material-magnify: Audit Mode** (default) | No GitOps repo onboarded | Detects, diagnoses, and sends alerts — zero cluster modifications |
| **:material-shield-check: Protect Mode** | GitOps repo onboarded | Full autonomous remediation — generates fixes, opens PRs via GitHub App |

---

## Architecture

```mermaid
graph TB
    subgraph "Kubernetes Cluster — Read-Only Access"
        Events[K8s Events]
        Logs[Pod Logs]
        Nodes[Node Conditions]
        Net[Network Telemetry]
        Metrics[Resource Metrics]
    end

    subgraph "Aotanami — The Digital SRE"
        subgraph "Observe"
            Watcher[Real-Time Watcher]
            Scanner[Security Scanner]
            CostEng[Cost Optimizer]
        end
        subgraph "Reason"
            AnomalyDet[Anomaly Detector]
            Correlator[Incident Correlator]
            Compliance[Compliance Engine]
            DriftDet[Drift Detector]
            LLM["LLM Reasoner — BYO Keys"]
        end
        subgraph "Act"
            Remediation[Remediation Engine]
            GitOps[GitHub App Engine]
            Notify[Notifier]
        end
    end

    subgraph "Integrations"
        GitRepo[Your GitOps Repo]
        Alerts["Slack · Teams · PagerDuty"]
        Prom["Prometheus · Grafana"]
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
    Notify --> Alerts
    Watcher --> Prom
```

---

## Quick Install

=== "Helm (OCI)"

    ```bash
    # Create namespace and LLM secret
    kubectl create namespace aotanami-system
    kubectl create secret generic aotanami-llm \
      --namespace aotanami-system \
      --from-literal=api-key=<YOUR_API_KEY>

    # Install from OCI registry
    helm install aotanami oci://ghcr.io/aotanami/charts/aotanami \
      --namespace aotanami-system \
      --set config.llm.provider=openrouter \
      --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
      --set config.llm.apiKeySecret=aotanami-llm
    ```

=== "Kustomize"

    ```bash
    kubectl apply -k https://github.com/aotanami/aotanami/config/default
    ```

[Full installation guide :material-arrow-right:](getting-started.md){ .md-button }

---

<p align="center" style="margin-top: 3rem; color: var(--md-default-fg-color--lighter);">
  An Aotanami Foundation project. Originally created with ❤️ by <a href="https://zelyo.ai">Zelyo AI</a>
</p>
