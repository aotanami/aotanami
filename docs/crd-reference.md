# CRD Reference

Complete field reference for all Aotanami Custom Resource Definitions.

## SecurityPolicy

Defines security rules to evaluate and enforce on Kubernetes workloads.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: enforce-security
spec:
  severity: medium           # critical | high | medium | low | info
  match:
    namespaces: ["production"]
    excludeNamespaces: ["kube-system"]
    labelSelector:
      matchLabels:
        app: my-app
    resourceKinds: ["Deployment", "StatefulSet"]
  rules:
    - name: non-root
      type: container-security-context  # See rule types below
      enforce: true
      params:
        key: value
  autoRemediate: false        # Requires GitOps repo
  schedule: "0 */6 * * *"    # Cron (empty = continuous)
  notificationChannels: ["slack-alerts"]
```

**Rule Types**: `container-security-context`, `rbac-audit`, `image-vulnerability`, `network-policy`, `pod-security`, `secrets-exposure`, `resource-limits`, `privilege-escalation`

---

## RemediationPolicy

Configures how Aotanami generates and submits GitOps PRs.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix
spec:
  targetPolicies: ["enforce-security"]  # Empty = all
  gitOpsRepository: my-infra-repo
  prTemplate:
    titlePrefix: "[Aotanami]"
    labels: ["security", "auto-fix"]
    assignees: ["team-lead"]
    branchPrefix: "aotanami/fix-"
  dryRun: false
  maxConcurrentPRs: 5
  autoMerge: false
  severityFilter: high        # critical | high | medium | low
```

---

## ClusterScan

Triggers security and compliance scans.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: ClusterScan
metadata:
  name: nightly-scan
spec:
  schedule: "0 2 * * *"
  scanners: ["rbac", "images", "netpol", "pod-security"]
  scope:
    namespaces: ["production", "staging"]
    excludeNamespaces: ["kube-system"]
  complianceFrameworks: ["cis", "nsa-cisa"]
  suspend: false
  historyLimit: 10
```

---

## GitOpsRepository

Onboards an existing GitOps repository.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths: ["clusters/production/", "clusters/staging/"]
  provider: github             # github | gitlab | bitbucket
  authSecret: github-creds
  syncStrategy: poll           # poll | webhook
  pollIntervalSeconds: 300
  enableDriftDetection: true
  namespaceMapping:
    - repoPath: "clusters/production/"
      namespace: production
```

---

## CostPolicy

Configures cost monitoring and workload rightsizing.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: CostPolicy
metadata:
  name: optimize-costs
spec:
  targetNamespaces: ["production"]
  resizeStrategy: conservative  # conservative | moderate | aggressive
  budgetLimits:
    monthlyBudgetUSD: "5000"
    costIncreaseThresholdPercent: 20
  idleDetection:
    enabled: true
    cpuThresholdPercent: 5
    memoryThresholdPercent: 5
    idleDurationMinutes: 60
```

---

## MonitoringPolicy

Configures real-time monitoring and anomaly detection.

```yaml
apiVersion: aotanami.com/v1alpha1
kind: MonitoringPolicy
metadata:
  name: realtime-watch
spec:
  targetNamespaces: ["production"]
  eventFilters:
    types: ["Warning"]
    reasons: ["OOMKilled", "CrashLoopBackOff", "FailedScheduling"]
  logMonitoring:
    enabled: true
    patterns:
      - name: error-detection
        regex: "(?i)(error|exception|fatal|panic)"
        severity: high
  nodeMonitoring:
    enabled: true
    conditions: ["MemoryPressure", "DiskPressure"]
  anomalyDetection:
    enabled: true
    baselineDurationHours: 168
    sensitivityPercent: 80
```

---

## NotificationChannel

Configures alert destinations.

```yaml
# Slack example
apiVersion: aotanami.com/v1alpha1
kind: NotificationChannel
metadata:
  name: slack-alerts
spec:
  type: slack
  credentialSecret: slack-token
  severityFilter: medium
  rateLimit:
    maxPerHour: 60
    aggregateSeconds: 30
  slack:
    channel: "#aotanami-alerts"
```

**Supported types**: `slack`, `msteams`, `pagerduty`, `alertmanager`, `telegram`, `whatsapp`, `webhook`, `email`

---

## AotanamiConfig

Global operator configuration (cluster-scoped).

```yaml
apiVersion: aotanami.com/v1alpha1
kind: AotanamiConfig
metadata:
  name: default
spec:
  mode: audit                  # audit | protect
  llm:
    provider: openrouter       # openrouter | openai | anthropic | azure-openai | ollama | custom
    model: "anthropic/claude-sonnet-4-20250514"
    apiKeySecret: aotanami-llm
    temperature: "0.1"
    maxTokensPerRequest: 4096
  tokenBudget:
    hourlyTokenLimit: 50000
    dailyTokenLimit: 500000
    monthlyTokenLimit: 10000000
    alertThresholdPercent: 80
    enableCaching: true
    batchingEnabled: true
  dashboard:
    enabled: true
    port: 8080
  telemetry:
    prometheusEnabled: true
    otelEnabled: false
```
