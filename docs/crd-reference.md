# CRD Reference

Complete field reference for all 10 Zelyo Operator Custom Resource Definitions, including both `spec` and `status` fields.

## SecurityPolicy

**What it does**: Defines security rules to continuously evaluate against your Kubernetes workloads. Think of it as a checklist of security requirements that Zelyo Operator checks automatically.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: enforce-security
  namespace: zelyo-system
spec:
  # Minimum severity to report. Findings below this level are filtered out.
  # Options: critical | high | medium | low | info
  severity: medium

  # Which pods to scan
  match:
    namespaces: ["production", "staging"]      # Scan pods in these namespaces
    excludeNamespaces: ["kube-system"]         # Skip these namespaces
    labelSelector:                              # Only scan pods with these labels
      matchLabels:
        app: my-app
    resourceKinds: ["Deployment", "StatefulSet"]  # Filter by owner kind

  # What to check
  rules:
    - name: non-root                            # Unique name for this rule
      type: container-security-context          # Scanner to use (see Scanners page)
      enforce: true                             # If true, violations block deployments
      params:                                   # Optional scanner-specific parameters
        key: value

  autoRemediate: false                          # Auto-create fix PRs (requires GitOps repo)
  schedule: "0 */6 * * *"                       # Cron schedule (empty = continuous scanning)
  notificationChannels: ["slack-alerts"]        # Where to send alerts
```

**Available rule types**: `container-security-context`, `rbac-audit`, `image-vulnerability`, `network-policy`, `pod-security`, `secrets-exposure`, `resource-limits`, `privilege-escalation`

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Error
  observedGeneration: 3                         # Last processed generation
  violationCount: 12                            # Number of findings from last scan
  lastEvaluated: "2026-03-03T15:30:00Z"         # When the last scan ran
  conditions:
    - type: Ready
      status: "True"
      reason: ReconcileSuccess
      message: "Policy is active and scanning"
      lastTransitionTime: "2026-03-03T15:30:00Z"
      observedGeneration: 3
    - type: ScanCompleted
      status: "True"
      reason: ViolationsFound
      message: "Scan completed: 12 violations found"
```

---

## ClusterScan

**What it does**: Runs scheduled security scans across the cluster and saves results as ScanReport resources. Like a scheduled job that produces reports.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: ClusterScan
metadata:
  name: nightly-scan
  namespace: zelyo-system
spec:
  schedule: "0 2 * * *"                         # Cron schedule
  scanners:                                     # Which scanners to run
    - container-security-context
    - resource-limits
    - image-vulnerability
    - pod-security
  scope:
    namespaces: ["production", "staging"]       # Which namespaces to scan
    excludeNamespaces: ["kube-system"]
  complianceFrameworks: ["cis", "nsa-cisa"]     # Compliance checks to include
  suspend: false                                # Pause scheduling
  historyLimit: 10                              # Max ScanReports to keep
```

### Status

```yaml
status:
  phase: Completed                              # Pending | Running | Completed | Failed
  observedGeneration: 1
  lastScheduleTime: "2026-03-03T02:00:00Z"      # When the scan was last triggered
  completedAt: "2026-03-03T02:05:30Z"           # When the scan finished
  findingsCount: 47                             # Total findings from last scan
  lastReportName: nightly-scan-1709481934       # Name of the latest ScanReport
  conditions:
    - type: ScanCompleted
      status: "True"
      reason: ScanSuccess
      message: "Scan completed: 47 findings across 120 resources"
```

**Key behavior**: When a ClusterScan is deleted, all its child ScanReports are automatically cleaned up via a finalizer.

---

## ScanReport

**What it does**: Stores the results of a ClusterScan run. Created automatically by the ClusterScan controller — you don't create these yourself.

### Spec (set by ClusterScan controller)

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: ScanReport
metadata:
  name: nightly-scan-1709481934
  namespace: zelyo-system
  ownerReferences:                              # Owned by the parent ClusterScan
    - apiVersion: zelyo.ai/v1alpha1
      kind: ClusterScan
      name: nightly-scan
spec:
  scanRef: nightly-scan                         # Parent ClusterScan name
  startedAt: "2026-03-03T02:00:00Z"
  completedAt: "2026-03-03T02:05:30Z"
  summary:
    totalFindings: 47
    critical: 3
    high: 12
    medium: 22
    low: 8
    info: 2
    resourcesScanned: 120
    passedControls: 340
    failedControls: 47
  findings:
    - ruleType: container-security-context
      severity: critical
      title: Container "app" runs as privileged
      description: "The container has privileged: true..."
      resourceKind: Pod
      resourceNamespace: production
      resourceName: my-app-6d8f9b4c5d-x2k9p
      recommendation: "Set privileged: false..."
```

### Status

```yaml
status:
  phase: Complete                               # Pending | Complete
  observedGeneration: 1
  acknowledged: false                           # Set to true after review
```

---

## ZelyoConfig

**What it does**: Global operator configuration. Cluster-scoped, and **only one instance is allowed** (singleton).

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: ZelyoConfig
metadata:
  name: default                                 # Must be "default"
spec:
  mode: audit                                   # audit | protect

  llm:
    provider: openrouter                        # openrouter | openai | anthropic | azure-openai | ollama | custom
    model: "anthropic/claude-sonnet-4-20250514"
    apiKeySecret: zelyo-llm                  # Secret must have an "api-key" data key
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

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Degraded | Error
  observedGeneration: 1
  conditions:
    - type: Ready
      status: "True"
      reason: ReconcileSuccess
    - type: SecretResolved
      status: "True"
      reason: SecretFound
      message: "LLM API key secret validated"
```

**Key behavior**: If you try to create a second ZelyoConfig, the controller marks it as `Degraded` and records a warning event.

---

## GitOpsRepository

**What it does**: Onboards a Git repository for drift detection and automated remediation PRs.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths: ["clusters/production/", "clusters/staging/"]
  provider: github                              # github | gitlab | bitbucket
  authSecret: github-creds                      # Secret with auth credentials
  syncStrategy: poll                            # poll | webhook
  pollIntervalSeconds: 300
  enableDriftDetection: true
  namespaceMapping:
    - repoPath: "clusters/production/"
      namespace: production
```

### Status

```yaml
status:
  phase: Synced                                 # Pending | Syncing | Synced | Error
  observedGeneration: 1
  lastSyncedCommit: "abc123def456"
  lastSyncTime: "2026-03-03T15:00:00Z"
  discoveredManifests: 42
  driftCount: 3
  lastError: ""
  conditions:
    - type: Ready
      status: "True"
      reason: ReconcileSuccess
    - type: SecretResolved
      status: "True"
      reason: SecretFound
    - type: GitOpsConnected
      status: "True"
      reason: RepoSynced
```

---

## RemediationPolicy

**What it does**: Configures how Zelyo Operator generates and submits GitOps PRs for detected violations.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix
  namespace: zelyo-system
spec:
  targetPolicies: ["enforce-security"]          # Empty = all policies
  gitOpsRepository: infra-repo                  # Must reference existing GitOpsRepository
  prTemplate:
    titlePrefix: "[Zelyo Operator]"
    labels: ["security", "auto-fix"]
    assignees: ["team-lead"]
    branchPrefix: "zelyo-operator/fix-"
  dryRun: false
  maxConcurrentPRs: 5
  autoMerge: false
  severityFilter: high
```

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Error
  observedGeneration: 1
  remediationsApplied: 15
  openPRs: 3
  lastRun: "2026-03-03T14:00:00Z"
```

---

## CostPolicy

**What it does**: Monitors pod resource usage and identifies rightsizing and cost optimization opportunities.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CostPolicy
metadata:
  name: optimize-costs
  namespace: zelyo-system
spec:
  targetNamespaces: ["production"]
  resizeStrategy: conservative                  # conservative | moderate | aggressive
  budgetLimits:
    monthlyBudgetUSD: "5000"
    costIncreaseThresholdPercent: 20
  idleDetection:
    enabled: true
    cpuThresholdPercent: 5
    memoryThresholdPercent: 5
    idleDurationMinutes: 60
```

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Error
  observedGeneration: 1
  estimatedMonthlyCostUSD: "3200"
  rightsizingRecommendations: 8
  idleWorkloads: 2
  lastEvaluated: "2026-03-03T15:30:00Z"
```

---

## MonitoringPolicy

**What it does**: Configures real-time monitoring, event filtering, and anomaly detection.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: MonitoringPolicy
metadata:
  name: realtime-watch
  namespace: zelyo-system
spec:
  targetNamespaces: ["production"]
  notificationChannels: ["slack-alerts"]        # Must reference existing NotificationChannels
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
    baselineDurationHours: 168                  # 7 days baseline
    sensitivityPercent: 80
```

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Error
  observedGeneration: 1
  activeIncidents: 0
  eventsProcessed: 15420
  lastEventTime: "2026-03-03T15:29:45Z"
```

---

## NotificationChannel

**What it does**: Configures a destination for Zelyo Operator alerts and reports.

### Spec

```yaml
# Slack example
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: slack-alerts
  namespace: zelyo-system
spec:
  type: slack                                   # slack | msteams | pagerduty | alertmanager |
                                                # telegram | whatsapp | webhook | email
  credentialSecret: slack-token                 # Secret with channel credentials
  severityFilter: medium                        # Only alert on this severity and above
  rateLimit:
    maxPerHour: 60
    aggregateSeconds: 30
  slack:
    channel: "#zelyo-operator-alerts"
```

### Status

```yaml
status:
  phase: Active                                 # Pending | Active | Error
  observedGeneration: 1
  lastSentAt: "2026-03-03T15:25:00Z"
  notificationsSent: 342
  lastError: ""
```

**Supported types**: `slack`, `msteams`, `pagerduty`, `alertmanager`, `telegram`, `whatsapp`, `webhook`, `email`

---

## Understanding Status Phases

Every Zelyo Operator resource goes through lifecycle phases. Here's what they mean:

| Phase | Meaning | What to Do |
|---|---|---|
| `Pending` | Resource was just created, not yet reconciled | Wait — the controller will process it shortly |
| `Active` | Resource is working correctly | Nothing — everything is healthy |
| `Synced` | (GitOps only) Repository is synced | Nothing — everything is healthy |
| `Completed` | (Scan only) Scan finished successfully | Check the findings |
| `Degraded` | Partially working (e.g., second ZelyoConfig) | Check Events for details |
| `Error` | Something went wrong | Check `conditions` and Events for the error |
| `Running` | (Scan only) Scan is currently in progress | Wait for completion |

## Understanding Conditions

Every resource has a `conditions` array providing detailed status. The most common conditions:

| Condition | What It Means |
|---|---|
| `Ready = True` | The resource is fully reconciled and operational |
| `Ready = False` | Something is wrong — check the `message` field |
| `SecretResolved = True` | A referenced Secret was found and validated |
| `SecretResolved = False` | A referenced Secret is missing or invalid |
| `ScanCompleted = True` | A scan has finished |
| `GitOpsConnected = True` | A referenced GitOps repository is accessible |

### Checking Conditions

```bash
# Quick status check
kubectl get securitypolicies -A

# Detailed conditions
kubectl get securitypolicy my-policy -o jsonpath='{.status.conditions}' | jq .

# Or use describe
kubectl describe securitypolicy my-policy
```

---

## CloudAccountConfig

**What it does**: Onboards an AWS, GCP, or Azure cloud account for multi-cloud security scanning. The controller authenticates to the cloud provider, runs the enabled scanner categories, and produces ScanReport resources with findings — just like Kubernetes scans.

### Spec

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-production
  namespace: zelyo-system
spec:
  # Cloud provider to scan
  # Options: aws | gcp | azure
  provider: aws

  # Cloud account identifier
  # AWS: 12-digit account ID, GCP: project ID, Azure: subscription ID
  accountId: "123456789012"

  # Regions to scan (provider-specific region codes)
  regions:
    - us-east-1
    - us-west-2

  # Authentication configuration
  authentication:
    method: irsa                              # aws: irsa | podIdentity | static
                                              # gcp: workloadIdentity | static
                                              # azure: podIdentity | static
    roleArn: "arn:aws:iam::123456789012:role/ZelyoSecurityAudit"  # AWS IRSA/Pod Identity
    # gcpServiceAccount: "zelyo@project.iam.gserviceaccount.com"  # GCP Workload Identity
    # azureClientId: "00000000-0000-0000-0000-000000000000"       # Azure Pod Identity
    credentialSecret: ""                      # Secret with static credentials (if method=static)

  # Which cloud scanner categories to enable
  # Options: cspm | ciem | network | dspm | supplychain | cicd
  scanCategories:
    - cspm
    - ciem
    - network
    - dspm
    - supplychain
    - cicd

  # Cron schedule for periodic scans (empty = scan once on creation)
  schedule: "0 */4 * * *"

  # Minimum severity to report. Findings below this level are filtered out.
  # Options: critical | high | medium | low | info
  severity: medium

  # Compliance frameworks to evaluate against cloud findings
  complianceFrameworks: ["soc2", "pci-dss", "hipaa"]

  # Where to send alerts
  notificationChannels: ["slack-alerts"]

  # Maximum number of ScanReports to retain
  historyLimit: 30

  # Pause scanning
  suspend: false
```

**Available scan categories**: `cspm`, `ciem`, `network`, `dspm`, `supplychain`, `cicd`

**Available authentication methods**:

| Provider | Method | Description |
|---|---|---|
| AWS | `irsa` | IAM Roles for Service Accounts (EKS) |
| AWS | `podIdentity` | EKS Pod Identity |
| AWS | `static` | Access key/secret in a Kubernetes Secret |
| GCP | `workloadIdentity` | GKE Workload Identity Federation |
| GCP | `static` | Service account JSON key in a Kubernetes Secret |
| Azure | `podIdentity` | Azure AD Pod Identity / Workload Identity |
| Azure | `static` | Client ID/secret in a Kubernetes Secret |

### Status

```yaml
status:
  phase: Active                               # Pending | Active | Scanning | Completed | Error
  observedGeneration: 2
  lastScanTime: "2026-03-03T16:00:00Z"        # When the last scan started
  completedAt: "2026-03-03T16:03:45Z"         # When the last scan finished
  findingsCount: 23                           # Total findings from last scan
  resourcesScanned: 412                       # Total cloud resources evaluated
  lastReportName: aws-production-1709481234   # Name of the latest ScanReport
  categorySummary:                            # Findings breakdown by category
    cspm: 5
    ciem: 8
    network: 4
    dspm: 3
    supplychain: 2
    cicd: 1
  conditions:
    - type: Ready
      status: "True"
      reason: ReconcileSuccess
      message: "Cloud account onboarded and scanning"
      lastTransitionTime: "2026-03-03T16:00:00Z"
      observedGeneration: 2
    - type: Authenticated
      status: "True"
      reason: CredentialsValid
      message: "Successfully authenticated to AWS account 123456789012"
    - type: ScanCompleted
      status: "True"
      reason: ScanSuccess
      message: "Scan completed: 23 findings across 412 resources"
```

**Key behaviors**:

- Authentication is validated on creation and before each scan. If credentials expire or are revoked, the controller sets `Authenticated = False` and emits a warning event.
- Cloud scans produce `ScanReport` resources owned by the `CloudAccountConfig`, automatically cleaned up when the parent is deleted (via finalizer).
- When `schedule` is set, the controller triggers scans at the specified cron interval. When empty, a single scan runs on resource creation.
- The `historyLimit` field controls how many ScanReports are retained. Older reports are garbage collected after each scan.
