# Quickstart

Get Zelyo Operator running on your Kubernetes cluster and scanning workloads in under 5 minutes.

Zelyo Operator is an open-source CNAPP that detects security misconfigurations across Kubernetes and cloud infrastructure, correlates them with an LLM, and opens GitOps PRs to fix them.

## Prerequisites

- A running Kubernetes cluster (EKS, GKE, AKS, or any conformant distribution)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) configured and pointing at your cluster
- [Helm](https://helm.sh/docs/intro/install/) 3.x

```bash
kubectl cluster-info && helm version
```

> **Note:** Webhook TLS certificates are self-signed by default. If you prefer cert-manager managed certificates, see [Optional: cert-manager for Webhook TLS](#optional-cert-manager-for-webhook-tls) below.

> **Pin a chart version.** The charts are published to an OCI registry, which has no "latest" alias — every `helm install` below needs `--version`. Find the current tag at [github.com/zelyo-ai/zelyo-operator/releases](https://github.com/zelyo-ai/zelyo-operator/releases) and export it before running the commands:
>
> ```bash
> # Use the latest release tag from https://github.com/zelyo-ai/zelyo-operator/releases
> export ZELYO_VERSION=1.0.0-alpha3
> ```

---

## 1. Install Zelyo Operator

```bash
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --version "$ZELYO_VERSION" \
  --namespace zelyo-system \
  --create-namespace \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set config.llm.apiKeySecret=zelyo-llm
```

This installs the operator, CRDs, and creates the `ZelyoConfig` CR automatically. Override `config.llm.provider` and `config.llm.model` to use a different LLM (see provider table below). The operator starts in Degraded phase until the LLM API key secret is created.

## 2. Add Your LLM API Key

Get a key from [openrouter.ai/keys](https://openrouter.ai/keys) (or any supported provider -- see table below), then:

```bash
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_API_KEY>
```

The operator auto-activates within seconds once the secret is created.

| Provider             | Config value     | Get a key                                                         |
| -------------------- | ---------------- | ----------------------------------------------------------------- |
| OpenRouter           | `openrouter`   | [openrouter.ai/keys](https://openrouter.ai/keys)                     |
| OpenAI               | `openai`       | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| Anthropic            | `anthropic`    | [console.anthropic.com](https://console.anthropic.com)               |
| Azure OpenAI         | `azure-openai` | [Azure Portal](https://portal.azure.com)                             |
| Ollama (self-hosted) | `ollama`       | [ollama.ai](https://ollama.ai)                                       |

## 3. Deploy Default Policies (Recommended)

The `zelyo-policies` Helm chart deploys production-ready security policies covering all 56 scanners in one command:

```bash
helm install zelyo-policies oci://ghcr.io/zelyo-ai/charts/zelyo-policies \
  --version "$ZELYO_VERSION" \
  --namespace zelyo-system
```

This creates:

- **3 SecurityPolicies** -- production (strict), staging (standard), default (standard) with per-environment namespace targeting
- **2 ClusterScans** -- nightly full scan + weekly compliance evaluation with CIS Kubernetes Benchmark
- **1 MonitoringPolicy** -- anomaly detection, warning events, log patterns for auth failures and secret exposure

Override the security profile globally or per-environment:

```bash
# Strict profile for regulated environments
helm install zelyo-policies oci://ghcr.io/zelyo-ai/charts/zelyo-policies \
  --version "$ZELYO_VERSION" \
  --namespace zelyo-system \
  --set global.profile=strict

# Enable SOC 2 + HIPAA compliance evaluation
helm install zelyo-policies oci://ghcr.io/zelyo-ai/charts/zelyo-policies \
  --version "$ZELYO_VERSION" \
  --namespace zelyo-system \
  --set compliance.presets.soc2=true \
  --set compliance.presets.hipaa=true
```

| Profile      | Severity Floor | Rules        | Enforcement           |
| ------------ | -------------- | ------------ | --------------------- |
| `starter`  | high           | 4 core rules | warn only             |
| `standard` | medium         | all 8 rules  | enforce critical+high |
| `strict`   | low            | all 8 rules  | enforce all           |

Verify:

```bash
kubectl get securitypolicies,clusterscans,monitoringpolicies -n zelyo-system
```

If you prefer to create policies manually, skip this step and follow the sections below.

---

## Manual Policy Configuration

The sections below show how to create each policy type individually. If you installed `zelyo-policies` above, these are already deployed and you can skip to [Scan a Cloud Account](#scan-a-cloud-account).

### Create a SecurityPolicy

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: baseline
  namespace: zelyo-system
spec:
  severity: medium
  match:
    namespaces: ["default", "production"]
  rules:
    - name: security-context
      type: container-security-context
      enforce: true
    - name: pod-security
      type: pod-security
      enforce: true
    - name: privilege-escalation
      type: privilege-escalation
      enforce: true
    - name: resource-limits
      type: resource-limits
      enforce: true
    - name: image-pinning
      type: image-vulnerability
      enforce: false
    - name: secrets-exposure
      type: secrets-exposure
      enforce: false
    - name: network-policy
      type: network-policy
      enforce: false
    - name: rbac-audit
      type: rbac-audit
      enforce: false
```

```bash
kubectl get securitypolicies -n zelyo-system
kubectl describe securitypolicy baseline -n zelyo-system
```

The 8 scanner rule types: `container-security-context`, `resource-limits`, `image-vulnerability`, `pod-security`, `privilege-escalation`, `secrets-exposure`, `network-policy`, `rbac-audit`. See [Scanner Reference](scanners.md) for details.

### Schedule a Cluster Scan

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: ClusterScan
metadata:
  name: nightly
  namespace: zelyo-system
spec:
  schedule: "0 2 * * *"
  scanners:
    - container-security-context
    - resource-limits
    - image-vulnerability
    - pod-security
    - privilege-escalation
    - secrets-exposure
    - network-policy
    - rbac-audit
  scope:
    excludeNamespaces: ["kube-system", "kube-public"]
  complianceFrameworks: ["cis"]
  historyLimit: 30
```

```bash
kubectl get scanreports -n zelyo-system
```

---

## Scan a Cloud Account

The `CloudAccountConfig` CRD onboards an AWS account for scanning across 48 cloud security checks in 6 categories.

**IRSA (recommended for EKS):**

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
  scanCategories: ["cspm", "ciem", "network", "dspm", "supply-chain", "cicd-pipeline"]
  complianceFrameworks: ["soc2", "pci-dss"]
  schedule: "0 2 * * *"
  historyLimit: 10
```

**EKS Pod Identity:**

```yaml
spec:
  credentials:
    method: pod-identity
    serviceAccountName: zelyo-operator
```

**Static credentials (non-EKS):**

```bash
kubectl create secret generic aws-creds \
  --namespace zelyo-system \
  --from-literal=aws-access-key-id=<ACCESS_KEY> \
  --from-literal=aws-secret-access-key=<SECRET_KEY>
```

```yaml
spec:
  credentials:
    method: secret
    secretRef: aws-creds
```

Check results:

```bash
kubectl get cloudaccountconfigs -n zelyo-system
kubectl get scanreports -n zelyo-system -l zelyo.ai/scan-type=cloud
```

| Scan category     | Count | Examples                                          |
| ----------------- | ----- | ------------------------------------------------- |
| `cspm`          | 8     | Public S3, unencrypted EBS, CloudTrail disabled   |
| `ciem`          | 8     | Overprivileged IAM, unused keys, MFA not enforced |
| `network`       | 8     | Open SSH/RDP, exposed DB ports, ALB without HTTPS |
| `dspm`          | 8     | Public S3 ACLs, unencrypted DynamoDB, public RDS  |
| `supply-chain`  | 8     | ECR CVEs, stale images, unsigned images           |
| `cicd-pipeline` | 8     | Hardcoded secrets, overprivileged CodeBuild       |

| Compliance framework | Config value    |
| -------------------- | --------------- |
| SOC 2                | `soc2`        |
| PCI-DSS              | `pci-dss`     |
| HIPAA                | `hipaa`       |
| CIS AWS              | `cis-aws`     |
| NIST 800-53          | `nist-800-53` |
| ISO 27001            | `iso-27001`   |

---

## Set Up Notifications

Route alerts to Slack, Teams, PagerDuty, Telegram, WhatsApp, webhooks, or email.

```bash
kubectl create secret generic slack-token \
  --namespace zelyo-system \
  --from-literal=webhook-url=https://hooks.slack.com/services/T.../B.../xxx
```

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: NotificationChannel
metadata:
  name: slack-security
  namespace: zelyo-system
spec:
  type: slack
  credentialSecret: slack-token
  severityFilter: high
  rateLimit:
    maxPerHour: 30
    aggregateSeconds: 60
  slack:
    channel: "#security-alerts"
```

Reference notification channels in your MonitoringPolicy:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: MonitoringPolicy
metadata:
  name: production-monitoring
  namespace: zelyo-system
spec:
  targetNamespaces: ["production"]
  notificationChannels: ["slack-security"]
  eventFilters:
    types: ["Warning"]
    reasons: ["OOMKilled", "CrashLoopBackOff", "FailedScheduling"]
  anomalyDetection:
    enabled: true
    baselineDurationHours: 168
    sensitivityPercent: 80
```

---

## Enable GitOps Remediation

Have Zelyo open GitHub PRs to fix detected issues automatically. This is what "Protect mode" actually means end-to-end: the `ZelyoConfig` mode switches the engine strategy to `gitops-pr`, and a `RemediationPolicy` pointed at a `GitOpsRepository` drives the PR creation.

All three pieces are required — skipping any one of them means no PRs:

| Piece | Role |
| --- | --- |
| `ZelyoConfig.spec.mode: protect` | Flips the remediation engine from `dry-run` to `gitops-pr`. Without this, plans are logged but never submitted. |
| `GitOpsRepository` | Tells Zelyo which repo, branch, and paths to write fixes into, and provides Git auth. |
| `RemediationPolicy` | The only controller that calls `GeneratePlan` + `ApplyPlan`. `severityFilter` gates which incidents qualify; `maxConcurrentPRs` caps the number of open Zelyo PRs on the target repo — already-open PRs count against the budget, so new PRs only open when existing ones merge or close. The current count surfaces on `status.openPRs`. |

**0. Switch `ZelyoConfig` to Protect mode** (`ZelyoConfig` is cluster-scoped — no `-n` flag):

```bash
kubectl patch zelyoconfig zelyo --type=merge -p '{"spec":{"mode":"protect"}}'
```

**1. Create a GitHub token secret:**

```bash
kubectl create secret generic github-creds \
  --namespace zelyo-system \
  --from-literal=token=ghp_xxxxxxxxxxxxxxxxxxxx
```

**2. Onboard your repo:**

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
  namespace: zelyo-system
spec:
  url: https://github.com/YOUR_ORG/YOUR_REPO
  branch: main
  paths: ["clusters/production/"]
  provider: github
  authSecret: github-creds
  enableDriftDetection: true
```

**3. Create a remediation policy:**

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix
  namespace: zelyo-system
spec:
  gitOpsRepository: infra-repo
  prTemplate:
    titlePrefix: "[Zelyo Auto-Fix]"
    labels: ["security", "automated"]
    branchPrefix: "zelyo/fix-"
  severityFilter: high
  maxConcurrentPRs: 3   # caps total open Zelyo PRs on the target repo
  dryRun: false
  autoMerge: false
```

To preview fix plans without opening any PRs, leave `ZelyoConfig.spec.mode: audit`. The remediation engine stays in its `dry-run` strategy and every `RemediationPolicy` logs the plan without submitting it — regardless of per-policy flags.

---

## Cost Optimization

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CostPolicy
metadata:
  name: optimize
  namespace: zelyo-system
spec:
  targetNamespaces: ["production", "staging"]
  resizeStrategy: conservative
  budgetLimits:
    monthlyBudgetUSD: "10000"
    costIncreaseThresholdPercent: 15
  idleDetection:
    enabled: true
    cpuThresholdPercent: 5
    memoryThresholdPercent: 5
    idleDurationMinutes: 60
  notificationChannels: ["slack-security"]
```

---

## Observability

```bash
# Operator logs
kubectl logs -f deploy/zelyo-operator -n zelyo-system

# All Zelyo resources at a glance
kubectl get securitypolicies,clusterscans,scanreports,cloudaccountconfigs,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories,zelyoconfigs -A

# Dashboard (port-forward or expose via Ingress)
kubectl port-forward -n zelyo-system svc/zelyo-operator 8080:8080
```

---

## Optional: cert-manager for Webhook TLS

By default, Zelyo Operator uses self-signed certificates for webhook TLS. If you prefer cert-manager managed certificates:

```bash
# Install cert-manager first
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

# Then install Zelyo Operator with cert-manager enabled
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --version "$ZELYO_VERSION" \
  --namespace zelyo-system \
  --create-namespace \
  --set webhook.certManager.enabled=true \
  --set webhook.selfSigned=false
```

---

## Teardown

```bash
helm uninstall zelyo-policies -n zelyo-system 2>/dev/null
helm uninstall zelyo-operator -n zelyo-system
# Only if you installed cert-manager:
# helm uninstall cert-manager -n cert-manager
```
