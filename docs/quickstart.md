# Quickstart

Deploy Zelyo Operator on a local cluster and run your first security scan in under 10 minutes.

Zelyo Operator is an open-source CNAPP that detects security misconfigurations across Kubernetes and cloud infrastructure, correlates them with an LLM, and opens GitOps PRs to fix them.

## Prerequisites

| Tool | Install |
|---|---|
| [Docker](https://docs.docker.com/get-docker/) | Required by k3d |
| [k3d](https://k3d.io/) | `brew install k3d` |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | `brew install kubectl` |
| [Helm](https://helm.sh/docs/intro/install/) | `brew install helm` |

```bash
docker --version && k3d --version && kubectl version --client && helm version
```

## 1. Create a Cluster

```bash
k3d cluster delete zelyo 2>/dev/null; k3d cluster create zelyo
kubectl get nodes
```

## 2. Install cert-manager

Required for webhook TLS certificates.

```bash
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.20.0 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=120s
```

## 3. Build and Load the Operator Image

```bash
make docker-build IMG=zelyo-operator:local
k3d image import zelyo-operator:local -c zelyo
```

## 4. Install Zelyo Operator

```bash
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace \
  --set image.repository=zelyo-operator \
  --set image.tag=local \
  --set image.pullPolicy=IfNotPresent \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set webhook.certManager.enabled=true

kubectl get pods -n zelyo-system
```

## 5. Add Your LLM API Key

Get a key from [openrouter.ai/keys](https://openrouter.ai/keys) (or any supported provider -- see table below), then:

```bash
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_API_KEY>
```

| Provider | Config value | Get a key |
|---|---|---|
| OpenRouter | `openrouter` | [openrouter.ai/keys](https://openrouter.ai/keys) |
| OpenAI | `openai` | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| Anthropic | `anthropic` | [console.anthropic.com](https://console.anthropic.com) |
| Azure OpenAI | `azure-openai` | [Azure Portal](https://portal.azure.com) |
| Ollama (local) | `ollama` | [ollama.ai](https://ollama.ai) |

## 6. Activate the Agent

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: ZelyoConfig
metadata:
  name: default
spec:
  mode: audit
  llm:
    provider: openrouter
    model: "anthropic/claude-sonnet-4-20250514"
    apiKeySecret: zelyo-llm
EOF
```

Set `mode: protect` to enable automated GitOps PR creation (requires a `GitOpsRepository` -- see below).

---

## Run a Security Scan

Deploy a deliberately insecure pod, then apply a SecurityPolicy to scan it:

```bash
kubectl run insecure-nginx --image=nginx:latest --restart=Never -n default

kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: baseline
  namespace: zelyo-system
spec:
  severity: medium
  match:
    namespaces: ["default"]
  rules:
    - name: security-context
      type: container-security-context
      enforce: true
    - name: resource-limits
      type: resource-limits
      enforce: true
    - name: image-pinning
      type: image-vulnerability
      enforce: false
    - name: pod-security
      type: pod-security
      enforce: true
    - name: privilege-escalation
      type: privilege-escalation
      enforce: true
    - name: secrets-exposure
      type: secrets-exposure
      enforce: false
    - name: network-policy
      type: network-policy
      enforce: false
    - name: rbac-audit
      type: rbac-audit
      enforce: false
EOF
```

Check results:

```bash
kubectl get securitypolicies -n zelyo-system
kubectl describe securitypolicy baseline -n zelyo-system
```

The 8 Kubernetes scanner rule types are: `container-security-context`, `resource-limits`, `image-vulnerability`, `pod-security`, `privilege-escalation`, `secrets-exposure`, `network-policy`, `rbac-audit`. See [Scanner Reference](scanners.md) for what each checks.

---

## Schedule a Cluster Scan

A `ClusterScan` runs scanners on a cron schedule and creates `ScanReport` resources for audit history.

```bash
kubectl apply -f - <<'EOF'
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
    namespaces: []
    excludeNamespaces: ["kube-system", "kube-public"]
  historyLimit: 30
EOF
```

```bash
kubectl get scanreports -n zelyo-system --watch
```

Set `schedule: "* * * * *"` to trigger immediately for testing.

---

## Scan a Cloud Account

The `CloudAccountConfig` CRD onboards an AWS account for scanning across 48 cloud security checks.

**IRSA (recommended for EKS):**

```bash
kubectl apply -f - <<'EOF'
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
  historyLimit: 10
EOF
```

**Static credentials (for local/non-EKS clusters):**

```bash
kubectl create secret generic aws-creds \
  --namespace zelyo-system \
  --from-literal=aws-access-key-id=AKIAIOSFODNN7EXAMPLE \
  --from-literal=aws-secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-staging
  namespace: zelyo-system
spec:
  provider: aws
  accountID: "987654321098"
  regions: ["us-east-1"]
  credentials:
    method: secret
    secretRef: aws-creds
  scanCategories: ["cspm", "ciem"]
  complianceFrameworks: ["cis-aws"]
  schedule: "0 6 * * *"
EOF
```

Check results:

```bash
kubectl get cloudaccountconfigs -n zelyo-system
kubectl get scanreports -n zelyo-system -l zelyo.ai/scan-type=cloud
```

| Scan category | Count | Examples |
|---|---|---|
| `cspm` | 8 | Public S3, unencrypted EBS, CloudTrail disabled |
| `ciem` | 8 | Overprivileged IAM, unused keys, MFA not enforced |
| `network` | 8 | Open SSH/RDP, exposed DB ports, ALB without HTTPS |
| `dspm` | 8 | Public S3 ACLs, unencrypted DynamoDB, public RDS |
| `supply-chain` | 8 | ECR CVEs, stale images, unsigned images |
| `cicd-pipeline` | 8 | Hardcoded secrets, overprivileged CodeBuild |

| Compliance framework | Config value |
|---|---|
| SOC 2 | `soc2` |
| PCI-DSS | `pci-dss` |
| HIPAA | `hipaa` |
| CIS AWS | `cis-aws` |
| NIST 800-53 | `nist-800-53` |
| ISO 27001 | `iso-27001` |

---

## Set Up Notifications

Route alerts to Slack (also supports Teams, PagerDuty, Telegram, WhatsApp, webhooks, email).

```bash
kubectl create secret generic slack-token \
  --namespace zelyo-system \
  --from-literal=webhook-url=https://hooks.slack.com/services/T.../B.../xxx

kubectl apply -f - <<'EOF'
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
EOF

kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: MonitoringPolicy
metadata:
  name: production-monitoring
  namespace: zelyo-system
spec:
  targetNamespaces: ["default"]
  notificationChannels: ["slack-security"]
  eventFilters:
    types: ["Warning"]
    reasons: ["OOMKilled", "CrashLoopBackOff", "FailedScheduling"]
EOF
```

---

## Enable GitOps Remediation

Have Zelyo open GitHub PRs to fix detected issues automatically.

**1. Create a GitHub token secret:**

```bash
kubectl create secret generic github-creds \
  --namespace zelyo-system \
  --from-literal=token=ghp_xxxxxxxxxxxxxxxxxxxx
```

**2. Onboard your repo:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: infra-repo
  namespace: zelyo-system
spec:
  url: https://github.com/YOUR_USERNAME/YOUR_REPO
  branch: main
  paths: ["./"]
  provider: github
  authSecret: github-creds
  enableDriftDetection: true
EOF
```

**3. Create a remediation policy:**

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix
  namespace: zelyo-system
spec:
  targetPolicies: ["baseline"]
  gitOpsRepository: infra-repo
  prTemplate:
    titlePrefix: "[Zelyo Auto-Fix]"
    labels: ["security", "automated"]
    branchPrefix: "zelyo-operator/fix-"
  severityFilter: high
  maxConcurrentPRs: 3
  dryRun: false
  autoMerge: false
EOF
```

Set `dryRun: true` to preview what PRs would be created without actually opening them.

---

## Cost Optimization

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: CostPolicy
metadata:
  name: optimize-default
  namespace: zelyo-system
spec:
  targetNamespaces: ["default"]
  resizeStrategy: conservative
  budgetLimits:
    monthlyBudgetUSD: "10000"
    costIncreaseThresholdPercent: 15
  idleDetection:
    enabled: true
    cpuThresholdPercent: 5
    memoryThresholdPercent: 5
    idleDurationMinutes: 60
EOF
```

---

## Observability

```bash
# Operator logs
kubectl logs -f deploy/zelyo-operator -n zelyo-system

# All Zelyo resources at a glance
kubectl get securitypolicies,clusterscans,scanreports,cloudaccountconfigs,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories,zelyoconfigs -A

# Dashboard
kubectl port-forward -n zelyo-system svc/zelyo-operator 8080:8080
# Open http://localhost:8080
```

---

## Teardown

```bash
kubectl delete cloudaccountconfigs,securitypolicies,clusterscans,scanreports,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories --all -n zelyo-system
kubectl delete zelyoconfigs --all
helm uninstall zelyo-operator -n zelyo-system
helm uninstall cert-manager -n cert-manager
k3d cluster delete zelyo
```
