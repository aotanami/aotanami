---
title: "Quickstart Guide - Secure Your Kubernetes Cluster and Cloud Infrastructure"
description: "Deploy Zelyo Operator and run autonomous security scanning across Kubernetes workloads and cloud accounts. Set up AI-powered remediation with GitOps PRs in under 15 minutes."
---

# Quickstart Guide

> [!NOTE]
> **Who is this guide for?**
> This is a complete, self-sufficient guide to setting up and using Zelyo Operator -- from a blank laptop to running AI-powered security scans across Kubernetes and cloud infrastructure. No prior Kubernetes operator experience required.
>
## What Is Zelyo Operator?

Zelyo Operator is an open-source **Cloud-Native Application Protection Platform (CNAPP)** -- an autonomous AI security agent that continuously secures both your Kubernetes clusters and cloud infrastructure.

It is the only open-source tool that auto-generates remediation code and submits it as GitOps pull requests with human review.

**The Detect-Correlate-Fix pipeline:**

```
Detect --> Correlate --> Fix
```

- **Detect**: 56 security scanners (8 Kubernetes + 48 cloud) continuously evaluate your infrastructure across 7 CNAPP security layers: CSPM, CIEM, Network Security, DSPM, Supply Chain, CI/CD Pipeline, and Kubernetes Workload Protection.
- **Correlate**: An LLM reasons over findings, explains root causes, maps violations to 6 compliance frameworks (CIS K8s Benchmark, NIST 800-53, SOC 2, PCI-DSS, HIPAA, ISO 27001), and scores risk.
- **Fix**: The AI agent generates JSON fix plans for Kubernetes YAML and cloud IaC (Terraform/CloudFormation), then opens GitHub PRs for human review.

**10 CRDs for declarative configuration:**

| CRD | Purpose |
|---|---|
| `ZelyoConfig` | Global operator config: LLM provider, mode, token budget |
| `SecurityPolicy` | Kubernetes workload security rules and enforcement |
| `ClusterScan` | Scheduled or on-demand security scans with history |
| `ScanReport` | Immutable audit trail of scan results |
| `CloudAccountConfig` | Cloud account onboarding (AWS, GCP, Azure) |
| `CostPolicy` | Cost monitoring, idle detection, rightsizing |
| `MonitoringPolicy` | Real-time event, log, and anomaly monitoring |
| `NotificationChannel` | Alert routing (Slack, Teams, PagerDuty, Telegram, WhatsApp, webhooks, email) |
| `GitOpsRepository` | Repository onboarding for drift detection and PRs |
| `RemediationPolicy` | Automated PR creation for detected violations |

## Prerequisites

Before starting, install these tools:

| Tool | Version | Install Guide |
|---|---|---|
| [Docker](https://docs.docker.com/get-docker/) | Latest | Required by k3d |
| [k3d](https://k3d.io/) | Latest | `brew install k3d` or [k3d.io](https://k3d.io/) |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | Latest | Comes with Docker Desktop or install standalone |
| [Helm](https://helm.sh/docs/intro/install/) | 3.x | `brew install helm` or [helm.sh](https://helm.sh/) |

> [!TIP]
> **Verify your tools are ready**
> ```bash
> docker --version && k3d --version && kubectl version --client && helm version
> ```
>
## Part 1 -- Environment Setup

### Step 0: Clean the Slate

Start fresh to avoid port conflicts with any previous cluster:

```bash
# Delete any existing zelyo cluster (safe to run even if it doesn't exist)
k3d cluster delete zelyo

# Optional: remove unused Docker networks
docker network prune -f
```

### Step 1: Create a Fresh Local Cluster

```bash
k3d cluster create zelyo
```

This creates a single-node Kubernetes cluster running inside Docker. It takes about 30 seconds.

> [!NOTE]
> **What's happening here?**
> k3d runs Kubernetes inside Docker containers -- much faster than spinning up real VMs. Your `kubectl` context is automatically switched to `k3d-zelyo`.
>
Verify the cluster is running:

```bash
kubectl get nodes
# NAME                 STATUS   ROLES                  AGE   VERSION
# k3d-zelyo-server-0   Ready    control-plane,master   30s   v1.31.x
```

### Step 1.5: Prepare Local Developer Build

> [!TIP]
> **Recommended for Demos**
> For the latest features including cloud scanning and enhanced GitOps logic, build and deploy the operator locally.
>
```bash
# 1. Build the local development image
make docker-build IMG=zelyo-operator:local

# 2. Import the image into your k3d cluster (named 'zelyo')
k3d image import zelyo-operator:local -c zelyo
```

### Step 2: Install cert-manager

Zelyo Operator uses **admission webhooks** to validate resources before they are stored. Webhooks must communicate over HTTPS, which requires TLS certificates. We use cert-manager to automate certificate provisioning.

```bash
# Install cert-manager from the official OCI chart
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.20.0 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true

# Wait until all 3 pods are Running (~60s)
kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=120s
```

Verify:

```bash
kubectl get pods -n cert-manager
# NAME                                       READY   STATUS    RESTARTS   AGE
# cert-manager-xxx                           1/1     Running   0          60s
# cert-manager-cainjector-xxx               1/1     Running   0          60s
# cert-manager-webhook-xxx                  1/1     Running   0          60s
```

### Step 3: Install Zelyo Operator

```bash
# Install the Zelyo Operator
# Note: we are telling it to use our 'local' image we just imported
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace \
  --set image.repository=zelyo-operator \
  --set image.tag=local \
  --set image.pullPolicy=IfNotPresent \
  --set config.llm.provider=openrouter \
  --set config.llm.model=google/gemini-2.0-flash-001 \
  --set webhook.certManager.enabled=true
```

> [!TIP]
> **Verify the operator is running**
> ```bash
> kubectl get pods -n zelyo-system
> # NAME                              READY   STATUS    RESTARTS   AGE
> # zelyo-operator-669577fb4b-7kpg2   1/1     Running   0          30s
> ```
>
> [!WARNING]
> **Webhook Error?**
> If you see `failed calling webhook "msecuritypolicy.zelyo.ai"` when applying resources, run the **[Webhook Patch](troubleshooting.md#webhooks)** commands. This is a known path mismatch in OCI chart `v0.0.1`.
>
### Step 4: Add Your LLM API Key

Now that the `zelyo-system` namespace exists, create the secret the operator will use to call the LLM.

Zelyo Operator needs an LLM to power the Correlate and Fix phases. You provide your own API key -- Zelyo never stores it centrally.

#### Getting an OpenRouter Key (Recommended)

OpenRouter is a gateway that gives you access to Claude, GPT-4, Nvidia, and 100+ other models from one API key with pay-per-use pricing.

1. Go to [openrouter.ai](https://openrouter.ai) and create a free account
2. Navigate to **Keys** -> **Create Key**
3. Copy your key (starts with `sk-or-v1-...`)
4. Add credit at **Credits** (minimum $1) -- models like Claude Haiku cost fractions of a cent per scan

> [!TIP]
> **Model Recommendations**
> | Tier | Model | Cost |
> |---|---|---|
> | **Free tier** | `nvidia/nemotron-3-super-120b-a12b:free` | No cost, great for initial testing |
> | **Best for testing** | `anthropic/claude-haiku` | Fast and cheap (~$0.001 per scan) |
> | **Best for production** | `anthropic/claude-sonnet-4-20250514` | Highest reasoning quality |
>
#### Other Supported Providers

| Provider | Where to Get a Key | Config Value |
|---|---|---|
| **OpenRouter** | [openrouter.ai/keys](https://openrouter.ai/keys) | `openrouter` |
| **OpenAI** | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) | `openai` |
| **Anthropic** | [console.anthropic.com](https://console.anthropic.com) | `anthropic` |
| **Azure OpenAI** | [Azure Portal](https://portal.azure.com) | `azure-openai` |
| **Ollama** (local, free) | [ollama.ai](https://ollama.ai) -- run locally | `ollama` |

#### Create the Kubernetes Secret

```bash
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_API_KEY>
```

> [!CAUTION]
> **Never commit API keys to git.**
> Use `kubectl create secret` or a secrets manager -- never paste them into YAML files.
>
### Step 5: Activate the AI Agent

The last piece of the setup is the `ZelyoConfig`. This is a cluster-scoped resource that tells the operator which LLM model to use and connects it to the secret you just created.

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: ZelyoConfig
metadata:
  name: default
spec:
  mode: protect
  llm:
    provider: openrouter
    model: "google/gemini-2.0-flash-001"
    apiKeySecret: zelyo-llm
EOF
```

> [!NOTE]
> **What's happening here?**
> Once applied, the operator reconciles this config, initializes a secure LLM client using your secret, and injects it into the remediation engine. You will see `ZelyoConfig reconciled successfully` in the logs.
>
> **Operating modes:**
> - `audit` -- Detect and report only. No automated changes.
> - `protect` -- Full pipeline. Detect, correlate, and generate fix PRs automatically.
>
## Part 2 -- The 8 Kubernetes Security Scanners

Zelyo Operator ships with **8 built-in Kubernetes scanners** that evaluate workload configurations in real time. An additional **48 cloud scanners** are available when you onboard a cloud account via `CloudAccountConfig` (see Recipe 7).

### How Scanning Works

1. You create a `SecurityPolicy` with rules (e.g., `type: container-security-context`)
2. The operator finds all pods matching your `spec.match` criteria
3. Each scanner runs and produces findings
4. Findings below your `spec.severity` threshold are filtered out
5. Results are stored in `.status` and emitted as Kubernetes Events

### Scanner Reference

=== "Security Context"

    **Rule type:** `container-security-context`

    Checks that containers follow security best practices for their `securityContext`.

    | Check | Severity | What It Means |
    |---|---|---|
    | No security context set | High | No restrictions at all |
    | `privileged: true` | Critical | Full access to the host kernel |
    | `runAsNonRoot` not set | High | Container might run as root |
    | `readOnlyRootFilesystem` not set | Medium | Filesystem is writable (aids attackers) |
    | `allowPrivilegeEscalation` not false | Medium | Child processes can gain more privileges |

=== "Resource Limits"

    **Rule type:** `resource-limits`

    Checks that every container has CPU and memory requests/limits. Without them, one pod can starve the whole node.

    | Check | Severity |
    |---|---|
    | No CPU request | Medium |
    | No CPU limit | Medium |
    | No memory request | Medium |
    | No memory limit | Medium |

=== "Image Pinning"

    **Rule type:** `image-vulnerability`

    Checks that images are pinned -- not floating on `:latest` or mutable tags.

    | Check | Severity | Why It Matters |
    |---|---|---|
    | Uses `:latest` tag | High | Image can change without notice |
    | No tag (defaults to latest) | High | Same risk |
    | Not pinned by digest | Medium | Even versioned tags can be overwritten |

=== "Pod Security"

    **Rule type:** `pod-security`

    Checks for Pod Security Standards violations.

    | Check | Severity |
    |---|---|
    | `hostNetwork: true` | Critical |
    | `hostPID: true` | Critical |
    | `hostIPC: true` | High |
    | HostPath volume mounts | High--Critical |
    | Dangerous capabilities (SYS_ADMIN, NET_RAW) | High |

=== "Privilege Escalation"

    **Rule type:** `privilege-escalation`

    Checks for settings that let attackers escalate privileges after compromise.

    | Check | Severity |
    |---|---|
    | Runs as root (UID 0) | Critical |
    | Service account token auto-mounted | Medium |
    | Root group (GID 0) | Medium |

    > [!TIP]
    > **Quick win**
    > Add `automountServiceAccountToken: false` to every pod that doesn't need Kubernetes API access. Eliminates the most common privilege escalation vector with one line.
    >
=== "Secrets Exposure"

    **Rule type:** `secrets-exposure`

    Checks for patterns that could leak sensitive data through environment variables.

    | Check | Severity |
    |---|---|
    | Hardcoded secret in env var | Critical |
    | Entire Secret injected via `envFrom` | Medium |
    | Secret passed via `secretKeyRef` | Low |

    **Detected patterns:** env var names containing `password`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credentials`, `auth`.

=== "Network Policy"

    **Rule type:** `network-policy`

    Checks for network segmentation gaps.

    | Check | Severity |
    |---|---|
    | Pod has no labels | Medium |
    | Container uses `hostPort` | High |

=== "RBAC Audit"

    **Rule type:** `rbac-audit`

    Checks for RBAC-related risks at the pod level.

    | Check | Severity |
    |---|---|
    | Uses the `default` service account | Medium |
    | Service account name contains "admin" or "root" | High |

## Part 3 -- Recipes

### Recipe 1: Security Baseline Scan

**Goal:** Find every security misconfiguration across your workloads using all 8 Kubernetes scanners.

#### Deploy a Vulnerable Test Pod

```bash
kubectl run insecure-nginx --image=nginx:latest --restart=Never -n default
```

This pod intentionally has multiple issues: `:latest` tag, no resource limits, no security context, auto-mounted service account token.

#### Apply the Policy

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: production-security-baseline
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

#### Check Results

```bash
# List all security policies and their violation counts
kubectl get securitypolicies -n zelyo-system

# See detailed findings with AI reasoning
kubectl describe securitypolicy production-security-baseline -n zelyo-system
```

**Expected output:**
```
NAME                           SEVERITY   PHASE    VIOLATIONS   AGE
production-security-baseline   medium     Active   8            30s
```

Look at the `Status > Conditions` section in the describe output -- you will see `ScanCompleted=True` and the full reasoning from the LLM.

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete pod insecure-nginx -n default
kubectl delete securitypolicy production-security-baseline -n zelyo-system
```

</details>

### Recipe 2: Critical-Only Alerting

**Goal:** Filter out noise -- only surface high and critical severity findings.

The `spec.severity` field sets the **minimum threshold**. Setting it to `high` means medium, low, and info findings are silently ignored.

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: critical-only
  namespace: zelyo-system
spec:
  severity: high
  match:
    namespaces: ["default"]
  rules:
    - name: privileged-containers
      type: container-security-context
      enforce: true
    - name: host-access
      type: pod-security
      enforce: true
    - name: root-containers
      type: privilege-escalation
      enforce: true
    - name: hardcoded-secrets
      type: secrets-exposure
      enforce: true
EOF
```

```bash
kubectl run insecure-nginx --image=nginx:latest --restart=Never -n default

# Wait 10s then check
kubectl get securitypolicies -n zelyo-system
kubectl describe securitypolicy critical-only -n zelyo-system
```

**Expected:** Fewer violations compared to Recipe 1 -- only high-severity issues appear.

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete pod insecure-nginx -n default
kubectl delete securitypolicy critical-only -n zelyo-system
```

</details>

### Recipe 3: Nightly Full-Cluster Scan

**Goal:** Run all 8 Kubernetes scanners on a schedule and maintain a 30-day history of reports.

A `ClusterScan` creates `ScanReport` resources after each run, giving you a historical audit trail.

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: ClusterScan
metadata:
  name: nightly-full-scan
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
  suspend: false
EOF
```

> [!TIP]
> **Test immediately without waiting until 2 AM**
> Change `schedule: "0 2 * * *"` to `schedule: "* * * * *"` to trigger a scan every minute.
>
#### Watch for Reports

```bash
# Watch ScanReports being created in real-time
kubectl get scanreports -n zelyo-system --watch

# View the latest report's findings
kubectl describe scanreport $(kubectl get scanreports -n zelyo-system \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}') \
  -n zelyo-system
```

**Expected output from `--watch`:**
```
NAME                           SCAN                FINDINGS   CRITICAL   HIGH   AGE
nightly-full-scan-1773826310   nightly-full-scan   20                    6      29s
```

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete clusterscan nightly-full-scan -n zelyo-system
kubectl delete scanreports --all -n zelyo-system
```

</details>

### Recipe 4: Cost Optimization

**Goal:** Find idle or oversized pods and get AI-powered rightsizing recommendations.

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

```bash
kubectl get costpolicy optimize-default -n zelyo-system -o wide
kubectl describe costpolicy optimize-default -n zelyo-system
```

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete costpolicy optimize-default -n zelyo-system
```

</details>

### Recipe 5: Slack Alerts

**Goal:** Send security alerts directly to a Slack channel when violations are found.

#### Step 1: Get a Slack Webhook URL

> [!TIP]
> **How to get a Slack Webhook URL**
> 1. Go to [api.slack.com/apps](https://api.slack.com/apps)
> 2. Click **Create New App** -> **From scratch**
> 3. Choose a name (e.g., "Zelyo Operator") and your workspace
> 4. Go to **Incoming Webhooks** -> toggle **Activate Incoming Webhooks** to On
> 5. Click **Add New Webhook to Workspace** -> choose your channel -> **Allow**
> 6. Copy the Webhook URL (starts with `https://hooks.slack.com/services/...`)
>
#### Step 2: Create the Secret

```bash
kubectl create secret generic slack-token \
  --namespace zelyo-system \
  --from-literal=webhook-url=https://hooks.slack.com/services/YOUR_WORKSPACE/YOUR_CHANNEL/YOUR_TOKEN
```

#### Step 3: Create the NotificationChannel

```bash
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
```

#### Step 4: Attach to a MonitoringPolicy

```bash
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

#### Verify Setup

```bash
kubectl get notificationchannel slack-security -n zelyo-system
kubectl get monitoringpolicy production-monitoring -n zelyo-system
```

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete monitoringpolicy production-monitoring -n zelyo-system
kubectl delete notificationchannel slack-security -n zelyo-system
kubectl delete secret slack-token -n zelyo-system
```

</details>

### Recipe 6: GitOps Automated Remediation

**Goal:** Have Zelyo Operator automatically open GitHub PRs to fix detected security issues -- no manual intervention required.

#### Step 1: Create a GitHub Personal Access Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Select scopes: `repo` (full control of private repos)
4. Click **Generate token** and copy it (starts with `ghp_...`)

> [!CAUTION]
> **Store your token securely.**
> GitHub only shows it once. If lost, you must regenerate it.
>
#### Step 2: Create the Kubernetes Secret

```bash
kubectl create secret generic github-creds \
  --namespace zelyo-system \
  --from-literal=token=ghp_xxxxxxxxxxxxxxxxxxxx
```

#### Step 3: Onboard Your Repository

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

Verify onboarding:

```bash
kubectl get gitopsrepository infra-repo -n zelyo-system
kubectl describe gitopsrepository infra-repo -n zelyo-system
```

Look for these conditions in the output:

- `SecretResolved` -> authentication secret found
- `GitOpsConnected` -> repository is reachable
- `Ready` -> everything is operational

#### Step 4: Create a RemediationPolicy

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-fix-security
  namespace: zelyo-system
spec:
  targetPolicies: ["production-security-baseline"]
  gitOpsRepository: infra-repo
  prTemplate:
    titlePrefix: "[Zelyo Operator Auto-Fix]"
    labels: ["security", "automated"]
    branchPrefix: "zelyo-operator/fix-"
  severityFilter: high
  maxConcurrentPRs: 3
  dryRun: false
  autoMerge: false
EOF
```

> [!NOTE]
> **`dryRun: true` for testing**
> Set this while testing to see what PRs would be created without actually opening them. Switch to `false` when ready to go live.
>
<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete remediationpolicy auto-fix-security -n zelyo-system
kubectl delete gitopsrepository infra-repo -n zelyo-system
kubectl delete secret github-creds -n zelyo-system
```

</details>

### Recipe 7: Cloud Account Security Scanning

**Goal:** Onboard an AWS account and scan it across CSPM, CIEM, Network Security, and DSPM -- the 48 cloud scanners that extend Zelyo Operator beyond Kubernetes.

Cloud scanning uses the `CloudAccountConfig` CRD. Each resource represents one cloud account and configures which regions, scanner categories, and compliance frameworks to evaluate.

#### Option A: IRSA Credentials (Recommended for EKS)

If your cluster runs on EKS, use IAM Roles for Service Accounts (IRSA) -- no static credentials needed.

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-production
  namespace: zelyo-system
spec:
  provider: aws
  accountID: "123456789012"
  regions:
    - us-east-1
    - us-west-2
  credentials:
    method: irsa
    roleARN: "arn:aws:iam::123456789012:role/ZelyoReadOnly"
  scanCategories:
    - cspm
    - ciem
    - network
    - dspm
  complianceFrameworks:
    - soc2
    - pci-dss
    - hipaa
  historyLimit: 10
EOF
```

**What the scan categories cover:**

| Category | Scanners | Examples |
|---|---|---|
| `cspm` | 8 scanners | Public S3 buckets, unencrypted EBS, CloudTrail disabled, KMS rotation |
| `ciem` | 8 scanners | Overprivileged IAM, unused access keys, wildcard permissions, MFA not enforced |
| `network` | 8 scanners | Open SSH/RDP, exposed DB ports, ALB without HTTPS, unrestricted egress |
| `dspm` | 8 scanners | Public S3 ACLs, unencrypted DynamoDB, public RDS, public EBS snapshots |
| `supply-chain` | 8 scanners | ECR critical CVEs, stale base images, unsigned images, missing SBOMs |
| `cicd-pipeline` | 8 scanners | Hardcoded secrets in repos, overprivileged CodeBuild, no audit logging |

#### Option B: Secret-Based Credentials (Non-EKS Environments)

For k3d, kind, or self-managed clusters that do not have IRSA/Pod Identity, use static credentials stored in a Kubernetes Secret.

```bash
# Create the credentials secret
kubectl create secret generic aws-creds \
  --namespace zelyo-system \
  --from-literal=aws-access-key-id=AKIAIOSFODNN7EXAMPLE \
  --from-literal=aws-secret-access-key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-staging
  namespace: zelyo-system
spec:
  provider: aws
  accountID: "987654321098"
  regions:
    - us-east-1
  credentials:
    method: secret
    secretRef: aws-creds
  scanCategories:
    - cspm
    - ciem
  complianceFrameworks:
    - cis-aws
    - nist-800-53
  schedule: "0 6 * * *"
  historyLimit: 5
EOF
```

> [!CAUTION]
> **Use IRSA or Pod Identity in production.**
> Static credentials are acceptable for local testing but should not be used in production environments. Prefer `irsa` (EKS), `workload-identity` (GKE), or `pod-identity` (EKS Pod Identity) in real deployments.
>
#### Check Results

```bash
# List all onboarded cloud accounts
kubectl get cloudaccountconfigs -n zelyo-system

# View detailed scan status and findings summary
kubectl describe cloudaccountconfig aws-production -n zelyo-system

# List cloud scan reports
kubectl get scanreports -n zelyo-system -l zelyo.ai/scan-type=cloud
```

**Expected output:**
```
NAME             PROVIDER   ACCOUNT        PHASE       FINDINGS   LAST SCAN              AGE
aws-production   aws        123456789012   Completed   42         2026-04-11T02:00:00Z   1d
aws-staging      aws        987654321098   Active      17         2026-04-11T06:00:00Z   1d
```

Look for these conditions in the describe output:

- `CloudConnected` -> cloud provider is reachable and credentials are valid
- `CloudScanCompleted` -> the last scan finished successfully
- `Ready` -> the resource is fully operational

**Available compliance frameworks for cloud accounts:**

| Framework | Config Value |
|---|---|
| SOC 2 | `soc2` |
| PCI-DSS | `pci-dss` |
| HIPAA | `hipaa` |
| CIS AWS Benchmark | `cis-aws` |
| NIST 800-53 | `nist-800-53` |
| ISO 27001 | `iso-27001` |

<details>
<summary><strong>Cleanup</strong></summary>

```bash
kubectl delete cloudaccountconfig aws-production -n zelyo-system
kubectl delete cloudaccountconfig aws-staging -n zelyo-system
kubectl delete secret aws-creds -n zelyo-system
```

</details>

## Part 4 -- Advanced Configuration

### LLM Configuration via ZelyoConfig

You can fine-tune the LLM behaviour and set cost limits using the `ZelyoConfig` CRD:

```bash
kubectl apply -f - <<'EOF'
apiVersion: zelyo.ai/v1alpha1
kind: ZelyoConfig
metadata:
  name: default
spec:
  mode: protect
  llm:
    provider: openrouter
    model: "anthropic/claude-sonnet-4-20250514"
    apiKeySecret: zelyo-llm
    maxTokensPerRequest: 4096
  tokenBudget:
    hourlyTokenLimit: 50000
    dailyTokenLimit: 500000
    monthlyTokenLimit: 10000000
    alertThresholdPercent: 80
    enableCaching: true
    batchingEnabled: true
EOF
```

Monitor LLM token usage:

```bash
kubectl get zelyoconfigs default -o jsonpath='{.status.tokenUsage}'
```

### Switching LLM Providers

| Provider | Model String | Note |
|---|---|---|
| OpenRouter | `anthropic/claude-sonnet-4-20250514` | Best quality |
| OpenRouter | `anthropic/claude-haiku` | Fast and cheap |
| OpenAI | `gpt-4o` | OpenAI native |
| Azure OpenAI | `gpt-4o` | Enterprise Azure |
| Ollama (local) | `llama3` | Free, no internet needed |

To switch:

```bash
helm upgrade zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --set config.llm.provider=openai \
  --set config.llm.model=gpt-4o \
  --set config.llm.apiKeySecret=zelyo-llm
```

## Part 5 -- Observability

### Check Operator Health

```bash
# Pod status
kubectl get pods -n zelyo-system

# Live log stream
kubectl logs -f deploy/zelyo-operator -n zelyo-system

# Events for a specific resource
kubectl events --for securitypolicy/production-security-baseline -n zelyo-system
```

### Inspect Resource Status

```bash
# List all Zelyo resources across namespaces (including cloud accounts)
kubectl get cloudaccountconfigs,securitypolicies,clusterscans,scanreports,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories,zelyoconfigs -A

# Get conditions as JSON for a security policy
kubectl get securitypolicy production-security-baseline -n zelyo-system \
  -o jsonpath='{.status.conditions}' | jq .

# View cloud account scan summary
kubectl get cloudaccountconfigs -n zelyo-system -o wide
```

### Dashboard

Zelyo Operator includes a built-in web dashboard:

```bash
kubectl port-forward -n zelyo-system svc/zelyo-operator 8080:8080
# Then open http://localhost:8080
```

## Part 6 -- Verification & Troubleshooting

After applying your policies, monitor the operator logs to ensure that notifications are being sent and remediation plans are being generated.

For specific commands to verify Slack alerts, AI reasoning (LLM) status, and GitOps PR creation, see the **[Troubleshooting Guide](troubleshooting.md)**.

> [!WARNING]
> **Webhook Error?**
> If you see `failed calling webhook "msecuritypolicy.zelyo.ai"` while applying any resource, run the [Webhook Patch](troubleshooting.md#webhooks) commands. This is a known issue with OCI chart `v0.0.1`.
>
## Part 7 -- Full Environment Teardown

When you are done testing, remove everything cleanly:

```bash
# Delete all Zelyo resources (including cloud accounts)
kubectl delete cloudaccountconfigs,securitypolicies,clusterscans,scanreports,costpolicies,monitoringpolicies,notificationchannels,remediationpolicies,gitopsrepositories --all -n zelyo-system
kubectl delete zelyoconfigs --all

# Uninstall the operator and cert-manager
helm uninstall zelyo-operator -n zelyo-system
helm uninstall cert-manager -n cert-manager

# Delete the cluster
k3d cluster delete zelyo
```
