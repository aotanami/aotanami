---
title: Quick Start
---

# Quick Start

Get Aotanami running in under 5 minutes with this hands-on guide.

## Prerequisites

- Kubernetes cluster (1.28+)
- `kubectl` configured
- Helm 3.x installed
- An LLM API key (OpenRouter, OpenAI, or Anthropic)

## Step 1: Create the Namespace

```bash
kubectl create namespace aotanami-system
```

## Step 2: Add Your LLM API Key

```bash
kubectl create secret generic aotanami-llm \
  --namespace aotanami-system \
  --from-literal=api-key=<YOUR_API_KEY>
```

!!! tip "Which provider?"
    We recommend [OpenRouter](https://openrouter.ai/) for the broadest model selection. See [LLM Configuration](llm-configuration.md) for all supported providers.

## Step 3: Install Aotanami

=== "Helm (OCI)"

    ```bash
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

## Step 4: Verify Installation

```bash
kubectl get pods -n aotanami-system
```

Expected output:

```
NAME                        READY   STATUS    RESTARTS   AGE
aotanami-controller-xxx     1/1     Running   0          30s
```

## Step 5: Apply Your First Policy

```yaml title="security-policy.yaml"
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: enforce-non-root
  namespace: aotanami-system
spec:
  severity: critical
  match:
    namespaces: ["default", "production"]
  rules:
    - type: container-security-context
      enforce: true
      autoRemediate: true
```

```bash
kubectl apply -f security-policy.yaml
```

## Step 6: Run a Cluster Scan

```yaml title="cluster-scan.yaml"
apiVersion: aotanami.com/v1alpha1
kind: ClusterScan
metadata:
  name: initial-scan
  namespace: aotanami-system
spec:
  schedule: "*/30 * * * *"
  scanTypes:
    - security
    - compliance
    - cost
  scope:
    namespaces: ["*"]
```

```bash
kubectl apply -f cluster-scan.yaml
```

## Step 7: Verify Image Signature

```bash
cosign verify ghcr.io/aotanami/aotanami:<tag> \
  --certificate-identity-regexp='https://github.com/aotanami/aotanami' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

---

## What's Next?

<div class="feature-grid" markdown>

<div class="feature-card" markdown>
### :material-book-open-variant: Architecture
[Understand how Aotanami works →](architecture.md)
</div>

<div class="feature-card" markdown>
### :material-source-branch: GitOps Onboarding
[Connect your repos for auto-remediation →](gitops-onboarding.md)
</div>

<div class="feature-card" markdown>
### :material-brain: LLM Configuration
[Set up your AI provider →](llm-configuration.md)
</div>

<div class="feature-card" markdown>
### :material-bell-ring: Integrations
[Configure Slack, Teams, PagerDuty →](integrations.md)
</div>

</div>
