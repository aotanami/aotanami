# Getting Started

Welcome to Zelyo Operator! This guide will walk you through a **from-scratch** setup on your local machine using **k3d**, **cert-manager**, and the **Zelyo Operator** Helm chart.

## Prerequisites

Make sure you have the following tools installed:

- **Docker**: For running the local cluster.
- **k3d**: To create a lightweight Kubernetes cluster.
- **kubectl**: To interact with the cluster.
- **Helm**: To install the charts.

---

## Step 1: Create a Local Cluster

First, let's create a fresh cluster named `zelyo`.

```bash
k3d cluster create zelyo
```

---

## Step 2: Install cert-manager

Zelyo Operator requires **cert-manager** to handle TLS certificates for its admission webhooks. Installation takes about 1 minute.

```bash
# Install cert-manager via Helm OCI
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager \
  --version v1.20.0 \
  --namespace cert-manager \
  --create-namespace \
  --set crds.enabled=true
```

## Step 3: Wait for Readiness

Wait until all cert-manager components are healthy before proceeding.

```bash
kubectl wait --for=condition=Ready pods --all -n cert-manager --timeout=120s
```

---

## Step 4: Add LLM API Secret & Install Zelyo Operator

Now, create the namespace and the secret containing your LLM API key (e.g., from OpenRouter). Then, install the operator using its OCI chart.

```bash
# Create the namespace
kubectl create namespace zelyo-system

# Add your LLM API key as a Kubernetes secret
kubectl create secret generic zelyo-llm \
  --namespace zelyo-system \
  --from-literal=api-key=<YOUR_OPENROUTER_API_KEY>

# Install Zelyo Operator from OCI registry
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set config.llm.apiKeySecret=zelyo-llm \
  --set webhook.certManager.enabled=true
```

## Step 5: Verify Installation

Check if the operator pod is running. It might take a moment to pull the image and start.

```bash
kubectl get pods -n zelyo-system
```

---

## Step 6: Test Observation (Observe → Reason)

### 6.1 Deploy a Test Workload
Deploy a deliberately insecure pod so Zelyo has something to find:

```bash
kubectl run insecure-nginx --image=nginx:latest --restart=Never -n default
```

### 6.2 Create a SecurityPolicy
Save this as `test-security-policy.yaml`:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: baseline-security
  namespace: zelyo-system
spec:
  severity: medium
  match:
    namespaces: ["default"]
  rules:
    - name: check-security-context
      type: container-security-context
      enforce: true
    - name: check-resource-limits
      type: resource-limits
      enforce: true
    - name: check-image-tags
      type: image-vulnerability
      enforce: false
    - name: check-privilege-escalation
      type: privilege-escalation
      enforce: true
```

Apply the policy:

```bash
kubectl apply -f test-security-policy.yaml
```

### 6.3 Verify the Findings

Wait a few seconds for the scan to complete, then check the status:

```bash
kubectl get securitypolicies -n zelyo-system
```

You should see a count in the `VIOLATIONS` column. For detailed findings, run:

```bash
kubectl describe securitypolicy baseline-security -n zelyo-system
```

---

## What's Next?

Now that you've got Zelyo Operator running, explore these guides:

| Guide | What You'll Learn |
|---|---|
| [Quick Start Recipes](quickstart.md) | Copy-paste YAML for common use cases |
| [Architecture](architecture.md) | The Observe → Reason → Act pipeline |
| [GitOps Onboarding](gitops-onboarding.md) | Enable **Protect Mode** with auto-fixes |
xes |
