# Getting Started

## Prerequisites

- Go 1.24+
- Docker
- kubectl
- [kind](https://kind.sigs.k8s.io/) (for local development)
- [Kubebuilder](https://kubebuilder.io/) 4.x
- Helm 3.x

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/aotanami/aotanami.git
cd aotanami
```

### 2. Create a Local Cluster

```bash
kind create cluster --name aotanami-dev
```

### 3. Install CRDs

```bash
make install
```

### 4. Run the Operator Locally

```bash
# Set your LLM API key (optional for development)
export AOTANAMI_LLM_API_KEY="your-openrouter-key"

make run
```

### 5. Apply a Sample SecurityPolicy

```yaml
# config/samples/aotanami_v1alpha1_securitypolicy.yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: baseline-security
  namespace: aotanami-system
spec:
  severity: medium
  match:
    namespaces: ["default"]
  rules:
    - name: non-root-containers
      type: container-security-context
      enforce: true
    - name: resource-limits
      type: resource-limits
      enforce: true
    - name: image-tags
      type: image-vulnerability
      enforce: false
```

```bash
kubectl apply -f config/samples/aotanami_v1alpha1_securitypolicy.yaml
```

### 6. Check Status

```bash
# View the policy status
kubectl get securitypolicies -A

# Check operator logs
kubectl logs -f deploy/aotanami-controller-manager -n aotanami-system

# View scan reports
kubectl get scanreports -A
```

## Deploying to a Cluster

### Via Helm (OCI)

```bash
# Create namespace
kubectl create namespace aotanami-system

# Create LLM API key secret
kubectl create secret generic aotanami-llm \
  --namespace aotanami-system \
  --from-literal=api-key=<YOUR_API_KEY>

# Install from OCI registry
helm install aotanami oci://ghcr.io/zelyo-ai/charts/aotanami \
  --namespace aotanami-system \
  --set config.llm.provider=openrouter \
  --set config.llm.model=anthropic/claude-sonnet-4-20250514 \
  --set config.llm.apiKeySecret=aotanami-llm
```

### Enabling Protect Mode

To enable autonomous PR-based remediation, onboard a GitOps repository:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: GitOpsRepository
metadata:
  name: my-infra
  namespace: aotanami-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths:
    - "clusters/production/"
  provider: github
  authSecret: github-credentials
  enableDriftDetection: true
```

## Next Steps

- [Architecture](architecture.md) — understand the system design
- [CRD Reference](crd-reference.md) — explore all CRD fields
- [LLM Configuration](llm-configuration.md) — set up your LLM provider
- [Integrations](integrations.md) — configure notifications
