# GitOps Repository Onboarding

This guide explains how to connect your existing GitOps repositories to Zelyo Operator for drift detection and automated remediation.

## Overview

When you onboard a GitOps repository, Zelyo Operator:

1. **Validates** connectivity and authentication
2. **Auto-discovers** manifest source types (Helm, Kustomize, raw YAML)
3. **Detects** GitOps controllers (ArgoCD, Flux) on the cluster
4. **Links** to controller-managed applications for sync awareness
5. **Discovers** Kubernetes manifests in the configured paths
6. **Maps** manifests to live cluster resources
7. **Detects drift** between repo state and cluster state
8. **Generates fix PRs** targeting the correct files in your repo

## Prerequisites

- A GitHub, GitLab, or Bitbucket repository containing Kubernetes manifests
- Authentication credentials (GitHub App, PAT, or deploy key)

## Step 1: Create Authentication Secret

### GitHub App (Recommended)

```bash
kubectl create secret generic github-app-creds \
  --namespace zelyo-system \
  --from-file=private-key=github-app.pem \
  --from-literal=app-id=12345 \
  --from-literal=installation-id=67890
```

### Personal Access Token

```bash
kubectl create secret generic github-pat \
  --namespace zelyo-system \
  --from-literal=token=ghp_xxxxxxxxxxxx
```

## Step 2: Create GitOpsRepository Resource

### Auto-Detect Everything (Recommended)

The simplest configuration — Zelyo Operator auto-detects your source type and GitOps controller:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: production-manifests
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths:
    - "clusters/production/"
    - "base/"
  provider: github
  authSecret: github-app-creds
  # sourceType: auto (default) - detects Helm/Kustomize/raw automatically
  # controllerType: auto (default) - detects ArgoCD/Flux automatically
  enableDriftDetection: true
  namespaceMapping:
    - repoPath: "clusters/production/apps/"
      namespace: production
    - repoPath: "clusters/production/monitoring/"
      namespace: monitoring
```

### ArgoCD + Helm Chart

For a repo managed by ArgoCD with Helm charts:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: frontend-helm
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/helm-charts
  branch: main
  paths:
    - "charts/frontend/"
  provider: github
  authSecret: github-app-creds
  sourceType: helm
  controllerType: argocd
  controllerRef:
    type: argocd
    name: frontend-app         # ArgoCD Application name
    namespace: argocd          # ArgoCD namespace
  helm:
    chartPath: "charts/frontend/"
    valuesFiles:
      - "charts/frontend/values.yaml"
      - "charts/frontend/values-production.yaml"
    releaseName: frontend
    releaseNamespace: production
  enableDriftDetection: true
```

### Flux + Kustomize Overlays

For a repo managed by Flux with Kustomize overlays:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: GitOpsRepository
metadata:
  name: platform-config
  namespace: zelyo-system
spec:
  url: https://github.com/my-org/platform-config
  branch: main
  paths:
    - "overlays/production/"
  provider: github
  authSecret: github-app-creds
  sourceType: kustomize
  controllerType: flux
  controllerRef:
    type: flux
    name: production-kustomization   # Flux Kustomization name
    namespace: flux-system           # Flux namespace
  kustomize:
    overlayPaths:
      - "overlays/production/"
      - "overlays/production/monitoring/"
    buildArgs:
      - "--enable-helm"
  enableDriftDetection: true
```

## Step 3: Verify Onboarding

```bash
kubectl get gitopsrepositories -n zelyo-system

# Expected output:
# NAME                  URL                                          BRANCH   SOURCE       CONTROLLER   PHASE    DRIFTS   AGE
# production-manifests  https://github.com/my-org/k8s-manifests     main     raw          argocd       Synced   3        5m
# frontend-helm         https://github.com/my-org/helm-charts       main     helm         argocd       Synced   0        3m
# platform-config       https://github.com/my-org/platform-config   main     kustomize    flux         Synced   1        2m
```

Check detailed status:

```bash
kubectl describe gitopsrepository production-manifests -n zelyo-system
```

Look for these conditions:
- `SecretResolved` — authentication secret found
- `SourceDetected` — manifest source type determined
- `ControllerLinked` — GitOps controller discovered and linked
- `GitOpsConnected` — repository is reachable
- `Ready` — everything is operational

## Step 4: Enable Protect Mode

Create a RemediationPolicy to start receiving fix PRs:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-remediate
  namespace: zelyo-system
spec:
  gitOpsRepository: production-manifests
  severityFilter: high
  prTemplate:
    titlePrefix: "[Zelyo Operator]"
    labels: ["auto-fix", "security"]
  maxConcurrentPRs: 3
```

## Supported Repository Structures

### Manifest Source Types

| Source Type | Detection Method | Description |
|---|---|---|
| `raw` | Fallback | Plain YAML/JSON Kubernetes manifests |
| `helm` | `Chart.yaml` present | Helm chart with templates and values |
| `kustomize` | `kustomization.yaml` present | Kustomize overlays and patches |
| `auto` (default) | Scans all markers | Zelyo Operator detects the type automatically |

### GitOps Controller Support

| Controller | Detection Method | Integration Features |
|---|---|---|
| ArgoCD | `argoproj.io/v1alpha1` API group | Application discovery, sync status, health |
| Flux | `source.toolkit.fluxcd.io` API group | GitRepository, Kustomization, HelmRelease discovery |
| None | — | Standalone Zelyo Operator drift detection |
| Auto (default) | Probes cluster APIs | Detects whichever controller is installed |

### Monorepo Support

Zelyo Operator supports monorepos with mixed source types:

```
my-monorepo/
├── apps/
│   ├── frontend/         # Helm chart (Chart.yaml)
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   └── templates/
│   └── backend/          # Kustomize (kustomization.yaml)
│       ├── kustomization.yaml
│       └── deployment.yaml
├── infra/                # Raw YAML
│   ├── namespace.yaml
│   └── rbac.yaml
```

Configure with multiple paths:

```yaml
spec:
  paths:
    - "apps/frontend/"
    - "apps/backend/"
    - "infra/"
  sourceType: auto   # Each path detected independently
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Phase stuck at `Pending` | Auth secret missing or invalid | Check secret exists and has correct keys |
| Phase shows `Error` | Cannot reach repo URL | Verify network access and URL |
| 0 discovered manifests | Wrong paths configured | Check `spec.paths` matches your repo structure |
| Drift count unexpectedly high | Namespace mapping incorrect | Verify `namespaceMapping` matches your layout |
| `SourceDetected` is False | Paths don't contain expected markers | Verify Chart.yaml/kustomization.yaml exist |
| `ControllerLinked` is False | GitOps controller CRDs not installed | Install ArgoCD/Flux or set `controllerType: none` |
| Applications count is 0 | Repo URL mismatch | Ensure ArgoCD/Flux app's `repoURL` matches `spec.url` |
