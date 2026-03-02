# GitOps Repository Onboarding

This guide explains how to connect your existing GitOps repositories to Aotanami for drift detection and automated remediation.

## Overview

When you onboard a GitOps repository, Aotanami:

1. **Validates** connectivity and authentication
2. **Discovers** Kubernetes manifests in the configured paths
3. **Maps** manifests to live cluster resources
4. **Detects drift** between repo state and cluster state
5. **Generates fix PRs** targeting the correct files in your repo

## Prerequisites

- A GitHub, GitLab, or Bitbucket repository containing Kubernetes manifests
- Authentication credentials (GitHub App, PAT, or deploy key)

## Step 1: Create Authentication Secret

### GitHub App (Recommended)

```bash
kubectl create secret generic github-app-creds \
  --namespace aotanami-system \
  --from-file=private-key=github-app.pem \
  --from-literal=app-id=12345 \
  --from-literal=installation-id=67890
```

### Personal Access Token

```bash
kubectl create secret generic github-pat \
  --namespace aotanami-system \
  --from-literal=token=ghp_xxxxxxxxxxxx
```

## Step 2: Create GitOpsRepository Resource

```yaml
apiVersion: aotanami.com/v1alpha1
kind: GitOpsRepository
metadata:
  name: production-manifests
  namespace: aotanami-system
spec:
  url: https://github.com/my-org/k8s-manifests
  branch: main
  paths:
    - "clusters/production/"
    - "base/"
  provider: github
  authSecret: github-app-creds
  syncStrategy: poll
  pollIntervalSeconds: 300
  enableDriftDetection: true
  namespaceMapping:
    - repoPath: "clusters/production/apps/"
      namespace: production
    - repoPath: "clusters/production/monitoring/"
      namespace: monitoring
```

## Step 3: Verify Onboarding

```bash
kubectl get gitopsrepositories -n aotanami-system

# Expected output:
# NAME                    URL                                          BRANCH   PHASE    DRIFTS   AGE
# production-manifests    https://github.com/my-org/k8s-manifests     main     Synced   3        5m
```

## Step 4: Enable Protect Mode

Create a RemediationPolicy to start receiving fix PRs:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: RemediationPolicy
metadata:
  name: auto-remediate
  namespace: aotanami-system
spec:
  gitOpsRepository: production-manifests
  severityFilter: high
  prTemplate:
    titlePrefix: "[Aotanami]"
    labels: ["auto-fix", "security"]
  maxConcurrentPRs: 3
```

## Supported Repository Structures

Aotanami supports:
- **Plain YAML/JSON** manifests
- **Kustomize** overlays (detects `kustomization.yaml`)
- **Helm values** files (detects `values.yaml` alongside `Chart.yaml`)

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Phase stuck at `Pending` | Auth secret missing or invalid | Check secret exists and has correct keys |
| Phase shows `Error` | Cannot reach repo URL | Verify network access and URL |
| 0 discovered manifests | Wrong paths configured | Check `spec.paths` matches your repo structure |
| Drift count unexpectedly high | Namespace mapping incorrect | Verify `namespaceMapping` matches your layout |
