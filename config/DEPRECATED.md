# ⚠️ Kustomize is DEPRECATED

**The Kustomize-based installation (`config/`) is deprecated in favor of the Helm chart.**

The `config/` directory exists for two purposes:
1. **Kubebuilder code generation** — `make manifests` still uses these files as output targets
2. **Historical reference** — existing users can see the original Kustomize layout

## Migration to Helm

```bash
# Install via Helm (recommended)
helm install zelyo-operator oci://ghcr.io/zelyo-ai/charts/zelyo-operator \
  --namespace zelyo-system \
  --create-namespace

# Or from local checkout
helm install zelyo-operator deploy/helm/zelyo-operator/ \
  --namespace zelyo-system \
  --create-namespace
```

## What the Helm chart provides that Kustomize didn't

- CRD lifecycle management (install, upgrade, keep on uninstall)
- Webhook TLS via cert-manager integration
- ServiceMonitor for Prometheus auto-discovery
- PodDisruptionBudget for HA
- NetworkPolicy for security hardening
- HorizontalPodAutoscaler
- PrometheusRule for pre-built alerting
- Full operator configuration via `values.yaml`
- Helm test infrastructure
- Rich post-install instructions

## Makefile targets still work

The following Makefile targets still use `config/` for code generation:

```bash
make manifests    # Regenerates CRDs and RBAC from Go markers
make generate     # Regenerates deepcopy functions
make install      # Applies CRDs via Kustomize (dev only)
make deploy       # Full Kustomize deploy (dev only)
```

For production, always use the Helm chart.
