# Compliance Frameworks

Aotanami evaluates your cluster against industry-standard compliance frameworks and maps findings to specific controls.

## Supported Frameworks

| Framework | Controls | Description |
|---|---|---|
| **CIS Kubernetes Benchmark** | ~120 | Industry-standard Kubernetes security configuration checks |
| **NSA/CISA Hardening Guide** | ~40 | US government Kubernetes hardening recommendations |
| **PCI-DSS** | ~30 | Payment Card Industry Data Security Standard |
| **SOC 2** | ~25 | Service Organization Control 2 trust service criteria |
| **HIPAA** | ~20 | Health Insurance Portability and Accountability Act |

## Running a Compliance Scan

```yaml
apiVersion: aotanami.com/v1alpha1
kind: ClusterScan
metadata:
  name: compliance-audit
spec:
  schedule: "0 2 * * 1"          # Weekly on Mondays at 2am
  scanners: ["rbac", "pod-security", "netpol", "images"]
  complianceFrameworks: ["cis", "nsa-cisa", "pci-dss"]
  scope:
    namespaces: ["production"]
  historyLimit: 12
```

## Viewing Results

```bash
# List scan reports
kubectl get scanreports -n aotanami-system

# View compliance results
kubectl get scanreport <name> -o jsonpath='{.spec.compliance}'
```

Results are also available in the dashboard under **Scan Results & Compliance**.

## CIS Kubernetes Benchmark

Covers:
- Control Plane configuration
- etcd security
- API server hardening
- Controller manager settings
- Scheduler configuration
- Worker node security
- Pod security policies/standards
- Network policies
- Secrets management
- RBAC configuration

## Custom Rules

You can extend compliance checks with custom CEL expressions in SecurityPolicy resources:

```yaml
apiVersion: aotanami.com/v1alpha1
kind: SecurityPolicy
metadata:
  name: custom-compliance
spec:
  severity: high
  match:
    namespaces: ["production"]
  rules:
    - name: require-labels
      type: container-security-context
      enforce: true
      params:
        required-labels: "app,team,environment"
```
