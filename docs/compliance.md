# Compliance Frameworks

As your Digital SRE and Security Engineer, Zelyo automatically evaluates your cluster against industry-standard compliance frameworks. Every `ClusterScan` maps security findings to specific compliance controls, generates audit-ready reports with evidence, and emits `ComplianceViolation` Kubernetes events.

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
apiVersion: zelyo.ai/v1alpha1
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
kubectl get scanreports -n zelyo-system

# View compliance results
kubectl get scanreport <name> -o jsonpath='{.spec.compliance}'
```

Results are also available in the dashboard under **Scan Results & Compliance**.

## CIS Kubernetes Benchmark

Zelyo Operator's `internal/compliance` package implements **15 CIS Kubernetes Benchmark v1.8 controls** mapped directly to scanner rule types:

| CIS Control | Title | Mapped Scanner Rules |
|---|---|---|
| 5.2.1 | Minimize admission of privileged containers | `container-security-context`, `pod-security` |
| 5.2.2 | Minimize host PID namespace sharing | `pod-security` |
| 5.2.3 | Minimize host IPC namespace sharing | `pod-security` |
| 5.2.4 | Minimize host network namespace sharing | `pod-security`, `network-policy` |
| 5.2.5 | Minimize allowPrivilegeEscalation | `privilege-escalation`, `container-security-context` |
| 5.2.6 | Minimize admission of root containers | `privilege-escalation`, `container-security-context` |
| 5.2.7 | Minimize NET_RAW capability | `pod-security` |
| 5.2.8 | Minimize added capabilities | `pod-security` |
| 5.2.9 | Minimize assigned capabilities | `pod-security` |
| 5.4.1 | Prefer secrets as files over env vars | `secrets-exposure` |
| 5.4.2 | Consider external secret storage | `secrets-exposure` |
| 5.7.1 | Administrative boundaries via namespaces | `rbac-audit` |
| 5.7.2 | Seccomp profile in pod definitions | `container-security-context` |
| 5.7.3 | Apply Security Context to pods | `container-security-context` |
| 5.7.4 | Default namespace not used | `rbac-audit` |

### How Evaluation Works

After every `ClusterScan`, the `EvaluateFindings()` function:

1. Loads the CIS control definitions with their `RelatedRuleTypes`
2. Builds a map of violated rule types from scan findings
3. For each control, checks if any `RelatedRuleType` matches a violated rule
4. Marks matched controls as **Failed** with evidence (finding title, resource ref, timestamp)
5. Marks unmatched controls as **Passed**
6. Calculates compliance percentage: `passed / total × 100`

If any controls fail, the controller emits a `ComplianceViolation` Kubernetes event:

```
CIS Kubernetes Benchmark: 73.3% compliant (11/15 controls passed, 4 failed)
```

## Custom Rules

You can extend compliance checks with custom CEL expressions in SecurityPolicy resources:

```yaml
apiVersion: zelyo.ai/v1alpha1
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
