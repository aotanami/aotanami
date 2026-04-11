# Compliance Frameworks

As your AI Security Agent, Zelyo automatically evaluates your cluster and cloud accounts against industry-standard compliance frameworks. Every `ClusterScan` and `CloudAccountConfig` maps security findings to specific compliance controls, generates audit-ready reports with evidence, and emits `ComplianceViolation` Kubernetes events.

## Supported Frameworks

| Framework | Controls | Description |
|---|---|---|
| **CIS Kubernetes Benchmark** | ~120 | Industry-standard Kubernetes security configuration checks |
| **NSA/CISA Hardening Guide** | ~40 | US government Kubernetes hardening recommendations |
| **PCI-DSS** | ~30 (K8s) + 10 (cloud) | Payment Card Industry Data Security Standard |
| **SOC 2** | ~25 (K8s) + 10 (cloud) | Service Organization Control 2 trust service criteria |
| **HIPAA** | ~20 (K8s) + 10 (cloud) | Health Insurance Portability and Accountability Act |

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

---

## Cloud Compliance Controls

In addition to the Kubernetes compliance controls above, Zelyo maps cloud security findings from `CloudAccountConfig` scans to SOC 2, PCI-DSS, and HIPAA controls. Cloud compliance evaluation works the same way as Kubernetes compliance — after each cloud scan, the compliance engine maps findings to control IDs, marks controls as Passed or Failed with evidence, and calculates a compliance percentage.

### SOC 2 Cloud Controls

10 SOC 2 Trust Services Criteria mapped to cloud scanner rule types:

| SOC 2 Control | Title | Mapped Cloud Rule Types |
|---|---|---|
| CC6.1 | Logical and Physical Access Controls | `ciem-overprivileged-iam`, `ciem-wildcard-permissions` |
| CC6.2 | Credentials and Authentication | `ciem-mfa-not-enforced`, `ciem-root-access-keys` |
| CC6.3 | Access Removal and Review | `ciem-unused-access-keys`, `ciem-inactive-users` |
| CC6.6 | Security for Transmission | `network-alb-not-https`, `network-ssh-open` |
| CC6.7 | Restrict Data Movement | `dspm-s3-public-acls`, `dspm-rds-public` |
| CC7.1 | Detection of Changes | `cspm-cloudtrail-disabled`, `cicd-no-audit-logging` |
| CC7.2 | Monitoring for Anomalies | `cspm-vpc-flow-logs`, `cspm-cloudtrail-disabled` |
| CC8.1 | Change Management | `cicd-no-manual-approval`, `cicd-hardcoded-secrets-repo` |
| A1.2 | Environmental Protections | `cspm-unencrypted-ebs`, `dspm-s3-no-encryption` |
| C1.1 | Confidential Information Protection | `dspm-ebs-snapshots-public`, `dspm-cloudwatch-unencrypted` |

### PCI-DSS Cloud Controls

10 PCI-DSS v4.0 requirements mapped to cloud scanner rule types:

| PCI-DSS Control | Title | Mapped Cloud Rule Types |
|---|---|---|
| 1.3.1 | Restrict Inbound Traffic | `network-ssh-open`, `network-rdp-open`, `network-db-ports-exposed` |
| 1.3.2 | Restrict Outbound Traffic | `network-unrestricted-egress`, `network-default-sg-traffic` |
| 2.2.1 | System Configuration Standards | `cspm-public-s3-bucket`, `cspm-vpc-flow-logs` |
| 3.4.1 | Encrypt Stored Cardholder Data | `cspm-unencrypted-ebs`, `dspm-s3-no-encryption`, `dspm-dynamodb-encryption` |
| 3.5.1 | Protect Cryptographic Keys | `cspm-kms-rotation`, `ciem-long-lived-service-keys` |
| 6.3.1 | Identify and Manage Vulnerabilities | `supplychain-ecr-critical-cves`, `supplychain-third-party-cves` |
| 7.2.1 | Restrict Access by Need | `ciem-overprivileged-iam`, `ciem-wildcard-permissions` |
| 8.3.1 | Multi-Factor Authentication | `ciem-mfa-not-enforced`, `ciem-root-access-keys` |
| 10.2.1 | Audit Log Coverage | `cspm-cloudtrail-disabled`, `cicd-no-audit-logging` |
| 11.3.1 | Vulnerability Scanning | `supplychain-images-not-scanned`, `supplychain-ecr-scan-on-push` |

### HIPAA Cloud Controls

10 HIPAA Security Rule safeguards mapped to cloud scanner rule types:

| HIPAA Control | Title | Mapped Cloud Rule Types |
|---|---|---|
| 164.312(a)(1) | Access Control | `ciem-overprivileged-iam`, `ciem-wildcard-permissions` |
| 164.312(a)(2)(i) | Unique User Identification | `ciem-inactive-users`, `ciem-unused-access-keys` |
| 164.312(a)(2)(iii) | Automatic Logoff | `ciem-long-lived-service-keys`, `ciem-unused-access-keys` |
| 164.312(b) | Audit Controls | `cspm-cloudtrail-disabled`, `cicd-no-audit-logging`, `cspm-vpc-flow-logs` |
| 164.312(c)(1) | Integrity Controls | `dspm-s3-object-lock`, `cspm-s3-versioning` |
| 164.312(d) | Person or Entity Authentication | `ciem-mfa-not-enforced`, `ciem-root-access-keys` |
| 164.312(e)(1) | Transmission Security | `network-alb-not-https`, `network-ssh-open` |
| 164.312(e)(2)(ii) | Encryption in Transit | `network-alb-not-https`, `dspm-s3-no-encryption` |
| 164.310(d)(1) | Device and Media Controls | `dspm-ebs-snapshots-public`, `cspm-unencrypted-ebs` |
| 164.308(a)(5)(ii)(B) | Security Awareness Training — Malicious Software | `supplychain-ecr-critical-cves`, `supplychain-hardcoded-secrets-env` |

### Running a Cloud Compliance Scan

To evaluate cloud accounts against compliance frameworks, specify `complianceFrameworks` in your `CloudAccountConfig`:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-production
  namespace: zelyo-system
spec:
  provider: aws
  accountId: "123456789012"
  regions: ["us-east-1"]
  authentication:
    method: irsa
    roleArn: "arn:aws:iam::123456789012:role/ZelyoSecurityAudit"
  scanCategories: ["cspm", "ciem", "network", "dspm", "supplychain", "cicd"]
  complianceFrameworks: ["soc2", "pci-dss", "hipaa"]
  schedule: "0 2 * * 1"
```

Cloud compliance results appear in the `ScanReport` alongside Kubernetes compliance results and are available in the dashboard under **Scan Results & Compliance**.
