# Security Scanners

Zelyo Operator ships with **56 built-in security scanners** — 8 Kubernetes scanners that check your workloads for common misconfigurations and vulnerabilities, plus 48 cloud security scanners that audit your AWS, GCP, and Azure accounts. Kubernetes scanners run automatically when triggered by a `SecurityPolicy` or `ClusterScan`. Cloud scanners run when triggered by a `CloudAccountConfig`.

## How Scanners Work

When you create a SecurityPolicy with a rule like `type: container-security-context`, here's what happens:

1. The controller finds all pods matching your `spec.match` criteria
2. It looks up the scanner registered for that rule type
3. The scanner examines each pod and returns a list of findings
4. Findings below your `spec.severity` threshold are filtered out
5. The remaining findings are recorded in `.status.violationCount` and as Kubernetes Events

## Scanner Reference

### Container Security Context

**Rule type**: `container-security-context`

Checks that containers follow security best practices for their `securityContext` settings.

| Check | Severity | What It Means |
|---|---|---|
| No security context set | High | The container has no security restrictions at all |
| `privileged: true` | Critical | The container has full access to the host kernel |
| `runAsNonRoot` not set | High | The container might run as root (UID 0) |
| `readOnlyRootFilesystem` not set | Medium | The container's filesystem is writable, which aids attackers |
| `allowPrivilegeEscalation` not set to false | Medium | Child processes could gain more privileges than the parent |

**Example Policy**:

```yaml
rules:
  - name: enforce-security-context
    type: container-security-context
    enforce: true
```

---

### Resource Limits

**Rule type**: `resource-limits`

Checks that containers have CPU and memory requests/limits set. Without these, a single pod can consume all resources on a node.

| Check | Severity | What It Means |
|---|---|---|
| No CPU request | Medium | Kubernetes can't properly schedule the pod |
| No CPU limit | Medium | The pod can consume unlimited CPU |
| No memory request | Medium | Kubernetes can't guarantee memory for the pod |
| No memory limit | Medium | The pod can cause OOM kills on the node |

**Example Policy**:

```yaml
rules:
  - name: enforce-resource-limits
    type: resource-limits
    enforce: true
```

---

### Image Pinning

**Rule type**: `image-vulnerability`

Checks that container images are pinned to specific versions, not floating tags.

| Check | Severity | What It Means |
|---|---|---|
| Uses `:latest` tag | High | The image could change without your knowledge |
| No tag at all (defaults to `:latest`) | High | Same as above — implicit latest |
| Not pinned by digest | Medium | Even versioned tags can be overwritten |

**Example Policy**:

```yaml
rules:
  - name: pin-images
    type: image-vulnerability
    enforce: false  # Alert only, don't block
```

---

### Pod Security

**Rule type**: `pod-security`

Checks for Pod Security Standards violations that could expose your cluster.

| Check | Severity | What It Means |
|---|---|---|
| `hostNetwork: true` | Critical | Pod can see all host network interfaces, bypasses NetworkPolicies |
| `hostPID: true` | Critical | Pod can see and signal all host processes |
| `hostIPC: true` | High | Pod can communicate with host processes via shared memory |
| HostPath volume mounts | High–Critical | Pod has access to host filesystem (Critical for `/var/run/docker.sock`, `/etc`, `/root`) |
| Dangerous capabilities (SYS_ADMIN, NET_RAW) | High | Container has elevated kernel privileges |
| `shareProcessNamespace: true` | Medium | Containers can see each other's processes |

---

### Privilege Escalation

**Rule type**: `privilege-escalation`

Checks for settings that could allow an attacker to escalate their privileges after compromise.

| Check | Severity | What It Means |
|---|---|---|
| Runs as root (UID 0) — pod or container level | Critical | Maximum impact if the container is compromised |
| Service account token auto-mounted | Medium | The pod can talk to the Kubernetes API if compromised |
| Root group (GID 0) | Medium | Files created by the container are owned by root group |
| Unmasked `/proc` mount | Critical | Exposes sensitive host information through /proc |

!!! tip "Quick win"
    Add `automountServiceAccountToken: false` to every pod that doesn't need Kubernetes API access. This eliminates the most common privilege escalation vector.

---

### Secrets Exposure

**Rule type**: `secrets-exposure`

Checks for patterns that could leak sensitive data.

| Check | Severity | What It Means |
|---|---|---|
| Hardcoded secret in environment variable | Critical | The secret is visible in the pod spec, etcd, and potentially logs |
| Entire Secret injected via `envFrom` | Medium | All keys exposed as env vars; harder to audit than volume mounts |
| Secret passed via `secretKeyRef` env var | Low | Better than hardcoding, but volume-mounted secrets are even better |

**What counts as "sensitive"?** Environment variable names containing: `password`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credentials`, `auth`.

---

### Network Policy

**Rule type**: `network-policy`

Checks for network segmentation issues.

| Check | Severity | What It Means |
|---|---|---|
| Pod has no labels | Medium | Impossible to target with NetworkPolicy podSelector rules |
| Container uses `hostPort` | High | Bypasses Kubernetes NetworkPolicies, exposes port on every node |

!!! note "System namespaces are skipped"
    Pods in `kube-system`, `kube-public`, `kube-node-lease`, and `zelyo-system` are excluded from network policy checks, since they typically have their own security model.

---

### RBAC Audit

**Rule type**: `rbac-audit`

Checks for RBAC-related security concerns at the pod level.

| Check | Severity | What It Means |
|---|---|---|
| Uses the `default` service account | Medium | May inherit overly broad permissions |
| Service account name contains "admin", "cluster-admin", "superuser", "root" | High | Suggests admin-level access |
| Uses deprecated `serviceAccount` field | Low | Should use `serviceAccountName` instead |

---

## Using Multiple Scanners Together

You can combine multiple scanners in a single SecurityPolicy:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: SecurityPolicy
metadata:
  name: comprehensive-scan
  namespace: zelyo-system
spec:
  severity: medium  # Only report medium and above
  match:
    namespaces: ["production", "staging"]
    excludeNamespaces: ["kube-system"]
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
```

## Using ClusterScan for Scheduled Scans

For periodic scans that create historical reports:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: ClusterScan
metadata:
  name: nightly-security-audit
  namespace: zelyo-system
spec:
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
    namespaces: ["production"]
    excludeNamespaces: ["kube-system"]
  historyLimit: 30
  suspend: false
```

After each scan completes, a `ScanReport` resource is created with the full findings:

```bash
# List recent scan reports
kubectl get scanreports -n zelyo-system

# View a specific report
kubectl describe scanreport nightly-security-audit-1709481234 -n zelyo-system
```

---

## Cloud Security Scanners

Zelyo Operator includes **48 cloud security scanners** across **6 categories** that audit your AWS, GCP, and Azure accounts for misconfigurations and compliance violations. Cloud scanners are triggered by `CloudAccountConfig` resources and produce `ScanReport` resources just like Kubernetes scans.

### How Cloud Scanners Work

When you create a `CloudAccountConfig`, here's what happens:

1. The controller authenticates to the cloud provider using the configured credentials (IRSA, Workload Identity, Pod Identity, or static credentials)
2. It runs the enabled scanner categories against the cloud account using native SDK calls
3. Each scanner evaluates resources and returns a list of findings with severity levels
4. Findings are recorded in a `ScanReport` resource and emitted as Kubernetes Events
5. If a `RemediationPolicy` is active, the LLM generates cloud IaC fixes (Terraform/CloudFormation) and opens GitOps PRs

---

### CSPM (Cloud Security Posture Management)

8 checks that evaluate your cloud infrastructure against security best practices.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| Public S3 buckets | `cspm-public-s3-bucket` | Critical | `s3:GetPublicAccessBlock` |
| Unencrypted EBS | `cspm-unencrypted-ebs` | High | `ec2:DescribeVolumes` |
| CloudTrail disabled | `cspm-cloudtrail-disabled` | Critical | `cloudtrail:GetTrailStatus` |
| RDS encryption | `cspm-rds-encryption` | High | `rds:DescribeDBInstances` |
| KMS key rotation | `cspm-kms-rotation` | Medium | `kms:GetKeyRotationStatus` |
| VPC Flow Logs | `cspm-vpc-flow-logs` | High | `ec2:DescribeFlowLogs` |
| S3 versioning | `cspm-s3-versioning` | Medium | `s3:GetBucketVersioning` |
| Secrets Manager rotation | `cspm-secrets-rotation` | Medium | `secretsmanager:DescribeSecret` |

---

### CIEM (Cloud Infrastructure Entitlement Management)

8 checks that audit identity and access management for overprivileged or stale credentials.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| Overprivileged IAM roles | `ciem-overprivileged-iam` | Critical | `iam:ListAttachedRolePolicies` |
| Unused access keys >90d | `ciem-unused-access-keys` | High | `iam:GetAccessKeyLastUsed` |
| Root account access keys | `ciem-root-access-keys` | Critical | `iam:GetAccountSummary` |
| Wildcard permissions | `ciem-wildcard-permissions` | High | `iam:GetPolicyVersion` |
| Cross-account trust | `ciem-cross-account-trust` | High | `iam:GetRole` |
| Inactive users >90d | `ciem-inactive-users` | Medium | `iam:GenerateCredentialReport` |
| MFA not enforced | `ciem-mfa-not-enforced` | Critical | `iam:ListMFADevices` |
| Long-lived service keys | `ciem-long-lived-service-keys` | High | `iam:ListAccessKeys` |

---

### Network Security

8 checks that evaluate network configurations for exposure and segmentation issues.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| SSH open to 0.0.0.0/0 | `network-ssh-open` | Critical | `ec2:DescribeSecurityGroups` |
| RDP open to 0.0.0.0/0 | `network-rdp-open` | Critical | `ec2:DescribeSecurityGroups` |
| Database ports exposed | `network-db-ports-exposed` | Critical | `ec2:DescribeSecurityGroups` |
| No NACLs on subnets | `network-no-nacls` | High | `ec2:DescribeNetworkAcls` |
| Unrestricted VPC peering | `network-unrestricted-peering` | High | `ec2:DescribeVpcPeeringConnections` |
| ALB not enforcing HTTPS | `network-alb-not-https` | High | `elbv2:DescribeListeners` |
| Default SG allows traffic | `network-default-sg-traffic` | Medium | `ec2:DescribeSecurityGroups` |
| Unrestricted egress | `network-unrestricted-egress` | Medium | `ec2:DescribeSecurityGroups` |

---

### DSPM (Data Security Posture Management)

8 checks that audit data storage services for encryption, access controls, and classification.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| S3 public ACLs | `dspm-s3-public-acls` | Critical | `s3:GetBucketAcl` |
| S3 no encryption | `dspm-s3-no-encryption` | High | `s3:GetBucketEncryption` |
| DynamoDB encryption at rest | `dspm-dynamodb-encryption` | High | `dynamodb:DescribeTable` |
| RDS publicly accessible | `dspm-rds-public` | Critical | `rds:DescribeDBInstances` |
| EBS snapshots public | `dspm-ebs-snapshots-public` | Critical | `ec2:DescribeSnapshotAttribute` |
| CloudWatch logs unencrypted | `dspm-cloudwatch-unencrypted` | Medium | `logs:DescribeLogGroups` |
| S3 Object Lock disabled | `dspm-s3-object-lock` | Medium | `s3:GetObjectLockConfiguration` |
| No data classification tags | `dspm-no-data-tags` | Medium | EC2 tag inspection |

---

### Supply Chain

8 checks that audit container registries and build artifacts for vulnerabilities and hygiene.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| ECR critical CVEs | `supplychain-ecr-critical-cves` | Critical | `ecr:DescribeImageScanFindings` |
| ECR scan-on-push disabled | `supplychain-ecr-scan-on-push` | High | `ecr:DescribeRepositories` |
| Base images >90 days old | `supplychain-base-images-stale` | Medium | `ecr:DescribeImages` |
| Hardcoded secrets in env | `supplychain-hardcoded-secrets-env` | Critical | `codebuild:BatchGetProjects` |
| Unsigned container images | `supplychain-unsigned-images` | High | `ecr:DescribeRepositories` |
| Third-party deps with CVEs | `supplychain-third-party-cves` | High | `ecr:DescribeImageScanFindings` |
| No SBOM generated | `supplychain-no-sbom` | Medium | `ecr:DescribeRepositories` |
| Images not scanned | `supplychain-images-not-scanned` | High | `ecr:DescribeImages` |

---

### CI/CD Pipeline

8 checks that audit CI/CD pipelines for secrets management, approval gates, and audit logging.

| Check | Rule Type | Severity | AWS API |
|---|---|---|---|
| Hardcoded secrets in repo | `cicd-hardcoded-secrets-repo` | Critical | `codebuild:BatchGetProjects` |
| Unencrypted pipeline artifacts | `cicd-unencrypted-artifacts` | High | `codepipeline:GetPipeline` |
| Secrets as plaintext env | `cicd-secrets-plaintext-env` | Critical | `codebuild:BatchGetProjects` |
| No manual approval gate | `cicd-no-manual-approval` | High | `codepipeline:GetPipeline` |
| Overprivileged CodeBuild | `cicd-overprivileged-codebuild` | High | `codebuild` + `iam` |
| Unmanaged build images | `cicd-unmanaged-build-images` | Medium | `codebuild:BatchGetProjects` |
| Artifact repo no encryption | `cicd-artifact-repo-no-encryption` | Medium | `codepipeline:GetPipeline` |
| No audit logging | `cicd-no-audit-logging` | High | `cloudtrail:DescribeTrails` |

---

## Using CloudAccountConfig for Cloud Scans

To onboard a cloud account for scanning, create a `CloudAccountConfig` resource:

```yaml
apiVersion: zelyo.ai/v1alpha1
kind: CloudAccountConfig
metadata:
  name: aws-production
  namespace: zelyo-system
spec:
  provider: aws
  accountId: "123456789012"
  regions:
    - us-east-1
    - us-west-2
  authentication:
    method: irsa                             # irsa | podIdentity | static
    roleArn: "arn:aws:iam::123456789012:role/ZelyoSecurityAudit"
  scanCategories:
    - cspm
    - ciem
    - network
    - dspm
    - supplychain
    - cicd
  schedule: "0 */4 * * *"                    # Scan every 4 hours
  severity: medium                           # Minimum severity to report
  notificationChannels: ["slack-alerts"]
```

After each cloud scan completes, a `ScanReport` resource is created with the full findings, just like Kubernetes scans:

```bash
# List cloud scan reports
kubectl get scanreports -n zelyo-system -l zelyo.ai/scan-type=cloud

# View a specific cloud scan report
kubectl describe scanreport aws-production-1709481234 -n zelyo-system
```
