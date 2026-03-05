# Security Scanners

Zelyo Operator ships with **8 built-in security scanners** that check your Kubernetes workloads for common misconfigurations and vulnerabilities. Each scanner runs automatically when triggered by a `SecurityPolicy` or `ClusterScan`.

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
