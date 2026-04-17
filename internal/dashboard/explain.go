/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package dashboard

import (
	"context"
	"crypto/sha1" //nolint:gosec // non-cryptographic: used only as a fast cache key hash.
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ExplainRequest is the input for a finding explanation.
type ExplainRequest struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	Title    string `json:"title"`
}

// ExplainResponse is the rendered output.
type ExplainResponse struct {
	Explanation string    `json:"explanation"`
	Source      string    `json:"source"` // "canned" | "llm" | "cache"
	GeneratedAt time.Time `json:"generatedAt"`
}

// Explainer renders a plain-English explanation of a security finding.
// Implementations should be safe to call from concurrent HTTP handlers.
type Explainer interface {
	Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error)
}

// ---- Canned explainer ------------------------------------------------------

// CannedExplainer returns curated explanations keyed by rule type. It is
// offline-safe (no external calls), deterministic, and serves as both a
// demo-quality default and a fallback when no LLM provider is configured.
type CannedExplainer struct{}

// Explain returns a curated explanation for the given rule. If no entry
// matches, a severity-aware generic explanation is synthesized.
func (c *CannedExplainer) Explain(_ context.Context, req *ExplainRequest) (*ExplainResponse, error) {
	rule := strings.ToLower(strings.TrimSpace(req.Rule))
	if entry, ok := cannedContent[rule]; ok {
		return &ExplainResponse{
			Explanation: (&entry).render(req),
			Source:      "canned",
			GeneratedAt: time.Now().UTC(),
		}, nil
	}
	return &ExplainResponse{
		Explanation: genericExplanation(req),
		Source:      "canned",
		GeneratedAt: time.Now().UTC(),
	}, nil
}

type cannedEntry struct {
	whatsWrong   string
	attackerCan  string
	blastRadius  string
	howFixWorks  string
	complianceTo string // e.g. "CIS 5.2.1, PCI-DSS 2.2.4"
}

func (e *cannedEntry) render(req *ExplainRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**What's wrong**\n%s (resource: `%s`)\n\n", e.whatsWrong, req.Resource)
	fmt.Fprintf(&b, "**Why an attacker cares**\n%s\n\n", e.attackerCan)
	fmt.Fprintf(&b, "**Blast radius**\n%s\n\n", e.blastRadius)
	fmt.Fprintf(&b, "**How the proposed fix works**\n%s\n", e.howFixWorks)
	if e.complianceTo != "" {
		fmt.Fprintf(&b, "\n*Maps to: %s*", e.complianceTo)
	}
	return b.String()
}

// cannedContent holds high-quality, demo-ready narratives for the rule
// types that ship with Zelyo out of the box. Extend freely — unknown rules
// fall back to genericExplanation().
var cannedContent = map[string]cannedEntry{
	"privileged": {
		whatsWrong:   "This pod runs with `privileged: true`, which disables nearly every container isolation boundary Kubernetes provides.",
		attackerCan:  "If any process in this pod is compromised (an RCE in a dependency, a malicious image, a mis-configured ingress), the attacker gets effective root on the host node. They can read every other pod's memory, access every secret mounted on the node, and pivot to the rest of the cluster.",
		blastRadius:  "One compromised pod → full node compromise → lateral movement across every workload scheduled there. In multi-tenant clusters this is a single-step escape from tenant isolation.",
		howFixWorks:  "The fix sets `privileged: false`, adds `allowPrivilegeEscalation: false`, makes the root filesystem read-only, and drops all Linux capabilities — restoring the isolation model the workload never needed to bypass.",
		complianceTo: "CIS Kubernetes 5.2.1, NIST SP 800-190 §4.5.2, PCI-DSS 2.2.4",
	},
	"root-user": {
		whatsWrong:   "The container runs as UID 0 (root) inside its namespace.",
		attackerCan:  "Any exploit that gains code execution in this container starts with root-equivalent access to everything the container can see. Combined with a stale kernel CVE or a writable host mount, that turns into host root with one additional step instead of two or three.",
		blastRadius:  "Inside the container: full filesystem write, chroot escape attempts, binary tampering. Outside: any hostPath or mounted secret is reachable without further privilege escalation.",
		howFixWorks:  "The fix sets `runAsNonRoot: true` with a specific non-zero UID and matching `fsGroup`. The workload keeps running — containers almost never need to be root — but the attacker's starting privilege drops from root to an unprivileged user.",
		complianceTo: "CIS Kubernetes 5.2.5, NIST SP 800-190 §4.3.3",
	},
	"capabilities": {
		whatsWrong:   "The container is granted Linux capabilities it does not need (commonly `SYS_ADMIN`, `NET_ADMIN`, or `SYS_PTRACE`).",
		attackerCan:  "`CAP_SYS_ADMIN` is colloquially called 'the new root' — it grants mount(), module loading, namespace manipulation, and dozens of other operations. An attacker with code execution in this container doesn't need a kernel exploit to escape; they just use the capabilities you already granted.",
		blastRadius:  "With `SYS_ADMIN` specifically, container escape to the host becomes a short script. With `NET_ADMIN`, the attacker can reconfigure networking to exfiltrate across VPCs.",
		howFixWorks:  "The fix drops all capabilities (`drop: [\"ALL\"]`) and adds back only the specific capability the app requires (usually none). This is the principle-of-least-privilege default that Kubernetes should have shipped with.",
		complianceTo: "CIS Kubernetes 5.2.7, NIST SP 800-190 §4.5.3",
	},
	"host-mounts": {
		whatsWrong:   "The pod mounts a path from the underlying node's filesystem, often `/var/run/docker.sock`, `/proc`, or `/`.",
		attackerCan:  "A docker.sock mount is the most severe variant: the Docker API running as root on the node is exposed inside a non-root container. Any RCE in that pod = `docker run --privileged --pid host` and the attacker is root on the node with one API call. Mounting `/` is worse.",
		blastRadius:  "Full cluster node compromise. Any secret on the node, any other workload on the node, the kubelet credentials, cloud IMDS — all reachable.",
		howFixWorks:  "The fix removes the hostPath volume entirely and replaces it with the modern CRI socket (`/run/containerd/containerd.sock`) or an API-driven alternative that doesn't require node-level access. Telemetry agents specifically can use the CRI API or kubelet's streaming API.",
		complianceTo: "CIS Kubernetes 5.2.9, NIST SP 800-190 §4.3.4",
	},
	"network-policy": {
		whatsWrong:   "The namespace has no default-deny `NetworkPolicy`. Every pod in this namespace can talk to every other pod in the cluster and dial the public internet.",
		attackerCan:  "Once one pod is compromised, lateral movement is unrestricted. The attacker enumerates the internal DNS, pivots to the database pod, dumps credentials, then tunnels out via an allowed egress.",
		blastRadius:  "The entire cluster network. No segmentation means a single stolen workload identity grants broad access to internal APIs, databases, and service mesh control planes.",
		howFixWorks:  "The fix adds a default-deny ingress and egress `NetworkPolicy`, then explicit `allow` rules for the specific traffic each workload needs. This is the firewall-between-services posture that every compliance framework assumes exists.",
		complianceTo: "CIS Kubernetes 5.3.2, NIST SP 800-53 SC-7, PCI-DSS 1.3",
	},
	"s3-public": {
		whatsWrong:   "This S3 bucket allows public access (READ, WRITE, or both). AWS's Block Public Access feature is either off or partially applied.",
		attackerCan:  "Public READ means every content-scraping bot and every competitor sees the contents within hours — Shodan indexes open buckets continuously. Public WRITE is materially worse: attackers can host malware on your domain, use the bucket for command-and-control, or plant phishing pages that inherit your brand's trust.",
		blastRadius:  "Data exfiltration (logs, PII, credentials accidentally left in the bucket), reputation damage from brand-associated malware hosting, and compliance violations (GDPR, HIPAA, SOC 2) that trigger mandatory breach disclosure.",
		howFixWorks:  "The fix sets all four `aws_s3_bucket_public_access_block` flags to `true`, which is the only configuration AWS treats as 'definitely not public' regardless of bucket policy, ACLs, or IAM.",
		complianceTo: "CIS AWS 2.1.5, SOC 2 CC6.1, PCI-DSS 1.2.1",
	},
	"iam-wildcards": {
		whatsWrong:   "An IAM role or policy uses `\"*\"` where a specific principal, action, or resource should be scoped.",
		attackerCan:  "A trust policy with `Principal: \"*\"` on `sts:AssumeRole` means any AWS account on earth can attempt to assume the role — the only remaining gate is the External ID or Condition, which is often missing. A resource policy with `Resource: \"*\"` on `s3:*` means any leaked credential with any S3 permission inherits full bucket control.",
		blastRadius:  "Role assumption by unknown accounts (leading to full account takeover if paired with any other credential leak), and privilege amplification where a low-scope credential leak becomes a high-scope breach.",
		howFixWorks:  "The fix constrains the trust policy to specific account IDs or role ARNs, adds an `aws:PrincipalOrgID` condition to keep assumption inside your AWS Organization, and replaces wildcard resources with specific ARNs.",
		complianceTo: "CIS AWS 1.16, SOC 2 CC6.3, NIST SP 800-53 AC-6",
	},
	"correlation": {
		whatsWrong:   "Raw scanner output is noisy: the same underlying misconfiguration often surfaces as five, ten, or dozens of findings (one per affected pod, per namespace, per bucket). Treating them as separate work items burns reviewer attention.",
		attackerCan:  "This isn't itself an exploitable weakness — it's a signal quality problem. But alert fatigue *is* exploitable: when every deploy fires 50 findings, reviewers learn to ignore them, and real incidents hide in the noise.",
		blastRadius:  "Correlation doesn't reduce blast radius directly — it reduces the *time-to-fix*. By collapsing N findings into M root causes, Zelyo turns 'triage 50 tickets' into 'review 3 PRs,' which is the difference between landing a fix this sprint and pushing it to next quarter.",
		howFixWorks:  "The correlator groups findings by shared resource, shared rule, and shared likely-fix. It emits one remediation proposal per root cause — the remediation engine then drafts a single PR that resolves all of them together, which is also what a human reviewer would have done by hand.",
		complianceTo: "",
	},
}

// genericExplanation renders a reasonable fallback for rule types not in
// the canned map. It's severity-aware so Critical findings don't read as
// gently as Info ones.
func genericExplanation(req *ExplainRequest) string {
	sev := strings.ToLower(req.Severity)
	tone := "This finding indicates a security weakness that warrants review."
	switch sev {
	case "critical":
		tone = "This is a critical finding — it represents a direct, exploitable path to compromise and should be remediated before the next deployment."
	case "high":
		tone = "This is a high-severity finding. While exploitation may require specific conditions, the impact is significant and the fix is typically cheap."
	case "medium":
		tone = "This is a medium-severity finding. It rarely causes compromise on its own but widens the blast radius of a separate incident."
	case "low", "info":
		tone = "This is a low-severity or informational finding. It's worth knowing about, but immediate action is usually not required."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "**What's wrong**\n%s Zelyo's %s rule flagged `%s`: %s\n\n", tone, req.Rule, req.Resource, req.Title)
	fmt.Fprint(&b, "**Why it matters**\nThe combination of this misconfiguration with any other vulnerability (a supply-chain compromise, a stolen credential, a publicly-exposed endpoint) is what makes a real-world breach possible. Each finding is a reduction in the defender's margin.\n\n")
	fmt.Fprint(&b, "**How to fix**\nReview the proposed diff in the remediation panel. If no remediation is drafted yet, Zelyo will generate one on the next reconcile cycle.")
	return b.String()
}

// ---- Caching + selection ---------------------------------------------------

// CachingExplainer wraps another Explainer with an in-memory TTL cache
// keyed by rule+severity. Resource is intentionally *not* part of the key —
// the narrative is about the rule, not a specific pod.
type CachingExplainer struct {
	Inner Explainer
	TTL   time.Duration

	mu    sync.Mutex
	cache map[string]cachedExplanation
}

type cachedExplanation struct {
	resp      *ExplainResponse
	expiresAt time.Time
}

// NewCachingExplainer returns a caching wrapper with the given TTL.
func NewCachingExplainer(inner Explainer, ttl time.Duration) *CachingExplainer {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &CachingExplainer{
		Inner: inner,
		TTL:   ttl,
		cache: map[string]cachedExplanation{},
	}
}

// Explain returns a cached response when fresh, otherwise delegates.
func (c *CachingExplainer) Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error) {
	key := cacheKey(req)

	c.mu.Lock()
	entry, ok := c.cache[key]
	c.mu.Unlock()
	if ok && time.Now().Before(entry.expiresAt) {
		out := *entry.resp
		out.Source = "cache"
		return &out, nil
	}

	resp, err := c.Inner.Explain(ctx, req)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[key] = cachedExplanation{resp: resp, expiresAt: time.Now().Add(c.TTL)}
	c.mu.Unlock()

	return resp, nil
}

func cacheKey(req *ExplainRequest) string {
	h := sha1.New() //nolint:gosec // non-cryptographic cache key.
	h.Write([]byte(strings.ToLower(req.Rule)))
	h.Write([]byte{'|'})
	h.Write([]byte(strings.ToLower(req.Severity)))
	return hex.EncodeToString(h.Sum(nil))
}

// defaultExplainer is the process-wide explainer used by the HTTP handler.
// It is replaceable for tests.
var (
	defaultExplainerMu sync.RWMutex
	defaultExplainer   Explainer = NewCachingExplainer(&CannedExplainer{}, 30*time.Minute)
)

// SetDefaultExplainer replaces the process-wide explainer. Intended for
// wiring the LLM-backed explainer once the ZelyoConfig provides credentials.
func SetDefaultExplainer(e Explainer) {
	defaultExplainerMu.Lock()
	defaultExplainer = e
	defaultExplainerMu.Unlock()
}

// getExplainer returns the current process-wide explainer.
func getExplainer() Explainer {
	defaultExplainerMu.RLock()
	defer defaultExplainerMu.RUnlock()
	return defaultExplainer
}
