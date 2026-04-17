/*
Copyright 2026 Zelyo AI
*/

package events

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// RunDemoSynthesizer fires realistic Scan → Correlate → Fix → Verify event
// sequences against the default bus on a ~10s cadence until ctx is canceled.
// Intended for investor demos and local UX work — real controllers emit real
// events on the same bus, so the two streams interleave naturally.
//
// Activation is gated by the caller (e.g. an env-var check in main) so this
// code never runs in production clusters by accident.
func RunDemoSynthesizer(ctx context.Context) {
	//nolint:gosec // non-cryptographic randomness is appropriate for demo synthesis.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	fireSequence(rng)

	ticker := time.NewTicker(11 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fireSequence(rng)
		}
	}
}

type demoScenario struct {
	scanName       string
	namespace      string
	scanners       []string
	findings       []demoFinding
	correlated     int
	repo           string
	prURL          string
	remediationTag string
	diff           string
	filesChanged   []string
}

type demoFinding struct {
	kind      string
	namespace string
	name      string
	rule      string
	severity  string
	title     string
}

func (f *demoFinding) resourceKey() string {
	return ResourceKey(f.kind, f.namespace, f.name)
}

func (f *demoFinding) displayResource() string {
	return fmt.Sprintf("%s/%s/%s", f.kind, f.namespace, f.name)
}

var demoScenarios = []demoScenario{
	{
		scanName:       "payments-hourly",
		namespace:      "payments",
		scanners:       []string{"privileged", "root-user", "capabilities"},
		correlated:     2,
		repo:           "zelyo-ai/payments-gitops",
		prURL:          "https://github.com/zelyo-ai/payments-gitops/pull/412",
		remediationTag: "Drop CAP_SYS_ADMIN + set runAsNonRoot",
		filesChanged:   []string{"apps/payments/checkout-api/deployment.yaml"},
		findings: []demoFinding{
			{"Pod", "payments", "checkout-api-7f8d", "privileged", "Critical", "Pod running in privileged mode"},
			{"Deployment", "payments", "checkout-api", "root-user", "High", "Container running as UID 0"},
			{"Pod", "payments", "ledger-writer-2bc9", "capabilities", "High", "CAP_SYS_ADMIN granted unnecessarily"},
		},
		diff: `--- a/apps/payments/checkout-api/deployment.yaml
+++ b/apps/payments/checkout-api/deployment.yaml
@@ -18,12 +18,17 @@ spec:
       labels:
         app: checkout-api
     spec:
+      securityContext:
+        runAsNonRoot: true
+        runAsUser: 10001
+        fsGroup: 10001
       containers:
         - name: api
           image: ghcr.io/zelyo-ai/checkout-api:1.14.2
           securityContext:
-            privileged: true
+            privileged: false
+            allowPrivilegeEscalation: false
+            readOnlyRootFilesystem: true
             capabilities:
-              add: ["SYS_ADMIN", "NET_ADMIN"]
+              drop: ["ALL"]
           ports:
             - containerPort: 8080
`,
	},
	{
		scanName:       "platform-nightly",
		namespace:      "platform",
		scanners:       []string{"host-mounts", "network-policy"},
		correlated:     1,
		repo:           "zelyo-ai/platform-gitops",
		prURL:          "https://github.com/zelyo-ai/platform-gitops/pull/88",
		remediationTag: "Remove hostPath mount from telemetry-agent",
		filesChanged:   []string{"apps/platform/telemetry-agent/daemonset.yaml"},
		findings: []demoFinding{
			{"DaemonSet", "platform", "telemetry-agent", "host-mounts", "Critical", "hostPath mount to /var/run/docker.sock"},
			{"Namespace", "platform", "platform", "network-policy", "High", "No default-deny NetworkPolicy"},
		},
		diff: `--- a/apps/platform/telemetry-agent/daemonset.yaml
+++ b/apps/platform/telemetry-agent/daemonset.yaml
@@ -22,11 +22,6 @@ spec:
       containers:
         - name: agent
           image: ghcr.io/zelyo-ai/telemetry-agent:0.9.3
-          volumeMounts:
-            - name: docker-sock
-              mountPath: /var/run/docker.sock
-      volumes:
-        - name: docker-sock
-          hostPath:
-            path: /var/run/docker.sock
+          env:
+            - name: CRI_ENDPOINT
+              value: "unix:///run/containerd/containerd.sock"
`,
	},
	{
		scanName:       "cloud-sweep-aws",
		namespace:      "zelyo-system",
		scanners:       []string{"s3-public", "iam-wildcards"},
		correlated:     3,
		repo:           "zelyo-ai/aws-infra",
		prURL:          "https://github.com/zelyo-ai/aws-infra/pull/203",
		remediationTag: "Lock down public S3 + tighten IAM",
		filesChanged:   []string{"terraform/s3.tf", "terraform/iam.tf"},
		findings: []demoFinding{
			{"S3Bucket", "", "acme-logs-prod", "s3-public", "Critical", "Bucket allows public READ"},
			{"S3Bucket", "", "acme-reports", "s3-public", "High", "Bucket allows public WRITE"},
			{"IAMRole", "", "ops-assumable", "iam-wildcards", "High", "Allows sts:AssumeRole from '*'"},
			{"IAMPolicy", "", "legacy-read-all", "iam-wildcards", "Medium", "Resource='*' on s3:*"},
		},
		diff: `--- a/terraform/s3.tf
+++ b/terraform/s3.tf
@@ -3,8 +3,12 @@ resource "aws_s3_bucket" "logs" {
 }

 resource "aws_s3_bucket_public_access_block" "logs" {
   bucket = aws_s3_bucket.logs.id
-  block_public_acls   = false
-  block_public_policy = false
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
 }
--- a/terraform/iam.tf
+++ b/terraform/iam.tf
@@ -10,7 +10,11 @@ data "aws_iam_policy_document" "ops_assume" {
   statement {
     actions = ["sts:AssumeRole"]
     principals {
       type        = "AWS"
-      identifiers = ["*"]
+      identifiers = [
+        "arn:aws:iam::${var.ops_account_id}:root",
+      ]
     }
+    condition {
+      test     = "StringEquals"
+      variable = "aws:PrincipalOrgID"
+      values   = [var.org_id]
+    }
   }
 }
`,
	},
}

func fireSequence(rng *rand.Rand) {
	scenario := demoScenarios[rng.Intn(len(demoScenarios))]

	// Stage 1: Scan starts.
	EmitScanStarted(scenario.scanName, scenario.namespace, scenario.scanners)

	// Stage 1b: findings stream in over a couple of seconds.
	go func() {
		for i := range scenario.findings {
			time.Sleep(time.Duration(300+rng.Intn(500)) * time.Millisecond)
			f := &scenario.findings[i]
			EmitFindingDetected(scenario.scanName, f.rule, f.severity, f.displayResource(), f.title)
		}

		// Stage 1c: scan completes.
		time.Sleep(600 * time.Millisecond)
		summary := summarizeFindings(scenario.findings)
		EmitScanCompleted(&ScanCompletion{
			Name:       scenario.scanName,
			Namespace:  scenario.namespace,
			ReportName: fmt.Sprintf("%s-report", scenario.scanName),
			Total:      int32(len(scenario.findings)), //nolint:gosec // demo-bounded
			Critical:   summary.critical,
			High:       summary.high,
			Medium:     summary.medium,
			DurationMs: int64(1800 + rng.Intn(2200)),
		})

		// Stage 2: correlator groups findings.
		time.Sleep(900 * time.Millisecond)
		EmitCorrelationGrouped(len(scenario.findings), scenario.correlated, scenario.scanName)

		// Stage 3: remediation drafted + PR opened. Populate the remediation
		// store *before* the pr.opened event so the dashboard finds context
		// the instant the user clicks.
		time.Sleep(1400 * time.Millisecond)
		items := make([]RemediationItem, 0, len(scenario.findings))
		for i := range scenario.findings {
			f := &scenario.findings[i]
			items = append(items, RemediationItem{
				ResourceKey: f.resourceKey(),
				Resource:    f.displayResource(),
				Rule:        f.rule,
				Severity:    f.severity,
				Title:       f.title,
			})
		}
		DefaultRemediationStore().Upsert(&RemediationContext{
			ScanRef:      scenario.scanName,
			Namespace:    scenario.namespace,
			Repo:         scenario.repo,
			PRURL:        scenario.prURL,
			Summary:      scenario.remediationTag,
			Findings:     items,
			Diff:         scenario.diff,
			FilesChanged: scenario.filesChanged,
		})

		EmitRemediationDrafted(scenario.scanName, scenario.remediationTag, scenario.correlated)
		time.Sleep(500 * time.Millisecond)
		EmitPullRequestOpened(scenario.prURL, scenario.repo, scenario.correlated)

		// Stage 3b: simulate a merge 2s later (in real life, human reviews first).
		time.Sleep(2100 * time.Millisecond)
		DefaultRemediationStore().MarkMerged(scenario.prURL, time.Now().UTC())
		EmitPullRequestMerged(scenario.prURL, scenario.repo)

		// Stage 4: re-scan verifies. Reconcile resolved findings with the store.
		time.Sleep(1200 * time.Millisecond)
		for i := range scenario.findings {
			if i >= scenario.correlated {
				break
			}
			f := &scenario.findings[i]
			DefaultRemediationStore().MarkResolved(f.resourceKey(), time.Now().UTC())
			EmitFindingResolved(f.displayResource(), f.rule)
			time.Sleep(250 * time.Millisecond)
		}
	}()
}

type sevSummary struct {
	critical, high, medium int32
}

func summarizeFindings(fs []demoFinding) sevSummary {
	var s sevSummary
	for _, f := range fs {
		switch f.severity {
		case "Critical":
			s.critical++
		case "High":
			s.high++
		case "Medium":
			s.medium++
		}
	}
	return s
}
