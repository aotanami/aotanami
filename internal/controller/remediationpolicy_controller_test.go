/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
	"github.com/zelyo-ai/zelyo-operator/internal/llm"
	"github.com/zelyo-ai/zelyo-operator/internal/remediation"
)

var _ = Describe("RemediationPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		remediationpolicy := &zelyov1alpha1.RemediationPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind RemediationPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, remediationpolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.RemediationPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: zelyov1alpha1.RemediationPolicySpec{
						GitOpsRepository: "test-repo",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &zelyov1alpha1.RemediationPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance RemediationPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &RemediationPolicyReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: record.NewFakeRecorder(100),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})

	// The CRD documents spec.targetPolicies as "the SecurityPolicy names this
	// remediation applies to. Empty means all." Before the scope-gate fix, the
	// reconciler validated that each referenced SecurityPolicy existed but
	// then processed incidents from ANY SecurityPolicy — a footgun where an
	// operator scoping a RemediationPolicy to one environment would still
	// get PRs for unrelated incidents. These tests pin the semantic: with
	// targetPolicies set, only incidents carrying events from a matching
	// SecurityPolicy reach the remediation engine.
	Context("When spec.targetPolicies is set", func() {
		const (
			rpName      = "rp-scope"
			repoName    = "scope-repo"
			targetedSP  = "only-one"
			otherSP     = "other-one"
			targetedPod = "pod-targeted"
			otherPod    = "pod-other"
			ns          = "default"
		)
		ctx := context.Background()

		AfterEach(func() {
			By("cleaning up scope-gate fixtures")
			for _, name := range []string{rpName} {
				rp := &zelyov1alpha1.RemediationPolicy{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, rp); err == nil {
					Expect(k8sClient.Delete(ctx, rp)).To(Succeed())
				}
			}
			for _, name := range []string{targetedSP, otherSP} {
				sp := &zelyov1alpha1.SecurityPolicy{}
				if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: ns}, sp); err == nil {
					Expect(k8sClient.Delete(ctx, sp)).To(Succeed())
				}
			}
			repo := &zelyov1alpha1.GitOpsRepository{}
			if err := k8sClient.Get(ctx, types.NamespacedName{Name: repoName, Namespace: ns}, repo); err == nil {
				Expect(k8sClient.Delete(ctx, repo)).To(Succeed())
			}
		})

		It("only routes incidents from targeted SecurityPolicies to the remediation engine", func() {
			By("creating two SecurityPolicy CRs")
			Expect(k8sClient.Create(ctx, newTestSecurityPolicy(targetedSP, ns))).To(Succeed())
			Expect(k8sClient.Create(ctx, newTestSecurityPolicy(otherSP, ns))).To(Succeed())

			By("creating the referenced GitOpsRepository")
			Expect(k8sClient.Create(ctx, newTestGitOpsRepo(repoName, ns))).To(Succeed())

			By("creating the RemediationPolicy scoped to only-one")
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: rpName, Namespace: ns},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					TargetPolicies:   []string{targetedSP},
					SeverityFilter:   zelyov1alpha1.SeverityHigh,
					MaxConcurrentPRs: 10,
				},
			})).To(Succeed())

			By("building a correlator with one incident per SecurityPolicy")
			corr := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			// Two events on pod-targeted tagged with the targeted SecurityPolicy
			// → forms a correlated incident. Use "critical" so it clears the
			// default "high" severity gate with room to spare.
			for i := 0; i < 2; i++ {
				corr.Ingest(&correlator.Event{
					Type:                    correlator.EventSecurityViolation,
					Source:                  "securitypolicy/" + targetedSP,
					SecurityPolicy:          targetedSP,
					SecurityPolicyNamespace: ns,
					Severity:                zelyov1alpha1.SeverityCritical,
					Namespace:               ns,
					Resource:                targetedPod,
					ResourceKind:            "Pod",
					Message:                 "privileged container",
				})
			}
			// Two events on pod-other tagged with a NON-targeted SecurityPolicy
			// → forms a second correlated incident that must be filtered out.
			for i := 0; i < 2; i++ {
				corr.Ingest(&correlator.Event{
					Type:                    correlator.EventSecurityViolation,
					Source:                  "securitypolicy/" + otherSP,
					SecurityPolicy:          otherSP,
					SecurityPolicyNamespace: ns,
					Severity:                zelyov1alpha1.SeverityCritical,
					Namespace:               ns,
					Resource:                otherPod,
					ResourceKind:            "Pod",
					Message:                 "privileged container",
				})
			}
			Expect(corr.GetOpenIncidents()).To(HaveLen(2))

			By("reconciling with a remediation engine that fails plan generation")
			// A nil LLM client makes GeneratePlan fail with a deterministic
			// error. That failure is recorded as a Kubernetes event whose
			// message names the incident ID. Filtered-out incidents never
			// reach GeneratePlan, so they produce no such event — counting
			// these events is how we observe the scope gate.
			remEngine := remediation.NewEngine(
				nil, nil,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard(),
			)
			recorder := record.NewFakeRecorder(100)
			reconciler := &RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          recorder,
				CorrelatorEngine:  corr,
				RemediationEngine: remEngine,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rpName, Namespace: ns},
			})
			Expect(err).NotTo(HaveOccurred())

			By("asserting only the targeted incident reached GeneratePlan")
			planFailures := drainEventsContaining(recorder, "LLM plan generation failed for incident")
			Expect(planFailures).To(HaveLen(1),
				"scope gate should have blocked the non-targeted incident; got events: %v", planFailures)

			By("asserting both incidents remain open (plan generation failed for the targeted one, the other was filtered)")
			// The targeted incident's PR was never created — remains open.
			// The non-targeted incident was filtered — remains open.
			Expect(corr.GetOpenIncidents()).To(HaveLen(2))
		})

		It("does not leak scope across namespaces when policy names collide", func() {
			// SecurityPolicy is a namespaced CRD; two tenants can legally
			// register policies named "only-one". A RemediationPolicy in
			// "default" must only see events from its own-namespace
			// "only-one", not from another namespace's "only-one". The
			// original fix matched on name alone and was still vulnerable
			// to this exact leak.
			By("creating the targeted SecurityPolicy in the RemediationPolicy's own namespace")
			Expect(k8sClient.Create(ctx, newTestSecurityPolicy(targetedSP, ns))).To(Succeed())

			By("creating the referenced GitOpsRepository")
			Expect(k8sClient.Create(ctx, newTestGitOpsRepo(repoName, ns))).To(Succeed())

			By("creating the RemediationPolicy scoped to only-one in default")
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: rpName, Namespace: ns},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					TargetPolicies:   []string{targetedSP},
					SeverityFilter:   zelyov1alpha1.SeverityHigh,
					MaxConcurrentPRs: 10,
				},
			})).To(Succeed())

			By("injecting an incident tagged with a same-named policy from another namespace")
			corr := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			// Two events from "team-b/only-one" — same name as the target
			// but foreign namespace. Scope gate MUST reject.
			for i := 0; i < 2; i++ {
				corr.Ingest(&correlator.Event{
					Type:                    correlator.EventSecurityViolation,
					SecurityPolicy:          targetedSP,
					SecurityPolicyNamespace: "team-b",
					Severity:                zelyov1alpha1.SeverityCritical,
					Namespace:               ns, // pod namespace — unrelated to policy namespace
					Resource:                "cross-ns-pod",
					ResourceKind:            "Pod",
					Message:                 "privileged container",
				})
			}
			Expect(corr.GetOpenIncidents()).To(HaveLen(1))

			remEngine := remediation.NewEngine(
				nil, nil,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard(),
			)
			recorder := record.NewFakeRecorder(100)
			reconciler := &RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          recorder,
				CorrelatorEngine:  corr,
				RemediationEngine: remEngine,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rpName, Namespace: ns},
			})
			Expect(err).NotTo(HaveOccurred())

			By("asserting the foreign-namespace incident was filtered before GeneratePlan")
			planFailures := drainEventsContaining(recorder, "LLM plan generation failed for incident")
			Expect(planFailures).To(BeEmpty(),
				"foreign-namespace incident must not reach GeneratePlan; got: %v", planFailures)
		})

		It("remediates every incident when targetPolicies is empty", func() {
			By("creating the referenced GitOpsRepository")
			Expect(k8sClient.Create(ctx, newTestGitOpsRepo(repoName, ns))).To(Succeed())

			By("creating a RemediationPolicy with no targetPolicies")
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: rpName, Namespace: ns},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					SeverityFilter:   zelyov1alpha1.SeverityHigh,
					MaxConcurrentPRs: 10,
				},
			})).To(Succeed())

			By("building a correlator with incidents from two different SecurityPolicies")
			corr := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			for i := 0; i < 2; i++ {
				corr.Ingest(&correlator.Event{
					Type:                    correlator.EventSecurityViolation,
					SecurityPolicy:          targetedSP,
					SecurityPolicyNamespace: ns,
					Severity:                zelyov1alpha1.SeverityCritical,
					Namespace:               ns, Resource: targetedPod,
					ResourceKind: "Pod", Message: "x",
				})
				corr.Ingest(&correlator.Event{
					Type:                    correlator.EventSecurityViolation,
					SecurityPolicy:          otherSP,
					SecurityPolicyNamespace: ns,
					Severity:                zelyov1alpha1.SeverityCritical,
					Namespace:               ns, Resource: otherPod,
					ResourceKind: "Pod", Message: "y",
				})
			}
			Expect(corr.GetOpenIncidents()).To(HaveLen(2))

			remEngine := remediation.NewEngine(
				nil, nil,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard(),
			)
			recorder := record.NewFakeRecorder(100)
			reconciler := &RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          recorder,
				CorrelatorEngine:  corr,
				RemediationEngine: remEngine,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rpName, Namespace: ns},
			})
			Expect(err).NotTo(HaveOccurred())

			By("asserting both incidents reached GeneratePlan (no scope gate)")
			planFailures := drainEventsContaining(recorder, "LLM plan generation failed for incident")
			Expect(planFailures).To(HaveLen(2))
		})
	})
})

// drainEventsContaining non-destructively reads everything currently buffered
// on a FakeRecorder and returns the subset of event messages containing
// needle. We read non-blocking so a buffered-but-unfilled channel doesn't
// stall the test.
func drainEventsContaining(recorder *record.FakeRecorder, needle string) []string {
	var matching []string
	for {
		select {
		case ev := <-recorder.Events:
			if strings.Contains(ev, needle) {
				matching = append(matching, ev)
			}
		default:
			return matching
		}
	}
}

// newTestSecurityPolicy returns a minimal valid SecurityPolicy — Match and
// Rules are required by the CRD schema (MinItems=1 on rules), so bare Specs
// get rejected by the envtest API server.
func newTestSecurityPolicy(name, namespace string) *zelyov1alpha1.SecurityPolicy {
	return &zelyov1alpha1.SecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: zelyov1alpha1.SecurityPolicySpec{
			Severity: zelyov1alpha1.SeverityHigh,
			Match:    zelyov1alpha1.PolicyMatch{Namespaces: []string{namespace}},
			Rules: []zelyov1alpha1.SecurityRule{
				{Name: "test-rule", Type: "container-security-context"},
			},
		},
	}
}

// newTestGitOpsRepo returns a minimal valid GitOpsRepository with a stub
// AuthSecret reference. The reconciler only tries to resolve the secret
// inside processIncidents to initialize the GitHub engine; when the secret
// is absent the engine init is silently skipped, which is fine for these
// tests — we never exercise PR creation, only the scope-gate filter.
func newTestGitOpsRepo(name, namespace string) *zelyov1alpha1.GitOpsRepository {
	return &zelyov1alpha1.GitOpsRepository{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: zelyov1alpha1.GitOpsRepositorySpec{
			URL:        "https://github.com/example/manifests.git",
			Paths:      []string{"clusters/"},
			AuthSecret: "no-such-secret",
		},
	}
}

// fakeDryRunLLM is an llm.Client that returns a canned structured JSON
// response the remediation engine can parse into a valid fix plan. Tracks
// the call count so tests can assert the plan generation step ran.
type fakeDryRunLLM struct {
	response string
	calls    int
}

func (f *fakeDryRunLLM) Complete(_ context.Context, _ llm.Request) (*llm.Response, error) {
	f.calls++
	return &llm.Response{Content: f.response, Model: "fake"}, nil
}
func (f *fakeDryRunLLM) Provider() llm.Provider { return "fake" }
func (f *fakeDryRunLLM) Close() error           { return nil }

// fakeDryRunGitops is a gitops.Engine that records whether a PR would have
// been opened. A dry-run reconcile must not reach this method — that is the
// CRD contract we are testing.
type fakeDryRunGitops struct {
	createPRCalls int
}

func (f *fakeDryRunGitops) CreatePullRequest(_ context.Context, _ *gitops.PullRequest) (*gitops.PullRequestResult, error) {
	f.createPRCalls++
	return &gitops.PullRequestResult{Number: 1, URL: "https://example.invalid/pr/1", Branch: "zelyo-operator/fix/test", CreatedAt: time.Now()}, nil
}
func (f *fakeDryRunGitops) GetFile(_ context.Context, _, _, _, _ string) ([]byte, error) {
	return nil, nil
}
func (f *fakeDryRunGitops) ListOpenPRs(_ context.Context, _, _ string) ([]gitops.PullRequestResult, error) {
	return nil, nil
}
func (f *fakeDryRunGitops) Close() error { return nil }

// structured JSON plan produced by fakeDryRunLLM — single safe update fix.
// The file_path must live under the test's repo.Spec.Paths (`clusters/`) so
// it survives the remediation engine's allowed-paths filter; otherwise all
// fixes get filtered out and GeneratePlan returns an error.
const fakeDryRunLLMResponse = `{
    "analysis": "Container nginx runs as root; enforce runAsNonRoot.",
    "fixes": [
        {
            "file_path": "clusters/app/nginx.yaml",
            "description": "Set runAsNonRoot=true",
            "patch": "apiVersion: apps/v1\nkind: Deployment",
            "operation": "update"
        }
    ],
    "risk_assessment": "Low risk.",
    "risk_score": 20
}`

var _ = Describe("RemediationPolicy Controller Dry-Run", func() {
	Context("against a fake GitOps engine", func() {
		const (
			namespace  = "default"
			policyName = "test-dryrun-policy"
			repoName   = "test-dryrun-repo"
		)
		ctx := context.Background()

		policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
		repoKey := types.NamespacedName{Name: repoName, Namespace: namespace}

		// newSeededCorrelator returns an engine with exactly one open
		// incident on app/nginx at "critical" severity. Two Ingests are
		// needed because findRelated requires >=2 events to materialize an
		// incident.
		newSeededCorrelator := func() (*correlator.Engine, string) {
			corr := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			corr.Ingest(&correlator.Event{
				Type:         correlator.EventSecurityViolation,
				Severity:     "critical",
				Namespace:    "app",
				Resource:     "nginx",
				ResourceKind: "Deployment",
				Message:      "Container runs as root",
			})
			inc := corr.Ingest(&correlator.Event{
				Type:         correlator.EventAnomaly,
				Severity:     "high",
				Namespace:    "app",
				Resource:     "nginx",
				ResourceKind: "Deployment",
				Message:      "Restart spike",
			})
			Expect(inc).NotTo(BeNil(), "two correlated events should materialize an incident")
			return corr, inc.ID
		}

		AfterEach(func() {
			policy := &zelyov1alpha1.RemediationPolicy{}
			if err := k8sClient.Get(ctx, policyKey, policy); err == nil {
				Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
			}
			repo := &zelyov1alpha1.GitOpsRepository{}
			if err := k8sClient.Get(ctx, repoKey, repo); err == nil {
				Expect(k8sClient.Delete(ctx, repo)).To(Succeed())
			}
		})

		It("generates the plan but does not open a PR or resolve the incident when spec.dryRun=true", func() {
			By("creating the GitOpsRepository — AuthSecret is intentionally unbacked so the controller does not overwrite our fake gitops engine with a real PAT-backed one")
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.GitOpsRepository{
				ObjectMeta: metav1.ObjectMeta{Name: repoName, Namespace: namespace},
				Spec: zelyov1alpha1.GitOpsRepositorySpec{
					URL:        "https://github.com/example/manifests",
					Paths:      []string{"clusters/"},
					AuthSecret: "no-such-secret",
				},
			})).To(Succeed())

			By("creating the RemediationPolicy with dryRun=true")
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: namespace},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					DryRun:           true,
					SeverityFilter:   "high",
					MaxConcurrentPRs: 5,
				},
			})).To(Succeed())

			corr, incidentID := newSeededCorrelator()
			fakeLLM := &fakeDryRunLLM{response: fakeDryRunLLMResponse}
			fakeGit := &fakeDryRunGitops{}
			engine := remediation.NewEngine(fakeLLM, fakeGit,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard())

			By("reconciling the policy once")
			_, err := (&RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          record.NewFakeRecorder(100),
				CorrelatorEngine:  corr,
				RemediationEngine: engine,
			}).Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("asserting the plan was generated but no PR was opened")
			Expect(fakeLLM.calls).To(Equal(1), "LLM should be called once to generate the preview plan")
			Expect(fakeGit.createPRCalls).To(Equal(0), "CreatePullRequest must not be called when spec.dryRun=true")

			By("asserting the incident stays open so a later non-dry-run reconcile can remediate")
			open := corr.GetOpenIncidents()
			Expect(open).To(HaveLen(1))
			Expect(open[0].ID).To(Equal(incidentID))
			Expect(open[0].Resolved).To(BeFalse())

			By("asserting status.remediationsApplied stays at 0 for a dry-run cycle")
			updated := &zelyov1alpha1.RemediationPolicy{}
			Expect(k8sClient.Get(ctx, policyKey, updated)).To(Succeed())
			Expect(updated.Status.RemediationsApplied).To(Equal(int32(0)))
			Expect(updated.Status.Phase).To(Equal(zelyov1alpha1.PhaseActive))
		})

		It("opens a PR against the same fake engine when spec.dryRun=false (counter-case)", func() {
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.GitOpsRepository{
				ObjectMeta: metav1.ObjectMeta{Name: repoName, Namespace: namespace},
				Spec: zelyov1alpha1.GitOpsRepositorySpec{
					URL:        "https://github.com/example/manifests",
					Paths:      []string{"clusters/"},
					AuthSecret: "no-such-secret",
				},
			})).To(Succeed())

			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: namespace},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					DryRun:           false,
					SeverityFilter:   "high",
					MaxConcurrentPRs: 5,
				},
			})).To(Succeed())

			corr, _ := newSeededCorrelator()
			fakeLLM := &fakeDryRunLLM{response: fakeDryRunLLMResponse}
			fakeGit := &fakeDryRunGitops{}
			engine := remediation.NewEngine(fakeLLM, fakeGit,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard())

			_, err := (&RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          record.NewFakeRecorder(100),
				CorrelatorEngine:  corr,
				RemediationEngine: engine,
			}).Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			Expect(fakeLLM.calls).To(Equal(1))
			Expect(fakeGit.createPRCalls).To(Equal(1), "CreatePullRequest must be called when spec.dryRun=false")
			Expect(corr.GetOpenIncidents()).To(BeEmpty(), "incident should be resolved after a successful PR")

			updated := &zelyov1alpha1.RemediationPolicy{}
			Expect(k8sClient.Get(ctx, policyKey, updated)).To(Succeed())
			Expect(updated.Status.RemediationsApplied).To(Equal(int32(1)))
		})

		// Regression guard: before this guard was added, prsCreated was the
		// only per-cycle counter and it never incremented in dry-run mode.
		// A policy with N open incidents and dryRun=true therefore hit the
		// LLM N times per reconcile, ignoring maxConcurrentPRs — a real
		// cost / timeout risk on clusters with many correlated incidents.
		It("caps LLM plan generation at maxConcurrentPRs even when spec.dryRun=true", func() {
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.GitOpsRepository{
				ObjectMeta: metav1.ObjectMeta{Name: repoName, Namespace: namespace},
				Spec: zelyov1alpha1.GitOpsRepositorySpec{
					URL:        "https://github.com/example/manifests",
					Paths:      []string{"clusters/"},
					AuthSecret: "no-such-secret",
				},
			})).To(Succeed())

			const maxPRs int32 = 2
			Expect(k8sClient.Create(ctx, &zelyov1alpha1.RemediationPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: namespace},
				Spec: zelyov1alpha1.RemediationPolicySpec{
					GitOpsRepository: repoName,
					DryRun:           true,
					SeverityFilter:   "high",
					MaxConcurrentPRs: maxPRs,
				},
			})).To(Succeed())

			By("seeding the correlator with more open incidents than maxConcurrentPRs allows")
			corr := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
			const incidentCount = 5
			for i := 0; i < incidentCount; i++ {
				resource := fmt.Sprintf("svc-%d", i)
				corr.Ingest(&correlator.Event{
					Type: correlator.EventSecurityViolation, Severity: "critical",
					Namespace: "app", Resource: resource, ResourceKind: "Deployment",
					Message: "Container runs as root",
				})
				inc := corr.Ingest(&correlator.Event{
					Type: correlator.EventAnomaly, Severity: "high",
					Namespace: "app", Resource: resource, ResourceKind: "Deployment",
					Message: "Restart spike",
				})
				Expect(inc).NotTo(BeNil())
			}
			Expect(corr.GetOpenIncidents()).To(HaveLen(incidentCount))

			fakeLLM := &fakeDryRunLLM{response: fakeDryRunLLMResponse}
			fakeGit := &fakeDryRunGitops{}
			engine := remediation.NewEngine(fakeLLM, fakeGit,
				remediation.EngineConfig{Strategy: remediation.StrategyGitOpsPR},
				logr.Discard())

			_, err := (&RemediationPolicyReconciler{
				Client:            k8sClient,
				Scheme:            k8sClient.Scheme(),
				Recorder:          record.NewFakeRecorder(100),
				CorrelatorEngine:  corr,
				RemediationEngine: engine,
			}).Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
			Expect(err).NotTo(HaveOccurred())

			By("asserting the LLM is called at most maxConcurrentPRs times, not once per incident")
			Expect(fakeLLM.calls).To(Equal(int(maxPRs)),
				"dry-run plan generation must respect spec.maxConcurrentPRs as a per-cycle ceiling")
			Expect(fakeGit.createPRCalls).To(Equal(0))
			Expect(corr.GetOpenIncidents()).To(HaveLen(incidentCount),
				"dry-run must leave every incident open for a later non-dry-run reconcile")
		})
	})
})
