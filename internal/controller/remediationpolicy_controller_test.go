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
})

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

// structured JSON plan produced by fakeDryRunLLM — single safe update fix
// that passes extractFixes validation.
const fakeDryRunLLMResponse = `{
    "analysis": "Container nginx runs as root; enforce runAsNonRoot.",
    "fixes": [
        {
            "file_path": "k8s/app/nginx.yaml",
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
