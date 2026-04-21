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
					Type:           correlator.EventSecurityViolation,
					Source:         "securitypolicy/" + targetedSP,
					SecurityPolicy: targetedSP,
					Severity:       zelyov1alpha1.SeverityCritical,
					Namespace:      ns,
					Resource:       targetedPod,
					ResourceKind:   "Pod",
					Message:        "privileged container",
				})
			}
			// Two events on pod-other tagged with a NON-targeted SecurityPolicy
			// → forms a second correlated incident that must be filtered out.
			for i := 0; i < 2; i++ {
				corr.Ingest(&correlator.Event{
					Type:           correlator.EventSecurityViolation,
					Source:         "securitypolicy/" + otherSP,
					SecurityPolicy: otherSP,
					Severity:       zelyov1alpha1.SeverityCritical,
					Namespace:      ns,
					Resource:       otherPod,
					ResourceKind:   "Pod",
					Message:        "privileged container",
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
					Type:           correlator.EventSecurityViolation,
					SecurityPolicy: targetedSP,
					Severity:       zelyov1alpha1.SeverityCritical,
					Namespace:      ns, Resource: targetedPod,
					ResourceKind: "Pod", Message: "x",
				})
				corr.Ingest(&correlator.Event{
					Type:           correlator.EventSecurityViolation,
					SecurityPolicy: otherSP,
					Severity:       zelyov1alpha1.SeverityCritical,
					Namespace:      ns, Resource: otherPod,
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
