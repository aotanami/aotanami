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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/scanner"
)

var _ = Describe("SecurityPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-policy"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		securitypolicy := &zelyov1alpha1.SecurityPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SecurityPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, securitypolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.SecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: zelyov1alpha1.SecurityPolicySpec{
						Severity: "medium",
						Match: zelyov1alpha1.PolicyMatch{
							Namespaces: []string{"default"},
						},
						Rules: []zelyov1alpha1.SecurityRule{
							{
								Name: "test-rule",
								Type: "container-security-context",
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &zelyov1alpha1.SecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance SecurityPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &SecurityPolicyReconciler{
				Client:          k8sClient,
				Scheme:          k8sClient.Scheme(),
				Recorder:        record.NewFakeRecorder(10),
				ScannerRegistry: scanner.DefaultRegistry(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify status was updated.
			policy := &zelyov1alpha1.SecurityPolicy{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, policy)).To(Succeed())

			// Should be Active after successful reconciliation.
			Expect(policy.Status.Phase).To(Equal(zelyov1alpha1.PhaseActive))
			Expect(policy.Status.ObservedGeneration).To(Equal(policy.Generation))
			Expect(policy.Status.LastEvaluated).NotTo(BeNil())
		})
	})
})
