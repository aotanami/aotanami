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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner"
)

var _ = Describe("CloudAccountConfig Controller", func() {
	Context("When reconciling a resource", func() {
		const (
			resourceName      = "test-aws-account"
			resourceNamespace = "default"
		)

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: resourceNamespace,
		}
		cloudaccount := &zelyov1alpha1.CloudAccountConfig{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind CloudAccountConfig")
			err := k8sClient.Get(ctx, typeNamespacedName, cloudaccount)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.CloudAccountConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: resourceNamespace,
					},
					Spec: zelyov1alpha1.CloudAccountConfigSpec{
						Provider:  "aws",
						AccountID: "123456789012",
						Regions:   []string{"us-east-1"},
						Credentials: zelyov1alpha1.CloudCredentials{
							Method:    "secret",
							SecretRef: "aws-credentials",
						},
						ScanCategories: []string{"cspm"},
						Suspend:        true, // Suspend to avoid actual cloud API calls.
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &zelyov1alpha1.CloudAccountConfig{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			if err == nil {
				By("Cleanup the specific resource instance CloudAccountConfig")
				Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
			}
		})

		It("should successfully reconcile a suspended resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &CloudAccountConfigReconciler{
				Client:               k8sClient,
				Scheme:               k8sClient.Scheme(),
				Recorder:             record.NewFakeRecorder(10),
				CloudScannerRegistry: cloudscanner.NewRegistry(),
			}

			// First reconcile adds the finalizer and requeues.
			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile processes the suspended state.
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Third reconcile updates status for suspended account.
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify the resource was updated.
			config := &zelyov1alpha1.CloudAccountConfig{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, config)).To(Succeed())

			// Since the account is suspended, phase should be Active.
			Expect(config.Status.Phase).To(Equal(zelyov1alpha1.PhaseActive))
		})

		It("should add finalizer during reconcile", func() {
			// Verify the first test's reconciliation added the finalizer.
			// The suspended resource test already runs reconcile cycles,
			// so we verify the finalizer is present after those cycles.
			config := &zelyov1alpha1.CloudAccountConfig{}
			err := k8sClient.Get(ctx, typeNamespacedName, config)
			if errors.IsNotFound(err) {
				Skip("Resource was cleaned up by previous test")
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(config.Finalizers).To(ContainElement(cloudAccountFinalizer))
		})
	})
})
