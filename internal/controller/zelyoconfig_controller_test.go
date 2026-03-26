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
)

var _ = Describe("ZelyoConfig Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-config"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name: resourceName,
		}
		zelyoconfig := &zelyov1alpha1.ZelyoConfig{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind ZelyoConfig")
			err := k8sClient.Get(ctx, typeNamespacedName, zelyoconfig)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.ZelyoConfig{
					ObjectMeta: metav1.ObjectMeta{
						Name: resourceName,
					},
					Spec: zelyov1alpha1.ZelyoConfigSpec{
						LLM: zelyov1alpha1.LLMConfig{
							Provider:     "openrouter",
							Model:        "test-model",
							APIKeySecret: "test-secret",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &zelyov1alpha1.ZelyoConfig{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance ZelyoConfig")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &ZelyoConfigReconciler{
				Client:   k8sClient,
				Scheme:   k8sClient.Scheme(),
				Recorder: record.NewFakeRecorder(10),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify status was updated.
			config := &zelyov1alpha1.ZelyoConfig{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, config)).To(Succeed())

			// Phase should be Degraded since the LLM secret doesn't exist in the test env.
			Expect(config.Status.Phase).To(Equal(zelyov1alpha1.PhaseDegraded))
			Expect(config.Status.ObservedGeneration).To(Equal(config.Generation))
		})
	})
})
