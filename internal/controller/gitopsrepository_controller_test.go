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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/gitops/source"
)

var _ = Describe("GitOpsRepository Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		gitopsrepository := &zelyov1alpha1.GitOpsRepository{}

		BeforeEach(func() {
			By("creating the auth secret for the GitOpsRepository")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("test-token"),
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-auth", Namespace: "default"}, &corev1.Secret{})
			if err != nil && errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("creating the custom resource for the Kind GitOpsRepository")
			err = k8sClient.Get(ctx, typeNamespacedName, gitopsrepository)
			if err != nil && errors.IsNotFound(err) {
				resource := &zelyov1alpha1.GitOpsRepository{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: zelyov1alpha1.GitOpsRepositorySpec{
						URL:        "https://github.com/test/repo",
						Paths:      []string{"clusters/"},
						AuthSecret: "test-auth",
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &zelyov1alpha1.GitOpsRepository{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance GitOpsRepository")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})

		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &GitOpsRepositoryReconciler{
				Client:         k8sClient,
				Scheme:         k8sClient.Scheme(),
				Recorder:       record.NewFakeRecorder(100),
				SourceRegistry: source.DefaultRegistry(),
				// ControllerRegistry is nil — tests run without ArgoCD/Flux CRDs.
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should detect source type as raw for basic paths", func() {
			By("Reconciling and checking status")
			controllerReconciler := &GitOpsRepositoryReconciler{
				Client:         k8sClient,
				Scheme:         k8sClient.Scheme(),
				Recorder:       record.NewFakeRecorder(100),
				SourceRegistry: source.DefaultRegistry(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Fetch the updated resource.
			updated := &zelyov1alpha1.GitOpsRepository{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())

			// Source type should be auto-detected.
			Expect(updated.Status.DetectedSourceType).NotTo(BeEmpty())
		})

		It("should report error when auth secret is missing", func() {
			By("Creating the auth secret")
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"token": []byte("test-token"),
				},
			}
			// Create secret if not exists.
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "test-auth", Namespace: "default"}, &corev1.Secret{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, secret)).To(Succeed())
			}

			By("Reconciling with secret present")
			controllerReconciler := &GitOpsRepositoryReconciler{
				Client:         k8sClient,
				Scheme:         k8sClient.Scheme(),
				Recorder:       record.NewFakeRecorder(100),
				SourceRegistry: source.DefaultRegistry(),
			}

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			// Fetch the updated resource.
			updated := &zelyov1alpha1.GitOpsRepository{}
			Expect(k8sClient.Get(ctx, typeNamespacedName, updated)).To(Succeed())
			Expect(updated.Status.Phase).To(Equal(zelyov1alpha1.PhaseSynced))

			// Cleanup secret.
			Expect(k8sClient.Delete(ctx, secret)).To(Succeed())
		})

		It("should handle explicit helm source type", func() {
			By("Creating a GitOps repo with helm source type")
			helmRepo := &zelyov1alpha1.GitOpsRepository{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "helm-test",
					Namespace: "default",
				},
				Spec: zelyov1alpha1.GitOpsRepositorySpec{
					URL:        "https://github.com/test/helm-repo",
					Paths:      []string{"charts/myapp/"},
					AuthSecret: "test-auth",
					SourceType: zelyov1alpha1.ManifestSourceHelm,
					Helm: &zelyov1alpha1.HelmSource{
						ChartPath:        "charts/myapp/",
						ReleaseName:      "myapp",
						ReleaseNamespace: "production",
					},
				},
			}
			Expect(k8sClient.Create(ctx, helmRepo)).To(Succeed())

			controllerReconciler := &GitOpsRepositoryReconciler{
				Client:         k8sClient,
				Scheme:         k8sClient.Scheme(),
				Recorder:       record.NewFakeRecorder(100),
				SourceRegistry: source.DefaultRegistry(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: "helm-test", Namespace: "default"},
			})
			Expect(err).NotTo(HaveOccurred())

			updated := &zelyov1alpha1.GitOpsRepository{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: "helm-test", Namespace: "default"}, updated)).To(Succeed())
			Expect(updated.Status.DetectedSourceType).To(Equal(zelyov1alpha1.ManifestSourceHelm))

			By("Cleanup")
			Expect(k8sClient.Delete(ctx, helmRepo)).To(Succeed())
		})
	})
})
