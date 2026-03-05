/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.

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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	aotanamiv1alpha1 "github.com/aotanami/aotanami/api/v1alpha1"
	"github.com/aotanami/aotanami/internal/conditions"
	aotmetrics "github.com/aotanami/aotanami/internal/metrics"
)

// CostPolicyReconciler reconciles a CostPolicy object.
// It validates the cost policy configuration and monitors workload
// resource utilization to identify rightsizing opportunities.
type CostPolicyReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=aotanami.com,resources=costpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=costpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=costpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile validates the CostPolicy and evaluates workload resource usage.
//
//nolint:gocyclo // Controller logic is inherently complex
func (r *CostPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("costpolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &aotanamiv1alpha1.CostPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching CostPolicy: %w", err)
	}

	log.Info("Reconciling CostPolicy", "name", policy.Name, "namespace", policy.Namespace,
		"strategy", policy.Spec.ResizeStrategy)

	// Mark as reconciling.
	conditions.MarkReconciling(&policy.Status.Conditions, "Reconciliation in progress", policy.Generation)

	// Resolve target namespaces and count pods.
	var targetNamespaces []string
	if len(policy.Spec.TargetNamespaces) > 0 {
		targetNamespaces = policy.Spec.TargetNamespaces
	} else {
		nsList := &corev1.NamespaceList{}
		if err := r.List(ctx, nsList); err != nil {
			return ctrl.Result{}, fmt.Errorf("listing namespaces: %w", err)
		}
		for i := range nsList.Items {
			ns := &nsList.Items[i]
			targetNamespaces = append(targetNamespaces, ns.Name)
		}
	}

	// Count pods without resource limits (idle detection basis).
	var totalPods, podsWithoutLimits int32
	for _, ns := range targetNamespaces {
		podList := &corev1.PodList{}
		if err := r.List(ctx, podList, client.InNamespace(ns)); err != nil {
			continue
		}
		for i := range podList.Items {
			if podList.Items[i].Status.Phase != corev1.PodRunning {
				continue
			}
			totalPods++
			// Count containers without limits
			for j := range podList.Items[i].Spec.Containers {
				c := &podList.Items[i].Spec.Containers[j]
				if c.Resources.Limits.Cpu() == nil || c.Resources.Limits.Cpu().IsZero() ||
					c.Resources.Limits.Memory() == nil || c.Resources.Limits.Memory().IsZero() {
					podsWithoutLimits++
					break
				}
			}
		}
	}

	// Update status.
	now := metav1.Now()
	policy.Status.Phase = aotanamiv1alpha1.PhaseActive
	policy.Status.LastEvaluated = &now
	policy.Status.RightsizingRecommendations = podsWithoutLimits
	policy.Status.ObservedGeneration = policy.Generation

	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
		aotanamiv1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("Evaluated %d pods across %d namespaces", totalPods, len(targetNamespaces)),
		policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonReconciled,
		fmt.Sprintf("CostPolicy evaluated: %d pods, %d need rightsizing", totalPods, podsWithoutLimits))

	aotmetrics.ReconcileTotal.WithLabelValues("costpolicy", "success").Inc()
	aotmetrics.CostRightsizingGauge.WithLabelValues(policy.Name, policy.Namespace).Set(float64(podsWithoutLimits))
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CostPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.CostPolicy{}).
		Named("costpolicy").
		Complete(r)
}
