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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/anomaly"
	"github.com/zelyo-ai/zelyo/internal/conditions"
	"github.com/zelyo-ai/zelyo/internal/correlator"
	aotmetrics "github.com/zelyo-ai/zelyo/internal/metrics"
)

// MonitoringPolicyReconciler reconciles a MonitoringPolicy object.
// It validates the monitoring configuration and sets up event/log watches.
type MonitoringPolicyReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	AnomalyDetector  *anomaly.Detector  // Shared anomaly detector for baseline learning.
	CorrelatorEngine *correlator.Engine // Shared correlator for cross-signal correlation.
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=monitoringpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=monitoringpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=monitoringpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=events,verbs=get;list;watch;create;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile validates and activates the MonitoringPolicy.
func (r *MonitoringPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("monitoringpolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &zelyov1alpha1.MonitoringPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching MonitoringPolicy: %w", err)
	}

	log.Info("Reconciling MonitoringPolicy", "name", policy.Name, "namespace", policy.Namespace)

	// Mark as reconciling.
	conditions.MarkReconciling(&policy.Status.Conditions, "Reconciliation in progress", policy.Generation)

	// Validate notification channels exist.
	for _, chName := range policy.Spec.NotificationChannels {
		ch := &zelyov1alpha1.NotificationChannel{}
		key := types.NamespacedName{Name: chName, Namespace: policy.Namespace}
		if err := r.Get(ctx, key, ch); err != nil {
			if errors.IsNotFound(err) {
				r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
					fmt.Sprintf("NotificationChannel %q not found", chName))
				conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
					zelyov1alpha1.ReasonTargetNotFound,
					fmt.Sprintf("NotificationChannel %q not found", chName), policy.Generation)
				policy.Status.Phase = zelyov1alpha1.PhaseDegraded
				policy.Status.ObservedGeneration = policy.Generation
				if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
					return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
				}
				return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
			}
			return ctrl.Result{}, fmt.Errorf("checking NotificationChannel: %w", err)
		}
	}

	// ── Observe pod metrics for anomaly detection ──
	var anomaliesDetected int
	if r.AnomalyDetector != nil {
		anomaliesDetected = r.observePodMetrics(ctx, policy)
	}

	// Mark as active.
	now := metav1.Now()
	policy.Status.Phase = zelyov1alpha1.PhaseActive
	policy.Status.LastEventTime = &now
	policy.Status.ObservedGeneration = policy.Generation
	conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("Monitoring policy is active (anomalies detected: %d)", anomaliesDetected), policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("MonitoringPolicy reconciled (event types: %v)", policy.Spec.EventFilters.Types))

	aotmetrics.ReconcileTotal.WithLabelValues("monitoringpolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// observePodMetrics lists pods in the policy's target namespaces and feeds
// restart counts into the anomaly detector. Detected anomalies are ingested
// into the correlator for cross-signal incident grouping.
func (r *MonitoringPolicyReconciler) observePodMetrics(ctx context.Context, policy *zelyov1alpha1.MonitoringPolicy) int {
	log := logf.FromContext(ctx)

	// Use policy's target namespaces, or fall back to the policy's own namespace.
	namespaces := policy.Spec.TargetNamespaces
	if len(namespaces) == 0 {
		namespaces = []string{policy.Namespace}
	}

	var anomaliesDetected int
	for _, ns := range namespaces {
		podList := &corev1.PodList{}
		if err := r.List(ctx, podList, client.InNamespace(ns)); err != nil {
			log.Error(err, "Failed to list pods for anomaly detection", "namespace", ns)
			continue
		}

		for i := range podList.Items {
			pod := &podList.Items[i]
			if pod.Status.Phase != corev1.PodRunning {
				continue
			}

			for j := range pod.Status.ContainerStatuses {
				cs := &pod.Status.ContainerStatuses[j]
				key := fmt.Sprintf("%s/%s/%s/restarts", pod.Namespace, pod.Name, cs.Name)
				anom := r.AnomalyDetector.Observe(key, float64(cs.RestartCount))
				if anom == nil {
					continue
				}

				anomaliesDetected++
				log.Info("Anomaly detected",
					"pod", pod.Name,
					"container", cs.Name,
					"severity", anom.Severity,
					"deviation", fmt.Sprintf("%.1fσ", anom.DeviationSigma))

				r.Recorder.Event(policy, corev1.EventTypeWarning, "AnomalyDetected",
					fmt.Sprintf("Anomaly: %s (%.1fσ deviation)", anom.Message, anom.DeviationSigma))

				// Feed into correlator for cross-signal correlation.
				if r.CorrelatorEngine != nil {
					r.CorrelatorEngine.Ingest(&correlator.Event{
						Type:         correlator.EventAnomaly,
						Source:       fmt.Sprintf("monitoringpolicy/%s", policy.Name),
						Severity:     anom.Severity,
						Namespace:    pod.Namespace,
						Resource:     pod.Name,
						ResourceKind: "Pod",
						Message:      anom.Message,
					})
				}
			}
		}
	}

	if anomaliesDetected > 0 {
		log.Info("Anomaly detection cycle complete", "anomaliesDetected", anomaliesDetected)
	}

	return anomaliesDetected
}

// SetupWithManager sets up the controller with the Manager.
func (r *MonitoringPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.MonitoringPolicy{}).
		Named("monitoringpolicy").
		Complete(r)
}
