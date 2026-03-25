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

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/conditions"
	aotmetrics "github.com/zelyo-ai/zelyo/internal/metrics"
)

// ScanReportReconciler reconciles a ScanReport object.
// ScanReports are primarily created by the ClusterScan controller.
// This controller manages their lifecycle and ensures proper status tracking.
type ScanReportReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=scanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=scanreports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=scanreports/finalizers,verbs=update

// Reconcile manages ScanReport lifecycle.
func (r *ScanReportReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	report := &zelyov1alpha1.ScanReport{}
	if err := r.Get(ctx, req.NamespacedName, report); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching ScanReport: %w", err)
	}

	log.Info("Reconciling ScanReport",
		"name", report.Name,
		"scanRef", report.Spec.ScanRef,
		"findings", report.Spec.Summary.TotalFindings)

	// Ensure status reflects the report content.
	if report.Status.Phase == "" {
		report.Status.Phase = zelyov1alpha1.PhaseComplete
		report.Status.ObservedGeneration = report.Generation
		conditions.MarkTrue(&report.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileSuccess,
			fmt.Sprintf("Report contains %d findings", report.Spec.Summary.TotalFindings),
			report.Generation)

		if err := r.Status().Update(ctx, report); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating ScanReport status: %w", err)
		}
		aotmetrics.ReconcileTotal.WithLabelValues("scanreport", "success").Inc()
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ScanReportReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.ScanReport{}).
		Named("scanreport").
		Complete(r)
}
