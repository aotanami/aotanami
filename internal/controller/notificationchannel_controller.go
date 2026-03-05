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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	aotmetrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
)

// NotificationChannelReconciler reconciles a NotificationChannel object.
// It validates the channel configuration and credential secret.
type NotificationChannelReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=notificationchannels,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=notificationchannels/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=notificationchannels/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile validates the notification channel configuration.
func (r *NotificationChannelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("notificationchannel").Observe(time.Since(start).Seconds())
	}()

	channel := &zelyov1alpha1.NotificationChannel{}
	if err := r.Get(ctx, req.NamespacedName, channel); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching NotificationChannel: %w", err)
	}

	log.Info("Reconciling NotificationChannel", "name", channel.Name, "type", channel.Spec.Type)

	// Mark as reconciling.
	conditions.MarkReconciling(&channel.Status.Conditions, "Reconciliation in progress", channel.Generation)

	// Validate credential secret exists.
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: channel.Spec.CredentialSecret, Namespace: channel.Namespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(channel, corev1.EventTypeWarning, zelyov1alpha1.EventReasonSecretMissing,
				fmt.Sprintf("Credential Secret %q not found", channel.Spec.CredentialSecret))
			conditions.MarkFalse(&channel.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
				zelyov1alpha1.ReasonSecretNotFound,
				fmt.Sprintf("Secret %q not found", channel.Spec.CredentialSecret), channel.Generation)
			conditions.MarkFalse(&channel.Status.Conditions, zelyov1alpha1.ConditionReady,
				zelyov1alpha1.ReasonSecretNotFound, "Credential secret not available", channel.Generation)
			channel.Status.Phase = zelyov1alpha1.PhaseError
			channel.Status.LastError = fmt.Sprintf("Secret %q not found", channel.Spec.CredentialSecret)
			channel.Status.ObservedGeneration = channel.Generation
			if statusErr := r.Status().Update(ctx, channel); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching credential secret: %w", err)
	}

	// Mark secret as resolved.
	conditions.MarkTrue(&channel.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
		zelyov1alpha1.ReasonSecretResolved, "Credential secret is available", channel.Generation)

	// Mark as active.
	channel.Status.Phase = zelyov1alpha1.PhaseActive
	channel.Status.LastError = ""
	channel.Status.ObservedGeneration = channel.Generation
	conditions.MarkTrue(&channel.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("Channel type %q is configured and ready", channel.Spec.Type), channel.Generation)

	if err := r.Status().Update(ctx, channel); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(channel, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("NotificationChannel configured (type=%s)", channel.Spec.Type))

	aotmetrics.ReconcileTotal.WithLabelValues("notificationchannel", "success").Inc()
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NotificationChannelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.NotificationChannel{}).
		Named("notificationchannel").
		Complete(r)
}
