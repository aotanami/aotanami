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

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
)

const (
	// requeueIntervalConfig is the default requeue interval for config reconciliation.
	requeueIntervalConfig = 5 * time.Minute
)

// ZelyoConfigReconciler reconciles an ZelyoConfig object.
// It validates the global configuration, checks LLM API key secrets,
// enforces singleton semantics, and manages the agent lifecycle phase.
type ZelyoConfigReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=zelyoconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=zelyoconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=zelyoconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the main reconciliation loop for ZelyoConfig.
func (r *ZelyoConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the ZelyoConfig resource.
	config := &zelyov1alpha1.ZelyoConfig{}
	if err := r.Get(ctx, req.NamespacedName, config); err != nil {
		if errors.IsNotFound(err) {
			log.Info("ZelyoConfig resource not found — likely deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching ZelyoConfig: %w", err)
	}

	log.Info("Reconciling ZelyoConfig", "name", config.Name, "generation", config.Generation)

	// Mark as reconciling.
	conditions.MarkUnknown(&config.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonProgressingMessage, "Reconciliation in progress", config.Generation)

	// ── Step 1: Enforce singleton ──
	// Only one ZelyoConfig should exist per cluster.
	configList := &zelyov1alpha1.ZelyoConfigList{}
	if err := r.List(ctx, configList); err != nil {
		return ctrl.Result{}, fmt.Errorf("listing ZelyoConfigs: %w", err)
	}
	if len(configList.Items) > 1 {
		r.Recorder.Event(config, corev1.EventTypeWarning, zelyov1alpha1.EventReasonSingletonConflict,
			fmt.Sprintf("Multiple ZelyoConfig resources found (%d). Only one is allowed per cluster.", len(configList.Items)))
		conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonSingletonViolation,
			"Multiple ZelyoConfig resources exist — only one is allowed per cluster", config.Generation)
		config.Status.Phase = zelyov1alpha1.PhaseError
		config.Status.ObservedGeneration = config.Generation
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: requeueIntervalConfig}, nil
	}

	// ── Step 2: Validate LLM API key secret ──
	llmSecretName := config.Spec.LLM.APIKeySecret
	if llmSecretName == "" {
		conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionLLMConfigured,
			zelyov1alpha1.ReasonLLMNotConfigured, "LLM API key secret name is empty", config.Generation)
		conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonLLMNotConfigured, "LLM configuration is incomplete", config.Generation)
		config.Status.Phase = zelyov1alpha1.PhaseDegraded
		config.Status.ObservedGeneration = config.Generation
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: requeueIntervalConfig}, nil
	}

	// Look up the secret in the operator's namespace (default to "zelyo-system").
	operatorNamespace := "zelyo-system"
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: llmSecretName, Namespace: operatorNamespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(config, corev1.EventTypeWarning, zelyov1alpha1.EventReasonSecretMissing,
				fmt.Sprintf("LLM API key Secret %q not found in namespace %q", llmSecretName, operatorNamespace))
			conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
				zelyov1alpha1.ReasonSecretNotFound,
				fmt.Sprintf("Secret %q not found in namespace %q", llmSecretName, operatorNamespace), config.Generation)
			conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionLLMConfigured,
				zelyov1alpha1.ReasonSecretNotFound, "LLM API key secret not found", config.Generation)
			conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionReady,
				zelyov1alpha1.ReasonSecretNotFound, "Required secret not available", config.Generation)
			config.Status.Phase = zelyov1alpha1.PhaseDegraded
			config.Status.ObservedGeneration = config.Generation
			if err := r.Status().Update(ctx, config); err != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
			}
			return ctrl.Result{RequeueAfter: requeueIntervalConfig}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching LLM secret: %w", err)
	}

	// Verify the secret contains the "api-key" data key.
	if _, ok := secret.Data["api-key"]; !ok {
		r.Recorder.Event(config, corev1.EventTypeWarning, zelyov1alpha1.EventReasonSecretMissing,
			fmt.Sprintf("Secret %q exists but is missing the \"api-key\" data key", llmSecretName))
		conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
			zelyov1alpha1.ReasonSecretKeyMissing,
			fmt.Sprintf("Secret %q is missing the \"api-key\" key", llmSecretName), config.Generation)
		conditions.MarkFalse(&config.Status.Conditions, zelyov1alpha1.ConditionLLMConfigured,
			zelyov1alpha1.ReasonSecretKeyMissing, "LLM API key not found in secret", config.Generation)
		config.Status.Phase = zelyov1alpha1.PhaseDegraded
		config.Status.ObservedGeneration = config.Generation
		if err := r.Status().Update(ctx, config); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: requeueIntervalConfig}, nil
	}

	// ── Step 3: All checks passed — mark as Active ──
	conditions.MarkTrue(&config.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
		zelyov1alpha1.ReasonSecretResolved, "All referenced secrets are valid", config.Generation)
	conditions.MarkTrue(&config.Status.Conditions, zelyov1alpha1.ConditionLLMConfigured,
		zelyov1alpha1.ReasonLLMReady,
		fmt.Sprintf("LLM provider %q with model %q is configured", config.Spec.LLM.Provider, config.Spec.LLM.Model), config.Generation)
	conditions.MarkTrue(&config.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess, "Zelyo Operator agent is active and ready", config.Generation)

	now := metav1.Now()
	config.Status.Phase = zelyov1alpha1.PhaseActive
	config.Status.ActiveMode = config.Spec.Mode
	config.Status.LastReconciled = &now
	config.Status.ObservedGeneration = config.Generation

	if err := r.Status().Update(ctx, config); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(config, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("ZelyoConfig reconciled successfully (mode=%s, provider=%s)", config.Spec.Mode, config.Spec.LLM.Provider))

	log.Info("ZelyoConfig reconciled successfully",
		"phase", config.Status.Phase,
		"mode", config.Status.ActiveMode,
		"provider", config.Spec.LLM.Provider)

	return ctrl.Result{RequeueAfter: requeueIntervalConfig}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ZelyoConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.ZelyoConfig{}).
		Named("zelyoconfig").
		Complete(r)
}
