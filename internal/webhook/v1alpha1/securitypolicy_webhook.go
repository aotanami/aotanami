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

package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	aotanamiv1alpha1 "github.com/aotanami/aotanami/api/v1alpha1"
)

// log is for logging in this package.
var securitypolicylog = logf.Log.WithName("securitypolicy-resource")

// SetupSecurityPolicyWebhookWithManager registers the webhook for SecurityPolicy in the manager.
func SetupSecurityPolicyWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, &aotanamiv1alpha1.SecurityPolicy{}).
		WithValidator(&SecurityPolicyCustomValidator{}).
		WithDefaulter(&SecurityPolicyCustomDefaulter{}).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-aotanami-zelyo-ai-v1alpha1-securitypolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=aotanami.com,resources=securitypolicies,verbs=create;update,versions=v1alpha1,name=msecuritypolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// SecurityPolicyCustomDefaulter sets default values on SecurityPolicy resources
// when they are created or updated.
type SecurityPolicyCustomDefaulter struct{}

// Default implements webhook.CustomDefaulter.
func (d *SecurityPolicyCustomDefaulter) Default(_ context.Context, obj *aotanamiv1alpha1.SecurityPolicy) error {
	securitypolicylog.Info("Defaulting for SecurityPolicy", "name", obj.GetName())

	// Default severity to "medium" if not set.
	if obj.Spec.Severity == "" {
		obj.Spec.Severity = aotanamiv1alpha1.SeverityMedium
	}

	// Default each rule's enforce field to true.
	for i := range obj.Spec.Rules {
		if !obj.Spec.Rules[i].Enforce {
			obj.Spec.Rules[i].Enforce = true
		}
	}

	return nil
}

// validRuleTypes is the set of accepted security rule types.
var validRuleTypes = map[string]bool{
	aotanamiv1alpha1.RuleTypeContainerSecurityContext: true,
	aotanamiv1alpha1.RuleTypeRBACAudit:                true,
	aotanamiv1alpha1.RuleTypeImageVulnerability:       true,
	aotanamiv1alpha1.RuleTypeNetworkPolicy:            true,
	aotanamiv1alpha1.RuleTypePodSecurity:              true,
	aotanamiv1alpha1.RuleTypeSecretsExposure:          true,
	aotanamiv1alpha1.RuleTypeResourceLimits:           true,
	aotanamiv1alpha1.RuleTypePrivilegeEscalation:      true,
}

// validSeverities is the set of accepted severity levels.
var validSeverities = map[string]bool{
	aotanamiv1alpha1.SeverityCritical: true,
	aotanamiv1alpha1.SeverityHigh:     true,
	aotanamiv1alpha1.SeverityMedium:   true,
	aotanamiv1alpha1.SeverityLow:      true,
	aotanamiv1alpha1.SeverityInfo:     true,
}

// +kubebuilder:webhook:path=/validate-aotanami-zelyo-ai-v1alpha1-securitypolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=aotanami.com,resources=securitypolicies,verbs=create;update,versions=v1alpha1,name=vsecuritypolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// SecurityPolicyCustomValidator validates SecurityPolicy resources
// when they are created, updated, or deleted.
type SecurityPolicyCustomValidator struct{}

// ValidateCreate implements webhook.CustomValidator.
func (v *SecurityPolicyCustomValidator) ValidateCreate(_ context.Context, obj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	securitypolicylog.Info("Validation for SecurityPolicy upon creation", "name", obj.GetName())
	return v.validate(obj)
}

// ValidateUpdate implements webhook.CustomValidator.
func (v *SecurityPolicyCustomValidator) ValidateUpdate(_ context.Context, _, newObj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	securitypolicylog.Info("Validation for SecurityPolicy upon update", "name", newObj.GetName())
	return v.validate(newObj)
}

// ValidateDelete implements webhook.CustomValidator.
func (v *SecurityPolicyCustomValidator) ValidateDelete(_ context.Context, _ *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	// No validation needed on delete.
	return nil, nil
}

// validate performs the common validation logic for create and update.
func (v *SecurityPolicyCustomValidator) validate(obj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	var allErrs field.ErrorList
	var warnings admission.Warnings
	specPath := field.NewPath("spec")

	// Validate severity.
	if obj.Spec.Severity != "" && !validSeverities[obj.Spec.Severity] {
		allErrs = append(allErrs, field.Invalid(
			specPath.Child("severity"),
			obj.Spec.Severity,
			fmt.Sprintf("must be one of: %s", strings.Join(sortedKeys(validSeverities), ", ")),
		))
	}

	// Validate rules — at least one required.
	rulesPath := specPath.Child("rules")
	if len(obj.Spec.Rules) == 0 {
		allErrs = append(allErrs, field.Required(rulesPath, "at least one rule is required"))
	}

	// Validate each rule.
	ruleNames := make(map[string]bool, len(obj.Spec.Rules))
	for i, rule := range obj.Spec.Rules {
		rulePath := rulesPath.Index(i)

		// Rule name must be unique.
		if rule.Name == "" {
			allErrs = append(allErrs, field.Required(rulePath.Child("name"), "rule name is required"))
		} else if ruleNames[rule.Name] {
			allErrs = append(allErrs, field.Duplicate(rulePath.Child("name"), rule.Name))
		}
		ruleNames[rule.Name] = true

		// Rule type must be valid.
		if !validRuleTypes[rule.Type] {
			allErrs = append(allErrs, field.Invalid(
				rulePath.Child("type"),
				rule.Type,
				fmt.Sprintf("must be one of: %s", strings.Join(sortedKeys(validRuleTypes), ", ")),
			))
		}
	}

	// Validate schedule (basic cron format check).
	if obj.Spec.Schedule != "" {
		parts := strings.Fields(obj.Spec.Schedule)
		if len(parts) != 5 {
			allErrs = append(allErrs, field.Invalid(
				specPath.Child("schedule"),
				obj.Spec.Schedule,
				"must be a valid cron expression with 5 fields (minute hour day month weekday)",
			))
		}
	}

	// Warn if autoRemediate is set (feature not yet available).
	if obj.Spec.AutoRemediate {
		warnings = append(warnings, "autoRemediate is enabled but auto-remediation requires a GitOpsRepository to be onboarded")
	}

	if len(allErrs) > 0 {
		return warnings, allErrs.ToAggregate()
	}
	return warnings, nil
}

// sortedKeys returns the sorted keys of a map for deterministic error messages.
func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort for deterministic output.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
