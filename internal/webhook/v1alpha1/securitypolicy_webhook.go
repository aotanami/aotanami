/*
Copyright 2026 Zelyo AI.

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

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-aotanami-zelyo-ai-v1alpha1-securitypolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=aotanami.com,resources=securitypolicies,verbs=create;update,versions=v1alpha1,name=msecuritypolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// SecurityPolicyCustomDefaulter struct is responsible for setting default values on the custom resource of the
// Kind SecurityPolicy when those are created or updated.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as it is used only for temporary operations and does not need to be deeply copied.
type SecurityPolicyCustomDefaulter struct {
	// TODO(user): Add more fields as needed for defaulting
}

// Default implements webhook.CustomDefaulter so a webhook will be registered for the Kind SecurityPolicy.
func (d *SecurityPolicyCustomDefaulter) Default(_ context.Context, obj *aotanamiv1alpha1.SecurityPolicy) error {
	securitypolicylog.Info("Defaulting for SecurityPolicy", "name", obj.GetName())

	// TODO(user): fill in your defaulting logic.

	return nil
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-aotanami-zelyo-ai-v1alpha1-securitypolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=aotanami.com,resources=securitypolicies,verbs=create;update,versions=v1alpha1,name=vsecuritypolicy-v1alpha1.kb.io,admissionReviewVersions=v1

// SecurityPolicyCustomValidator struct is responsible for validating the SecurityPolicy resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type SecurityPolicyCustomValidator struct {
	// TODO(user): Add more fields as needed for validation
}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type SecurityPolicy.
func (v *SecurityPolicyCustomValidator) ValidateCreate(_ context.Context, obj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	securitypolicylog.Info("Validation for SecurityPolicy upon creation", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object creation.

	return nil, nil
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type SecurityPolicy.
func (v *SecurityPolicyCustomValidator) ValidateUpdate(_ context.Context, oldObj, newObj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	securitypolicylog.Info("Validation for SecurityPolicy upon update", "name", newObj.GetName())

	// TODO(user): fill in your validation logic upon object update.

	return nil, nil
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type SecurityPolicy.
func (v *SecurityPolicyCustomValidator) ValidateDelete(_ context.Context, obj *aotanamiv1alpha1.SecurityPolicy) (admission.Warnings, error) {
	securitypolicylog.Info("Validation for SecurityPolicy upon deletion", "name", obj.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}
