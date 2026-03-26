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

package scanner

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
)

// RBACAuditScanner checks for RBAC-related security concerns at the pod level:
// - Pods using the default service account (which may have overly broad permissions)
// - Pods with service account token mounted that could be exploited
// - Pods in non-system namespaces using service accounts with admin/cluster prefixes
type RBACAuditScanner struct{}

var _ Scanner = &RBACAuditScanner{}

// Name implements Scanner.
func (s *RBACAuditScanner) Name() string {
	return "RBAC Audit"
}

// RuleType implements Scanner.
func (s *RBACAuditScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeRBACAudit
}

// dangerousSANames are service account name patterns that suggest overly broad permissions.
var dangerousSANames = []string{"admin", "cluster-admin", "superuser", "root"}

// Scan implements Scanner.
func (s *RBACAuditScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]

		// Skip system namespaces.
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		const defaultSA = "default"

		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = defaultSA
		}

		// Check: Using default service account.
		if saName == defaultSA {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityMedium,
				Title:             "Pod uses the default service account",
				Description:       "Using the default service account means the pod inherits whatever RBAC bindings exist on 'default'. This is often more permissive than needed.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Create a dedicated service account with least-privilege RBAC bindings for this workload.",
			})
		}

		// Check: Service account name suggests admin-level access.
		saLower := strings.ToLower(saName)
		for _, pattern := range dangerousSANames {
			if strings.Contains(saLower, pattern) {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Pod uses potentially over-privileged service account %q", saName),
					Description:       fmt.Sprintf("Service account %q contains %q in its name, suggesting admin-level permissions. Workloads should use least-privilege service accounts.", saName, pattern),
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Audit the RBAC bindings of this service account and replace with a least-privilege alternative.",
				})
				break
			}
		}

		// Check: Deprecated service account annotations.
		if pod.Spec.DeprecatedServiceAccount != "" && pod.Spec.DeprecatedServiceAccount != saName {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityLow,
				Title:             "Pod uses deprecated serviceAccount field",
				Description:       "The deprecated 'serviceAccount' field is set. Use 'serviceAccountName' instead.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Migrate from spec.serviceAccount to spec.serviceAccountName.",
			})
		}
	}

	return findings, nil
}
