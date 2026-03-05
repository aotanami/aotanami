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

	corev1 "k8s.io/api/core/v1"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
)

// PrivilegeEscalationScanner checks containers for privilege escalation vectors:
// - Containers running as root (UID 0)
// - Writable /proc/sys via procMount
// - Service account token auto-mounted (default=true, a common attack vector)
// - Root group (GID 0) usage
type PrivilegeEscalationScanner struct{}

var _ Scanner = &PrivilegeEscalationScanner{}

// Name implements Scanner.
func (s *PrivilegeEscalationScanner) Name() string {
	return "Privilege Escalation"
}

// RuleType implements Scanner.
func (s *PrivilegeEscalationScanner) RuleType() string {
	return zelyov1alpha1.RuleTypePrivilegeEscalation
}

// Scan implements Scanner.
//
//nolint:gocyclo // Container iteration involves multiple contextual checks
func (s *PrivilegeEscalationScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]

		// Check: Service account token auto-mounted
		// Default is true — workloads that don't need the K8s API should disable this.
		if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityMedium,
				Title:             "Service account token is auto-mounted",
				Description:       "The pod auto-mounts the service account token. If compromised, an attacker can use it to access the Kubernetes API.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Set automountServiceAccountToken: false on pods that don't need Kubernetes API access.",
			})
		}

		// Check: Pod-level RunAsUser is 0 (root)
		if pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.RunAsUser != nil &&
			*pod.Spec.SecurityContext.RunAsUser == 0 {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityCritical,
				Title:             "Pod runs as root user (UID 0)",
				Description:       "The pod is configured to run as UID 0. A container escape from a root process is especially dangerous.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Set runAsUser to a non-zero UID, or set runAsNonRoot: true.",
			})
		}

		// Check: Pod-level RunAsGroup is 0 (root group)
		if pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.RunAsGroup != nil &&
			*pod.Spec.SecurityContext.RunAsGroup == 0 {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityMedium,
				Title:             "Pod runs as root group (GID 0)",
				Description:       "The pod is configured to run as GID 0 (root group). Files created by the container will be owned by the root group.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Set runAsGroup to a non-zero GID.",
			})
		}

		// Check container-level escalation vectors.
		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			if container.SecurityContext == nil {
				continue
			}

			// Container explicitly runs as root.
			if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("Container %q runs as root user (UID 0)", container.Name),
					Description:       "The container is configured to run as UID 0 (root). This maximizes the impact of a container escape.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set runAsUser to a non-zero UID in the container's securityContext.",
				})
			}

			// ProcMount set to Unmasked.
			if container.SecurityContext.ProcMount != nil {
				pm := *container.SecurityContext.ProcMount
				if pm == corev1.UnmaskedProcMount {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityCritical,
						Title:             fmt.Sprintf("Container %q has unmasked /proc mount", container.Name),
						Description:       "procMount is set to Unmasked, exposing the full /proc filesystem. This can leak sensitive host information.",
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Remove procMount or set it to Default.",
					})
				}
			}
		}
	}

	return findings, nil
}
