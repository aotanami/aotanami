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

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
)

// ContainerSecurityContextScanner checks containers for insecure security contexts:
// - runAsNonRoot not set or false
// - readOnlyRootFilesystem not set or false
// - privileged containers
// - allowPrivilegeEscalation not explicitly disabled
type ContainerSecurityContextScanner struct{}

var _ Scanner = &ContainerSecurityContextScanner{}

// Name implements Scanner.
func (s *ContainerSecurityContextScanner) Name() string {
	return "Container Security Context"
}

// RuleType implements Scanner.
func (s *ContainerSecurityContextScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeContainerSecurityContext
}

// Scan implements Scanner.
func (s *ContainerSecurityContextScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...) //nolint:gocritic

		for j := range allContainers {
			container := &allContainers[j]
			sc := container.SecurityContext

			// Check: No security context at all
			if sc == nil {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Container %q has no security context", container.Name),
					Description:       "No SecurityContext is defined. This means the container runs with default privileges, which may be excessive.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set a SecurityContext with runAsNonRoot: true, readOnlyRootFilesystem: true, and allowPrivilegeEscalation: false.",
				})
				continue
			}

			// Check: Privileged container
			if sc.Privileged != nil && *sc.Privileged {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("Container %q runs as privileged", container.Name),
					Description:       "Running as privileged gives the container full access to the host. This is a critical security risk.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Remove privileged: true from the security context unless absolutely required.",
				})
			}

			// Check: runAsNonRoot not set or false
			if sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
				// Also check pod-level security context
				podRunAsNonRoot := pod.Spec.SecurityContext != nil &&
					pod.Spec.SecurityContext.RunAsNonRoot != nil &&
					*pod.Spec.SecurityContext.RunAsNonRoot

				if !podRunAsNonRoot {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityMedium,
						Title:             fmt.Sprintf("Container %q may run as root", container.Name),
						Description:       "runAsNonRoot is not set to true. The container may run as UID 0 (root).",
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Set securityContext.runAsNonRoot: true.",
					})
				}
			}

			// Check: readOnlyRootFilesystem
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityLow,
					Title:             fmt.Sprintf("Container %q has writable root filesystem", container.Name),
					Description:       "readOnlyRootFilesystem is not set to true. An attacker could write to the container filesystem.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set securityContext.readOnlyRootFilesystem: true and use emptyDir volumes for writable paths.",
				})
			}

			// Check: allowPrivilegeEscalation not explicitly disabled
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Container %q allows privilege escalation", container.Name),
					Description:       "allowPrivilegeEscalation is not set to false. A process inside the container could gain more privileges than its parent.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set securityContext.allowPrivilegeEscalation: false.",
				})
			}
		}
	}

	return findings, nil
}
