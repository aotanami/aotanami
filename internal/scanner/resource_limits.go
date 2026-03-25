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

// ResourceLimitsScanner checks containers for missing CPU/memory requests and limits.
// Workloads without resource limits can starve other pods and cause node instability.
type ResourceLimitsScanner struct{}

var _ Scanner = &ResourceLimitsScanner{}

// Name implements Scanner.
func (s *ResourceLimitsScanner) Name() string {
	return "Resource Limits"
}

// RuleType implements Scanner.
func (s *ResourceLimitsScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeResourceLimits
}

// Scan implements Scanner.
func (s *ResourceLimitsScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]

		for j := range pod.Spec.Containers {
			container := &pod.Spec.Containers[j]
			resources := container.Resources

			// Check: Missing CPU request
			if resources.Requests.Cpu() == nil || resources.Requests.Cpu().IsZero() {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Container %q has no CPU request", container.Name),
					Description:       "No CPU request is defined. The scheduler cannot make optimal placement decisions without resource requests.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set resources.requests.cpu to a value that reflects the container's expected CPU usage.",
				})
			}

			// Check: Missing memory request
			if resources.Requests.Memory() == nil || resources.Requests.Memory().IsZero() {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Container %q has no memory request", container.Name),
					Description:       "No memory request is defined. The scheduler cannot make optimal placement decisions without resource requests.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set resources.requests.memory to a value that reflects the container's expected memory usage.",
				})
			}

			// Check: Missing CPU limit
			if resources.Limits.Cpu() == nil || resources.Limits.Cpu().IsZero() {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Container %q has no CPU limit", container.Name),
					Description:       "No CPU limit is defined. The container can consume unbounded CPU, potentially starving other workloads.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set resources.limits.cpu to prevent unbounded CPU consumption.",
				})
			}

			// Check: Missing memory limit
			if resources.Limits.Memory() == nil || resources.Limits.Memory().IsZero() {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Container %q has no memory limit", container.Name),
					Description:       "No memory limit is defined. The container can consume unbounded memory, leading to OOMKill of other pods.",
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Set resources.limits.memory to prevent unbounded memory consumption.",
				})
			}
		}
	}

	return findings, nil
}
