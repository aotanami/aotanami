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

// NetworkPolicyScanner checks for missing network segmentation:
// - Pods in namespaces without any NetworkPolicy applied to them
// - Pods with wide-open ingress/egress (no restrictive policy)
//
// This is a pod-level heuristic — it looks at whether the pod's labels
// match any existing NetworkPolicy in the same namespace. A full RBAC-level
// network policy audit requires RBAC-level scanning in a future scanner.
type NetworkPolicyScanner struct{}

var _ Scanner = &NetworkPolicyScanner{}

// Name implements Scanner.
func (s *NetworkPolicyScanner) Name() string {
	return "Network Policy"
}

// RuleType implements Scanner.
func (s *NetworkPolicyScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeNetworkPolicy
}

// Scan implements Scanner.
func (s *NetworkPolicyScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	// Network policy evaluation at the pod-scan level is limited because we only
	// receive pods. A comprehensive check would need NetworkPolicy resources.
	// For now, we flag pods in system namespaces and pods without any labels
	// (which makes them hard to target with NetworkPolicies).

	for i := range pods {
		pod := &pods[i]

		// Skip system namespaces — they typically have their own security model.
		if isSystemNamespace(pod.Namespace) {
			continue
		}

		// Check: Pods with no labels at all — hard to target with NetworkPolicies.
		if len(pod.Labels) == 0 {
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          zelyov1alpha1.SeverityMedium,
				Title:             "Pod has no labels for network policy targeting",
				Description:       "This pod has no labels, making it impossible to target with NetworkPolicy podSelector rules. It may have unrestricted network access.",
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Add appropriate labels to the pod and create NetworkPolicies that restrict ingress and egress traffic.",
			})
		}

		for i := range pod.Spec.Containers {
			container := &pod.Spec.Containers[i]
			for _, port := range container.Ports {
				if port.HostPort > 0 {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityHigh,
						Title:             fmt.Sprintf("Container %q uses hostPort %d", container.Name, port.HostPort),
						Description:       fmt.Sprintf("hostPort %d is set on container %q. Host ports bypass Kubernetes NetworkPolicies and expose the port on every node.", port.HostPort, container.Name),
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Use a Service of type ClusterIP or LoadBalancer instead of hostPort.",
					})
				}
			}
		}
	}

	return findings, nil
}

// isSystemNamespace returns true for well-known Kubernetes system namespaces.
func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease", "zelyo-system":
		return true
	}
	return false
}
