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

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
)

// PodSecurityScanner checks pods for Pod Security Standards violations:
// - HostNetwork, HostPID, HostIPC enabled
// - HostPath volumes mounted
// - Containers sharing process namespace
// - Dangerous capabilities (SYS_ADMIN, NET_RAW, etc.)
type PodSecurityScanner struct{}

var _ Scanner = &PodSecurityScanner{}

// Name implements Scanner.
func (s *PodSecurityScanner) Name() string {
	return "Pod Security"
}

// RuleType implements Scanner.
func (s *PodSecurityScanner) RuleType() string {
	return zelyov1alpha1.RuleTypePodSecurity
}

// dangerousCapabilities that should be dropped or never added.
var dangerousCapabilities = map[corev1.Capability]bool{
	"SYS_ADMIN":    true,
	"NET_RAW":      true,
	"SYS_PTRACE":   true,
	"SYS_MODULE":   true,
	"DAC_OVERRIDE": true,
}

// Scan implements Scanner.
//
// Scan implements Scanner.
func (s *PodSecurityScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]

		if fs := s.checkHostNamespaces(pod); len(fs) > 0 {
			findings = append(findings, fs...)
		}

		if fs := s.checkHostPaths(pod); len(fs) > 0 {
			findings = append(findings, fs...)
		}

		if fs := s.checkCapabilities(pod); len(fs) > 0 {
			findings = append(findings, fs...)
		}

		if fs := s.checkProcessSharing(pod); len(fs) > 0 {
			findings = append(findings, fs...)
		}
	}

	return findings, nil
}

func (s *PodSecurityScanner) checkHostNamespaces(pod *corev1.Pod) []Finding {
	var findings []Finding

	// Check: HostNetwork
	if pod.Spec.HostNetwork {
		findings = append(findings, Finding{
			RuleType:          s.RuleType(),
			Severity:          zelyov1alpha1.SeverityCritical,
			Title:             "Pod uses host network",
			Description:       "hostNetwork is enabled, giving the pod access to the host's network interfaces. This bypasses network policies.",
			ResourceKind:      "Pod",
			ResourceNamespace: pod.Namespace,
			ResourceName:      pod.Name,
			Recommendation:    "Remove hostNetwork: true unless the pod genuinely needs host networking (e.g., CNI plugins).",
		})
	}

	// Check: HostPID
	if pod.Spec.HostPID {
		findings = append(findings, Finding{
			RuleType:          s.RuleType(),
			Severity:          zelyov1alpha1.SeverityCritical,
			Title:             "Pod uses host PID namespace",
			Description:       "hostPID is enabled, allowing the pod to see and signal all host processes.",
			ResourceKind:      "Pod",
			ResourceNamespace: pod.Namespace,
			ResourceName:      pod.Name,
			Recommendation:    "Remove hostPID: true. This is rarely needed outside of system-level debugging.",
		})
	}

	// Check: HostIPC
	if pod.Spec.HostIPC {
		findings = append(findings, Finding{
			RuleType:          s.RuleType(),
			Severity:          zelyov1alpha1.SeverityHigh,
			Title:             "Pod uses host IPC namespace",
			Description:       "hostIPC is enabled, enabling shared memory communication with host processes.",
			ResourceKind:      "Pod",
			ResourceNamespace: pod.Namespace,
			ResourceName:      pod.Name,
			Recommendation:    "Remove hostIPC: true unless required for legacy IPC communication.",
		})
	}

	return findings
}

func (s *PodSecurityScanner) checkHostPaths(pod *corev1.Pod) []Finding {
	var findings []Finding

	// Check: HostPath volumes
	for i := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[i]
		if vol.HostPath != nil {
			sev := zelyov1alpha1.SeverityHigh
			if strings.HasPrefix(vol.HostPath.Path, "/var/run/docker.sock") ||
				strings.HasPrefix(vol.HostPath.Path, "/etc") ||
				strings.HasPrefix(vol.HostPath.Path, "/root") {
				sev = zelyov1alpha1.SeverityCritical
			}
			findings = append(findings, Finding{
				RuleType:          s.RuleType(),
				Severity:          sev,
				Title:             fmt.Sprintf("Pod mounts host path %q", vol.HostPath.Path),
				Description:       fmt.Sprintf("Volume %q mounts host path %q. This can expose sensitive host files.", vol.Name, vol.HostPath.Path),
				ResourceKind:      "Pod",
				ResourceNamespace: pod.Namespace,
				ResourceName:      pod.Name,
				Recommendation:    "Use PersistentVolumeClaims or emptyDir instead of hostPath. If hostPath is needed, use readOnly mode.",
			})
		}
	}

	return findings
}

func (s *PodSecurityScanner) checkCapabilities(pod *corev1.Pod) []Finding {
	var findings []Finding

	// Check: Dangerous capabilities on containers
	allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...) //nolint:gocritic
	for j := range allContainers {
		container := &allContainers[j]
		if container.SecurityContext == nil || container.SecurityContext.Capabilities == nil {
			continue
		}
		for _, cap := range container.SecurityContext.Capabilities.Add {
			if dangerousCapabilities[cap] {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Container %q adds dangerous capability %s", container.Name, cap),
					Description:       fmt.Sprintf("Capability %s is added to the container. This grants elevated kernel privileges.", cap),
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    fmt.Sprintf("Remove %s from securityContext.capabilities.add unless absolutely required.", cap),
				})
			}
		}
	}

	return findings
}

func (s *PodSecurityScanner) checkProcessSharing(pod *corev1.Pod) []Finding {
	var findings []Finding

	// Check: ShareProcessNamespace
	if pod.Spec.ShareProcessNamespace != nil && *pod.Spec.ShareProcessNamespace {
		findings = append(findings, Finding{
			RuleType:          s.RuleType(),
			Severity:          zelyov1alpha1.SeverityMedium,
			Title:             "Pod shares process namespace between containers",
			Description:       "shareProcessNamespace is enabled. Containers can see and signal each other's processes.",
			ResourceKind:      "Pod",
			ResourceNamespace: pod.Namespace,
			ResourceName:      pod.Name,
			Recommendation:    "Disable shareProcessNamespace unless containers genuinely need to share PID namespace.",
		})
	}

	return findings
}
