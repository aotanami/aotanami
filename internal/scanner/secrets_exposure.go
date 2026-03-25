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

// SecretsExposureScanner checks for common patterns that leak sensitive data:
//   - Secrets passed as environment variables (should use volume mounts instead)
//   - Environment variables containing sensitive keywords (password, token, key)
//     with plain-text values (not from secretKeyRef)
type SecretsExposureScanner struct{}

var _ Scanner = &SecretsExposureScanner{}

// Name implements Scanner.
func (s *SecretsExposureScanner) Name() string {
	return "Secrets Exposure"
}

// RuleType implements Scanner.
func (s *SecretsExposureScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeSecretsExposure
}

// sensitiveKeywords that often indicate secrets in environment variable names.
var sensitiveKeywords = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey",
	"access_key", "private_key", "credentials", "auth",
}

// Scan implements Scanner.
func (s *SecretsExposureScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...) //nolint:gocritic

		for j := range allContainers {
			container := &allContainers[j]

			// Check: EnvFrom with secretRef (medium — better to use volume-mounted secrets)
			for _, envFrom := range container.EnvFrom {
				if envFrom.SecretRef != nil {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityMedium,
						Title:             fmt.Sprintf("Container %q injects entire Secret %q as env vars", container.Name, envFrom.SecretRef.Name),
						Description:       "Using envFrom with a secretRef exposes all keys as environment variables. Environment variables can be leaked via /proc, core dumps, or logs.",
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Mount the Secret as a volume instead. Volume-mounted secrets can be auto-rotated and are less likely to leak.",
					})
				}
			}

			// Check: Individual env vars with sensitive names that use plain values.
			for _, env := range container.Env {
				envNameLower := strings.ToLower(env.Name)
				isSensitive := false
				for _, keyword := range sensitiveKeywords {
					if strings.Contains(envNameLower, keyword) {
						isSensitive = true
						break
					}
				}

				if !isSensitive {
					continue
				}

				// If value is set directly (not via secretKeyRef), it's hardcoded.
				if env.Value != "" && env.ValueFrom == nil {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityCritical,
						Title:             fmt.Sprintf("Container %q has hardcoded secret in env var %q", container.Name, env.Name),
						Description:       fmt.Sprintf("Environment variable %q appears to contain a secret but is set as a plain-text value. This is visible in the pod spec and etcd.", env.Name),
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Use a Kubernetes Secret with secretKeyRef, or mount the Secret as a file volume.",
					})
				}

				// If using secretKeyRef as env var (medium — volume mount is better).
				if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
					findings = append(findings, Finding{
						RuleType:          s.RuleType(),
						Severity:          zelyov1alpha1.SeverityLow,
						Title:             fmt.Sprintf("Container %q passes secret via env var %q (secretKeyRef)", container.Name, env.Name),
						Description:       "Using secretKeyRef is better than plain text, but environment variables can still be leaked. Volume-mounted secrets are the best practice.",
						ResourceKind:      "Pod",
						ResourceNamespace: pod.Namespace,
						ResourceName:      pod.Name,
						Recommendation:    "Consider mounting the Secret as a file volume instead of using environment variables for enhanced security.",
					})
				}
			}
		}
	}

	return findings, nil
}
