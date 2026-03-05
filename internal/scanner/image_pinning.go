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

// ImagePinningScanner checks container images for:
// - Use of the :latest tag (or no tag at all, which defaults to :latest)
// - Missing digest pinning (sha256:...)
// Unpinned images are a supply chain risk — the same tag can point to different images.
type ImagePinningScanner struct{}

var _ Scanner = &ImagePinningScanner{}

// Name implements Scanner.
func (s *ImagePinningScanner) Name() string {
	return "Image Pinning"
}

// RuleType implements Scanner.
func (s *ImagePinningScanner) RuleType() string {
	return zelyov1alpha1.RuleTypeImageVulnerability
}

// Scan implements Scanner.
func (s *ImagePinningScanner) Scan(_ context.Context, pods []corev1.Pod, _ map[string]string) ([]Finding, error) {
	var findings []Finding

	for i := range pods {
		pod := &pods[i]
		allContainers := append(pod.Spec.InitContainers, pod.Spec.Containers...) //nolint:gocritic

		for j := range allContainers {
			container := &allContainers[j]
			image := container.Image

			// Check: Image uses :latest tag
			if isLatestTag(image) {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Container %q uses :latest tag", container.Name),
					Description:       fmt.Sprintf("Image %q uses the :latest tag (or no tag). This is unreliable because the underlying image can change without notice.", image),
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Pin the image to a specific version tag (e.g., :v1.2.3) or a digest (sha256:...).",
				})
			}

			// Check: Image not pinned by digest
			if !isDigestPinned(image) {
				findings = append(findings, Finding{
					RuleType:          s.RuleType(),
					Severity:          zelyov1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Container %q image not pinned by digest", container.Name),
					Description:       fmt.Sprintf("Image %q is not pinned by digest (sha256:...). Tags are mutable — the same tag can point to different images over time.", image),
					ResourceKind:      "Pod",
					ResourceNamespace: pod.Namespace,
					ResourceName:      pod.Name,
					Recommendation:    "Pin the image by digest for immutable deployments (e.g., image@sha256:abc123...).",
				})
			}
		}
	}

	return findings, nil
}

// isLatestTag checks if the image reference uses :latest or has no tag (which defaults to :latest).
func isLatestTag(image string) bool {
	// Image with digest — never considered :latest
	if strings.Contains(image, "@sha256:") {
		return false
	}

	// No colon at all or just registry:port/name → no tag → defaults to :latest
	lastSlash := strings.LastIndex(image, "/")
	nameTag := image
	if lastSlash >= 0 {
		nameTag = image[lastSlash+1:]
	}

	if !strings.Contains(nameTag, ":") {
		return true // No tag → defaults to :latest
	}

	return strings.HasSuffix(image, ":latest")
}

// isDigestPinned checks if the image reference includes a digest (sha256:...).
func isDigestPinned(image string) bool {
	return strings.Contains(image, "@sha256:")
}
