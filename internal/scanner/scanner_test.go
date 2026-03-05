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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
)

// ─── ContainerSecurityContextScanner Tests ───

func TestContainerSecurityContextScanner_NoSecurityContext(t *testing.T) {
	s := &ContainerSecurityContextScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "has no security context", zelyov1alpha1.SeverityHigh)
}

func TestContainerSecurityContextScanner_Privileged(t *testing.T) {
	s := &ContainerSecurityContextScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			SecurityContext: &corev1.SecurityContext{
				Privileged: ptr.To(true),
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "runs as privileged", zelyov1alpha1.SeverityCritical)
}

func TestContainerSecurityContextScanner_FullySecure(t *testing.T) {
	s := &ContainerSecurityContextScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			SecurityContext: &corev1.SecurityContext{
				RunAsNonRoot:             ptr.To(true),
				ReadOnlyRootFilesystem:   ptr.To(true),
				AllowPrivilegeEscalation: ptr.To(false),
				Privileged:               ptr.To(false),
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for fully secure container, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  finding: %s (%s)", f.Title, f.Severity)
		}
	}
}

func TestContainerSecurityContextScanner_PodLevelRunAsNonRoot(t *testing.T) {
	s := &ContainerSecurityContextScanner{}
	pod := makePod("test-pod", "default", corev1.Container{
		Name:  "app",
		Image: "nginx:1.25",
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
		},
	})
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsNonRoot: ptr.To(true),
	}

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Title == `Container "app" may run as root` {
			t.Error("should not flag runAsNonRoot when set at pod level")
		}
	}
}

// ─── ResourceLimitsScanner Tests ───

func TestResourceLimitsScanner_NoLimits(t *testing.T) {
	s := &ResourceLimitsScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 4 {
		t.Errorf("expected 4 findings for container with no limits, got %d", len(findings))
	}
}

func TestResourceLimitsScanner_FullLimits(t *testing.T) {
	s := &ResourceLimitsScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("500m"),
					corev1.ResourceMemory: resource.MustParse("256Mi"),
				},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for container with full limits, got %d", len(findings))
	}
}

// ─── ImagePinningScanner Tests ───

func TestImagePinningScanner_LatestTag(t *testing.T) {
	s := &ImagePinningScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:latest",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "uses :latest tag", zelyov1alpha1.SeverityHigh)
	assertHasFinding(t, findings, "not pinned by digest", zelyov1alpha1.SeverityMedium)
}

func TestImagePinningScanner_NoTag(t *testing.T) {
	s := &ImagePinningScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "uses :latest tag", zelyov1alpha1.SeverityHigh)
}

func TestImagePinningScanner_DigestPinned(t *testing.T) {
	s := &ImagePinningScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx@sha256:abc123def456",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for digest-pinned image, got %d", len(findings))
	}
}

func TestImagePinningScanner_VersionTag(t *testing.T) {
	s := &ImagePinningScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25.3",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, f := range findings {
		if f.Severity == zelyov1alpha1.SeverityHigh {
			t.Errorf("should not flag :latest for version tag, got: %s", f.Title)
		}
	}
	assertHasFinding(t, findings, "not pinned by digest", zelyov1alpha1.SeverityMedium)
}

func TestImagePinningScanner_RegistryWithPort(t *testing.T) {
	s := &ImagePinningScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "myregistry.com:5000/myapp",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "uses :latest tag", zelyov1alpha1.SeverityHigh)
}

// ─── PodSecurityScanner Tests ───

func TestPodSecurityScanner_HostNetwork(t *testing.T) {
	s := &PodSecurityScanner{}
	pod := makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.HostNetwork = true

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "host network", zelyov1alpha1.SeverityCritical)
}

func TestPodSecurityScanner_HostPID(t *testing.T) {
	s := &PodSecurityScanner{}
	pod := makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.HostPID = true

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "host PID", zelyov1alpha1.SeverityCritical)
}

func TestPodSecurityScanner_HostPath(t *testing.T) {
	s := &PodSecurityScanner{}
	pod := makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.Volumes = []corev1.Volume{
		{
			Name: "docker-socket",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: "/var/run/docker.sock",
				},
			},
		},
	}

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "mounts host path", zelyov1alpha1.SeverityCritical)
}

func TestPodSecurityScanner_DangerousCapabilities(t *testing.T) {
	s := &PodSecurityScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"SYS_ADMIN", "NET_RAW"},
				},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "SYS_ADMIN", zelyov1alpha1.SeverityHigh)
	assertHasFinding(t, findings, "NET_RAW", zelyov1alpha1.SeverityHigh)
}

func TestPodSecurityScanner_Clean(t *testing.T) {
	s := &PodSecurityScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean pod, got %d", len(findings))
	}
}

// ─── PrivilegeEscalationScanner Tests ───

func TestPrivilegeEscalationScanner_AutomountSAToken(t *testing.T) {
	s := &PrivilegeEscalationScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "auto-mounted", zelyov1alpha1.SeverityMedium)
}

func TestPrivilegeEscalationScanner_RunAsRoot(t *testing.T) {
	s := &PrivilegeEscalationScanner{}
	pod := makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.AutomountServiceAccountToken = ptr.To(false)
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsUser: ptr.To(int64(0)),
	}

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "root user (UID 0)", zelyov1alpha1.SeverityCritical)
}

func TestPrivilegeEscalationScanner_ContainerRunAsRoot(t *testing.T) {
	s := &PrivilegeEscalationScanner{}
	pod := makePod("test-pod", "default", corev1.Container{
		Name:  "app",
		Image: "nginx:1.25",
		SecurityContext: &corev1.SecurityContext{
			RunAsUser: ptr.To(int64(0)),
		},
	})
	pod.Spec.AutomountServiceAccountToken = ptr.To(false)

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "root user (UID 0)", zelyov1alpha1.SeverityCritical)
}

func TestPrivilegeEscalationScanner_Clean(t *testing.T) {
	s := &PrivilegeEscalationScanner{}
	pod := makePod("test-pod", "default", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.AutomountServiceAccountToken = ptr.To(false)
	pod.Spec.SecurityContext = &corev1.PodSecurityContext{
		RunAsUser:  ptr.To(int64(1000)),
		RunAsGroup: ptr.To(int64(1000)),
	}

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean pod, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  [%s] %s", f.Severity, f.Title)
		}
	}
}

// ─── SecretsExposureScanner Tests ───

func TestSecretsExposureScanner_HardcodedSecret(t *testing.T) {
	s := &SecretsExposureScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Env: []corev1.EnvVar{
				{Name: "DB_PASSWORD", Value: "super-secret-123"},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "hardcoded secret", zelyov1alpha1.SeverityCritical)
}

func TestSecretsExposureScanner_SecretKeyRef(t *testing.T) {
	s := &SecretsExposureScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Env: []corev1.EnvVar{
				{
					Name: "API_TOKEN",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
							Key:                  "token",
						},
					},
				},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "secretKeyRef", zelyov1alpha1.SeverityLow)
}

func TestSecretsExposureScanner_EnvFromSecret(t *testing.T) {
	s := &SecretsExposureScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			EnvFrom: []corev1.EnvFromSource{
				{
					SecretRef: &corev1.SecretEnvSource{
						LocalObjectReference: corev1.LocalObjectReference{Name: "my-secret"},
					},
				},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "injects entire Secret", zelyov1alpha1.SeverityMedium)
}

func TestSecretsExposureScanner_NonSensitiveEnv(t *testing.T) {
	s := &SecretsExposureScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "default", corev1.Container{
			Name:  "app",
			Image: "nginx:1.25",
			Env: []corev1.EnvVar{
				{Name: "LOG_LEVEL", Value: "debug"},
				{Name: "PORT", Value: "8080"},
			},
		}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-sensitive env vars, got %d", len(findings))
	}
}

// ─── NetworkPolicyScanner Tests ───

func TestNetworkPolicyScanner_NoLabels(t *testing.T) {
	s := &NetworkPolicyScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "my-namespace", corev1.Container{Name: "app", Image: "nginx:1.25"}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "no labels", zelyov1alpha1.SeverityMedium)
}

func TestNetworkPolicyScanner_HostPort(t *testing.T) {
	s := &NetworkPolicyScanner{}
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "my-namespace",
				Labels:    map[string]string{"app": "test"},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx:1.25",
						Ports: []corev1.ContainerPort{
							{ContainerPort: 80, HostPort: 8080},
						},
					},
				},
			},
		},
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "hostPort", zelyov1alpha1.SeverityHigh)
}

func TestNetworkPolicyScanner_SystemNamespaceSkipped(t *testing.T) {
	s := &NetworkPolicyScanner{}
	pods := []corev1.Pod{
		makePod("test-pod", "kube-system", corev1.Container{Name: "app", Image: "nginx:1.25"}),
	}

	findings, err := s.Scan(context.Background(), pods, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for system namespace, got %d", len(findings))
	}
}

// ─── RBACAuditScanner Tests ───

func TestRBACAuditScanner_DefaultSA(t *testing.T) {
	s := &RBACAuditScanner{}
	pod := makePod("test-pod", "my-namespace", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Labels = map[string]string{"app": "test"}
	pod.Spec.ServiceAccountName = "default"

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "default service account", zelyov1alpha1.SeverityMedium)
}

func TestRBACAuditScanner_AdminSA(t *testing.T) {
	s := &RBACAuditScanner{}
	pod := makePod("test-pod", "my-namespace", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Labels = map[string]string{"app": "test"}
	pod.Spec.ServiceAccountName = "cluster-admin-sa"

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertHasFinding(t, findings, "over-privileged service account", zelyov1alpha1.SeverityHigh)
}

func TestRBACAuditScanner_DedicatedSA(t *testing.T) {
	s := &RBACAuditScanner{}
	pod := makePod("test-pod", "my-namespace", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Labels = map[string]string{"app": "test"}
	pod.Spec.ServiceAccountName = "my-app-sa"

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for dedicated SA, got %d", len(findings))
		for _, f := range findings {
			t.Logf("  [%s] %s", f.Severity, f.Title)
		}
	}
}

func TestRBACAuditScanner_SystemNamespaceSkipped(t *testing.T) {
	s := &RBACAuditScanner{}
	pod := makePod("test-pod", "kube-system", corev1.Container{Name: "app", Image: "nginx:1.25"})
	pod.Spec.ServiceAccountName = "default"

	findings, err := s.Scan(context.Background(), []corev1.Pod{pod}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for system namespace, got %d", len(findings))
	}
}

// ─── Registry Tests ───

func TestRegistry_DefaultRegistry(t *testing.T) {
	r := DefaultRegistry()

	types := r.List()
	if len(types) != 8 {
		t.Fatalf("expected 8 registered scanners, got %d: %v", len(types), types)
	}

	for _, ruleType := range []string{
		zelyov1alpha1.RuleTypeContainerSecurityContext,
		zelyov1alpha1.RuleTypeResourceLimits,
		zelyov1alpha1.RuleTypeImageVulnerability,
		zelyov1alpha1.RuleTypePodSecurity,
		zelyov1alpha1.RuleTypePrivilegeEscalation,
		zelyov1alpha1.RuleTypeSecretsExposure,
		zelyov1alpha1.RuleTypeNetworkPolicy,
		zelyov1alpha1.RuleTypeRBACAudit,
	} {
		if r.Get(ruleType) == nil {
			t.Errorf("expected scanner for rule type %q", ruleType)
		}
	}
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	r := NewRegistry()
	r.Register(&ContainerSecurityContextScanner{})

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register(&ContainerSecurityContextScanner{})
}

// ─── Helpers ───

//nolint:unparam // test helper
func makePod(name, namespace string, containers ...corev1.Container) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: containers,
		},
	}
}

func assertHasFinding(t *testing.T, findings []Finding, titleSubstring, expectedSeverity string) {
	t.Helper()
	for _, f := range findings {
		if contains(f.Title, titleSubstring) && f.Severity == expectedSeverity {
			return
		}
	}
	t.Errorf("expected finding with title containing %q and severity %q, got %d findings:",
		titleSubstring, expectedSeverity, len(findings))
	for _, f := range findings {
		t.Logf("  [%s] %s", f.Severity, f.Title)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
