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

package cspm

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// SecretsRotationScanner checks for Secrets Manager secrets that do not have rotation enabled.
type SecretsRotationScanner struct{}

func (s *SecretsRotationScanner) Name() string     { return "Secrets Rotation" }
func (s *SecretsRotationScanner) RuleType() string { return v1alpha1.RuleTypeCSPMSecretsRotation }
func (s *SecretsRotationScanner) Category() string { return category }
func (s *SecretsRotationScanner) Provider() string { return provider }
func (s *SecretsRotationScanner) IsGlobal() bool   { return false }

func (s *SecretsRotationScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := secretsmanager.NewListSecretsPaginator(cc.AWSClients.SecretsManager, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing secrets: %w", err)
		}

		for _, secret := range page.SecretList {
			if !awssdk.ToBool(secret.RotationEnabled) {
				secretName := awssdk.ToString(secret.Name)
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCSPMSecretsRotation,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Secret %q does not have rotation enabled", secretName),
					Description:       fmt.Sprintf("Secrets Manager secret %q in region %s does not have automatic rotation enabled. Long-lived secrets increase the window of exposure if credentials are compromised.", secretName, cc.Region),
					ResourceKind:      "Secret",
					ResourceNamespace: cc.Region,
					ResourceName:      secretName,
					Recommendation:    "Enable automatic rotation for this secret by configuring a rotation Lambda function and a rotation schedule.",
				})
			}
		}
	}

	return findings, nil
}
