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
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// KMSRotationScanner checks for customer-managed KMS keys that do not have automatic rotation enabled.
type KMSRotationScanner struct{}

func (s *KMSRotationScanner) Name() string     { return "KMS Key Rotation" }
func (s *KMSRotationScanner) RuleType() string { return v1alpha1.RuleTypeCSPMKMSRotation }
func (s *KMSRotationScanner) Category() string { return category }
func (s *KMSRotationScanner) Provider() string { return provider }
func (s *KMSRotationScanner) IsGlobal() bool   { return false }

func (s *KMSRotationScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := kms.NewListKeysPaginator(cc.AWSClients.KMS, &kms.ListKeysInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing KMS keys: %w", err)
		}

		for _, key := range page.Keys {
			keyID := awssdk.ToString(key.KeyId)

			// Describe the key to determine if it is customer-managed.
			descOut, err := cc.AWSClients.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				slog.Warn("failed to describe KMS key, skipping",
					"keyId", keyID, "error", err)
				continue
			}

			// Skip AWS-managed keys and keys not in enabled state.
			meta := descOut.KeyMetadata
			if meta.KeyManager != kmstypes.KeyManagerTypeCustomer {
				continue
			}
			if meta.KeyState != kmstypes.KeyStateEnabled {
				continue
			}

			rotOut, err := cc.AWSClients.KMS.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: key.KeyId,
			})
			if err != nil {
				slog.Warn("failed to get key rotation status, skipping",
					"keyId", keyID, "error", err)
				continue
			}

			if !rotOut.KeyRotationEnabled {
				keyARN := awssdk.ToString(meta.Arn)
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCSPMKMSRotation,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("KMS key %s does not have automatic rotation enabled", keyID),
					Description:       fmt.Sprintf("Customer-managed KMS key %s (%s) in region %s does not have automatic key rotation enabled. Without rotation, the same key material is used indefinitely, increasing the impact of a potential key compromise.", keyID, keyARN, cc.Region),
					ResourceKind:      "KMSKey",
					ResourceNamespace: cc.Region,
					ResourceName:      keyID,
					Recommendation:    "Enable automatic key rotation for this customer-managed KMS key. AWS will automatically rotate the key material annually.",
				})
			}
		}
	}

	return findings, nil
}
