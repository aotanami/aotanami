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

package ciem

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

const unusedAccessKeyThresholdDays = 90

// UnusedAccessKeysScanner checks for IAM access keys that have not been used in over 90 days.
type UnusedAccessKeysScanner struct{}

func (s *UnusedAccessKeysScanner) Name() string     { return "Unused Access Keys" }
func (s *UnusedAccessKeysScanner) RuleType() string { return v1alpha1.RuleTypeCIEMUnusedAccessKeys }
func (s *UnusedAccessKeysScanner) Category() string { return category }
func (s *UnusedAccessKeysScanner) Provider() string { return provider }
func (s *UnusedAccessKeysScanner) IsGlobal() bool   { return true }

func (s *UnusedAccessKeysScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}
	threshold := time.Now().AddDate(0, 0, -unusedAccessKeyThresholdDays)

	paginator := iam.NewListUsersPaginator(cc.AWSClients.IAM, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM users: %w", err)
		}

		for _, user := range page.Users {
			userName := awssdk.ToString(user.UserName)

			keysOut, err := cc.AWSClients.IAM.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: user.UserName,
			})
			if err != nil {
				slog.Warn("failed to list access keys for user, skipping",
					"user", userName, "error", err)
				continue
			}

			for _, key := range keysOut.AccessKeyMetadata {
				if key.Status != iamtypes.StatusTypeActive {
					continue
				}

				accessKeyID := awssdk.ToString(key.AccessKeyId)

				lastUsedOut, err := cc.AWSClients.IAM.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
					AccessKeyId: key.AccessKeyId,
				})
				if err != nil {
					slog.Warn("failed to get last used info for access key, skipping",
						"user", userName, "keyId", accessKeyID, "error", err)
					continue
				}

				lastUsed := lastUsedOut.AccessKeyLastUsed
				var isUnused bool
				if lastUsed.LastUsedDate == nil {
					// Key has never been used; check creation date.
					if key.CreateDate != nil && key.CreateDate.Before(threshold) {
						isUnused = true
					}
				} else if lastUsed.LastUsedDate.Before(threshold) {
					isUnused = true
				}

				if isUnused {
					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeCIEMUnusedAccessKeys,
						Severity:          v1alpha1.SeverityHigh,
						Title:             fmt.Sprintf("Access key %s for user %q is unused for over %d days", accessKeyID, userName, unusedAccessKeyThresholdDays),
						Description:       fmt.Sprintf("IAM access key %s belonging to user %q in account %s has not been used in over %d days. Unused active access keys pose a security risk as they may be compromised without detection.", accessKeyID, userName, cc.AccountID, unusedAccessKeyThresholdDays),
						ResourceKind:      "IAMAccessKey",
						ResourceNamespace: cc.AccountID,
						ResourceName:      fmt.Sprintf("%s/%s", userName, accessKeyID),
						Recommendation:    "Deactivate or delete this unused access key. If the key is still needed, consider rotating it and updating any dependent applications.",
					})
				}
			}
		}
	}

	return findings, nil
}
