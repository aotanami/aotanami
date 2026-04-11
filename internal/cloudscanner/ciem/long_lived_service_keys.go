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

const longLivedKeyThresholdDays = 180

// LongLivedKeysScanner checks for IAM access keys that are older than 180 days.
type LongLivedKeysScanner struct{}

func (s *LongLivedKeysScanner) Name() string     { return "Long-Lived Service Keys" }
func (s *LongLivedKeysScanner) RuleType() string { return v1alpha1.RuleTypeCIEMLongLivedKeys }
func (s *LongLivedKeysScanner) Category() string { return category }
func (s *LongLivedKeysScanner) Provider() string { return provider }
func (s *LongLivedKeysScanner) IsGlobal() bool   { return true }

func (s *LongLivedKeysScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}
	threshold := time.Now().AddDate(0, 0, -longLivedKeyThresholdDays)

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

				if key.CreateDate == nil {
					continue
				}

				if key.CreateDate.Before(threshold) {
					accessKeyID := awssdk.ToString(key.AccessKeyId)
					keyAgeDays := int(time.Since(*key.CreateDate).Hours() / 24)

					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeCIEMLongLivedKeys,
						Severity:          v1alpha1.SeverityHigh,
						Title:             fmt.Sprintf("Access key %s for user %q is %d days old", accessKeyID, userName, keyAgeDays),
						Description:       fmt.Sprintf("IAM access key %s belonging to user %q in account %s was created %d days ago (threshold: %d days). Long-lived access keys increase the risk of undetected compromise.", accessKeyID, userName, cc.AccountID, keyAgeDays, longLivedKeyThresholdDays),
						ResourceKind:      "IAMAccessKey",
						ResourceNamespace: cc.AccountID,
						ResourceName:      fmt.Sprintf("%s/%s", userName, accessKeyID),
						Recommendation:    "Rotate this access key by creating a new key, updating all dependent applications, and then deactivating the old key. Consider using IAM roles with temporary credentials instead of long-lived access keys.",
					})
				}
			}
		}
	}

	return findings, nil
}
