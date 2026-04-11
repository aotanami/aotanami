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
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

const inactiveUserThresholdDays = 90

// InactiveUsersScanner checks for IAM users who have not used their console password
// in over 90 days.
type InactiveUsersScanner struct{}

func (s *InactiveUsersScanner) Name() string     { return "Inactive IAM Users" }
func (s *InactiveUsersScanner) RuleType() string { return v1alpha1.RuleTypeCIEMInactiveUsers }
func (s *InactiveUsersScanner) Category() string { return category }
func (s *InactiveUsersScanner) Provider() string { return provider }
func (s *InactiveUsersScanner) IsGlobal() bool   { return true }

func (s *InactiveUsersScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}
	threshold := time.Now().AddDate(0, 0, -inactiveUserThresholdDays)

	paginator := iam.NewListUsersPaginator(cc.AWSClients.IAM, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM users: %w", err)
		}

		for _, user := range page.Users {
			userName := awssdk.ToString(user.UserName)

			// PasswordLastUsed is nil if the user has never logged in via console
			// or has no console password. Only flag users that have a password
			// but have not used it recently.
			if user.PasswordLastUsed == nil {
				continue
			}

			if user.PasswordLastUsed.Before(threshold) {
				daysSinceUse := int(time.Since(*user.PasswordLastUsed).Hours() / 24)
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCIEMInactiveUsers,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("IAM user %q has been inactive for %d days", userName, daysSinceUse),
					Description:       fmt.Sprintf("IAM user %q in account %s has not used their console password in %d days (threshold: %d days). Inactive accounts increase the attack surface and may indicate orphaned credentials.", userName, cc.AccountID, daysSinceUse, inactiveUserThresholdDays),
					ResourceKind:      "IAMUser",
					ResourceNamespace: cc.AccountID,
					ResourceName:      userName,
					Recommendation:    "Review whether this user account is still needed. If not, disable the console password and delete access keys. Consider implementing an automated offboarding process.",
				})
			}
		}
	}

	return findings, nil
}
