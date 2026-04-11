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

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// MFANotEnforcedScanner checks for IAM users that have console access but no MFA device configured.
type MFANotEnforcedScanner struct{}

func (s *MFANotEnforcedScanner) Name() string     { return "MFA Not Enforced" }
func (s *MFANotEnforcedScanner) RuleType() string { return v1alpha1.RuleTypeCIEMMFANotEnforced }
func (s *MFANotEnforcedScanner) Category() string { return category }
func (s *MFANotEnforcedScanner) Provider() string { return provider }
func (s *MFANotEnforcedScanner) IsGlobal() bool   { return true }

func (s *MFANotEnforcedScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := iam.NewListUsersPaginator(cc.AWSClients.IAM, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM users: %w", err)
		}

		for _, user := range page.Users {
			userName := awssdk.ToString(user.UserName)

			// Check if user has console access (has ever logged in or has a login profile).
			// PasswordLastUsed being non-nil indicates console access.
			if user.PasswordLastUsed == nil {
				// Also check for login profile to catch users who have a password
				// but have never logged in.
				_, err := cc.AWSClients.IAM.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
					UserName: user.UserName,
				})
				if err != nil {
					// No login profile, so no console access — skip.
					continue
				}
			}

			// Check if user has MFA devices.
			mfaOut, err := cc.AWSClients.IAM.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})
			if err != nil {
				slog.Warn("failed to list MFA devices for user, skipping",
					"user", userName, "error", err)
				continue
			}

			if len(mfaOut.MFADevices) == 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCIEMMFANotEnforced,
					Severity:          v1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("IAM user %q has console access without MFA", userName),
					Description:       fmt.Sprintf("IAM user %q in account %s has console access but no MFA device configured. Without MFA, the account is vulnerable to credential theft attacks such as phishing.", userName, cc.AccountID),
					ResourceKind:      "IAMUser",
					ResourceNamespace: cc.AccountID,
					ResourceName:      userName,
					Recommendation:    "Enable MFA for this IAM user. Use a virtual MFA device, hardware TOTP token, or FIDO2 security key. Consider enforcing MFA via an IAM policy condition.",
				})
			}
		}
	}

	return findings, nil
}
