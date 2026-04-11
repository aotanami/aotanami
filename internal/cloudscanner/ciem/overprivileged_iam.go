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

// overprivilegedPolicies contains the AWS-managed policy names that grant broad privileges.
var overprivilegedPolicies = map[string]bool{
	"AdministratorAccess": true,
	"PowerUserAccess":     true,
}

// OverprivilegedIAMScanner checks for IAM roles with overly broad permissions
// such as AdministratorAccess or PowerUserAccess policies attached.
type OverprivilegedIAMScanner struct{}

func (s *OverprivilegedIAMScanner) Name() string     { return "Overprivileged IAM Role" }
func (s *OverprivilegedIAMScanner) RuleType() string { return v1alpha1.RuleTypeCIEMOverprivilegedIAM }
func (s *OverprivilegedIAMScanner) Category() string { return category }
func (s *OverprivilegedIAMScanner) Provider() string { return provider }
func (s *OverprivilegedIAMScanner) IsGlobal() bool   { return true }

func (s *OverprivilegedIAMScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := iam.NewListRolesPaginator(cc.AWSClients.IAM, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM roles: %w", err)
		}

		for _, role := range page.Roles {
			roleName := awssdk.ToString(role.RoleName)

			policiesOut, err := cc.AWSClients.IAM.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			if err != nil {
				slog.Warn("failed to list attached policies for role, skipping",
					"role", roleName, "error", err)
				continue
			}

			for _, policy := range policiesOut.AttachedPolicies {
				policyName := awssdk.ToString(policy.PolicyName)
				if overprivilegedPolicies[policyName] {
					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeCIEMOverprivilegedIAM,
						Severity:          v1alpha1.SeverityCritical,
						Title:             fmt.Sprintf("IAM role %q has %s policy attached", roleName, policyName),
						Description:       fmt.Sprintf("IAM role %q in account %s has the %s managed policy attached, granting overly broad permissions. This violates the principle of least privilege and increases the blast radius of a compromise.", roleName, cc.AccountID, policyName),
						ResourceKind:      "IAMRole",
						ResourceNamespace: cc.AccountID,
						ResourceName:      roleName,
						Recommendation:    fmt.Sprintf("Replace the %s policy with a scoped-down custom policy that grants only the permissions required by this role.", policyName),
					})
				}
			}
		}
	}

	return findings, nil
}
