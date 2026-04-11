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

package cicd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// overprivilegedPolicies contains AWS managed policy names that grant excessive permissions.
var overprivilegedPolicies = []string{
	"AdministratorAccess",
	"IAMFullAccess",
	"PowerUserAccess",
}

// Compile-time interface check.

// OverprivilegedCodeBuildScanner checks CodeBuild projects for service roles
// with overly permissive IAM policies such as AdministratorAccess.
type OverprivilegedCodeBuildScanner struct{}

func (s *OverprivilegedCodeBuildScanner) Name() string { return "Overprivileged CodeBuild" }
func (s *OverprivilegedCodeBuildScanner) RuleType() string {
	return v1alpha1.RuleTypeCICDOverprivCodeBuild
}
func (s *OverprivilegedCodeBuildScanner) Category() string { return category }
func (s *OverprivilegedCodeBuildScanner) Provider() string { return provider }
func (s *OverprivilegedCodeBuildScanner) IsGlobal() bool   { return false }

func (s *OverprivilegedCodeBuildScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	listOut, err := cc.AWSClients.CodeBuild.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing CodeBuild projects: %w", err)
	}

	if len(listOut.Projects) == 0 {
		return findings, nil
	}

	for i := 0; i < len(listOut.Projects); i += 100 {
		end := i + 100
		if end > len(listOut.Projects) {
			end = len(listOut.Projects)
		}
		batch := listOut.Projects[i:end]

		batchOut, err := cc.AWSClients.CodeBuild.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{
			Names: batch,
		})
		if err != nil {
			return nil, fmt.Errorf("batch getting CodeBuild projects: %w", err)
		}

		for _, project := range batchOut.Projects {
			projectName := awssdk.ToString(project.Name)
			serviceRole := awssdk.ToString(project.ServiceRole)

			if serviceRole == "" {
				continue
			}

			// Extract the role name from the ARN.
			roleName := serviceRole
			if parts := strings.Split(serviceRole, "/"); len(parts) > 1 {
				roleName = parts[len(parts)-1]
			}

			policiesOut, err := cc.AWSClients.IAM.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: awssdk.String(roleName),
			})
			if err != nil {
				slog.Warn("failed to list attached role policies, skipping project",
					"project", projectName, "role", roleName, "error", err)
				continue
			}

			for _, policy := range policiesOut.AttachedPolicies {
				policyName := awssdk.ToString(policy.PolicyName)

				for _, overprivPolicy := range overprivilegedPolicies {
					if policyName == overprivPolicy {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeCICDOverprivCodeBuild,
							Severity:          v1alpha1.SeverityHigh,
							Title:             fmt.Sprintf("CodeBuild project %q has overprivileged role with %s", projectName, policyName),
							Description:       fmt.Sprintf("CodeBuild project %q in region %s uses service role %q which has the %s policy attached. Overprivileged build roles can be exploited to escalate privileges, access sensitive resources, or make unauthorized changes to the AWS account.", projectName, cc.Region, roleName, policyName),
							ResourceKind:      "CodeBuildProject",
							ResourceNamespace: cc.Region,
							ResourceName:      projectName,
							Recommendation:    fmt.Sprintf("Replace the %s policy with a least-privilege policy that grants only the permissions required for the build process. Use separate roles for different build stages.", policyName),
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
