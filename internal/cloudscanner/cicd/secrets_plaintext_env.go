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

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// SecretsPlaintextEnvScanner checks CodeBuild projects for any environment variables
// stored as PLAINTEXT type, which should instead use PARAMETER_STORE or SECRETS_MANAGER.
type SecretsPlaintextEnvScanner struct{}

func (s *SecretsPlaintextEnvScanner) Name() string     { return "Secrets in Plaintext Environment" }
func (s *SecretsPlaintextEnvScanner) RuleType() string { return v1alpha1.RuleTypeCICDSecretsPlaintext }
func (s *SecretsPlaintextEnvScanner) Category() string { return category }
func (s *SecretsPlaintextEnvScanner) Provider() string { return provider }
func (s *SecretsPlaintextEnvScanner) IsGlobal() bool   { return false }

func (s *SecretsPlaintextEnvScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
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

			if project.Environment == nil {
				continue
			}

			plaintextCount := 0
			for _, envVar := range project.Environment.EnvironmentVariables {
				if envVar.Type == cbtypes.EnvironmentVariableTypePlaintext {
					plaintextCount++
				}
			}

			if plaintextCount > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCICDSecretsPlaintext,
					Severity:          v1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("CodeBuild project %q has %d PLAINTEXT environment variables", projectName, plaintextCount),
					Description:       fmt.Sprintf("CodeBuild project %q in region %s has %d environment variables configured with PLAINTEXT type. Plaintext environment variables are visible in the AWS Console, API responses, and potentially in build logs. Sensitive values should use PARAMETER_STORE or SECRETS_MANAGER types.", projectName, cc.Region, plaintextCount),
					ResourceKind:      "CodeBuildProject",
					ResourceNamespace: cc.Region,
					ResourceName:      projectName,
					Recommendation:    "Migrate all PLAINTEXT environment variables to AWS Secrets Manager or SSM Parameter Store. Use SECRETS_MANAGER or PARAMETER_STORE environment variable types in CodeBuild project configuration.",
				})
			}
		}
	}

	return findings, nil
}
