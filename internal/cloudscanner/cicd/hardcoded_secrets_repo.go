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
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// secretPatterns contains environment variable name patterns that suggest secrets.
var secretPatterns = []string{
	"PASSWORD", "SECRET", "API_KEY", "APIKEY", "TOKEN",
	"PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "AUTH_TOKEN",
	"DB_PASS", "DATABASE_PASSWORD", "ENCRYPT_KEY",
}

// Compile-time interface check.

// HardcodedSecretsRepoScanner checks CodeBuild projects for environment variables
// with suspicious names stored as PLAINTEXT, indicating potential hardcoded secrets
// in CI/CD pipeline configurations.
type HardcodedSecretsRepoScanner struct{}

func (s *HardcodedSecretsRepoScanner) Name() string     { return "Hardcoded Secrets in CI/CD" }
func (s *HardcodedSecretsRepoScanner) RuleType() string { return v1alpha1.RuleTypeCICDHardcodedSecrets }
func (s *HardcodedSecretsRepoScanner) Category() string { return category }
func (s *HardcodedSecretsRepoScanner) Provider() string { return provider }
func (s *HardcodedSecretsRepoScanner) IsGlobal() bool   { return false }

func (s *HardcodedSecretsRepoScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
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

			for _, envVar := range project.Environment.EnvironmentVariables {
				if envVar.Type != cbtypes.EnvironmentVariableTypePlaintext {
					continue
				}

				varName := awssdk.ToString(envVar.Name)
				upperName := strings.ToUpper(varName)

				for _, pattern := range secretPatterns {
					if strings.Contains(upperName, pattern) {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeCICDHardcodedSecrets,
							Severity:          v1alpha1.SeverityCritical,
							Title:             fmt.Sprintf("CodeBuild project %q has hardcoded secret %q in PLAINTEXT", projectName, varName),
							Description:       fmt.Sprintf("CodeBuild project %q in region %s has environment variable %q configured as PLAINTEXT that appears to contain a secret. Secrets in CI/CD configurations can be exposed in build logs, audit trails, and API responses.", projectName, cc.Region, varName),
							ResourceKind:      "CodeBuildProject",
							ResourceNamespace: cc.Region,
							ResourceName:      projectName,
							Recommendation:    "Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them using SECRETS_MANAGER or PARAMETER_STORE environment variable types. Never store secrets as PLAINTEXT in build configurations.",
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
