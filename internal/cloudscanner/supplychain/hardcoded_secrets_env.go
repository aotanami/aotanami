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

package supplychain

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

// suspiciousEnvNames contains patterns that suggest a secret value.
var suspiciousEnvNames = []string{
	"PASSWORD", "SECRET", "API_KEY", "APIKEY", "TOKEN",
	"PRIVATE_KEY", "ACCESS_KEY", "CREDENTIAL", "AUTH",
}

// Compile-time interface check.

// HardcodedSecretsEnvScanner checks CodeBuild projects for environment variables
// with suspicious names (e.g., PASSWORD, SECRET, TOKEN) stored as PLAINTEXT
// rather than using Parameter Store or Secrets Manager references.
type HardcodedSecretsEnvScanner struct{}

func (s *HardcodedSecretsEnvScanner) Name() string { return "Hardcoded Secrets in Environment" }
func (s *HardcodedSecretsEnvScanner) RuleType() string {
	return v1alpha1.RuleTypeSupplyChainHardcodedSecrets
}
func (s *HardcodedSecretsEnvScanner) Category() string { return category }
func (s *HardcodedSecretsEnvScanner) Provider() string { return provider }
func (s *HardcodedSecretsEnvScanner) IsGlobal() bool   { return false }

func (s *HardcodedSecretsEnvScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	listOut, err := cc.AWSClients.CodeBuild.ListProjects(ctx, &codebuild.ListProjectsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing CodeBuild projects: %w", err)
	}

	if len(listOut.Projects) == 0 {
		return findings, nil
	}

	// BatchGetProjects accepts up to 100 project names at a time.
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

				for _, pattern := range suspiciousEnvNames {
					if strings.Contains(upperName, pattern) {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeSupplyChainHardcodedSecrets,
							Severity:          v1alpha1.SeverityCritical,
							Title:             fmt.Sprintf("CodeBuild project %q has hardcoded secret in env var %q", projectName, varName),
							Description:       fmt.Sprintf("CodeBuild project %q in region %s has environment variable %q with type PLAINTEXT that appears to contain a secret value. Hardcoded secrets in build environments can be exposed in build logs and are difficult to rotate.", projectName, cc.Region, varName),
							ResourceKind:      "CodeBuildProject",
							ResourceNamespace: cc.Region,
							ResourceName:      projectName,
							Recommendation:    "Store secrets in AWS Secrets Manager or SSM Parameter Store and reference them using SECRETS_MANAGER or PARAMETER_STORE environment variable types instead of PLAINTEXT.",
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
