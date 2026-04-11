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

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// NoSBOMScanner checks whether ECR repositories have scanning configured.
// Repositories without any scan configuration lack SBOM (Software Bill of Materials)
// generation capabilities, making it impossible to track software components.
type NoSBOMScanner struct{}

func (s *NoSBOMScanner) Name() string     { return "No SBOM" }
func (s *NoSBOMScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainNoSBOM }
func (s *NoSBOMScanner) Category() string { return category }
func (s *NoSBOMScanner) Provider() string { return provider }
func (s *NoSBOMScanner) IsGlobal() bool   { return false }

func (s *NoSBOMScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			// Check if the repository has any scanning configuration.
			// A repository without scan-on-push has no automated SBOM generation.
			if repo.ImageScanningConfiguration == nil || !repo.ImageScanningConfiguration.ScanOnPush {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeSupplyChainNoSBOM,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("ECR repository %q has no scanning configured for SBOM generation", repoName),
					Description:       fmt.Sprintf("ECR repository %q in region %s does not have image scanning configured. Without scanning, no Software Bill of Materials (SBOM) is generated for container images, making it impossible to track software components and their known vulnerabilities.", repoName, cc.Region),
					ResourceKind:      "ECRRepository",
					ResourceNamespace: cc.Region,
					ResourceName:      repoName,
					Recommendation:    "Enable ECR enhanced scanning with Amazon Inspector to generate SBOMs for container images. Enhanced scanning provides continuous monitoring and detailed component inventory.",
				})
			}
		}
	}

	return findings, nil
}
