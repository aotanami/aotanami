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
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// ThirdPartyCVEsScanner checks ECR repositories for images with HIGH severity
// CVEs in third-party dependencies detected by ECR image scanning.
type ThirdPartyCVEsScanner struct{}

func (s *ThirdPartyCVEsScanner) Name() string     { return "Third-Party CVEs" }
func (s *ThirdPartyCVEsScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainThirdPartyCVEs }
func (s *ThirdPartyCVEsScanner) Category() string { return category }
func (s *ThirdPartyCVEsScanner) Provider() string { return provider }
func (s *ThirdPartyCVEsScanner) IsGlobal() bool   { return false }

func (s *ThirdPartyCVEsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		page, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			scanOut, err := cc.AWSClients.ECR.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
				RepositoryName: repo.RepositoryName,
				ImageId: &ecrtypes.ImageIdentifier{
					ImageTag: awssdk.String("latest"),
				},
			})
			if err != nil {
				slog.Warn("failed to get image scan findings, skipping repository",
					"repository", repoName, "error", err)
				continue
			}

			if scanOut.ImageScanFindings == nil {
				continue
			}

			highCount, hasHigh := scanOut.ImageScanFindings.FindingSeverityCounts[string(ecrtypes.FindingSeverityHigh)]
			if hasHigh && highCount > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeSupplyChainThirdPartyCVEs,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("ECR repository %q has %d high-severity CVEs in latest image", repoName, highCount),
					Description:       fmt.Sprintf("ECR repository %q in region %s contains images with %d high-severity vulnerabilities in third-party dependencies detected by ECR image scanning. High-severity CVEs in dependencies can be exploited to compromise application security.", repoName, cc.Region, highCount),
					ResourceKind:      "ECRRepository",
					ResourceNamespace: cc.Region,
					ResourceName:      repoName,
					Recommendation:    "Update third-party dependencies to patched versions. Use tools like Dependabot or Renovate to automate dependency updates. Rebuild and push updated images.",
				})
			}
		}
	}

	return findings, nil
}
