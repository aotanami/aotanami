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

// ECRScanOnPushScanner checks that ECR repositories have scan-on-push enabled
// so that images are automatically scanned for vulnerabilities when pushed.
type ECRScanOnPushScanner struct{}

func (s *ECRScanOnPushScanner) Name() string     { return "ECR Scan On Push" }
func (s *ECRScanOnPushScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainECRScanOnPush }
func (s *ECRScanOnPushScanner) Category() string { return category }
func (s *ECRScanOnPushScanner) Provider() string { return provider }
func (s *ECRScanOnPushScanner) IsGlobal() bool   { return false }

func (s *ECRScanOnPushScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			if repo.ImageScanningConfiguration == nil || !repo.ImageScanningConfiguration.ScanOnPush {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeSupplyChainECRScanOnPush,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("ECR repository %q does not have scan-on-push enabled", repoName),
					Description:       fmt.Sprintf("ECR repository %q in region %s does not have automatic image scanning on push enabled. Without scan-on-push, newly pushed images are not automatically checked for known vulnerabilities.", repoName, cc.Region),
					ResourceKind:      "ECRRepository",
					ResourceNamespace: cc.Region,
					ResourceName:      repoName,
					Recommendation:    "Enable scan-on-push in the ECR repository image scanning configuration to automatically scan images for vulnerabilities when they are pushed.",
				})
			}
		}
	}

	return findings, nil
}
