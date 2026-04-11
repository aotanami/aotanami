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
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// UnsignedImagesScanner checks ECR repositories for image tag mutability enabled,
// which indicates that image tags can be overwritten and images are not protected
// by tag immutability (a prerequisite for trusted image provenance).
type UnsignedImagesScanner struct{}

func (s *UnsignedImagesScanner) Name() string     { return "Unsigned Images" }
func (s *UnsignedImagesScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainUnsignedImages }
func (s *UnsignedImagesScanner) Category() string { return category }
func (s *UnsignedImagesScanner) Provider() string { return provider }
func (s *UnsignedImagesScanner) IsGlobal() bool   { return false }

func (s *UnsignedImagesScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			if repo.ImageTagMutability != ecrtypes.ImageTagMutabilityImmutable {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeSupplyChainUnsignedImages,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("ECR repository %q does not have image tag immutability enabled", repoName),
					Description:       fmt.Sprintf("ECR repository %q in region %s has mutable image tags. Without tag immutability, image tags can be overwritten, undermining image provenance and making it impossible to guarantee that a given tag always refers to the same image.", repoName, cc.Region),
					ResourceKind:      "ECRRepository",
					ResourceNamespace: cc.Region,
					ResourceName:      repoName,
					Recommendation:    "Enable image tag immutability on the ECR repository to prevent image tags from being overwritten. Use image signing with AWS Signer or cosign to establish trusted image provenance.",
				})
			}
		}
	}

	return findings, nil
}
