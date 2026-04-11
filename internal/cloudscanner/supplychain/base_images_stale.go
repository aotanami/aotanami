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
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// staleImageThreshold is the maximum acceptable age for container images.
const staleImageThreshold = 90 * 24 * time.Hour

// Compile-time interface check.

// StaleImagesScanner checks for ECR images that have not been updated in over 90 days,
// indicating potentially stale base images with unpatched vulnerabilities.
type StaleImagesScanner struct{}

func (s *StaleImagesScanner) Name() string     { return "Stale Base Images" }
func (s *StaleImagesScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainStaleImages }
func (s *StaleImagesScanner) Category() string { return category }
func (s *StaleImagesScanner) Provider() string { return provider }
func (s *StaleImagesScanner) IsGlobal() bool   { return false }

func (s *StaleImagesScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}
	now := time.Now()

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		repoPage, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range repoPage.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			imgPaginator := ecr.NewDescribeImagesPaginator(cc.AWSClients.ECR, &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
				Filter: &ecrtypes.DescribeImagesFilter{
					TagStatus: ecrtypes.TagStatusTagged,
				},
			})

			for imgPaginator.HasMorePages() {
				imgPage, err := imgPaginator.NextPage(ctx)
				if err != nil {
					return nil, fmt.Errorf("describing images in repository %s: %w", repoName, err)
				}

				for _, img := range imgPage.ImageDetails {
					if img.ImagePushedAt == nil {
						continue
					}

					age := now.Sub(*img.ImagePushedAt)
					if age > staleImageThreshold {
						imageTag := "untagged"
						if len(img.ImageTags) > 0 {
							imageTag = img.ImageTags[0]
						}

						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeSupplyChainStaleImages,
							Severity:          v1alpha1.SeverityMedium,
							Title:             fmt.Sprintf("ECR image %s:%s is over 90 days old", repoName, imageTag),
							Description:       fmt.Sprintf("ECR image %s:%s in region %s was pushed %d days ago. Stale images may contain unpatched vulnerabilities in base image layers and outdated dependencies.", repoName, imageTag, cc.Region, int(age.Hours()/24)),
							ResourceKind:      "ECRImage",
							ResourceNamespace: cc.Region,
							ResourceName:      fmt.Sprintf("%s:%s", repoName, imageTag),
							Recommendation:    "Rebuild and push images regularly to incorporate the latest security patches. Set up automated image rebuild pipelines to ensure images stay up to date.",
						})
					}
				}
			}
		}
	}

	return findings, nil
}
