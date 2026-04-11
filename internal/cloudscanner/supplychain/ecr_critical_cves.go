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

// ECRCriticalCVEsScanner checks ECR repositories for images with critical CVEs
// found during image scanning.
type ECRCriticalCVEsScanner struct{}

func (s *ECRCriticalCVEsScanner) Name() string { return "ECR Critical CVEs" }
func (s *ECRCriticalCVEsScanner) RuleType() string {
	return v1alpha1.RuleTypeSupplyChainECRCriticalCVEs
}
func (s *ECRCriticalCVEsScanner) Category() string { return category }
func (s *ECRCriticalCVEsScanner) Provider() string { return provider }
func (s *ECRCriticalCVEsScanner) IsGlobal() bool   { return false }

func (s *ECRCriticalCVEsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		page, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range page.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			// Find the most recently pushed image to check scan results.
			imagesOut, err := cc.AWSClients.ECR.DescribeImages(ctx, &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
				Filter:         &ecrtypes.DescribeImagesFilter{TagStatus: ecrtypes.TagStatusTagged},
			})
			if err != nil {
				slog.Warn("failed to describe images, skipping repository",
					"repository", repoName, "error", err)
				continue
			}
			if len(imagesOut.ImageDetails) == 0 {
				continue
			}

			// Pick the most recently pushed image.
			mostRecent := imagesOut.ImageDetails[0]
			for i := range imagesOut.ImageDetails {
				if imagesOut.ImageDetails[i].ImagePushedAt != nil &&
					mostRecent.ImagePushedAt != nil &&
					imagesOut.ImageDetails[i].ImagePushedAt.After(*mostRecent.ImagePushedAt) {
					mostRecent = imagesOut.ImageDetails[i]
				}
			}

			imageID := &ecrtypes.ImageIdentifier{ImageDigest: mostRecent.ImageDigest}
			tagLabel := awssdk.ToString(mostRecent.ImageDigest)
			if len(mostRecent.ImageTags) > 0 {
				tagLabel = mostRecent.ImageTags[0]
			}

			scanOut, err := cc.AWSClients.ECR.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
				RepositoryName: repo.RepositoryName,
				ImageId:        imageID,
			})
			if err != nil {
				slog.Warn("failed to get image scan findings, skipping repository",
					"repository", repoName, "error", err)
				continue
			}

			if scanOut.ImageScanFindings == nil {
				continue
			}

			criticalCount, hasCritical := scanOut.ImageScanFindings.FindingSeverityCounts[string(ecrtypes.FindingSeverityCritical)]
			if hasCritical && criticalCount > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeSupplyChainECRCriticalCVEs,
					Severity:          v1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("ECR repository %q has %d critical CVEs in image %s", repoName, criticalCount, tagLabel),
					Description:       fmt.Sprintf("ECR repository %q in region %s contains image %s with %d critical vulnerabilities detected by ECR image scanning. Critical CVEs represent exploitable vulnerabilities that could lead to full system compromise.", repoName, cc.Region, tagLabel, criticalCount),
					ResourceKind:      "ECRRepository",
					ResourceNamespace: cc.Region,
					ResourceName:      repoName,
					Recommendation:    "Update base images and dependencies to patched versions. Rebuild and push updated images to resolve critical CVEs. Consider using ECR enhanced scanning for continuous monitoring.",
				})
			}
		}
	}

	return findings, nil
}
