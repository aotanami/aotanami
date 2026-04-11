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

// ImagesNotScannedScanner checks for ECR repositories where recent images
// have not been scanned for vulnerabilities.
type ImagesNotScannedScanner struct{}

func (s *ImagesNotScannedScanner) Name() string     { return "Images Not Scanned" }
func (s *ImagesNotScannedScanner) RuleType() string { return v1alpha1.RuleTypeSupplyChainNotScanned }
func (s *ImagesNotScannedScanner) Category() string { return category }
func (s *ImagesNotScannedScanner) Provider() string { return provider }
func (s *ImagesNotScannedScanner) IsGlobal() bool   { return false }

func (s *ImagesNotScannedScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	repoPaginator := ecr.NewDescribeRepositoriesPaginator(cc.AWSClients.ECR, &ecr.DescribeRepositoriesInput{})

	for repoPaginator.HasMorePages() {
		repoPage, err := repoPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing ECR repositories: %w", err)
		}

		for _, repo := range repoPage.Repositories {
			repoName := awssdk.ToString(repo.RepositoryName)

			// Check the latest tagged image for scan status.
			imgOut, err := cc.AWSClients.ECR.DescribeImages(ctx, &ecr.DescribeImagesInput{
				RepositoryName: repo.RepositoryName,
				Filter: &ecrtypes.DescribeImagesFilter{
					TagStatus: ecrtypes.TagStatusTagged,
				},
				MaxResults: awssdk.Int32(10),
			})
			if err != nil {
				slog.Warn("failed to describe images, skipping repository",
					"repository", repoName, "error", err)
				continue
			}

			for _, img := range imgOut.ImageDetails {
				if img.ImageScanStatus == nil || img.ImageScanStatus.Status != ecrtypes.ScanStatusComplete {
					imageTag := "untagged"
					if len(img.ImageTags) > 0 {
						imageTag = img.ImageTags[0]
					}

					scanStatus := "UNKNOWN"
					if img.ImageScanStatus != nil {
						scanStatus = string(img.ImageScanStatus.Status)
					}

					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeSupplyChainNotScanned,
						Severity:          v1alpha1.SeverityHigh,
						Title:             fmt.Sprintf("ECR image %s:%s has not been scanned (status: %s)", repoName, imageTag, scanStatus),
						Description:       fmt.Sprintf("ECR image %s:%s in region %s has scan status %q. Images that have not been scanned may contain unknown vulnerabilities that could be exploited in production environments.", repoName, imageTag, cc.Region, scanStatus),
						ResourceKind:      "ECRRepository",
						ResourceNamespace: cc.Region,
						ResourceName:      repoName,
						Recommendation:    "Enable scan-on-push for the repository and manually trigger a scan for existing images. Consider using ECR enhanced scanning with Amazon Inspector for continuous vulnerability monitoring.",
					})
				}
			}
		}
	}

	return findings, nil
}
