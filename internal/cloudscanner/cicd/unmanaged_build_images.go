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

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// awsManagedImagePrefix is the prefix for AWS-managed CodeBuild images.
const awsManagedImagePrefix = "aws/codebuild/"

// Compile-time interface check.

// UnmanagedBuildImagesScanner checks CodeBuild projects for build environments
// using non-AWS-managed images, which may not receive regular security updates.
type UnmanagedBuildImagesScanner struct{}

func (s *UnmanagedBuildImagesScanner) Name() string     { return "Unmanaged Build Images" }
func (s *UnmanagedBuildImagesScanner) RuleType() string { return v1alpha1.RuleTypeCICDUnmanagedImages }
func (s *UnmanagedBuildImagesScanner) Category() string { return category }
func (s *UnmanagedBuildImagesScanner) Provider() string { return provider }
func (s *UnmanagedBuildImagesScanner) IsGlobal() bool   { return false }

func (s *UnmanagedBuildImagesScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
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

			image := awssdk.ToString(project.Environment.Image)
			if image == "" {
				continue
			}

			// Check if the image is an AWS-managed CodeBuild image.
			if !strings.HasPrefix(image, awsManagedImagePrefix) {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCICDUnmanagedImages,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("CodeBuild project %q uses unmanaged build image %q", projectName, image),
					Description:       fmt.Sprintf("CodeBuild project %q in region %s uses build image %q which is not an AWS-managed image (aws/codebuild/*). Custom or third-party build images may not receive regular security updates and could contain vulnerabilities or malicious code.", projectName, cc.Region, image),
					ResourceKind:      "CodeBuildProject",
					ResourceNamespace: cc.Region,
					ResourceName:      projectName,
					Recommendation:    "Use AWS-managed CodeBuild images (aws/codebuild/*) which are regularly patched and maintained by AWS. If custom images are required, ensure they are built from trusted base images, scanned for vulnerabilities, and regularly updated.",
				})
			}
		}
	}

	return findings, nil
}
