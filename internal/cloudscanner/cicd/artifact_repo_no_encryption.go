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
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// ArtifactRepoNoEncryptionScanner checks CodePipeline artifact stores for
// missing KMS encryption, ensuring build artifacts are encrypted at rest.
type ArtifactRepoNoEncryptionScanner struct{}

func (s *ArtifactRepoNoEncryptionScanner) Name() string { return "Artifact Repo No Encryption" }
func (s *ArtifactRepoNoEncryptionScanner) RuleType() string {
	return v1alpha1.RuleTypeCICDArtifactNoEncrypt
}
func (s *ArtifactRepoNoEncryptionScanner) Category() string { return category }
func (s *ArtifactRepoNoEncryptionScanner) Provider() string { return provider }
func (s *ArtifactRepoNoEncryptionScanner) IsGlobal() bool   { return false }

func (s *ArtifactRepoNoEncryptionScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	listOut, err := cc.AWSClients.CodePipeline.ListPipelines(ctx, &codepipeline.ListPipelinesInput{})
	if err != nil {
		return nil, fmt.Errorf("listing CodePipeline pipelines: %w", err)
	}

	for _, pipelineSummary := range listOut.Pipelines {
		pipelineName := awssdk.ToString(pipelineSummary.Name)

		pipelineOut, err := cc.AWSClients.CodePipeline.GetPipeline(ctx, &codepipeline.GetPipelineInput{
			Name: pipelineSummary.Name,
		})
		if err != nil {
			slog.Warn("failed to get pipeline details, skipping",
				"pipeline", pipelineName, "error", err)
			continue
		}

		if pipelineOut.Pipeline == nil {
			continue
		}

		// Check the primary artifact store.
		if pipelineOut.Pipeline.ArtifactStore != nil &&
			pipelineOut.Pipeline.ArtifactStore.EncryptionKey == nil {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCICDArtifactNoEncrypt,
				Severity:          v1alpha1.SeverityMedium,
				Title:             fmt.Sprintf("CodePipeline %q artifact store lacks KMS encryption", pipelineName),
				Description:       fmt.Sprintf("CodePipeline %q in region %s has an artifact store without customer-managed KMS encryption. Artifacts stored without encryption may expose sensitive build outputs including source code, configuration files, and compiled binaries.", pipelineName, cc.Region),
				ResourceKind:      "CodePipeline",
				ResourceNamespace: cc.Region,
				ResourceName:      pipelineName,
				Recommendation:    "Configure a customer-managed KMS key for the CodePipeline artifact store. Use the artifactStore.encryptionKey configuration to specify a KMS key ARN for artifact encryption at rest.",
			})
		}

		// Check per-region artifact stores if configured.
		for region, store := range pipelineOut.Pipeline.ArtifactStores {
			if store.EncryptionKey == nil {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCICDArtifactNoEncrypt,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("CodePipeline %q artifact store in region %s lacks KMS encryption", pipelineName, region),
					Description:       fmt.Sprintf("CodePipeline %q has a cross-region artifact store in region %s without customer-managed KMS encryption. Cross-region artifacts are particularly sensitive as they transit between regions.", pipelineName, region),
					ResourceKind:      "CodePipeline",
					ResourceNamespace: cc.Region,
					ResourceName:      pipelineName,
					Recommendation:    "Configure a customer-managed KMS key for the cross-region artifact store. Ensure each region's artifact store has its own KMS key for encryption at rest.",
				})
			}
		}
	}

	return findings, nil
}
