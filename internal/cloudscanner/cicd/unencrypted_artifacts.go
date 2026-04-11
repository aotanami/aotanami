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

// UnencryptedArtifactsScanner checks CodePipeline pipelines for artifact stores
// that do not have KMS encryption configured.
type UnencryptedArtifactsScanner struct{}

func (s *UnencryptedArtifactsScanner) Name() string { return "Unencrypted CI/CD Artifacts" }
func (s *UnencryptedArtifactsScanner) RuleType() string {
	return v1alpha1.RuleTypeCICDUnencryptedArtifacts
}
func (s *UnencryptedArtifactsScanner) Category() string { return category }
func (s *UnencryptedArtifactsScanner) Provider() string { return provider }
func (s *UnencryptedArtifactsScanner) IsGlobal() bool   { return false }

func (s *UnencryptedArtifactsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
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

		if pipelineOut.Pipeline == nil || pipelineOut.Pipeline.ArtifactStore == nil {
			continue
		}

		if pipelineOut.Pipeline.ArtifactStore.EncryptionKey == nil {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCICDUnencryptedArtifacts,
				Severity:          v1alpha1.SeverityHigh,
				Title:             fmt.Sprintf("CodePipeline %q does not have KMS encryption for artifacts", pipelineName),
				Description:       fmt.Sprintf("CodePipeline %q in region %s does not have a customer-managed KMS key configured for artifact encryption. Build artifacts may contain source code, compiled binaries, or configuration data that should be encrypted at rest.", pipelineName, cc.Region),
				ResourceKind:      "CodePipeline",
				ResourceNamespace: cc.Region,
				ResourceName:      pipelineName,
				Recommendation:    "Configure a customer-managed KMS key for the CodePipeline artifact store to encrypt build artifacts at rest. Update the pipeline's artifactStore.encryptionKey configuration.",
			})
		}
	}

	return findings, nil
}
