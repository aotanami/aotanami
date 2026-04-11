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
	cptypes "github.com/aws/aws-sdk-go-v2/service/codepipeline/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// NoManualApprovalScanner checks CodePipeline pipelines for the absence of a
// manual approval gate before production deployment stages.
type NoManualApprovalScanner struct{}

func (s *NoManualApprovalScanner) Name() string     { return "No Manual Approval Gate" }
func (s *NoManualApprovalScanner) RuleType() string { return v1alpha1.RuleTypeCICDNoApprovalGate }
func (s *NoManualApprovalScanner) Category() string { return category }
func (s *NoManualApprovalScanner) Provider() string { return provider }
func (s *NoManualApprovalScanner) IsGlobal() bool   { return false }

func (s *NoManualApprovalScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
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

		hasApproval := false
		for _, stage := range pipelineOut.Pipeline.Stages {
			for _, action := range stage.Actions {
				if action.ActionTypeId.Category == cptypes.ActionCategoryApproval {
					hasApproval = true
					break
				}
			}
			if hasApproval {
				break
			}
		}

		if !hasApproval {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCICDNoApprovalGate,
				Severity:          v1alpha1.SeverityHigh,
				Title:             fmt.Sprintf("CodePipeline %q has no manual approval stage", pipelineName),
				Description:       fmt.Sprintf("CodePipeline %q in region %s does not contain a manual approval action in any stage. Without an approval gate, code changes can be automatically deployed to production without human review, increasing the risk of deploying vulnerable or untested code.", pipelineName, cc.Region),
				ResourceKind:      "CodePipeline",
				ResourceNamespace: cc.Region,
				ResourceName:      pipelineName,
				Recommendation:    "Add a manual approval action stage before production deployment stages in the pipeline. Configure SNS notifications to alert approvers when their review is needed.",
			})
		}
	}

	return findings, nil
}
