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
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// NoAuditLoggingScanner checks whether CloudTrail is configured to capture
// CI/CD service events (CodeBuild, CodePipeline) for audit logging.
type NoAuditLoggingScanner struct{}

func (s *NoAuditLoggingScanner) Name() string     { return "No CI/CD Audit Logging" }
func (s *NoAuditLoggingScanner) RuleType() string { return v1alpha1.RuleTypeCICDNoAuditLogging }
func (s *NoAuditLoggingScanner) Category() string { return category }
func (s *NoAuditLoggingScanner) Provider() string { return provider }
func (s *NoAuditLoggingScanner) IsGlobal() bool   { return true }

func (s *NoAuditLoggingScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	trailsOut, err := cc.AWSClients.CloudTrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing CloudTrail trails: %w", err)
	}

	if len(trailsOut.TrailList) == 0 {
		findings = append(findings, scanner.Finding{
			RuleType:          v1alpha1.RuleTypeCICDNoAuditLogging,
			Severity:          v1alpha1.SeverityHigh,
			Title:             "No CloudTrail trails configured for CI/CD audit logging",
			Description:       "No CloudTrail trails are configured in this account. Without CloudTrail, CI/CD pipeline events from CodeBuild and CodePipeline are not captured for audit and forensic purposes.",
			ResourceKind:      "CloudTrail",
			ResourceNamespace: cc.AccountID,
			ResourceName:      "none",
			Recommendation:    "Create a CloudTrail trail that captures management events for all AWS services, including CodeBuild and CodePipeline. Enable log file validation and deliver logs to a secured S3 bucket.",
		})
		return findings, nil
	}

	// Check if any trail captures management events (which include CI/CD service events).
	hasManagementEventTrail := false
	for _, trail := range trailsOut.TrailList {
		trailName := awssdk.ToString(trail.Name)
		trailARN := awssdk.ToString(trail.TrailARN)

		selectorsOut, err := cc.AWSClients.CloudTrail.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
			TrailName: trail.TrailARN,
		})
		if err != nil {
			slog.Warn("failed to get event selectors for trail, skipping",
				"trail", trailName, "error", err)
			continue
		}

		if hasClassicManagementSelectors(selectorsOut.EventSelectors) ||
			hasAdvancedManagementSelectors(selectorsOut.AdvancedEventSelectors) {
			hasManagementEventTrail = true
			slog.Debug("found trail capturing management events for CI/CD audit",
				"trail", trailName, "arn", trailARN)
			break
		}
	}

	if !hasManagementEventTrail {
		findings = append(findings, scanner.Finding{
			RuleType:          v1alpha1.RuleTypeCICDNoAuditLogging,
			Severity:          v1alpha1.SeverityHigh,
			Title:             "No CloudTrail trail captures management events for CI/CD audit",
			Description:       "No CloudTrail trail in this account is configured to capture management events (write or all). Without management event logging, actions taken in CodeBuild and CodePipeline are not recorded for audit, compliance, or incident investigation purposes.",
			ResourceKind:      "CloudTrail",
			ResourceNamespace: cc.AccountID,
			ResourceName:      "no-management-event-trail",
			Recommendation:    "Configure a CloudTrail trail with management event logging enabled (ReadWriteType: All). Ensure the trail is multi-region and captures events from all AWS services including CodeBuild and CodePipeline.",
		})
	}

	return findings, nil
}

// hasClassicManagementSelectors checks if any classic event selector captures management events.
func hasClassicManagementSelectors(selectors []cttypes.EventSelector) bool {
	for i := range selectors {
		if selectors[i].ReadWriteType == cttypes.ReadWriteTypeAll ||
			selectors[i].ReadWriteType == cttypes.ReadWriteTypeWriteOnly {
			return true
		}
	}
	return false
}

// hasAdvancedManagementSelectors checks if any advanced event selector captures management events.
func hasAdvancedManagementSelectors(selectors []cttypes.AdvancedEventSelector) bool {
	for i := range selectors {
		for j := range selectors[i].FieldSelectors {
			if awssdk.ToString(selectors[i].FieldSelectors[j].Field) != "eventCategory" {
				continue
			}
			for _, val := range selectors[i].FieldSelectors[j].Equals {
				if val == "Management" {
					return true
				}
			}
		}
	}
	return false
}
