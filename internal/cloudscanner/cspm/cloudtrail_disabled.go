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

package cspm

import (
	"context"
	"fmt"
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// CloudTrailDisabledScanner checks for CloudTrail trails that are not actively logging.
type CloudTrailDisabledScanner struct{}

func (s *CloudTrailDisabledScanner) Name() string     { return "CloudTrail Disabled" }
func (s *CloudTrailDisabledScanner) RuleType() string { return v1alpha1.RuleTypeCSPMCloudTrail }
func (s *CloudTrailDisabledScanner) Category() string { return category }
func (s *CloudTrailDisabledScanner) Provider() string { return provider }
func (s *CloudTrailDisabledScanner) IsGlobal() bool   { return true }

func (s *CloudTrailDisabledScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	descOut, err := cc.AWSClients.CloudTrail.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing CloudTrail trails: %w", err)
	}

	if len(descOut.TrailList) == 0 {
		findings = append(findings, scanner.Finding{
			RuleType:          v1alpha1.RuleTypeCSPMCloudTrail,
			Severity:          v1alpha1.SeverityCritical,
			Title:             "No CloudTrail trails configured",
			Description:       fmt.Sprintf("AWS account %s has no CloudTrail trails configured. API activity is not being logged, making it impossible to audit actions or detect security incidents.", cc.AccountID),
			ResourceKind:      "CloudTrail",
			ResourceNamespace: cc.AccountID,
			ResourceName:      "none",
			Recommendation:    "Create a CloudTrail trail that logs management events for all regions and delivers logs to an S3 bucket with encryption enabled.",
		})
		return findings, nil
	}

	for _, trail := range descOut.TrailList {
		trailName := awssdk.ToString(trail.Name)
		trailARN := awssdk.ToString(trail.TrailARN)

		statusOut, err := cc.AWSClients.CloudTrail.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
			Name: trail.TrailARN,
		})
		if err != nil {
			slog.Warn("failed to get trail status, skipping",
				"trail", trailName, "error", err)
			continue
		}

		if statusOut.IsLogging == nil || !*statusOut.IsLogging {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMCloudTrail,
				Severity:          v1alpha1.SeverityCritical,
				Title:             fmt.Sprintf("CloudTrail trail %q is not logging", trailName),
				Description:       fmt.Sprintf("CloudTrail trail %q (%s) has logging disabled. API activity is not being recorded, leaving a gap in audit and incident detection capabilities.", trailName, trailARN),
				ResourceKind:      "CloudTrail",
				ResourceNamespace: cc.AccountID,
				ResourceName:      trailName,
				Recommendation:    "Enable logging on this CloudTrail trail by calling StartLogging. Ensure the trail's S3 bucket still exists and the trail has write permissions.",
			})
		}
	}

	return findings, nil
}
