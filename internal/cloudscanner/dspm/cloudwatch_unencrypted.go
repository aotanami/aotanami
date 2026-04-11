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

package dspm

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// CloudWatchUnencryptedScanner detects CloudWatch log groups without KMS encryption.
type CloudWatchUnencryptedScanner struct{}

func (s *CloudWatchUnencryptedScanner) Name() string {
	return "CloudWatch Log Groups Without Encryption"
}
func (s *CloudWatchUnencryptedScanner) RuleType() string {
	return v1alpha1.RuleTypeDSPMCloudWatchEncryption
}
func (s *CloudWatchUnencryptedScanner) Category() string { return category }
func (s *CloudWatchUnencryptedScanner) Provider() string { return provider }
func (s *CloudWatchUnencryptedScanner) IsGlobal() bool   { return false }

func (s *CloudWatchUnencryptedScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(cc.AWSClients.CloudWatchLogs, &cloudwatchlogs.DescribeLogGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing CloudWatch log groups: %w", err)
		}

		for _, logGroup := range page.LogGroups {
			if logGroup.KmsKeyId != nil && awssdk.ToString(logGroup.KmsKeyId) != "" {
				continue
			}

			logGroupName := awssdk.ToString(logGroup.LogGroupName)

			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeDSPMCloudWatchEncryption,
				Severity:          v1alpha1.SeverityMedium,
				Title:             fmt.Sprintf("CloudWatch log group %s is not encrypted with KMS", logGroupName),
				Description:       fmt.Sprintf("CloudWatch log group %s does not have a KMS key associated for encryption. Log data is encrypted with CloudWatch default encryption but not with a customer-managed key.", logGroupName),
				ResourceKind:      "CloudWatchLogGroup",
				ResourceNamespace: cc.Region,
				ResourceName:      logGroupName,
				Recommendation:    "Associate a KMS key with the log group using the kmsKeyId property. This provides customer-managed encryption with full key control and CloudTrail audit logging.",
			})
		}
	}

	return findings, nil
}
