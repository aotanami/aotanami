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
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// dataClassificationTagKeys are the tag keys that indicate data classification.
var dataClassificationTagKeys = []string{
	"DataClassification",
	"data-classification",
	"Sensitivity",
	"sensitivity",
	"data_classification",
}

// NoDataTagsScanner detects EC2 instances that are missing data classification tags.
type NoDataTagsScanner struct{}

func (s *NoDataTagsScanner) Name() string     { return "EC2 Instances Missing Data Classification Tags" }
func (s *NoDataTagsScanner) RuleType() string { return v1alpha1.RuleTypeDSPMNoDataTags }
func (s *NoDataTagsScanner) Category() string { return category }
func (s *NoDataTagsScanner) Provider() string { return provider }
func (s *NoDataTagsScanner) IsGlobal() bool   { return false }

func (s *NoDataTagsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeInstancesPaginator(cc.AWSClients.EC2, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing EC2 instances: %w", err)
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				// Skip terminated instances.
				if instance.State != nil && instance.State.Name == ec2types.InstanceStateNameTerminated {
					continue
				}

				instanceID := awssdk.ToString(instance.InstanceId)
				if hasDataClassificationTag(instance.Tags) {
					continue
				}

				// Get the instance name from tags for context.
				instanceName := instanceID
				for _, tag := range instance.Tags {
					if awssdk.ToString(tag.Key) == "Name" {
						instanceName = fmt.Sprintf("%s (%s)", awssdk.ToString(tag.Value), instanceID)
						break
					}
				}

				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeDSPMNoDataTags,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("EC2 instance %s is missing data classification tags", instanceName),
					Description:       fmt.Sprintf("EC2 instance %s does not have any data classification tags (DataClassification, data-classification, or Sensitivity). Without classification tags, the data sensitivity level of resources cannot be automatically determined.", instanceID),
					ResourceKind:      "EC2Instance",
					ResourceNamespace: cc.Region,
					ResourceName:      instanceID,
					Recommendation:    "Add a DataClassification tag with an appropriate value (e.g., Public, Internal, Confidential, Restricted) to all EC2 instances. Enforce tagging policies using AWS Organizations SCPs or AWS Config rules.",
				})
			}
		}
	}

	return findings, nil
}

// hasDataClassificationTag checks if any tag matches the known data classification tag keys.
func hasDataClassificationTag(tags []ec2types.Tag) bool {
	for _, tag := range tags {
		tagKey := awssdk.ToString(tag.Key)
		for _, classKey := range dataClassificationTagKeys {
			if strings.EqualFold(tagKey, classKey) {
				return true
			}
		}
	}
	return false
}
