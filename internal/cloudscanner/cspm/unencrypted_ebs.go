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

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// UnencryptedEBSScanner checks for EBS volumes that are not encrypted.
type UnencryptedEBSScanner struct{}

func (s *UnencryptedEBSScanner) Name() string     { return "Unencrypted EBS Volume" }
func (s *UnencryptedEBSScanner) RuleType() string { return v1alpha1.RuleTypeCSPMUnencryptedEBS }
func (s *UnencryptedEBSScanner) Category() string { return category }
func (s *UnencryptedEBSScanner) Provider() string { return provider }
func (s *UnencryptedEBSScanner) IsGlobal() bool   { return false }

func (s *UnencryptedEBSScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := ec2.NewDescribeVolumesPaginator(cc.AWSClients.EC2, &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("encrypted"),
				Values: []string{"false"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing EBS volumes: %w", err)
		}

		for _, vol := range page.Volumes {
			volumeID := awssdk.ToString(vol.VolumeId)
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMUnencryptedEBS,
				Severity:          v1alpha1.SeverityHigh,
				Title:             fmt.Sprintf("EBS volume %s is not encrypted", volumeID),
				Description:       fmt.Sprintf("EBS volume %s in region %s is not encrypted at rest. Data stored on this volume could be exposed if the underlying storage is compromised.", volumeID, cc.Region),
				ResourceKind:      "EBSVolume",
				ResourceNamespace: cc.Region,
				ResourceName:      volumeID,
				Recommendation:    "Enable encryption on EBS volumes. Create a new encrypted volume from a snapshot of this volume and migrate data, or enable default EBS encryption for the region.",
			})
		}
	}

	return findings, nil
}
