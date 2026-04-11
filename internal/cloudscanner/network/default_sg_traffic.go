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

package network

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

// DefaultSGTrafficScanner detects default security groups that have inbound rules allowing traffic.
type DefaultSGTrafficScanner struct{}

func (s *DefaultSGTrafficScanner) Name() string     { return "Default Security Group Allows Traffic" }
func (s *DefaultSGTrafficScanner) RuleType() string { return v1alpha1.RuleTypeNetworkDefaultSGTraffic }
func (s *DefaultSGTrafficScanner) Category() string { return category }
func (s *DefaultSGTrafficScanner) Provider() string { return provider }
func (s *DefaultSGTrafficScanner) IsGlobal() bool   { return false }

func (s *DefaultSGTrafficScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(cc.AWSClients.EC2, &ec2.DescribeSecurityGroupsInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("group-name"),
				Values: []string{"default"},
			},
		},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing default security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			if len(sg.IpPermissions) > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeNetworkDefaultSGTraffic,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("Default security group %s in VPC %s has inbound rules", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.VpcId)),
					Description:       fmt.Sprintf("The default security group %s in VPC %s has %d inbound rules allowing traffic. AWS best practice recommends the default security group have no inbound or outbound rules.", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.VpcId), len(sg.IpPermissions)),
					ResourceKind:      "SecurityGroup",
					ResourceNamespace: cc.Region,
					ResourceName:      awssdk.ToString(sg.GroupId),
					Recommendation:    "Remove all inbound and outbound rules from the default security group. Create custom security groups for your resources with least-privilege rules.",
				})
			}
		}
	}

	return findings, nil
}
