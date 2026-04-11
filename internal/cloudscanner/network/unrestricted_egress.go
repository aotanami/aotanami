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

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// UnrestrictedEgressScanner detects security groups that allow unrestricted outbound traffic
// to 0.0.0.0/0 on all ports.
type UnrestrictedEgressScanner struct{}

func (s *UnrestrictedEgressScanner) Name() string { return "Unrestricted Egress Traffic" }
func (s *UnrestrictedEgressScanner) RuleType() string {
	return v1alpha1.RuleTypeNetworkUnrestrictedEgress
}
func (s *UnrestrictedEgressScanner) Category() string { return category }
func (s *UnrestrictedEgressScanner) Provider() string { return provider }
func (s *UnrestrictedEgressScanner) IsGlobal() bool   { return false }

func (s *UnrestrictedEgressScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(cc.AWSClients.EC2, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			// Skip default security groups — they are covered by DefaultSGTrafficScanner.
			if awssdk.ToString(sg.GroupName) == "default" {
				continue
			}

			for _, perm := range sg.IpPermissionsEgress {
				// Check for all-traffic rules (protocol -1 means all).
				if perm.IpProtocol == nil || awssdk.ToString(perm.IpProtocol) != "-1" {
					continue
				}
				for _, ipRange := range perm.IpRanges {
					if awssdk.ToString(ipRange.CidrIp) == cidrAll {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeNetworkUnrestrictedEgress,
							Severity:          v1alpha1.SeverityMedium,
							Title:             fmt.Sprintf("Security group %s allows unrestricted egress to 0.0.0.0/0", awssdk.ToString(sg.GroupId)),
							Description:       fmt.Sprintf("Security group %s (%s) has an outbound rule allowing all traffic to 0.0.0.0/0. Unrestricted egress can facilitate data exfiltration.", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.GroupName)),
							ResourceKind:      "SecurityGroup",
							ResourceNamespace: cc.Region,
							ResourceName:      awssdk.ToString(sg.GroupId),
							Recommendation:    "Restrict egress rules to only necessary destinations and ports. Use VPC endpoints for AWS service access and a NAT gateway with restrictive outbound rules.",
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
