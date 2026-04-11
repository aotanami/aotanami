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

// RDPOpenScanner detects security groups that allow RDP (port 3389) access from the internet.
type RDPOpenScanner struct{}

func (s *RDPOpenScanner) Name() string     { return "RDP Open to Internet" }
func (s *RDPOpenScanner) RuleType() string { return v1alpha1.RuleTypeNetworkRDPOpen }
func (s *RDPOpenScanner) Category() string { return category }
func (s *RDPOpenScanner) Provider() string { return provider }
func (s *RDPOpenScanner) IsGlobal() bool   { return false }

func (s *RDPOpenScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(cc.AWSClients.EC2, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			for _, perm := range sg.IpPermissions {
				if !coversPort(perm.FromPort, perm.ToPort, 3389) {
					continue
				}
				for _, ipRange := range perm.IpRanges {
					if awssdk.ToString(ipRange.CidrIp) == cidrAll {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeNetworkRDPOpen,
							Severity:          v1alpha1.SeverityCritical,
							Title:             fmt.Sprintf("Security group %s allows RDP from 0.0.0.0/0", awssdk.ToString(sg.GroupId)),
							Description:       fmt.Sprintf("Security group %s (%s) has an inbound rule allowing RDP (port 3389) access from any IPv4 address.", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.GroupName)),
							ResourceKind:      "SecurityGroup",
							ResourceNamespace: cc.Region,
							ResourceName:      awssdk.ToString(sg.GroupId),
							Recommendation:    "Restrict RDP access to specific trusted IP addresses or use a VPN/bastion host. Consider using AWS Systems Manager Fleet Manager for remote desktop access.",
						})
						break
					}
				}
				for _, ipv6Range := range perm.Ipv6Ranges {
					if awssdk.ToString(ipv6Range.CidrIpv6) == "::/0" {
						findings = append(findings, scanner.Finding{
							RuleType:          v1alpha1.RuleTypeNetworkRDPOpen,
							Severity:          v1alpha1.SeverityCritical,
							Title:             fmt.Sprintf("Security group %s allows RDP from ::/0", awssdk.ToString(sg.GroupId)),
							Description:       fmt.Sprintf("Security group %s (%s) has an inbound rule allowing RDP (port 3389) access from any IPv6 address.", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.GroupName)),
							ResourceKind:      "SecurityGroup",
							ResourceNamespace: cc.Region,
							ResourceName:      awssdk.ToString(sg.GroupId),
							Recommendation:    "Restrict RDP access to specific trusted IP addresses or use a VPN/bastion host. Consider using AWS Systems Manager Fleet Manager for remote desktop access.",
						})
						break
					}
				}
			}
		}
	}

	return findings, nil
}
