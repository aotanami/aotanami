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

// NoNACLsScanner detects subnets that rely only on the default NACL with allow-all rules.
type NoNACLsScanner struct{}

func (s *NoNACLsScanner) Name() string     { return "No Custom Network ACLs" }
func (s *NoNACLsScanner) RuleType() string { return v1alpha1.RuleTypeNetworkNoNACLs }
func (s *NoNACLsScanner) Category() string { return category }
func (s *NoNACLsScanner) Provider() string { return provider }
func (s *NoNACLsScanner) IsGlobal() bool   { return false }

func (s *NoNACLsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeNetworkAclsPaginator(cc.AWSClients.EC2, &ec2.DescribeNetworkAclsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing network ACLs: %w", err)
		}

		for _, nacl := range page.NetworkAcls {
			if !awssdk.ToBool(nacl.IsDefault) {
				continue
			}

			if hasAllowAllRules(nacl.Entries) && len(nacl.Associations) > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeNetworkNoNACLs,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Default NACL %s has allow-all rules with %d associated subnets", awssdk.ToString(nacl.NetworkAclId), len(nacl.Associations)),
					Description:       fmt.Sprintf("The default Network ACL %s in VPC %s has allow-all inbound/outbound rules and is associated with %d subnets. Subnets are not protected by custom NACLs.", awssdk.ToString(nacl.NetworkAclId), awssdk.ToString(nacl.VpcId), len(nacl.Associations)),
					ResourceKind:      "NetworkACL",
					ResourceNamespace: cc.Region,
					ResourceName:      awssdk.ToString(nacl.NetworkAclId),
					Recommendation:    "Create custom Network ACLs with restrictive inbound and outbound rules and associate them with your subnets. Use NACLs as a secondary defense layer alongside security groups.",
				})
			}
		}
	}

	return findings, nil
}

// hasAllowAllRules checks if the NACL entries contain allow-all rules for both inbound and outbound.
func hasAllowAllRules(entries []ec2types.NetworkAclEntry) bool {
	var allowAllInbound, allowAllOutbound bool
	for _, entry := range entries {
		if awssdk.ToString(entry.CidrBlock) != cidrAll {
			continue
		}
		if entry.RuleAction != ec2types.RuleActionAllow {
			continue
		}
		if awssdk.ToString(entry.Protocol) != "-1" {
			continue
		}
		if awssdk.ToBool(entry.Egress) {
			allowAllOutbound = true
		} else {
			allowAllInbound = true
		}
	}
	return allowAllInbound && allowAllOutbound
}
