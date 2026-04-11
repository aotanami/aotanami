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

// UnrestrictedPeeringScanner detects VPC peering connections where route tables send
// all traffic (0.0.0.0/0) through the peering connection.
type UnrestrictedPeeringScanner struct{}

func (s *UnrestrictedPeeringScanner) Name() string { return "Unrestricted VPC Peering Routes" }
func (s *UnrestrictedPeeringScanner) RuleType() string {
	return v1alpha1.RuleTypeNetworkUnrestrictedPeer
}
func (s *UnrestrictedPeeringScanner) Category() string { return category }
func (s *UnrestrictedPeeringScanner) Provider() string { return provider }
func (s *UnrestrictedPeeringScanner) IsGlobal() bool   { return false }

func (s *UnrestrictedPeeringScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	// Get all active VPC peering connections.
	peerings, err := cc.AWSClients.EC2.DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{
		Filters: []ec2types.Filter{
			{
				Name:   awssdk.String("status-code"),
				Values: []string{"active"},
			},
		},
	})
	if err != nil {
		return findings, fmt.Errorf("describing VPC peering connections: %w", err)
	}

	if len(peerings.VpcPeeringConnections) == 0 {
		return findings, nil
	}

	// Build a set of peering connection IDs for quick lookup.
	peeringIDs := make(map[string]ec2types.VpcPeeringConnection)
	for _, p := range peerings.VpcPeeringConnections {
		peeringIDs[awssdk.ToString(p.VpcPeeringConnectionId)] = p
	}

	// Check route tables for routes that send all traffic through a peering connection.
	rtPaginator := ec2.NewDescribeRouteTablesPaginator(cc.AWSClients.EC2, &ec2.DescribeRouteTablesInput{})
	for rtPaginator.HasMorePages() {
		page, err := rtPaginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing route tables: %w", err)
		}

		for _, rt := range page.RouteTables {
			for _, route := range rt.Routes {
				if route.VpcPeeringConnectionId == nil {
					continue
				}
				cidr := awssdk.ToString(route.DestinationCidrBlock)
				if cidr != cidrAll {
					continue
				}
				pcxID := awssdk.ToString(route.VpcPeeringConnectionId)
				if _, ok := peeringIDs[pcxID]; ok {
					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeNetworkUnrestrictedPeer,
						Severity:          v1alpha1.SeverityHigh,
						Title:             fmt.Sprintf("Route table %s sends all traffic through VPC peering %s", awssdk.ToString(rt.RouteTableId), pcxID),
						Description:       fmt.Sprintf("Route table %s has a route directing all traffic (0.0.0.0/0) through VPC peering connection %s. This allows unrestricted network access between peered VPCs.", awssdk.ToString(rt.RouteTableId), pcxID),
						ResourceKind:      "VPCPeering",
						ResourceNamespace: cc.Region,
						ResourceName:      pcxID,
						Recommendation:    "Replace the 0.0.0.0/0 route with specific CIDR blocks matching the peer VPC's address space. Use the principle of least privilege for peering routes.",
					})
				}
			}
		}
	}

	return findings, nil
}
