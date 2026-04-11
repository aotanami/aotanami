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

// VPCFlowLogsScanner checks for VPCs that do not have flow logs enabled.
type VPCFlowLogsScanner struct{}

func (s *VPCFlowLogsScanner) Name() string     { return "VPC Flow Logs" }
func (s *VPCFlowLogsScanner) RuleType() string { return v1alpha1.RuleTypeCSPMVPCFlowLogs }
func (s *VPCFlowLogsScanner) Category() string { return category }
func (s *VPCFlowLogsScanner) Provider() string { return provider }
func (s *VPCFlowLogsScanner) IsGlobal() bool   { return false }

func (s *VPCFlowLogsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	// Get all VPCs.
	vpcOut, err := cc.AWSClients.EC2.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing VPCs: %w", err)
	}

	// Get all flow logs to build a set of VPC IDs that have flow logs.
	flowOut, err := cc.AWSClients.EC2.DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{
		Filter: []ec2types.Filter{
			{
				Name:   awssdk.String("resource-type"),
				Values: []string{"VPC"},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("describing flow logs: %w", err)
	}

	vpcWithFlowLogs := make(map[string]bool)
	for _, fl := range flowOut.FlowLogs {
		resourceID := awssdk.ToString(fl.ResourceId)
		vpcWithFlowLogs[resourceID] = true
	}

	for _, vpc := range vpcOut.Vpcs {
		vpcID := awssdk.ToString(vpc.VpcId)
		if !vpcWithFlowLogs[vpcID] {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMVPCFlowLogs,
				Severity:          v1alpha1.SeverityHigh,
				Title:             fmt.Sprintf("VPC %s does not have flow logs enabled", vpcID),
				Description:       fmt.Sprintf("VPC %s in region %s does not have VPC Flow Logs enabled. Without flow logs, network traffic metadata is not captured, making it difficult to detect suspicious activity or troubleshoot connectivity issues.", vpcID, cc.Region),
				ResourceKind:      "VPC",
				ResourceNamespace: cc.Region,
				ResourceName:      vpcID,
				Recommendation:    "Enable VPC Flow Logs for this VPC. Configure flow logs to capture accepted and rejected traffic, and deliver logs to CloudWatch Logs or an S3 bucket for analysis.",
			})
		}
	}

	return findings, nil
}
