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
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// EBSSnapshotsPublicScanner detects EBS snapshots that are shared publicly.
type EBSSnapshotsPublicScanner struct{}

func (s *EBSSnapshotsPublicScanner) Name() string     { return "Publicly Shared EBS Snapshots" }
func (s *EBSSnapshotsPublicScanner) RuleType() string { return v1alpha1.RuleTypeDSPMEBSSnapshotsPublic }
func (s *EBSSnapshotsPublicScanner) Category() string { return category }
func (s *EBSSnapshotsPublicScanner) Provider() string { return provider }
func (s *EBSSnapshotsPublicScanner) IsGlobal() bool   { return false }

func (s *EBSSnapshotsPublicScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeSnapshotsPaginator(cc.AWSClients.EC2, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing EBS snapshots: %w", err)
		}

		for _, snapshot := range page.Snapshots {
			snapshotID := awssdk.ToString(snapshot.SnapshotId)

			attrOutput, err := cc.AWSClients.EC2.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
				SnapshotId: snapshot.SnapshotId,
				Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
			})
			if err != nil {
				// Continue scanning other snapshots on individual failures.
				continue
			}

			for _, perm := range attrOutput.CreateVolumePermissions {
				if perm.Group == ec2types.PermissionGroupAll {
					findings = append(findings, scanner.Finding{
						RuleType:          v1alpha1.RuleTypeDSPMEBSSnapshotsPublic,
						Severity:          v1alpha1.SeverityCritical,
						Title:             fmt.Sprintf("EBS snapshot %s is publicly shared", snapshotID),
						Description:       fmt.Sprintf("EBS snapshot %s has createVolumePermission set to 'all', making it publicly accessible. Any AWS account can create volumes from this snapshot and access its data.", snapshotID),
						ResourceKind:      "EBSSnapshot",
						ResourceNamespace: cc.Region,
						ResourceName:      snapshotID,
						Recommendation:    "Remove the public sharing permission from the snapshot. Share snapshots only with specific trusted AWS account IDs when cross-account access is needed.",
					})
					break
				}
			}
		}
	}

	return findings, nil
}
