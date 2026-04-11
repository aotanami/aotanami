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
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// RDSPublicScanner detects RDS instances that are publicly accessible.
type RDSPublicScanner struct{}

func (s *RDSPublicScanner) Name() string     { return "Publicly Accessible RDS Instances" }
func (s *RDSPublicScanner) RuleType() string { return v1alpha1.RuleTypeDSPMRDSPublic }
func (s *RDSPublicScanner) Category() string { return category }
func (s *RDSPublicScanner) Provider() string { return provider }
func (s *RDSPublicScanner) IsGlobal() bool   { return false }

func (s *RDSPublicScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := rds.NewDescribeDBInstancesPaginator(cc.AWSClients.RDS, &rds.DescribeDBInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, instance := range page.DBInstances {
			if !awssdk.ToBool(instance.PubliclyAccessible) {
				continue
			}

			instanceID := awssdk.ToString(instance.DBInstanceIdentifier)
			engine := awssdk.ToString(instance.Engine)

			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeDSPMRDSPublic,
				Severity:          v1alpha1.SeverityCritical,
				Title:             fmt.Sprintf("RDS instance %s (%s) is publicly accessible", instanceID, engine),
				Description:       fmt.Sprintf("RDS instance %s running %s is configured with PubliclyAccessible=true, allowing connections from the public internet if security groups permit it.", instanceID, engine),
				ResourceKind:      "RDSInstance",
				ResourceNamespace: cc.Region,
				ResourceName:      instanceID,
				Recommendation:    "Set PubliclyAccessible to false and place the RDS instance in private subnets. Use VPN, bastion hosts, or AWS PrivateLink for secure database access.",
			})
		}
	}

	return findings, nil
}
