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

// dbPorts maps common database ports to their service names.
var dbPorts = map[int32]string{
	3306:  "MySQL",
	5432:  "PostgreSQL",
	1433:  "MSSQL",
	27017: "MongoDB",
}

// DBPortsExposedScanner detects security groups that expose database ports to the internet.
type DBPortsExposedScanner struct{}

func (s *DBPortsExposedScanner) Name() string     { return "Database Ports Exposed to Internet" }
func (s *DBPortsExposedScanner) RuleType() string { return v1alpha1.RuleTypeNetworkDBPortsExposed }
func (s *DBPortsExposedScanner) Category() string { return category }
func (s *DBPortsExposedScanner) Provider() string { return provider }
func (s *DBPortsExposedScanner) IsGlobal() bool   { return false }

func (s *DBPortsExposedScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(cc.AWSClients.EC2, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing security groups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			for _, perm := range sg.IpPermissions {
				for port, dbName := range dbPorts {
					if !coversPort(perm.FromPort, perm.ToPort, port) {
						continue
					}
					for _, ipRange := range perm.IpRanges {
						if awssdk.ToString(ipRange.CidrIp) == cidrAll {
							findings = append(findings, scanner.Finding{
								RuleType:          v1alpha1.RuleTypeNetworkDBPortsExposed,
								Severity:          v1alpha1.SeverityCritical,
								Title:             fmt.Sprintf("Security group %s exposes %s port %d to the internet", awssdk.ToString(sg.GroupId), dbName, port),
								Description:       fmt.Sprintf("Security group %s (%s) allows inbound traffic on %s port %d from 0.0.0.0/0, exposing the database to the public internet.", awssdk.ToString(sg.GroupId), awssdk.ToString(sg.GroupName), dbName, port),
								ResourceKind:      "SecurityGroup",
								ResourceNamespace: cc.Region,
								ResourceName:      awssdk.ToString(sg.GroupId),
								Recommendation:    fmt.Sprintf("Remove the 0.0.0.0/0 rule for port %d. Restrict %s access to application subnets only. Use private subnets and VPC endpoints for database connectivity.", port, dbName),
							})
							break
						}
					}
				}
			}
		}
	}

	return findings, nil
}
