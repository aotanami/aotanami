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
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// RDSEncryptionScanner checks for RDS instances that do not have storage encryption enabled.
type RDSEncryptionScanner struct{}

func (s *RDSEncryptionScanner) Name() string     { return "RDS Encryption" }
func (s *RDSEncryptionScanner) RuleType() string { return v1alpha1.RuleTypeCSPMRDSEncryption }
func (s *RDSEncryptionScanner) Category() string { return category }
func (s *RDSEncryptionScanner) Provider() string { return provider }
func (s *RDSEncryptionScanner) IsGlobal() bool   { return false }

func (s *RDSEncryptionScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := rds.NewDescribeDBInstancesPaginator(cc.AWSClients.RDS, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describing RDS instances: %w", err)
		}

		for _, db := range page.DBInstances {
			if db.StorageEncrypted == nil || !*db.StorageEncrypted {
				dbID := awssdk.ToString(db.DBInstanceIdentifier)
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCSPMRDSEncryption,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("RDS instance %s does not have storage encryption enabled", dbID),
					Description:       fmt.Sprintf("RDS instance %s in region %s does not have storage encryption enabled. Data at rest in this database is not protected by encryption.", dbID, cc.Region),
					ResourceKind:      "RDSInstance",
					ResourceNamespace: cc.Region,
					ResourceName:      dbID,
					Recommendation:    "Enable encryption at rest for RDS instances. Since encryption cannot be enabled on an existing instance, create an encrypted snapshot and restore to a new encrypted instance.",
				})
			}
		}
	}

	return findings, nil
}
