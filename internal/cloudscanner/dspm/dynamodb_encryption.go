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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dynamodbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// DynamoDBEncryptionScanner detects DynamoDB tables that do not use KMS encryption at rest.
type DynamoDBEncryptionScanner struct{}

func (s *DynamoDBEncryptionScanner) Name() string { return "DynamoDB Tables Without KMS Encryption" }
func (s *DynamoDBEncryptionScanner) RuleType() string {
	return v1alpha1.RuleTypeDSPMDynamoDBEncryption
}
func (s *DynamoDBEncryptionScanner) Category() string { return category }
func (s *DynamoDBEncryptionScanner) Provider() string { return provider }
func (s *DynamoDBEncryptionScanner) IsGlobal() bool   { return false }

func (s *DynamoDBEncryptionScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := dynamodb.NewListTablesPaginator(cc.AWSClients.DynamoDB, &dynamodb.ListTablesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("listing DynamoDB tables: %w", err)
		}

		for _, tableName := range page.TableNames {
			descOutput, err := cc.AWSClients.DynamoDB.DescribeTable(ctx, &dynamodb.DescribeTableInput{
				TableName: awssdk.String(tableName),
			})
			if err != nil {
				// Continue scanning other tables on individual failures.
				continue
			}

			table := descOutput.Table
			if table.SSEDescription == nil || table.SSEDescription.Status != dynamodbtypes.SSEStatusEnabled {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeDSPMDynamoDBEncryption,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("DynamoDB table %s does not have KMS encryption at rest", tableName),
					Description:       fmt.Sprintf("DynamoDB table %s uses default encryption (AWS owned key) instead of a customer-managed KMS key. This limits visibility and control over encryption keys.", tableName),
					ResourceKind:      "DynamoDBTable",
					ResourceNamespace: cc.Region,
					ResourceName:      tableName,
					Recommendation:    "Enable encryption at rest using a customer-managed KMS key (CMK) for full control over key rotation, access policies, and audit logging via CloudTrail.",
				})
			}
		}
	}

	return findings, nil
}
