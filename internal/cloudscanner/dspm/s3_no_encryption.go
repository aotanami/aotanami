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
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"

	smithy "github.com/aws/smithy-go"

	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
)

// S3NoEncryptionScanner detects S3 buckets that do not have default encryption configured.
type S3NoEncryptionScanner struct{}

func (s *S3NoEncryptionScanner) Name() string     { return "S3 Buckets Without Encryption" }
func (s *S3NoEncryptionScanner) RuleType() string { return v1alpha1.RuleTypeDSPMS3NoEncryption }
func (s *S3NoEncryptionScanner) Category() string { return category }
func (s *S3NoEncryptionScanner) Provider() string { return provider }
func (s *S3NoEncryptionScanner) IsGlobal() bool   { return true }

func (s *S3NoEncryptionScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	listOutput, err := cc.AWSClients.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return findings, fmt.Errorf("listing S3 buckets: %w", err)
	}

	for _, bucket := range listOutput.Buckets {
		bucketName := awssdk.ToString(bucket.Name)

		_, err := cc.AWSClients.S3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// ServerSideEncryptionConfigurationNotFoundError means no encryption is configured.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError" {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeDSPMS3NoEncryption,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("S3 bucket %s has no default encryption", bucketName),
					Description:       fmt.Sprintf("S3 bucket %s does not have default server-side encryption configured. Objects uploaded without explicit encryption will be stored unencrypted.", bucketName),
					ResourceKind:      "S3Bucket",
					ResourceNamespace: cc.AccountID,
					ResourceName:      bucketName,
					Recommendation:    "Enable default encryption on the bucket using SSE-S3 (AES-256) or SSE-KMS. Use a bucket policy to deny unencrypted uploads (s3:PutObject without encryption headers).",
				})
			}
			// Other errors (access denied, wrong region) are skipped.
			continue
		}
	}

	return findings, nil
}
