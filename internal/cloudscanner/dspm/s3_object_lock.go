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
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"

	smithy "github.com/aws/smithy-go"

	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
)

// S3ObjectLockScanner detects S3 buckets that do not have Object Lock enabled.
type S3ObjectLockScanner struct{}

func (s *S3ObjectLockScanner) Name() string     { return "S3 Buckets Without Object Lock" }
func (s *S3ObjectLockScanner) RuleType() string { return v1alpha1.RuleTypeDSPMS3ObjectLock }
func (s *S3ObjectLockScanner) Category() string { return category }
func (s *S3ObjectLockScanner) Provider() string { return provider }
func (s *S3ObjectLockScanner) IsGlobal() bool   { return true }

func (s *S3ObjectLockScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	listOutput, err := cc.AWSClients.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return findings, fmt.Errorf("listing S3 buckets: %w", err)
	}

	for _, bucket := range listOutput.Buckets {
		bucketName := awssdk.ToString(bucket.Name)

		lockOutput, err := cc.AWSClients.S3.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// ObjectLockConfigurationNotFoundError means Object Lock is not enabled.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ObjectLockConfigurationNotFoundError" {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeDSPMS3ObjectLock,
					Severity:          v1alpha1.SeverityMedium,
					Title:             fmt.Sprintf("S3 bucket %s does not have Object Lock enabled", bucketName),
					Description:       fmt.Sprintf("S3 bucket %s does not have Object Lock configured. Without Object Lock, objects can be deleted or overwritten, which may not meet data retention or compliance requirements.", bucketName),
					ResourceKind:      "S3Bucket",
					ResourceNamespace: cc.AccountID,
					ResourceName:      bucketName,
					Recommendation:    "Enable Object Lock on the bucket with a retention policy (Governance or Compliance mode). Note: Object Lock must be enabled at bucket creation time.",
				})
			}
			// Other errors (access denied, wrong region) are skipped.
			continue
		}

		// Object Lock exists but may not be enabled.
		if lockOutput.ObjectLockConfiguration == nil ||
			lockOutput.ObjectLockConfiguration.ObjectLockEnabled != s3types.ObjectLockEnabledEnabled {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeDSPMS3ObjectLock,
				Severity:          v1alpha1.SeverityMedium,
				Title:             fmt.Sprintf("S3 bucket %s has Object Lock configuration but it is not enabled", bucketName),
				Description:       fmt.Sprintf("S3 bucket %s has an Object Lock configuration present but it is not in the Enabled state.", bucketName),
				ResourceKind:      "S3Bucket",
				ResourceNamespace: cc.AccountID,
				ResourceName:      bucketName,
				Recommendation:    "Ensure Object Lock is fully enabled with an appropriate retention policy (Governance or Compliance mode) and a default retention period.",
			})
		}
	}

	return findings, nil
}
