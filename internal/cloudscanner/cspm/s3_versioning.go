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
	"log/slog"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// S3VersioningScanner checks for S3 buckets that do not have versioning enabled.
type S3VersioningScanner struct{}

func (s *S3VersioningScanner) Name() string     { return "S3 Versioning" }
func (s *S3VersioningScanner) RuleType() string { return v1alpha1.RuleTypeCSPMS3Versioning }
func (s *S3VersioningScanner) Category() string { return category }
func (s *S3VersioningScanner) Provider() string { return provider }
func (s *S3VersioningScanner) IsGlobal() bool   { return true }

func (s *S3VersioningScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	listOut, err := cc.AWSClients.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing S3 buckets: %w", err)
	}

	for _, bucket := range listOut.Buckets {
		bucketName := awssdk.ToString(bucket.Name)

		verOut, err := cc.AWSClients.S3.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			slog.Warn("failed to get bucket versioning, skipping",
				"bucket", bucketName, "error", err)
			continue
		}

		if verOut.Status != s3types.BucketVersioningStatusEnabled {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMS3Versioning,
				Severity:          v1alpha1.SeverityMedium,
				Title:             fmt.Sprintf("S3 bucket %q does not have versioning enabled", bucketName),
				Description:       fmt.Sprintf("S3 bucket %q does not have versioning enabled. Without versioning, objects that are overwritten or deleted cannot be recovered, increasing the risk of data loss from accidental or malicious actions.", bucketName),
				ResourceKind:      "S3Bucket",
				ResourceNamespace: cc.AccountID,
				ResourceName:      bucketName,
				Recommendation:    "Enable versioning on this S3 bucket to protect against accidental deletion and to maintain a history of object changes.",
			})
		}
	}

	return findings, nil
}
