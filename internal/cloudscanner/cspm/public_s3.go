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

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// PublicS3Scanner checks for S3 buckets that do not have public access fully blocked.
type PublicS3Scanner struct{}

func (s *PublicS3Scanner) Name() string     { return "Public S3 Bucket" }
func (s *PublicS3Scanner) RuleType() string { return v1alpha1.RuleTypeCSPMPublicS3 }
func (s *PublicS3Scanner) Category() string { return category }
func (s *PublicS3Scanner) Provider() string { return provider }
func (s *PublicS3Scanner) IsGlobal() bool   { return true }

func (s *PublicS3Scanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	listOut, err := cc.AWSClients.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("listing S3 buckets: %w", err)
	}

	for _, bucket := range listOut.Buckets {
		bucketName := awssdk.ToString(bucket.Name)

		pabOut, err := cc.AWSClients.S3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// If the public access block is not configured, the bucket is potentially public.
			slog.Warn("failed to get public access block, treating as public",
				"bucket", bucketName, "error", err)
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMPublicS3,
				Severity:          v1alpha1.SeverityCritical,
				Title:             fmt.Sprintf("S3 bucket %q has no public access block configured", bucketName),
				Description:       fmt.Sprintf("S3 bucket %q does not have a public access block configuration. This may allow public access to bucket contents.", bucketName),
				ResourceKind:      "S3Bucket",
				ResourceNamespace: cc.AccountID,
				ResourceName:      bucketName,
				Recommendation:    "Enable S3 Block Public Access on this bucket with all four settings set to true.",
			})
			continue
		}

		cfg := pabOut.PublicAccessBlockConfiguration
		if cfg == nil ||
			!awssdk.ToBool(cfg.BlockPublicAcls) ||
			!awssdk.ToBool(cfg.BlockPublicPolicy) ||
			!awssdk.ToBool(cfg.IgnorePublicAcls) ||
			!awssdk.ToBool(cfg.RestrictPublicBuckets) {
			findings = append(findings, scanner.Finding{
				RuleType:          v1alpha1.RuleTypeCSPMPublicS3,
				Severity:          v1alpha1.SeverityCritical,
				Title:             fmt.Sprintf("S3 bucket %q does not have public access fully blocked", bucketName),
				Description:       fmt.Sprintf("S3 bucket %q has one or more public access block settings disabled. This could allow unintended public access to bucket contents.", bucketName),
				ResourceKind:      "S3Bucket",
				ResourceNamespace: cc.AccountID,
				ResourceName:      bucketName,
				Recommendation:    "Enable all four S3 Block Public Access settings: BlockPublicAcls, BlockPublicPolicy, IgnorePublicAcls, and RestrictPublicBuckets.",
			})
		}
	}

	return findings, nil
}
