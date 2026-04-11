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
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// S3PublicACLsScanner detects S3 buckets with ACLs granting access to AllUsers or AuthenticatedUsers.
type S3PublicACLsScanner struct{}

func (s *S3PublicACLsScanner) Name() string     { return "S3 Buckets with Public ACLs" }
func (s *S3PublicACLsScanner) RuleType() string { return v1alpha1.RuleTypeDSPMS3PublicACLs }
func (s *S3PublicACLsScanner) Category() string { return category }
func (s *S3PublicACLsScanner) Provider() string { return provider }
func (s *S3PublicACLsScanner) IsGlobal() bool   { return true }

func (s *S3PublicACLsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	listOutput, err := cc.AWSClients.S3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return findings, fmt.Errorf("listing S3 buckets: %w", err)
	}

	for _, bucket := range listOutput.Buckets {
		bucketName := awssdk.ToString(bucket.Name)

		aclOutput, err := cc.AWSClients.S3.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: bucket.Name,
		})
		if err != nil {
			// Bucket may be in a different region or access denied; continue scanning.
			continue
		}

		for _, grant := range aclOutput.Grants {
			if grant.Grantee == nil || grant.Grantee.URI == nil {
				continue
			}
			uri := awssdk.ToString(grant.Grantee.URI)
			if uri == "http://acs.amazonaws.com/groups/global/AllUsers" ||
				uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				grantLabel := "AllUsers (public)"
				if uri == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
					grantLabel = "AuthenticatedUsers (any AWS account)"
				}

				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeDSPMS3PublicACLs,
					Severity:          v1alpha1.SeverityCritical,
					Title:             fmt.Sprintf("S3 bucket %s has public ACL granting %s %s access", bucketName, grantLabel, string(grant.Permission)),
					Description:       fmt.Sprintf("S3 bucket %s has a bucket ACL granting %s permission to %s. This may expose sensitive data to unauthorized users.", bucketName, string(grant.Permission), grantLabel),
					ResourceKind:      "S3Bucket",
					ResourceNamespace: cc.AccountID,
					ResourceName:      bucketName,
					Recommendation:    "Remove public ACL grants and use S3 Block Public Access settings at the account and bucket level. Use bucket policies with specific principal restrictions instead of ACLs.",
				})
				break // One finding per bucket is sufficient.
			}
		}
	}

	return findings, nil
}
