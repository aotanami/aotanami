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

// Package aws provides authenticated AWS service clients for cloud scanning.
// All clients are configured for read-only access — the operator never writes
// to cloud resources.
package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/codepipeline"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// CloudContext provides authenticated cloud clients and metadata to scanners.
// It is constructed by the CloudAccountConfig controller for each scan invocation.
type CloudContext struct {
	// Provider is the cloud provider identifier ("aws", "gcp", "azure").
	Provider string
	// AccountID is the cloud account identifier (AWS Account ID, GCP Project ID, etc.).
	AccountID string
	// Region is the cloud region being scanned (empty for global resources like IAM).
	Region string
	// AWSClients holds pre-configured AWS service clients. Nil for non-AWS providers.
	AWSClients *Clients
}

// Clients holds pre-configured AWS service clients for a specific region.
// All clients are configured for read-only access.
type Clients struct {
	S3             *s3.Client
	EC2            *ec2.Client
	IAM            *iam.Client
	CloudTrail     *cloudtrail.Client
	RDS            *rds.Client
	KMS            *kms.Client
	ECR            *ecr.Client
	SecretsManager *secretsmanager.Client
	DynamoDB       *dynamodb.Client
	ELBv2          *elasticloadbalancingv2.Client
	CloudWatchLogs *cloudwatchlogs.Client
	CodeBuild      *codebuild.Client
	CodePipeline   *codepipeline.Client
	STS            *sts.Client
}

// CredentialMethod defines how to authenticate to AWS.
type CredentialMethod string

const (
	// CredentialMethodIRSA uses IAM Roles for Service Accounts (EKS).
	CredentialMethodIRSA CredentialMethod = "irsa"
	// CredentialMethodPodIdentity uses EKS Pod Identity.
	CredentialMethodPodIdentity CredentialMethod = "pod-identity"
	// CredentialMethodSecret uses static credentials from a Kubernetes Secret.
	CredentialMethodSecret CredentialMethod = "secret"
)

// CredentialConfig configures how to authenticate to AWS.
type CredentialConfig struct {
	// Method is the authentication mechanism.
	Method CredentialMethod
	// Region is the AWS region to configure clients for.
	Region string
	// RoleARN is the IAM role ARN to assume (for cross-account access).
	RoleARN string
	// ExternalID for STS AssumeRole calls.
	ExternalID string
	// AccessKeyID is the static access key (for secret method).
	AccessKeyID string
	// SecretAccessKey is the static secret key (for secret method).
	SecretAccessKey string
}

// NewClients creates authenticated AWS service clients based on the credential config.
// All clients use read-only access patterns.
func NewClients(ctx context.Context, cc *CredentialConfig) (*Clients, error) {
	cfg, err := loadAWSConfig(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	return &Clients{
		S3:             s3.NewFromConfig(cfg),
		EC2:            ec2.NewFromConfig(cfg),
		IAM:            iam.NewFromConfig(cfg),
		CloudTrail:     cloudtrail.NewFromConfig(cfg),
		RDS:            rds.NewFromConfig(cfg),
		KMS:            kms.NewFromConfig(cfg),
		ECR:            ecr.NewFromConfig(cfg),
		SecretsManager: secretsmanager.NewFromConfig(cfg),
		DynamoDB:       dynamodb.NewFromConfig(cfg),
		ELBv2:          elasticloadbalancingv2.NewFromConfig(cfg),
		CloudWatchLogs: cloudwatchlogs.NewFromConfig(cfg),
		CodeBuild:      codebuild.NewFromConfig(cfg),
		CodePipeline:   codepipeline.NewFromConfig(cfg),
		STS:            sts.NewFromConfig(cfg),
	}, nil
}

// loadAWSConfig builds an aws.Config based on the credential method.
func loadAWSConfig(ctx context.Context, cc *CredentialConfig) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if cc.Region != "" {
		opts = append(opts, config.WithRegion(cc.Region))
	}

	switch cc.Method {
	case CredentialMethodIRSA, CredentialMethodPodIdentity:
		// IRSA and Pod Identity use the default credential chain.
		// The projected service account token is automatically picked up.
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("loading default config for %s: %w", cc.Method, err)
		}

		// If a role ARN is specified, assume it (cross-account access).
		if cc.RoleARN != "" {
			cfg = assumeRole(cfg, cc)
		}
		return cfg, nil

	case CredentialMethodSecret:
		if cc.AccessKeyID == "" || cc.SecretAccessKey == "" {
			return aws.Config{}, fmt.Errorf("access key ID and secret access key are required for secret method")
		}

		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cc.AccessKeyID, cc.SecretAccessKey, ""),
		))

		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("loading config with static credentials: %w", err)
		}

		// If a role ARN is specified, assume it.
		if cc.RoleARN != "" {
			cfg = assumeRole(cfg, cc)
		}
		return cfg, nil

	default:
		return aws.Config{}, fmt.Errorf("unsupported credential method: %s", cc.Method)
	}
}

// assumeRole wraps the config with STS AssumeRole credentials.
func assumeRole(cfg aws.Config, cc *CredentialConfig) aws.Config {
	stsClient := sts.NewFromConfig(cfg)

	var assumeOpts []func(*stscreds.AssumeRoleOptions)
	if cc.ExternalID != "" {
		assumeOpts = append(assumeOpts, func(opts *stscreds.AssumeRoleOptions) {
			opts.ExternalID = &cc.ExternalID
		})
	}

	creds := stscreds.NewAssumeRoleProvider(stsClient, cc.RoleARN, assumeOpts...)
	cfg.Credentials = aws.NewCredentialsCache(creds)

	return cfg
}

// VerifyIdentity calls STS GetCallerIdentity to verify the credentials are valid.
// Returns the account ID and ARN on success.
func (c *Clients) VerifyIdentity(ctx context.Context) (accountID, arn string, err error) {
	result, err := c.STS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", fmt.Errorf("verifying AWS identity: %w", err)
	}
	return aws.ToString(result.Account), aws.ToString(result.Arn), nil
}
