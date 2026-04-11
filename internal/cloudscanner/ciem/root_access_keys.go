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

package ciem

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// RootAccessKeysScanner checks if the AWS root account has access keys configured.
type RootAccessKeysScanner struct{}

func (s *RootAccessKeysScanner) Name() string     { return "Root Access Keys" }
func (s *RootAccessKeysScanner) RuleType() string { return v1alpha1.RuleTypeCIEMRootAccessKeys }
func (s *RootAccessKeysScanner) Category() string { return category }
func (s *RootAccessKeysScanner) Provider() string { return provider }
func (s *RootAccessKeysScanner) IsGlobal() bool   { return true }

func (s *RootAccessKeysScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	summaryOut, err := cc.AWSClients.IAM.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, fmt.Errorf("getting account summary: %w", err)
	}

	keysPresent, ok := summaryOut.SummaryMap["AccountAccessKeysPresent"]
	if ok && keysPresent > 0 {
		findings = append(findings, scanner.Finding{
			RuleType:          v1alpha1.RuleTypeCIEMRootAccessKeys,
			Severity:          v1alpha1.SeverityCritical,
			Title:             fmt.Sprintf("Root account in %s has active access keys", cc.AccountID),
			Description:       fmt.Sprintf("AWS account %s has %d root access key(s) configured. Root access keys provide unrestricted access to all resources and services in the account. If compromised, an attacker would have full control.", cc.AccountID, keysPresent),
			ResourceKind:      "AWSAccount",
			ResourceNamespace: cc.AccountID,
			ResourceName:      cc.AccountID,
			Recommendation:    "Delete root account access keys immediately. Use IAM users or roles with least-privilege policies for programmatic access instead.",
		})
	}

	return findings, nil
}
