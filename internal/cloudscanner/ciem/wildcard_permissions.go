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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// WildcardPermissionsScanner checks for customer-managed IAM policies that contain
// wildcard ("*") actions, which grant overly broad permissions.
type WildcardPermissionsScanner struct{}

func (s *WildcardPermissionsScanner) Name() string     { return "Wildcard Permissions" }
func (s *WildcardPermissionsScanner) RuleType() string { return v1alpha1.RuleTypeCIEMWildcardPerms }
func (s *WildcardPermissionsScanner) Category() string { return category }
func (s *WildcardPermissionsScanner) Provider() string { return provider }
func (s *WildcardPermissionsScanner) IsGlobal() bool   { return true }

// iamPolicyDocument represents the structure of an IAM policy document.
type iamPolicyDocument struct {
	Statement []iamPolicyStatement `json:"Statement"`
}

// iamPolicyStatement represents a single statement in an IAM policy.
type iamPolicyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

func (s *WildcardPermissionsScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	// Only check customer-managed policies (Scope=Local).
	paginator := iam.NewListPoliciesPaginator(cc.AWSClients.IAM, &iam.ListPoliciesInput{
		Scope: "Local",
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM policies: %w", err)
		}

		for _, policy := range page.Policies {
			policyName := awssdk.ToString(policy.PolicyName)
			policyARN := awssdk.ToString(policy.Arn)

			versionOut, err := cc.AWSClients.IAM.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
			if err != nil {
				slog.Warn("failed to get policy version, skipping",
					"policy", policyName, "error", err)
				continue
			}

			docStr := awssdk.ToString(versionOut.PolicyVersion.Document)
			// The policy document is URL-encoded.
			decoded, err := url.QueryUnescape(docStr)
			if err != nil {
				slog.Warn("failed to URL-decode policy document, skipping",
					"policy", policyName, "error", err)
				continue
			}

			var doc iamPolicyDocument
			if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
				slog.Warn("failed to parse policy document, skipping",
					"policy", policyName, "error", err)
				continue
			}

			if hasWildcardAction(doc) {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCIEMWildcardPerms,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("IAM policy %q contains wildcard (*) actions", policyName),
					Description:       fmt.Sprintf("Customer-managed IAM policy %q (%s) in account %s contains statements with wildcard (*) actions. This grants overly broad permissions and violates the principle of least privilege.", policyName, policyARN, cc.AccountID),
					ResourceKind:      "IAMPolicy",
					ResourceNamespace: cc.AccountID,
					ResourceName:      policyName,
					Recommendation:    "Replace wildcard actions with specific API actions required by the workload. Use IAM Access Analyzer to identify the minimum permissions needed.",
				})
			}
		}
	}

	return findings, nil
}

// hasWildcardAction checks if any Allow statement in the policy has a "*" action.
func hasWildcardAction(doc iamPolicyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if containsWildcard(stmt.Action) {
			return true
		}
	}
	return false
}

// containsWildcard checks if the action field contains "*".
// Action can be a string or a list of strings.
func containsWildcard(action interface{}) bool {
	switch a := action.(type) {
	case string:
		return a == "*"
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok && s == "*" {
				return true
			}
		}
	}
	return false
}
