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
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Compile-time interface check.

// CrossAccountTrustScanner checks for IAM roles with trust policies that allow
// cross-account access without conditions (ExternalId, MFA, etc.).
type CrossAccountTrustScanner struct{}

func (s *CrossAccountTrustScanner) Name() string     { return "Cross-Account Trust" }
func (s *CrossAccountTrustScanner) RuleType() string { return v1alpha1.RuleTypeCIEMCrossAccountTrust }
func (s *CrossAccountTrustScanner) Category() string { return category }
func (s *CrossAccountTrustScanner) Provider() string { return provider }
func (s *CrossAccountTrustScanner) IsGlobal() bool   { return true }

// trustPolicyDocument represents the structure of an IAM role trust (assume-role) policy.
type trustPolicyDocument struct {
	Statement []trustPolicyStatement `json:"Statement"`
}

// trustPolicyStatement represents a single statement in a trust policy.
type trustPolicyStatement struct {
	Effect    string      `json:"Effect"`
	Principal interface{} `json:"Principal"`
	Condition interface{} `json:"Condition"`
}

func (s *CrossAccountTrustScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	findings := []scanner.Finding{}

	paginator := iam.NewListRolesPaginator(cc.AWSClients.IAM, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing IAM roles: %w", err)
		}

		for _, role := range page.Roles {
			roleName := awssdk.ToString(role.RoleName)
			docStr := awssdk.ToString(role.AssumeRolePolicyDocument)

			decoded, err := url.QueryUnescape(docStr)
			if err != nil {
				slog.Warn("failed to URL-decode trust policy, skipping",
					"role", roleName, "error", err)
				continue
			}

			var doc trustPolicyDocument
			if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
				slog.Warn("failed to parse trust policy, skipping",
					"role", roleName, "error", err)
				continue
			}

			externalAccounts := findUnconditionedCrossAccountPrincipals(doc, cc.AccountID)
			if len(externalAccounts) > 0 {
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeCIEMCrossAccountTrust,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("IAM role %q trusts external accounts without conditions", roleName),
					Description:       fmt.Sprintf("IAM role %q in account %s has a trust policy that allows assume-role from external account(s) %s without requiring conditions (e.g., ExternalId or MFA). This may allow unauthorized cross-account access.", roleName, cc.AccountID, strings.Join(externalAccounts, ", ")),
					ResourceKind:      "IAMRole",
					ResourceNamespace: cc.AccountID,
					ResourceName:      roleName,
					Recommendation:    "Add conditions to the trust policy such as aws:SourceAccount, sts:ExternalId, or aws:MultiFactorAuthPresent to restrict cross-account access.",
				})
			}
		}
	}

	return findings, nil
}

// findUnconditionedCrossAccountPrincipals returns external account IDs that are
// trusted without conditions in the trust policy.
func findUnconditionedCrossAccountPrincipals(doc trustPolicyDocument, ownAccountID string) []string {
	var externalAccounts []string

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		// If conditions are present, consider it safer.
		if stmt.Condition != nil {
			continue
		}

		principals := extractARNPrincipals(stmt.Principal)
		for _, p := range principals {
			// Wildcard principal without conditions is extremely dangerous.
			if p == "*" {
				externalAccounts = append(externalAccounts, "*")
				continue
			}
			accountID := extractAccountFromARN(p)
			if accountID != "" && accountID != ownAccountID {
				externalAccounts = append(externalAccounts, accountID)
			}
		}
	}

	return externalAccounts
}

// extractARNPrincipals extracts ARN strings from the Principal field,
// which can be a string, a map with "AWS" key, or a list.
func extractARNPrincipals(principal interface{}) []string {
	var arns []string

	switch p := principal.(type) {
	case string:
		arns = append(arns, p)
	case map[string]interface{}:
		if awsVal, ok := p["AWS"]; ok {
			switch v := awsVal.(type) {
			case string:
				arns = append(arns, v)
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						arns = append(arns, s)
					}
				}
			}
		}
	}

	return arns
}

// extractAccountFromARN extracts the AWS account ID from an ARN string.
// Returns empty string if the ARN format is unrecognized.
func extractAccountFromARN(arn string) string {
	// Handle root account format: "123456789012"
	if !strings.Contains(arn, ":") && len(arn) == 12 {
		return arn
	}
	// Handle ARN format: arn:aws:iam::123456789012:...
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
