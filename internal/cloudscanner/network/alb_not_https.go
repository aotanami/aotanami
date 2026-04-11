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

package network

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// ALBNotHTTPSScanner detects internet-facing Application Load Balancers with non-HTTPS listeners.
type ALBNotHTTPSScanner struct{}

func (s *ALBNotHTTPSScanner) Name() string     { return "ALB Not Using HTTPS" }
func (s *ALBNotHTTPSScanner) RuleType() string { return v1alpha1.RuleTypeNetworkALBNotHTTPS }
func (s *ALBNotHTTPSScanner) Category() string { return category }
func (s *ALBNotHTTPSScanner) Provider() string { return provider }
func (s *ALBNotHTTPSScanner) IsGlobal() bool   { return false }

func (s *ALBNotHTTPSScanner) Scan(ctx context.Context, cc *awsclients.CloudContext) ([]scanner.Finding, error) {
	var findings []scanner.Finding

	paginator := elbv2.NewDescribeLoadBalancersPaginator(cc.AWSClients.ELBv2, &elbv2.DescribeLoadBalancersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("describing load balancers: %w", err)
		}

		for _, lb := range page.LoadBalancers {
			// Only check internet-facing ALBs.
			if lb.Scheme != elbv2types.LoadBalancerSchemeEnumInternetFacing {
				continue
			}
			if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
				continue
			}

			lbARN := awssdk.ToString(lb.LoadBalancerArn)
			lbName := awssdk.ToString(lb.LoadBalancerName)

			listeners, err := cc.AWSClients.ELBv2.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
				LoadBalancerArn: lb.LoadBalancerArn,
			})
			if err != nil {
				// Log and continue scanning other load balancers.
				continue
			}

			for _, listener := range listeners.Listeners {
				if listener.Protocol == elbv2types.ProtocolEnumHttps {
					continue
				}
				port := int32(0)
				if listener.Port != nil {
					port = *listener.Port
				}
				findings = append(findings, scanner.Finding{
					RuleType:          v1alpha1.RuleTypeNetworkALBNotHTTPS,
					Severity:          v1alpha1.SeverityHigh,
					Title:             fmt.Sprintf("Internet-facing ALB %s has non-HTTPS listener on port %d", lbName, port),
					Description:       fmt.Sprintf("Internet-facing Application Load Balancer %s has a listener on port %d using protocol %s instead of HTTPS. Traffic is not encrypted in transit.", lbName, port, string(listener.Protocol)),
					ResourceKind:      "LoadBalancer",
					ResourceNamespace: cc.Region,
					ResourceName:      lbARN,
					Recommendation:    "Configure the listener to use HTTPS with an ACM certificate. Add a redirect action on port 80 to automatically redirect HTTP traffic to HTTPS.",
				})
			}
		}
	}

	return findings, nil
}
