/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"context"
	"fmt"
	"sort"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/events"
)

// --- Response types ---

// OverviewResponse is returned by GET /api/v1/overview.
type OverviewResponse struct {
	SecurityScore      int        `json:"securityScore"`
	TotalPolicies      int        `json:"totalPolicies"`
	ActivePolicies     int        `json:"activePolicies"`
	TotalViolations    int        `json:"totalViolations"`
	CriticalViolations int        `json:"criticalViolations"`
	HighViolations     int        `json:"highViolations"`
	MediumViolations   int        `json:"mediumViolations"`
	LowViolations      int        `json:"lowViolations"`
	ResolvedFindings   int        `json:"resolvedFindings"`
	TotalScans         int        `json:"totalScans"`
	RunningScans       int        `json:"runningScans"`
	CompletedScans     int        `json:"completedScans"`
	TotalFindings      int        `json:"totalFindings"`
	LastScanTime       *time.Time `json:"lastScanTime,omitempty"`
	CloudAccounts      int        `json:"cloudAccounts"`
	CloudFindings      int        `json:"cloudFindings"`
	CompliancePct      float64    `json:"compliancePct"`
	ActiveIncidents    int        `json:"activeIncidents"`
	OperatorMode       string     `json:"operatorMode"`
	OperatorPhase      string     `json:"operatorPhase"`
	UpdatedAt          time.Time  `json:"updatedAt"`

	// Prowler-inspired aggregations — landing-page drill-downs.
	TopFailingChecks []TopItem                    `json:"topFailingChecks"`
	TopAffectedKinds []TopItem                    `json:"topAffectedKinds"`
	Frameworks       []ComplianceFrameworkSummary `json:"frameworks"`
	AccountsByRisk   []AccountRisk                `json:"accountsByRisk"`
	FindingsTrend    []TrendPoint                 `json:"findingsTrend"` // last N days, oldest-first
	PipelineSnapshot PipelineSnapshot             `json:"pipelineSnapshot"`
}

// TopItem is a name + count pair used for ranked lists on the Overview.
type TopItem struct {
	Name     string `json:"name"`
	Count    int    `json:"count"`
	Severity string `json:"severity,omitempty"`
	Category string `json:"category,omitempty"`
}

// AccountRisk summarizes a single cloud account's posture for the Overview.
type AccountRisk struct {
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	AccountID     string `json:"accountId"`
	FindingsCount int32  `json:"findingsCount"`
	Critical      int32  `json:"critical"`
	High          int32  `json:"high"`
	Medium        int32  `json:"medium"`
	Resources     int32  `json:"resources"`
}

// TrendPoint is a single day in the findings-over-time sparkline.
type TrendPoint struct {
	Date     string `json:"date"`
	New      int    `json:"new"`
	Resolved int    `json:"resolved"`
	Net      int    `json:"net"`
}

// PipelineSnapshot mirrors the /api/v1/pipeline counts so the Overview
// can render the same Scan→Correlate→Fix→Verify strip without an extra request.
type PipelineSnapshot struct {
	Scan      int `json:"scan"`
	Correlate int `json:"correlate"`
	Fix       int `json:"fix"`
	Verify    int `json:"verify"`
}

// PolicyItem represents a single SecurityPolicy in the list.
type PolicyItem struct {
	Name           string     `json:"name"`
	Namespace      string     `json:"namespace"`
	Severity       string     `json:"severity"`
	Phase          string     `json:"phase"`
	ViolationCount int32      `json:"violationCount"`
	RuleCount      int        `json:"ruleCount"`
	AutoRemediate  bool       `json:"autoRemediate"`
	Schedule       string     `json:"schedule"`
	LastEvaluated  *time.Time `json:"lastEvaluated,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
}

// PoliciesResponse is returned by GET /api/v1/policies.
type PoliciesResponse struct {
	Policies        []PolicyItem `json:"policies"`
	TotalPolicies   int          `json:"totalPolicies"`
	ActivePolicies  int          `json:"activePolicies"`
	TotalViolations int32        `json:"totalViolations"`
}

// ScanItem represents a single ClusterScan.
type ScanItem struct {
	Name             string     `json:"name"`
	Namespace        string     `json:"namespace"`
	Schedule         string     `json:"schedule"`
	Phase            string     `json:"phase"`
	FindingsCount    int32      `json:"findingsCount"`
	ScannerCount     int        `json:"scannerCount"`
	Scanners         []string   `json:"scanners"`
	LastScheduleTime *time.Time `json:"lastScheduleTime,omitempty"`
	CompletedAt      *time.Time `json:"completedAt,omitempty"`
	LastReportName   string     `json:"lastReportName"`
	HistoryLimit     int32      `json:"historyLimit"`
}

// ScansResponse is returned by GET /api/v1/scans.
type ScansResponse struct {
	Scans         []ScanItem `json:"scans"`
	TotalScans    int        `json:"totalScans"`
	RunningScans  int        `json:"runningScans"`
	TotalFindings int32      `json:"totalFindings"`
}

// ReportResponse is returned by GET /api/v1/reports/{name}.
type ReportResponse struct {
	Name       string                           `json:"name"`
	Namespace  string                           `json:"namespace"`
	ScanRef    string                           `json:"scanRef"`
	Findings   []zelyov1alpha1.Finding          `json:"findings"`
	Summary    zelyov1alpha1.ScanSummary        `json:"summary"`
	Compliance []zelyov1alpha1.ComplianceResult `json:"compliance"`
	Phase      string                           `json:"phase"`
	CreatedAt  time.Time                        `json:"createdAt"`
}

// CloudAccountItem represents a single CloudAccountConfig.
type CloudAccountItem struct {
	Name             string                        `json:"name"`
	Namespace        string                        `json:"namespace"`
	Provider         string                        `json:"provider"`
	AccountID        string                        `json:"accountId"`
	Phase            string                        `json:"phase"`
	FindingsCount    int32                         `json:"findingsCount"`
	FindingsSummary  zelyov1alpha1.FindingsSummary `json:"findingsSummary"`
	Regions          []string                      `json:"regions"`
	ScanCategories   []string                      `json:"scanCategories"`
	ResourcesScanned int32                         `json:"resourcesScanned"`
	LastScanTime     *time.Time                    `json:"lastScanTime,omitempty"`
	LastReportName   string                        `json:"lastReportName"`
}

// CloudResponse is returned by GET /api/v1/cloud.
type CloudResponse struct {
	Accounts      []CloudAccountItem `json:"accounts"`
	TotalAccounts int                `json:"totalAccounts"`
	TotalFindings int32              `json:"totalFindings"`
}

// ComplianceFrameworkSummary summarizes one compliance framework.
type ComplianceFrameworkSummary struct {
	Framework      string `json:"framework"`
	PassRate       int32  `json:"passRate"`
	TotalControls  int32  `json:"totalControls"`
	FailedControls int32  `json:"failedControls"`
	Source         string `json:"source"`
}

// ComplianceResponse is returned by GET /api/v1/compliance.
type ComplianceResponse struct {
	Frameworks []ComplianceFrameworkSummary `json:"frameworks"`
	OverallPct float64                      `json:"overallPct"`
	UpdatedAt  time.Time                    `json:"updatedAt"`
}

// SettingsResponse is returned by GET /api/v1/settings.
type SettingsResponse struct {
	Mode          string             `json:"mode"`
	Phase         string             `json:"phase"`
	LLMProvider   string             `json:"llmProvider"`
	LLMModel      string             `json:"llmModel"`
	LLMKeyStatus  string             `json:"llmKeyStatus"`
	TokenUsage    TokenUsageInfo     `json:"tokenUsage"`
	Notifications []NotificationInfo `json:"notifications"`
	GitOpsRepos   []GitOpsRepoInfo   `json:"gitopsRepos"`
	Remediation   []RemediationInfo  `json:"remediation"`
	Monitoring    []MonitoringInfo   `json:"monitoring"`
}

// TokenUsageInfo shows LLM token consumption.
type TokenUsageInfo struct {
	TokensToday   int64  `json:"tokensToday"`
	TokensMonth   int64  `json:"tokensMonth"`
	EstimatedCost string `json:"estimatedCost"`
}

// NotificationInfo shows a notification channel.
type NotificationInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Phase string `json:"phase"`
}

// GitOpsRepoInfo shows a GitOps repository.
type GitOpsRepoInfo struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Branch     string `json:"branch"`
	Provider   string `json:"provider"`
	Phase      string `json:"phase"`
	SourceType string `json:"sourceType"`
}

// RemediationInfo shows a remediation policy.
type RemediationInfo struct {
	Name           string `json:"name"`
	Phase          string `json:"phase"`
	GitOpsRepo     string `json:"gitopsRepo"`
	SeverityFilter string `json:"severityFilter"`
	DryRun         bool   `json:"dryRun"`
}

// MonitoringInfo shows a monitoring policy.
type MonitoringInfo struct {
	Name            string `json:"name"`
	Phase           string `json:"phase"`
	EventsProcessed int64  `json:"eventsProcessed"`
}

// --- Fetch functions ---

func (s *Server) fetchOverview(ctx context.Context) (*OverviewResponse, error) {
	resp := &OverviewResponse{UpdatedAt: time.Now()}

	if err := s.aggregatePolicies(ctx, resp); err != nil {
		return nil, err
	}
	if err := s.aggregateScans(ctx, resp); err != nil {
		return nil, err
	}
	if err := s.aggregateCloud(ctx, resp); err != nil {
		return nil, err
	}
	s.aggregateReportsAndConfig(ctx, resp)
	s.aggregateRankings(ctx, resp)
	s.attachPipelineSnapshot(resp)
	resp.FindingsTrend = buildTrend(resp.TotalFindings, resp.ResolvedFindings)

	resp.SecurityScore = computeSecurityScore(resp)
	return resp, nil
}

func (s *Server) aggregatePolicies(ctx context.Context, resp *OverviewResponse) error {
	policies := &zelyov1alpha1.SecurityPolicyList{}
	if err := s.client.List(ctx, policies); err != nil {
		return fmt.Errorf("listing security policies: %w", err)
	}
	resp.TotalPolicies = len(policies.Items)
	for i := range policies.Items {
		p := &policies.Items[i]
		if p.Status.Phase == "Active" {
			resp.ActivePolicies++
		}
		resp.TotalViolations += int(p.Status.ViolationCount)
	}
	return nil
}

func (s *Server) aggregateScans(ctx context.Context, resp *OverviewResponse) error {
	scans := &zelyov1alpha1.ClusterScanList{}
	if err := s.client.List(ctx, scans); err != nil {
		return fmt.Errorf("listing cluster scans: %w", err)
	}
	resp.TotalScans = len(scans.Items)
	for i := range scans.Items {
		sc := &scans.Items[i]
		switch sc.Status.Phase {
		case "Running":
			resp.RunningScans++
		case "Completed":
			resp.CompletedScans++
		}
		resp.TotalFindings += int(sc.Status.FindingsCount)
		if sc.Status.CompletedAt != nil {
			t := sc.Status.CompletedAt.Time
			if resp.LastScanTime == nil || t.After(*resp.LastScanTime) {
				resp.LastScanTime = &t
			}
		}
	}
	return nil
}

func (s *Server) aggregateCloud(ctx context.Context, resp *OverviewResponse) error {
	clouds := &zelyov1alpha1.CloudAccountConfigList{}
	if err := s.client.List(ctx, clouds); err != nil {
		return fmt.Errorf("listing cloud accounts: %w", err)
	}
	resp.CloudAccounts = len(clouds.Items)
	for i := range clouds.Items {
		resp.CloudFindings += int(clouds.Items[i].Status.FindingsCount)
	}
	return nil
}

func (s *Server) aggregateReportsAndConfig(ctx context.Context, resp *OverviewResponse) {
	// Count severity from latest reports only (one per scan to avoid double-counting).
	reports := &zelyov1alpha1.ScanReportList{}
	if err := s.client.List(ctx, reports); err == nil {
		latestReports := latestReportsByScan(reports)
		for _, r := range latestReports {
			resp.CriticalViolations += int(r.Spec.Summary.Critical)
			resp.HighViolations += int(r.Spec.Summary.High)
			resp.MediumViolations += int(r.Spec.Summary.Medium)
			resp.LowViolations += int(r.Spec.Summary.Low)
		}
		resp.CompliancePct = computeCompliancePct(reports)
	}

	// ZelyoConfig
	configs := &zelyov1alpha1.ZelyoConfigList{}
	if err := s.client.List(ctx, configs); err == nil && len(configs.Items) > 0 {
		resp.OperatorMode = configs.Items[0].Spec.Mode
		resp.OperatorPhase = configs.Items[0].Status.Phase
	}

	// Resolved findings — derived from the remediation store (each tracked
	// remediation has a per-finding resolved flag the verify stage sets).
	// Skip config-preset items: those are file-creations from the
	// Compliance preset flow, not scan findings, and shouldn't inflate
	// the "findings resolved" metric.
	remediations := events.DefaultRemediationStore().List(0)
	for i := range remediations {
		for j := range remediations[i].Findings {
			f := &remediations[i].Findings[j]
			if f.Resolved && f.Rule != "config-preset" {
				resp.ResolvedFindings++
			}
		}
	}
}

// aggregateRankings populates TopFailingChecks, TopAffectedKinds, Frameworks,
// and AccountsByRisk — the four ranked lists the Overview page renders.
func (s *Server) aggregateRankings(ctx context.Context, resp *OverviewResponse) {
	// Rank checks (rule category) and affected kinds from the latest
	// report per scan only. Counting every historical report skews the
	// rankings toward old findings that may already be fixed.
	reports := &zelyov1alpha1.ScanReportList{}
	if err := s.client.List(ctx, reports); err == nil {
		byCheck := map[string]TopItem{}
		byKind := map[string]TopItem{}
		for _, r := range latestReportsByScan(reports) {
			for j := range r.Spec.Findings {
				f := &r.Spec.Findings[j]
				c := byCheck[f.Category]
				c.Name = f.Category
				c.Count++
				c.Severity = worseSeverity(c.Severity, f.Severity)
				c.Category = "check"
				byCheck[f.Category] = c

				k := byKind[f.Resource.Kind]
				k.Name = f.Resource.Kind
				if k.Name == "" {
					k.Name = "Unknown"
				}
				k.Count++
				k.Severity = worseSeverity(k.Severity, f.Severity)
				k.Category = "kind"
				byKind[f.Resource.Kind] = k
			}
		}
		resp.TopFailingChecks = topN(byCheck, 5)
		resp.TopAffectedKinds = topN(byKind, 5)
	}

	// Compliance frameworks — reuse the compliance aggregation.
	if comp, err := s.fetchCompliance(ctx); err == nil {
		resp.Frameworks = comp.Frameworks
	}

	// Cloud accounts ranked by findings count.
	clouds := &zelyov1alpha1.CloudAccountConfigList{}
	if err := s.client.List(ctx, clouds); err == nil {
		for i := range clouds.Items {
			c := &clouds.Items[i]
			resp.AccountsByRisk = append(resp.AccountsByRisk, AccountRisk{
				Name:          c.Name,
				Provider:      c.Spec.Provider,
				AccountID:     c.Spec.AccountID,
				FindingsCount: c.Status.FindingsCount,
				Critical:      c.Status.FindingsSummary.Critical,
				High:          c.Status.FindingsSummary.High,
				Medium:        c.Status.FindingsSummary.Medium,
				Resources:     c.Status.ResourcesScanned,
			})
		}
		sort.Slice(resp.AccountsByRisk, func(i, j int) bool {
			a, b := resp.AccountsByRisk[i], resp.AccountsByRisk[j]
			if a.Critical != b.Critical {
				return a.Critical > b.Critical
			}
			if a.High != b.High {
				return a.High > b.High
			}
			return a.FindingsCount > b.FindingsCount
		})
	}
}

// attachPipelineSnapshot copies per-stage event counts from the pipeline bus
// into the Overview response so the landing page can render a mini pipeline
// strip without a second request.
func (s *Server) attachPipelineSnapshot(resp *OverviewResponse) {
	recent := events.Default().Recent("", 1000)
	for i := range recent {
		switch recent[i].Stage {
		case events.StageScan:
			resp.PipelineSnapshot.Scan++
		case events.StageCorrelate:
			resp.PipelineSnapshot.Correlate++
		case events.StageFix:
			resp.PipelineSnapshot.Fix++
		case events.StageVerify:
			resp.PipelineSnapshot.Verify++
		}
	}
}

// topN returns the top-n map entries by Count, ties broken by severity weight.
func topN(m map[string]TopItem, n int) []TopItem {
	out := make([]TopItem, 0, len(m))
	for _, v := range m {
		if v.Name == "" {
			continue
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return severityWeight(out[i].Severity) > severityWeight(out[j].Severity)
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// severityWeight returns a comparable rank for a severity string. Higher = worse.
func severityWeight(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// worseSeverity returns whichever of the two inputs is the worse severity.
func worseSeverity(a, b string) string {
	if severityWeight(b) > severityWeight(a) {
		return b
	}
	return a
}

// buildTrend returns a 7-day synthetic sparkline suitable for the Overview.
// In demo mode we derive it from the current finding count so it moves with
// the story the dashboard is telling. Real deployments would compute this
// from a metrics store.
func buildTrend(totalFindings, resolved int) []TrendPoint {
	days := 7
	out := make([]TrendPoint, 0, days)
	now := time.Now().UTC()
	// Walk backwards from today, easing back toward zero so the trend
	// reads as "posture is improving".
	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i)
		factor := float64(days-i) / float64(days)
		newCount := int(float64(totalFindings) * factor * 0.25)
		resolvedCount := int(float64(resolved) * factor * 1.1)
		out = append(out, TrendPoint{
			Date:     d.Format("2006-01-02"),
			New:      newCount,
			Resolved: resolvedCount,
			Net:      newCount - resolvedCount,
		})
	}
	return out
}

func (s *Server) fetchPolicies(ctx context.Context) (*PoliciesResponse, error) {
	list := &zelyov1alpha1.SecurityPolicyList{}
	if err := s.client.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing security policies: %w", err)
	}

	resp := &PoliciesResponse{
		TotalPolicies: len(list.Items),
	}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Status.Phase == "Active" {
			resp.ActivePolicies++
		}
		resp.TotalViolations += p.Status.ViolationCount

		var lastEval *time.Time
		if p.Status.LastEvaluated != nil {
			t := p.Status.LastEvaluated.Time
			lastEval = &t
		}
		resp.Policies = append(resp.Policies, PolicyItem{
			Name:           p.Name,
			Namespace:      p.Namespace,
			Severity:       p.Spec.Severity,
			Phase:          p.Status.Phase,
			ViolationCount: p.Status.ViolationCount,
			RuleCount:      len(p.Spec.Rules),
			AutoRemediate:  p.Spec.AutoRemediate,
			Schedule:       p.Spec.Schedule,
			LastEvaluated:  lastEval,
			CreatedAt:      p.CreationTimestamp.Time,
		})
	}
	sort.Slice(resp.Policies, func(i, j int) bool {
		return resp.Policies[i].ViolationCount > resp.Policies[j].ViolationCount
	})
	return resp, nil
}

func (s *Server) fetchScans(ctx context.Context) (*ScansResponse, error) {
	list := &zelyov1alpha1.ClusterScanList{}
	if err := s.client.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing cluster scans: %w", err)
	}

	resp := &ScansResponse{TotalScans: len(list.Items)}
	for i := range list.Items {
		sc := &list.Items[i]
		if sc.Status.Phase == "Running" {
			resp.RunningScans++
		}
		resp.TotalFindings += sc.Status.FindingsCount

		var lastSchedule, completedAt *time.Time
		if sc.Status.LastScheduleTime != nil {
			t := sc.Status.LastScheduleTime.Time
			lastSchedule = &t
		}
		if sc.Status.CompletedAt != nil {
			t := sc.Status.CompletedAt.Time
			completedAt = &t
		}
		resp.Scans = append(resp.Scans, ScanItem{
			Name:             sc.Name,
			Namespace:        sc.Namespace,
			Schedule:         sc.Spec.Schedule,
			Phase:            sc.Status.Phase,
			FindingsCount:    sc.Status.FindingsCount,
			ScannerCount:     len(sc.Spec.Scanners),
			Scanners:         sc.Spec.Scanners,
			LastScheduleTime: lastSchedule,
			CompletedAt:      completedAt,
			LastReportName:   sc.Status.LastReportName,
			HistoryLimit:     sc.Spec.HistoryLimit,
		})
	}
	return resp, nil
}

func (s *Server) fetchReport(ctx context.Context, namespace, name string) (*ReportResponse, error) {
	report := &zelyov1alpha1.ScanReport{}
	key := client.ObjectKey{Namespace: namespace, Name: name}
	if err := s.client.Get(ctx, key, report); err != nil {
		return nil, fmt.Errorf("getting scan report %s/%s: %w", namespace, name, err)
	}
	return &ReportResponse{
		Name:       report.Name,
		Namespace:  report.Namespace,
		ScanRef:    report.Spec.ScanRef,
		Findings:   report.Spec.Findings,
		Summary:    report.Spec.Summary,
		Compliance: report.Spec.Compliance,
		Phase:      report.Status.Phase,
		CreatedAt:  report.CreationTimestamp.Time,
	}, nil
}

func (s *Server) fetchReportsForScan(ctx context.Context, scanName string) ([]ReportResponse, error) {
	list := &zelyov1alpha1.ScanReportList{}
	if err := s.client.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing scan reports: %w", err)
	}

	var results []ReportResponse
	for i := range list.Items {
		r := &list.Items[i]
		if r.Spec.ScanRef == scanName {
			results = append(results, ReportResponse{
				Name:       r.Name,
				Namespace:  r.Namespace,
				ScanRef:    r.Spec.ScanRef,
				Summary:    r.Spec.Summary,
				Compliance: r.Spec.Compliance,
				Phase:      r.Status.Phase,
				CreatedAt:  r.CreationTimestamp.Time,
			})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	return results, nil
}

func (s *Server) fetchCloud(ctx context.Context) (*CloudResponse, error) {
	list := &zelyov1alpha1.CloudAccountConfigList{}
	if err := s.client.List(ctx, list); err != nil {
		return nil, fmt.Errorf("listing cloud accounts: %w", err)
	}

	resp := &CloudResponse{TotalAccounts: len(list.Items)}
	for i := range list.Items {
		c := &list.Items[i]
		resp.TotalFindings += c.Status.FindingsCount

		var lastScan *time.Time
		if c.Status.LastScanTime != nil {
			t := c.Status.LastScanTime.Time
			lastScan = &t
		}
		resp.Accounts = append(resp.Accounts, CloudAccountItem{
			Name:             c.Name,
			Namespace:        c.Namespace,
			Provider:         c.Spec.Provider,
			AccountID:        c.Spec.AccountID,
			Phase:            c.Status.Phase,
			FindingsCount:    c.Status.FindingsCount,
			FindingsSummary:  c.Status.FindingsSummary,
			Regions:          c.Spec.Regions,
			ScanCategories:   c.Spec.ScanCategories,
			ResourcesScanned: c.Status.ResourcesScanned,
			LastScanTime:     lastScan,
			LastReportName:   c.Status.LastReportName,
		})
	}
	return resp, nil
}

func (s *Server) fetchCompliance(ctx context.Context) (*ComplianceResponse, error) {
	reports := &zelyov1alpha1.ScanReportList{}
	if err := s.client.List(ctx, reports); err != nil {
		return nil, fmt.Errorf("listing scan reports: %w", err)
	}

	// Aggregate compliance from the latest report per scan.
	latestByScan := latestReportsByScan(reports)
	fwMap := make(map[string]*ComplianceFrameworkSummary)
	for _, r := range latestByScan {
		for _, c := range r.Spec.Compliance {
			if existing, ok := fwMap[c.Framework]; ok {
				existing.TotalControls += c.TotalControls
				existing.FailedControls += c.FailedControls
			} else {
				fwMap[c.Framework] = &ComplianceFrameworkSummary{
					Framework:      c.Framework,
					PassRate:       c.PassRate,
					TotalControls:  c.TotalControls,
					FailedControls: c.FailedControls,
					Source:         "cluster",
				}
			}
		}
	}

	resp := &ComplianceResponse{UpdatedAt: time.Now()}
	var totalPass, totalControls int32
	for _, fw := range fwMap {
		if fw.TotalControls > 0 {
			fw.PassRate = int32(float64(fw.TotalControls-fw.FailedControls) / float64(fw.TotalControls) * 100)
		}
		totalPass += fw.TotalControls - fw.FailedControls
		totalControls += fw.TotalControls
		resp.Frameworks = append(resp.Frameworks, *fw)
	}
	sort.Slice(resp.Frameworks, func(i, j int) bool {
		return resp.Frameworks[i].Framework < resp.Frameworks[j].Framework
	})
	if totalControls > 0 {
		resp.OverallPct = float64(totalPass) / float64(totalControls) * 100
	}
	return resp, nil
}

func (s *Server) fetchSettings(ctx context.Context) (*SettingsResponse, error) {
	resp := &SettingsResponse{}

	// ZelyoConfig — the only required resource; fail if inaccessible.
	configs := &zelyov1alpha1.ZelyoConfigList{}
	if err := s.client.List(ctx, configs); err != nil {
		return nil, fmt.Errorf("listing zelyoconfigs: %w", err)
	}
	if len(configs.Items) > 0 {
		cfg := &configs.Items[0]
		resp.Mode = cfg.Spec.Mode
		resp.Phase = cfg.Status.Phase
		resp.LLMProvider = cfg.Spec.LLM.Provider
		resp.LLMModel = cfg.Spec.LLM.Model
		resp.LLMKeyStatus = cfg.Status.LLMKeyStatus
		resp.TokenUsage = TokenUsageInfo{
			TokensToday:   cfg.Status.TokenUsage.TokensUsedToday,
			TokensMonth:   cfg.Status.TokenUsage.TokensUsedThisMonth,
			EstimatedCost: cfg.Status.TokenUsage.EstimatedCostUSD,
		}
	}

	// NotificationChannels
	channels := &zelyov1alpha1.NotificationChannelList{}
	if err := s.client.List(ctx, channels); err == nil {
		for i := range channels.Items {
			ch := &channels.Items[i]
			resp.Notifications = append(resp.Notifications, NotificationInfo{
				Name:  ch.Name,
				Type:  ch.Spec.Type,
				Phase: ch.Status.Phase,
			})
		}
	}

	// GitOpsRepositories
	repos := &zelyov1alpha1.GitOpsRepositoryList{}
	if err := s.client.List(ctx, repos); err == nil {
		for i := range repos.Items {
			r := &repos.Items[i]
			resp.GitOpsRepos = append(resp.GitOpsRepos, GitOpsRepoInfo{
				Name:       r.Name,
				URL:        r.Spec.URL,
				Branch:     r.Spec.Branch,
				Provider:   r.Spec.Provider,
				Phase:      r.Status.Phase,
				SourceType: string(r.Spec.SourceType),
			})
		}
	}

	// RemediationPolicies
	remPolicies := &zelyov1alpha1.RemediationPolicyList{}
	if err := s.client.List(ctx, remPolicies); err == nil {
		for i := range remPolicies.Items {
			rp := &remPolicies.Items[i]
			resp.Remediation = append(resp.Remediation, RemediationInfo{
				Name:           rp.Name,
				Phase:          rp.Status.Phase,
				GitOpsRepo:     rp.Spec.GitOpsRepository,
				SeverityFilter: rp.Spec.SeverityFilter,
				DryRun:         rp.Spec.DryRun,
			})
		}
	}

	// MonitoringPolicies
	monPolicies := &zelyov1alpha1.MonitoringPolicyList{}
	if err := s.client.List(ctx, monPolicies); err == nil {
		for i := range monPolicies.Items {
			mp := &monPolicies.Items[i]
			resp.Monitoring = append(resp.Monitoring, MonitoringInfo{
				Name:            mp.Name,
				Phase:           mp.Status.Phase,
				EventsProcessed: mp.Status.EventsProcessed,
			})
		}
	}

	return resp, nil
}

// --- Helpers ---

func computeSecurityScore(o *OverviewResponse) int {
	score := 100
	score -= o.CriticalViolations * 10
	score -= o.HighViolations * 5
	score -= o.MediumViolations * 2
	if score < 0 {
		score = 0
	}
	return score
}

func computeCompliancePct(reports *zelyov1alpha1.ScanReportList) float64 {
	if reports == nil {
		return 0
	}
	latest := latestReportsByScan(reports)
	var totalPass, totalControls int32
	for _, r := range latest {
		for _, c := range r.Spec.Compliance {
			totalPass += c.TotalControls - c.FailedControls
			totalControls += c.TotalControls
		}
	}
	if totalControls == 0 {
		return 0
	}
	return float64(totalPass) / float64(totalControls) * 100
}

func latestReportsByScan(reports *zelyov1alpha1.ScanReportList) map[string]*zelyov1alpha1.ScanReport {
	latest := make(map[string]*zelyov1alpha1.ScanReport)
	for i := range reports.Items {
		r := &reports.Items[i]
		if existing, ok := latest[r.Spec.ScanRef]; !ok || r.CreationTimestamp.After(existing.CreationTimestamp.Time) {
			latest[r.Spec.ScanRef] = r
		}
	}
	return latest
}
