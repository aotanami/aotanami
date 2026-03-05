# Monitoring & Metrics

Zelyo Operator exposes **custom Prometheus metrics** at the standard `/metrics` endpoint, giving you full observability into the operator's performance and security posture.

## Prometheus Integration

Zelyo Operator's metrics are automatically available to any Prometheus instance scraping the operator pod. If you're using the [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack), a `ServiceMonitor` is included in the Helm chart.

### Quick Check

To see metrics locally while running the operator with `make run`:

```bash
curl http://localhost:8080/metrics | grep zelyo_operator_
```

## Available Metrics

### Controller Metrics

These tell you how your controllers are performing:

| Metric | Type | Labels | What It Tells You |
|---|---|---|---|
| `zelyo_operator_controller_reconcile_total` | Counter | `controller`, `result` | How many reconciles happened, and whether they succeeded or failed |
| `zelyo_operator_controller_reconcile_duration_seconds` | Histogram | `controller` | How long each reconcile takes (useful for spotting slowdowns) |

**Example queries:**

```promql
# Reconcile error rate for SecurityPolicy controller
rate(zelyo_operator_controller_reconcile_total{controller="securitypolicy", result="error"}[5m])

# p99 reconcile latency
histogram_quantile(0.99, rate(zelyo_operator_controller_reconcile_duration_seconds_bucket{controller="securitypolicy"}[5m]))
```

### Scanner Metrics

These track what the security scanners are finding:

| Metric | Type | Labels | What It Tells You |
|---|---|---|---|
| `zelyo_operator_scanner_findings_total` | Counter | `scanner`, `severity` | Total findings by scanner type and severity |
| `zelyo_operator_scanner_scan_duration_seconds` | Histogram | `scanner` | How long scans take to complete |
| `zelyo_operator_scanner_resources_scanned_total` | Counter | `scanner` | How many resources (pods) have been scanned |

**Example queries:**

```promql
# Critical findings per minute
rate(zelyo_operator_scanner_findings_total{severity="critical"}[5m])

# Total resources scanned in the last hour
increase(zelyo_operator_scanner_resources_scanned_total[1h])
```

### Policy Metrics

These track the security posture of your policies:

| Metric | Type | Labels | What It Tells You |
|---|---|---|---|
| `zelyo_operator_policy_violations` | Gauge | `policy`, `namespace`, `severity` | Current violation count per policy (goes up and down) |
| `zelyo_operator_policy_phase_info` | Gauge | `policy`, `namespace`, `phase` | Current phase of each policy (Active, Error, etc.) |

**Example queries:**

```promql
# All policies with violations
zelyo_operator_policy_violations > 0

# Policies in Error state
zelyo_operator_policy_phase_info{phase="Error"} == 1
```

### ClusterScan Metrics

These track scheduled cluster-wide scans:

| Metric | Type | Labels | What It Tells You |
|---|---|---|---|
| `zelyo_operator_clusterscan_completed_total` | Counter | `scan`, `namespace` | How many scans have completed |
| `zelyo_operator_clusterscan_findings` | Gauge | `scan`, `namespace` | Findings from the most recent scan run |

### Cost Metrics

| Metric | Type | Labels | What It Tells You |
|---|---|---|---|
| `zelyo_operator_cost_rightsizing_recommendations` | Gauge | `policy`, `namespace` | How many pods need resource limit adjustments |

## Grafana Dashboard

You can build a Grafana dashboard using these metrics. Here's a suggested layout:

### Panel Ideas

| Panel | Query | Visualization |
|---|---|---|
| **Security Score** | `1 - (zelyo_operator_policy_violations / zelyo_operator_scanner_resources_scanned_total)` | Gauge (0-100%) |
| **Critical Findings** | `zelyo_operator_scanner_findings_total{severity="critical"}` | Stat (big number) |
| **Violations Over Time** | `sum(zelyo_operator_policy_violations) by (severity)` | Time series |
| **Reconcile Latency** | `histogram_quantile(0.95, ...)` | Time series |
| **Scan Completion Rate** | `rate(zelyo_operator_clusterscan_completed_total[24h])` | Stat |

## Alerting Rules

Here are example Prometheus alerting rules for Zelyo Operator:

```yaml
groups:
  - name: zelyo-operator
    rules:
      - alert: Zelyo OperatorCriticalViolations
        expr: zelyo_operator_scanner_findings_total{severity="critical"} > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Critical security violations detected"
          description: "{{ $labels.scanner }} found {{ $value }} critical findings"

      - alert: Zelyo OperatorReconcileErrors
        expr: rate(zelyo_operator_controller_reconcile_total{result="error"}[5m]) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Zelyo Operator controller {{ $labels.controller }} has high error rate"

      - alert: Zelyo OperatorSlowReconcile
        expr: histogram_quantile(0.99, rate(zelyo_operator_controller_reconcile_duration_seconds_bucket[5m])) > 30
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Zelyo Operator controller {{ $labels.controller }} reconcile taking >30s"
```
