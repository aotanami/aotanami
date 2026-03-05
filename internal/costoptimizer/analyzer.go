/*
Copyright 2026 Zelyo AI
*/

// Package costoptimizer provides resource right-sizing recommendations and idle
// workload detection for Kubernetes clusters. It compares actual resource usage
// against requests/limits to identify over-provisioned and under-provisioned workloads.
package costoptimizer

import (
	"fmt"
	"time"
)

// Recommendation is a single right-sizing recommendation.
type Recommendation struct {
	// ResourceKind is the K8s resource type (Deployment, StatefulSet, etc.).
	ResourceKind string `json:"resource_kind"`

	// ResourceName is the workload name.
	ResourceName string `json:"resource_name"`

	// Namespace is the workload namespace.
	Namespace string `json:"namespace"`

	// ContainerName is the specific container.
	ContainerName string `json:"container_name"`

	// Type classifies the recommendation.
	Type RecommendationType `json:"type"`

	// CurrentCPU is the current CPU request/limit (in millicores).
	CurrentCPU ResourceSpec `json:"current_cpu"`

	// CurrentMemory is the current memory request/limit (in MiB).
	CurrentMemory ResourceSpec `json:"current_memory"`

	// RecommendedCPU is the recommended CPU request/limit.
	RecommendedCPU ResourceSpec `json:"recommended_cpu"`

	// RecommendedMemory is the recommended memory request/limit.
	RecommendedMemory ResourceSpec `json:"recommended_memory"`

	// EstimatedSavingsPct is the estimated cost reduction percentage.
	EstimatedSavingsPct float64 `json:"estimated_savings_pct"`

	// Confidence is the confidence level of this recommendation (0-100).
	Confidence int `json:"confidence"`

	// ObservationPeriod is how long the workload was monitored.
	ObservationPeriod time.Duration `json:"observation_period"`

	// GeneratedAt is when the recommendation was generated.
	GeneratedAt time.Time `json:"generated_at"`

	// Message is a human-readable explanation.
	Message string `json:"message"`
}

// ResourceSpec holds request/limit values.
type ResourceSpec struct {
	Request string `json:"request"`
	Limit   string `json:"limit"`
}

// RecommendationType classifies the recommendation.
type RecommendationType string

const (
	// RecommendationDownsize means the workload is over-provisioned.
	RecommendationDownsize RecommendationType = "downsize"

	// RecommendationUpsize means the workload is under-provisioned (risk of OOM/throttle).
	RecommendationUpsize RecommendationType = "upsize"

	// RecommendationIdle means the workload appears unused.
	RecommendationIdle RecommendationType = "idle"

	// RecommendationMissingLimits means the workload has no resource limits.
	RecommendationMissingLimits RecommendationType = "missing_limits"
)

// UsageMetrics holds in observed resource usage for a container.
type UsageMetrics struct {
	// CPUAvgMillicores is the average CPU usage in millicores.
	CPUAvgMillicores float64 `json:"cpu_avg_millicores"`

	// CPUMaxMillicores is the peak CPU usage in millicores.
	CPUMaxMillicores float64 `json:"cpu_max_millicores"`

	// CPUp95Millicores is the 95th percentile CPU.
	CPUp95Millicores float64 `json:"cpu_p95_millicores"`

	// MemoryAvgMiB is the average memory usage in MiB.
	MemoryAvgMiB float64 `json:"memory_avg_mib"`

	// MemoryMaxMiB is the peak memory usage in MiB.
	MemoryMaxMiB float64 `json:"memory_max_mib"`

	// MemoryP95MiB is the 95th percentile memory.
	MemoryP95MiB float64 `json:"memory_p95_mib"`
}

// Analyzer generates right-sizing recommendations.
type Analyzer struct {
	config Config
}

// Config configures the cost optimizer.
type Config struct {
	// DownsizeThreshold is the minimum utilization below which to recommend downsizing.
	// E.g., 0.3 means "if using less than 30% of requested, recommend downsizing".
	DownsizeThreshold float64 `json:"downsize_threshold"`

	// UpsizeThreshold is the utilization above which to recommend upsizing.
	// E.g., 0.9 means "if using more than 90% of limit, recommend upsizing".
	UpsizeThreshold float64 `json:"upsize_threshold"`

	// IdleThreshold is the utilization below which a workload is considered idle.
	IdleThreshold float64 `json:"idle_threshold"`

	// MinObservationPeriod is the minimum time to observe before recommending.
	MinObservationPeriod time.Duration `json:"min_observation_period"`

	// CPUHeadroom is extra CPU to add above p95 for the recommendation.
	CPUHeadroom float64 `json:"cpu_headroom"`

	// MemoryHeadroom is extra memory to add above p95 for the recommendation.
	MemoryHeadroom float64 `json:"memory_headroom"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		DownsizeThreshold:    0.3,
		UpsizeThreshold:      0.9,
		IdleThreshold:        0.05,
		MinObservationPeriod: 7 * 24 * time.Hour,
		CPUHeadroom:          0.2,  // 20% above p95
		MemoryHeadroom:       0.15, // 15% above p95
	}
}

// NewAnalyzer creates a new cost analyzer.
func NewAnalyzer(cfg Config) *Analyzer {
	return &Analyzer{config: cfg}
}

// Analyze generates recommendations for a container based on its usage metrics.
func (a *Analyzer) Analyze(kind, name, namespace, container string,
	requestCPU, limitCPU, requestMemMiB, limitMemMiB float64,
	usage UsageMetrics, observationPeriod time.Duration) *Recommendation {
	rec := &Recommendation{
		ResourceKind:      kind,
		ResourceName:      name,
		Namespace:         namespace,
		ContainerName:     container,
		CurrentCPU:        ResourceSpec{Request: fmt.Sprintf("%dm", int(requestCPU)), Limit: fmt.Sprintf("%dm", int(limitCPU))},
		CurrentMemory:     ResourceSpec{Request: fmt.Sprintf("%dMi", int(requestMemMiB)), Limit: fmt.Sprintf("%dMi", int(limitMemMiB))},
		ObservationPeriod: observationPeriod,
		GeneratedAt:       time.Now(),
	}

	// Check: missing limits.
	if limitCPU == 0 || limitMemMiB == 0 {
		rec.Type = RecommendationMissingLimits
		rec.Confidence = 100
		rec.Message = "Container has no resource limits set. This could lead to unbounded resource consumption."
		return rec
	}

	// Check: idle workload.
	cpuUtil := usage.CPUAvgMillicores / requestCPU
	memUtil := usage.MemoryAvgMiB / requestMemMiB
	if cpuUtil < a.config.IdleThreshold && memUtil < a.config.IdleThreshold {
		rec.Type = RecommendationIdle
		rec.Confidence = 85
		rec.EstimatedSavingsPct = 95
		rec.Message = fmt.Sprintf("Container appears idle: CPU %.1f%%, Memory %.1f%% of requested", cpuUtil*100, memUtil*100)
		return rec
	}

	// Check: over-provisioned (downsize).
	if cpuUtil < a.config.DownsizeThreshold && memUtil < a.config.DownsizeThreshold {
		recCPU := usage.CPUp95Millicores * (1 + a.config.CPUHeadroom)
		recMem := usage.MemoryP95MiB * (1 + a.config.MemoryHeadroom)
		savings := (1 - (recCPU*recMem)/(requestCPU*requestMemMiB)) * 100

		rec.Type = RecommendationDownsize
		rec.RecommendedCPU = ResourceSpec{
			Request: fmt.Sprintf("%dm", int(recCPU)),
			Limit:   fmt.Sprintf("%dm", int(recCPU*1.5)),
		}
		rec.RecommendedMemory = ResourceSpec{
			Request: fmt.Sprintf("%dMi", int(recMem)),
			Limit:   fmt.Sprintf("%dMi", int(recMem*1.25)),
		}
		rec.EstimatedSavingsPct = savings
		rec.Confidence = 75
		rec.Message = fmt.Sprintf("Over-provisioned: using %.0f%% CPU, %.0f%% memory of requested", cpuUtil*100, memUtil*100)
		return rec
	}

	// Check: under-provisioned (upsize).
	cpuLimitUtil := usage.CPUMaxMillicores / limitCPU
	memLimitUtil := usage.MemoryMaxMiB / limitMemMiB
	if cpuLimitUtil > a.config.UpsizeThreshold || memLimitUtil > a.config.UpsizeThreshold {
		rec.Type = RecommendationUpsize
		rec.Confidence = 80
		rec.Message = fmt.Sprintf("Under-provisioned: peak CPU %.0f%%, peak memory %.0f%% of limit", cpuLimitUtil*100, memLimitUtil*100)
		return rec
	}

	return nil // No recommendation needed.
}
