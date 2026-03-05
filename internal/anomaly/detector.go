/*
Copyright 2026 Zelyo AI
*/

// Package anomaly provides real-time anomaly detection for Kubernetes workloads.
// It learns baseline behavior and flags deviations in resource usage, restart
// patterns, and error rates.
package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// Detector watches workload metrics and flags anomalous behavior.
type Detector struct {
	mu        sync.RWMutex
	baselines map[string]*Baseline
	config    Config
}

// Config configures the anomaly detector.
type Config struct {
	LearningPeriod time.Duration `json:"learning_period"`
	Sensitivity    float64       `json:"sensitivity"`
	MinDataPoints  int           `json:"min_data_points"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		LearningPeriod: 24 * time.Hour,
		Sensitivity:    3.0,
		MinDataPoints:  30,
	}
}

// Baseline tracks the normal behavior of a single metric for a specific workload.
type Baseline struct {
	Key           string    `json:"key"`
	Values        []float64 `json:"-"`
	Mean          float64   `json:"mean"`
	StdDev        float64   `json:"std_dev"`
	Min           float64   `json:"min"`
	Max           float64   `json:"max"`
	Count         int       `json:"count"`
	LearningUntil time.Time `json:"learning_until"`
	LastUpdated   time.Time `json:"last_updated"`
}

// Anomaly describes a detected anomaly.
type Anomaly struct {
	Key            string    `json:"key"`
	Value          float64   `json:"value"`
	ExpectedMean   float64   `json:"expected_mean"`
	ExpectedStdDev float64   `json:"expected_std_dev"`
	DeviationSigma float64   `json:"deviation_sigma"`
	Severity       string    `json:"severity"`
	DetectedAt     time.Time `json:"detected_at"`
	Message        string    `json:"message"`
}

// NewDetector creates a new anomaly detector.
func NewDetector(cfg Config) *Detector {
	if cfg.Sensitivity == 0 {
		cfg.Sensitivity = 3.0
	}
	if cfg.MinDataPoints == 0 {
		cfg.MinDataPoints = 30
	}
	return &Detector{
		baselines: make(map[string]*Baseline),
		config:    cfg,
	}
}

// Observe records a new metric value for a workload.
func (d *Detector) Observe(key string, value float64) *Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()

	baseline, exists := d.baselines[key]
	if !exists {
		baseline = &Baseline{
			Key:           key,
			Values:        make([]float64, 0, 100),
			Min:           value,
			Max:           value,
			LearningUntil: time.Now().Add(d.config.LearningPeriod),
		}
		d.baselines[key] = baseline
	}

	baseline.Values = append(baseline.Values, value)
	if len(baseline.Values) > 1000 {
		baseline.Values = baseline.Values[len(baseline.Values)-1000:]
	}

	baseline.Count++
	baseline.LastUpdated = time.Now()
	baseline.Mean = mean(baseline.Values)
	baseline.StdDev = stddev(baseline.Values, baseline.Mean)
	if value < baseline.Min {
		baseline.Min = value
	}
	if value > baseline.Max {
		baseline.Max = value
	}

	if time.Now().Before(baseline.LearningUntil) || baseline.Count < d.config.MinDataPoints {
		return nil
	}

	if baseline.StdDev == 0 {
		return nil
	}

	deviation := math.Abs(value-baseline.Mean) / baseline.StdDev
	if deviation < d.config.Sensitivity {
		return nil
	}

	var severity string
	switch {
	case deviation > d.config.Sensitivity*2:
		severity = "critical"
	case deviation > d.config.Sensitivity*1.5:
		severity = "high"
	default:
		severity = "medium"
	}

	return &Anomaly{
		Key:            key,
		Value:          value,
		ExpectedMean:   baseline.Mean,
		ExpectedStdDev: baseline.StdDev,
		DeviationSigma: deviation,
		Severity:       severity,
		DetectedAt:     time.Now(),
		Message: fmt.Sprintf("Anomaly detected for %s: value %.2f is %.1fσ from mean %.2f (std: %.2f)",
			key, value, deviation, baseline.Mean, baseline.StdDev),
	}
}

// GetBaseline returns the current baseline for a key, or nil if not found.
func (d *Detector) GetBaseline(key string) *Baseline {
	d.mu.RLock()
	defer d.mu.RUnlock()
	b, ok := d.baselines[key]
	if !ok {
		return nil
	}
	result := *b
	return &result
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64, m float64) float64 {
	if len(values) < 2 {
		return 0
	}
	sumSq := 0.0
	for _, v := range values {
		diff := v - m
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)-1))
}
