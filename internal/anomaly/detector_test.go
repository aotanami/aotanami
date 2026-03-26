/*
Copyright 2026 Zelyo AI
*/

package anomaly

import (
	"testing"
	"time"
)

func TestDetector_LearningPeriod(t *testing.T) {
	d := NewDetector(Config{
		LearningPeriod: 0, // No learning period for testing.
		Sensitivity:    3.0,
		MinDataPoints:  5,
	})

	// Feed stable baseline data with some natural variance.
	baselineValues := []float64{48, 49, 50, 51, 52, 49, 50, 51, 50, 49}
	for i, v := range baselineValues {
		result := d.Observe("cpu", v)
		if result != nil && i >= 5 {
			t.Errorf("Expected no anomaly during baseline formation, got %v at iteration %d", result, i)
		}
	}

	// No anomaly for values within normal range (well within mean ± 3σ).
	result := d.Observe("cpu", 50.5)
	if result != nil {
		t.Errorf("Expected no anomaly for value very close to mean, got %v", result)
	}
}

func TestDetector_AnomalyDetection(t *testing.T) {
	d := NewDetector(Config{
		LearningPeriod: 0,
		Sensitivity:    2.0, // Lower sensitivity for easier triggering.
		MinDataPoints:  5,
	})

	// Build a stable baseline.
	for i := 0; i < 20; i++ {
		d.Observe("restarts", 2.0)
	}

	// Massive spike should trigger anomaly.
	result := d.Observe("restarts", 100.0)
	if result != nil {
		if result.Severity == "" {
			t.Error("Expected non-empty severity")
		}
		if result.DeviationSigma < 2.0 {
			t.Errorf("Expected deviation >= 2.0σ, got %.2f", result.DeviationSigma)
		}
	} else {
		t.Fatal("Expected anomaly for extreme value, got nil")
	}
}

func TestDetector_SeverityClassification(t *testing.T) {
	d := NewDetector(Config{
		LearningPeriod: 0,
		Sensitivity:    2.0,
		MinDataPoints:  5,
	})

	// Build baseline.
	for i := 0; i < 30; i++ {
		d.Observe("metric", 10.0)
	}

	// Test critical severity (> 2x sensitivity = > 4σ).
	anom := d.Observe("metric", 1000.0) // Huge deviation.
	if anom != nil {
		if anom.Severity != "critical" {
			t.Errorf("Expected critical severity for extreme deviation, got %q", anom.Severity)
		}
	} else {
		t.Fatal("Expected anomaly")
	}
}

func TestDetector_GetBaseline(t *testing.T) {
	d := NewDetector(DefaultConfig())

	// No baseline yet.
	if b := d.GetBaseline("unknown"); b != nil {
		t.Error("Expected nil baseline for unknown key")
	}

	d.Observe("test", 10.0)
	d.Observe("test", 20.0)
	d.Observe("test", 30.0)

	b := d.GetBaseline("test")
	if b != nil {
		if b.Count != 3 {
			t.Errorf("Expected count 3, got %d", b.Count)
		}
		if b.Mean != 20.0 {
			t.Errorf("Expected mean 20.0, got %.2f", b.Mean)
		}
		if b.Min != 10.0 {
			t.Errorf("Expected min 10.0, got %.2f", b.Min)
		}
		if b.Max != 30.0 {
			t.Errorf("Expected max 30.0, got %.2f", b.Max)
		}
	} else {
		t.Fatal("Expected baseline for observed key")
	}
}

func TestDetector_SlidingWindow(t *testing.T) {
	d := NewDetector(Config{
		LearningPeriod: 0,
		Sensitivity:    3.0,
		MinDataPoints:  5,
	})

	// Observe more than 1000 values to trigger pruning.
	for i := 0; i < 1100; i++ {
		d.Observe("large", float64(i))
	}

	b := d.GetBaseline("large")
	if b != nil {
		if b.Count != 1100 {
			t.Errorf("Expected count 1100, got %d", b.Count)
		}
		// Values should be pruned to last 1000.
		if len(b.Values) > 1000 {
			t.Errorf("Expected at most 1000 stored values, got %d", len(b.Values))
		}
	} else {
		t.Fatal("Expected baseline")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.LearningPeriod != 24*time.Hour {
		t.Errorf("Expected 24h learning period, got %v", cfg.LearningPeriod)
	}
	if cfg.Sensitivity != 3.0 {
		t.Errorf("Expected 3.0 sensitivity, got %.1f", cfg.Sensitivity)
	}
	if cfg.MinDataPoints != 30 {
		t.Errorf("Expected 30 min data points, got %d", cfg.MinDataPoints)
	}
}
