/*
Copyright 2026 Zelyo AI.
*/

// Package threat provides threat intelligence integration for Aotanami.
// It aggregates data from CVE feeds, known-bad image registries, and EPSS
// scoring to enrich security findings with real-world threat context.
package threat

import (
	"context"
	"sync"
	"time"
)

// CVE represents a Common Vulnerability and Exposure.
type CVE struct {
	// ID is the CVE identifier (e.g., CVE-2024-1234).
	ID string `json:"id"`

	// Severity is the CVSS severity (critical, high, medium, low).
	Severity string `json:"severity"`

	// CVSSScore is the CVSS v3.1 base score (0.0-10.0).
	CVSSScore float64 `json:"cvss_score"`

	// EPSSScore is the Exploit Prediction Scoring System score (0.0-1.0).
	// Higher = more likely to be exploited in the wild.
	EPSSScore float64 `json:"epss_score"`

	// Description is the vulnerability description.
	Description string `json:"description"`

	// AffectedPackage is the vulnerable package name.
	AffectedPackage string `json:"affected_package"`

	// FixedVersion is the version that fixes the vulnerability (empty if no fix).
	FixedVersion string `json:"fixed_version,omitempty"`

	// PublishedAt is when the CVE was published.
	PublishedAt time.Time `json:"published_at"`

	// ExploitAvailable indicates if a public exploit exists.
	ExploitAvailable bool `json:"exploit_available"`

	// References are URLs to advisories, patches, and exploits.
	References []string `json:"references,omitempty"`
}

// ImageThreat associates a container image with known threats.
type ImageThreat struct {
	// Image is the container image reference (registry/repo:tag or @sha256:...).
	Image string `json:"image"`

	// CVEs are known vulnerabilities in this image.
	CVEs []CVE `json:"cves"`

	// KnownMalicious indicates the image is from a known-bad registry or is flagged.
	KnownMalicious bool `json:"known_malicious"`

	// LastScanned is when this image was last checked.
	LastScanned time.Time `json:"last_scanned"`

	// RiskScore is an aggregate risk score (0-100).
	RiskScore int `json:"risk_score"`
}

// Feed is the interface for threat intelligence feeds.
type Feed interface {
	// Name returns the feed identifier.
	Name() string

	// Refresh updates the feed data.
	Refresh(ctx context.Context) error

	// LookupImage checks if an image has known threats.
	LookupImage(ctx context.Context, image string) (*ImageThreat, error)

	// LookupCVE returns details for a specific CVE.
	LookupCVE(ctx context.Context, cveID string) (*CVE, error)
}

// Aggregator combines multiple threat feeds into a unified view.
type Aggregator struct {
	mu    sync.RWMutex
	feeds []Feed
	cache map[string]*ImageThreat
	ttl   time.Duration
}

// NewAggregator creates a new threat aggregator.
func NewAggregator(feeds []Feed, cacheTTL time.Duration) *Aggregator {
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}
	return &Aggregator{
		feeds: feeds,
		cache: make(map[string]*ImageThreat),
		ttl:   cacheTTL,
	}
}

// LookupImage queries all feeds for threats related to an image.
func (a *Aggregator) LookupImage(ctx context.Context, image string) (*ImageThreat, error) {
	// Check cache first.
	a.mu.RLock()
	if cached, ok := a.cache[image]; ok && time.Since(cached.LastScanned) < a.ttl {
		a.mu.RUnlock()
		return cached, nil
	}
	a.mu.RUnlock()

	// Query all feeds.
	merged := &ImageThreat{
		Image:       image,
		LastScanned: time.Now(),
	}

	for _, feed := range a.feeds {
		threat, err := feed.LookupImage(ctx, image)
		if err != nil {
			continue // Best-effort: skip failing feeds.
		}
		if threat == nil {
			continue
		}
		merged.CVEs = append(merged.CVEs, threat.CVEs...)
		if threat.KnownMalicious {
			merged.KnownMalicious = true
		}
	}

	merged.RiskScore = calculateRiskScore(merged)

	// Update cache.
	a.mu.Lock()
	a.cache[image] = merged
	a.mu.Unlock()

	return merged, nil
}

// RefreshAll refreshes all feeds.
func (a *Aggregator) RefreshAll(ctx context.Context) error {
	for _, feed := range a.feeds {
		if err := feed.Refresh(ctx); err != nil {
			return err
		}
	}
	return nil
}

func calculateRiskScore(threat *ImageThreat) int {
	if threat.KnownMalicious {
		return 100
	}

	score := 0
	for i := range threat.CVEs {
		cve := threat.CVEs[i]
		// Weight by CVSS score.
		cveScore := int(cve.CVSSScore * 5)

		// Boost if exploit is available.
		if cve.ExploitAvailable {
			cveScore += 20
		}

		// Boost by EPSS score.
		cveScore += int(cve.EPSSScore * 30)

		if cveScore > score {
			score = cveScore
		}
	}

	if score > 100 {
		score = 100
	}
	return score
}
