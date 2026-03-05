/*
Copyright 2026 Zelyo AI
*/

// Package supplychain provides supply chain security verification for container
// images. It checks SBOM presence, signature verification (Cosign/Notation),
// and SLSA provenance attestations.
package supplychain

import (
	"context"
	"time"
)

// VerificationResult describes the supply chain verification of a container image.
type VerificationResult struct {
	// Image is the container image reference.
	Image string `json:"image"`

	// SignatureVerified indicates Cosign/Notation signature is valid.
	SignatureVerified bool `json:"signature_verified"`

	// SignatureIssuer is the OIDC issuer for keyless signing.
	SignatureIssuer string `json:"signature_issuer,omitempty"`

	// SBOMPresent indicates an SBOM attestation exists.
	SBOMPresent bool `json:"sbom_present"`

	// SBOMFormat is the SBOM format (spdx, cyclonedx).
	SBOMFormat string `json:"sbom_format,omitempty"`

	// SBOMPackageCount is the number of packages in the SBOM.
	SBOMPackageCount int `json:"sbom_package_count,omitempty"`

	// ProvenancePresent indicates a SLSA provenance attestation exists.
	ProvenancePresent bool `json:"provenance_present"`

	// ProvenanceLevel is the SLSA level (1-4).
	ProvenanceLevel int `json:"provenance_level,omitempty"`

	// BuilderID identifies the CI/CD system that built the image.
	BuilderID string `json:"builder_id,omitempty"`

	// SourceRepo is the source repository (from provenance).
	SourceRepo string `json:"source_repo,omitempty"`

	// VerifiedAt is when the verification was performed.
	VerifiedAt time.Time `json:"verified_at"`

	// TrustScore is an aggregate trust score (0-100).
	TrustScore int `json:"trust_score"`

	// Errors collects any verification errors.
	Errors []string `json:"errors,omitempty"`
}

// Verifier is the interface for supply chain verification.
type Verifier interface {
	// VerifyImage performs all supply chain checks on a container image.
	VerifyImage(ctx context.Context, image string) (*VerificationResult, error)

	// VerifySignature checks the image signature using Cosign/Notation.
	VerifySignature(ctx context.Context, image string) (bool, string, error)

	// VerifySBOM checks for an SBOM attestation.
	VerifySBOM(ctx context.Context, image string) (bool, string, int, error)

	// VerifyProvenance checks for SLSA provenance.
	VerifyProvenance(ctx context.Context, image string) (bool, int, string, error)
}

// Config configures the supply chain verifier.
type Config struct {
	// CosignPublicKey is the public key for Cosign verification (PEM).
	// If empty, keyless verification is attempted.
	CosignPublicKey string `json:"cosign_public_key,omitempty"`

	// AllowedIssuers restricts which OIDC issuers are trusted for keyless signing.
	AllowedIssuers []string `json:"allowed_issuers,omitempty"`

	// RequireSignature fails verification if no valid signature exists.
	RequireSignature bool `json:"require_signature"`

	// RequireSBOM fails verification if no SBOM attestation exists.
	RequireSBOM bool `json:"require_sbom"`

	// RequireProvenance fails verification if no SLSA provenance exists.
	RequireProvenance bool `json:"require_provenance"`

	// MinProvenanceLevel is the minimum SLSA level required.
	MinProvenanceLevel int `json:"min_provenance_level"`
}

// CalculateTrustScore computes a trust score based on verification results.
func CalculateTrustScore(result *VerificationResult) int {
	score := 0

	// Signature: 40 points
	if result.SignatureVerified {
		score += 40
	}

	// SBOM: 30 points
	if result.SBOMPresent {
		score += 20
		if result.SBOMPackageCount > 0 {
			score += 10 // Full SBOM with package data.
		}
	}

	// Provenance: 30 points
	if result.ProvenancePresent {
		score += 15
		// Additional points for higher SLSA levels.
		switch {
		case result.ProvenanceLevel >= 3:
			score += 15
		case result.ProvenanceLevel >= 2:
			score += 10
		case result.ProvenanceLevel >= 1:
			score += 5
		}
	}

	return min(score, 100)
}

// PolicyCheck evaluates a verification result against a supply chain policy.
func PolicyCheck(result *VerificationResult, cfg Config) []string {
	var violations []string

	if cfg.RequireSignature && !result.SignatureVerified {
		violations = append(violations, "Image signature is missing or invalid")
	}

	if cfg.RequireSBOM && !result.SBOMPresent {
		violations = append(violations, "SBOM attestation is missing")
	}

	if cfg.RequireProvenance && !result.ProvenancePresent {
		violations = append(violations, "SLSA provenance attestation is missing")
	}

	if cfg.MinProvenanceLevel > 0 && result.ProvenanceLevel < cfg.MinProvenanceLevel {
		violations = append(violations, "SLSA provenance level is below minimum")
	}

	return violations
}
