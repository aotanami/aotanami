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

package cloudscanner

import (
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/cicd"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/ciem"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/cspm"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/dspm"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/network"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/supplychain"
)

// DefaultRegistry returns a new Registry pre-loaded with all 48 built-in cloud scanners.
func DefaultRegistry() *Registry {
	r := NewRegistry()

	// ── CSPM: Cloud Security Posture Management (8 checks) ──
	r.Register(&cspm.PublicS3Scanner{})
	r.Register(&cspm.UnencryptedEBSScanner{})
	r.Register(&cspm.CloudTrailDisabledScanner{})
	r.Register(&cspm.RDSEncryptionScanner{})
	r.Register(&cspm.KMSRotationScanner{})
	r.Register(&cspm.VPCFlowLogsScanner{})
	r.Register(&cspm.S3VersioningScanner{})
	r.Register(&cspm.SecretsRotationScanner{})

	// ── CIEM: Cloud Identity & Entitlement Management (8 checks) ──
	r.Register(&ciem.OverprivilegedIAMScanner{})
	r.Register(&ciem.UnusedAccessKeysScanner{})
	r.Register(&ciem.RootAccessKeysScanner{})
	r.Register(&ciem.WildcardPermissionsScanner{})
	r.Register(&ciem.CrossAccountTrustScanner{})
	r.Register(&ciem.InactiveUsersScanner{})
	r.Register(&ciem.MFANotEnforcedScanner{})
	r.Register(&ciem.LongLivedKeysScanner{})

	// ── Network Security (8 checks) ──
	r.Register(&network.SSHOpenScanner{})
	r.Register(&network.RDPOpenScanner{})
	r.Register(&network.DBPortsExposedScanner{})
	r.Register(&network.NoNACLsScanner{})
	r.Register(&network.UnrestrictedPeeringScanner{})
	r.Register(&network.ALBNotHTTPSScanner{})
	r.Register(&network.DefaultSGTrafficScanner{})
	r.Register(&network.UnrestrictedEgressScanner{})

	// ── DSPM: Data Security Posture Management (8 checks) ──
	r.Register(&dspm.S3PublicACLsScanner{})
	r.Register(&dspm.S3NoEncryptionScanner{})
	r.Register(&dspm.DynamoDBEncryptionScanner{})
	r.Register(&dspm.RDSPublicScanner{})
	r.Register(&dspm.EBSSnapshotsPublicScanner{})
	r.Register(&dspm.CloudWatchUnencryptedScanner{})
	r.Register(&dspm.S3ObjectLockScanner{})
	r.Register(&dspm.NoDataTagsScanner{})

	// ── Supply Chain Security (8 checks) ──
	r.Register(&supplychain.ECRCriticalCVEsScanner{})
	r.Register(&supplychain.ECRScanOnPushScanner{})
	r.Register(&supplychain.StaleImagesScanner{})
	r.Register(&supplychain.HardcodedSecretsEnvScanner{})
	r.Register(&supplychain.UnsignedImagesScanner{})
	r.Register(&supplychain.ThirdPartyCVEsScanner{})
	r.Register(&supplychain.NoSBOMScanner{})
	r.Register(&supplychain.ImagesNotScannedScanner{})

	// ── CI/CD Pipeline Security (8 checks) ──
	r.Register(&cicd.HardcodedSecretsRepoScanner{})
	r.Register(&cicd.UnencryptedArtifactsScanner{})
	r.Register(&cicd.SecretsPlaintextEnvScanner{})
	r.Register(&cicd.NoManualApprovalScanner{})
	r.Register(&cicd.OverprivilegedCodeBuildScanner{})
	r.Register(&cicd.UnmanagedBuildImagesScanner{})
	r.Register(&cicd.ArtifactRepoNoEncryptionScanner{})
	r.Register(&cicd.NoAuditLoggingScanner{})

	return r
}
