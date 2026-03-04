/*
Copyright 2026 Zelyo AI.
*/

// Package multicluster provides multi-cluster federation for Aotanami.
// It enables aggregating security posture, scan results, and incidents
// across multiple Kubernetes clusters into a unified view.
package multicluster

import (
	"context"
	"sync"
	"time"
)

// ClusterInfo represents a registered Kubernetes cluster.
type ClusterInfo struct {
	// Name is the cluster's display name.
	Name string `json:"name"`

	// ID is a unique identifier for the cluster.
	ID string `json:"id"`

	// APIEndpoint is the cluster's API server URL.
	APIEndpoint string `json:"api_endpoint"`

	// Region is the cloud region or datacenter.
	Region string `json:"region,omitempty"`

	// Provider is the cloud provider (aws, gcp, azure, on-prem).
	Provider string `json:"provider,omitempty"`

	// Status is the cluster's health status.
	Status ClusterStatus `json:"status"`

	// LastHeartbeat is the last time the cluster reported in.
	LastHeartbeat time.Time `json:"last_heartbeat"`

	// SecurityScore is the cluster's overall security score.
	SecurityScore int `json:"security_score"`

	// ViolationCount is total violations across the cluster.
	ViolationCount int `json:"violation_count"`

	// NodeCount is the number of nodes in the cluster.
	NodeCount int `json:"node_count"`

	// PodCount is the number of running pods.
	PodCount int `json:"pod_count"`
}

// ClusterStatus indicates the cluster's health.
type ClusterStatus string

// Enumeration values.
const (
	ClusterStatusHealthy      ClusterStatus = "healthy"
	ClusterStatusDegraded     ClusterStatus = "degraded"
	ClusterStatusUnreachable  ClusterStatus = "unreachable"
	ClusterStatusUnregistered ClusterStatus = "unregistered"
)

// AggregatedView is the multi-cluster security overview.
type AggregatedView struct {
	// Clusters is the list of all registered clusters.
	Clusters []ClusterInfo `json:"clusters"`

	// TotalClusters is the number of registered clusters.
	TotalClusters int `json:"total_clusters"`

	// HealthyClusters is the number of reachable and healthy clusters.
	HealthyClusters int `json:"healthy_clusters"`

	// TotalViolations is aggregate violations across all clusters.
	TotalViolations int `json:"total_violations"`

	// AverageSecurityScore is the weighted average security score.
	AverageSecurityScore float64 `json:"average_security_score"`

	// UpdatedAt is when the view was last computed.
	UpdatedAt time.Time `json:"updated_at"`
}

// Manager handles multi-cluster registration and aggregation.
type Manager struct {
	mu       sync.RWMutex
	clusters map[string]*ClusterInfo
}

// NewManager creates a new multi-cluster manager.
func NewManager() *Manager {
	return &Manager{
		clusters: make(map[string]*ClusterInfo),
	}
}

// Register adds or updates a cluster in the federation.
func (m *Manager) Register(_ context.Context, cluster *ClusterInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cluster.LastHeartbeat = time.Now()
	if cluster.Status == "" {
		cluster.Status = ClusterStatusHealthy
	}
	m.clusters[cluster.ID] = cluster
}

// Heartbeat updates the last-seen time for a cluster.
func (m *Manager) Heartbeat(clusterID string, score, violations int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.clusters[clusterID]; ok {
		c.LastHeartbeat = time.Now()
		c.SecurityScore = score
		c.ViolationCount = violations
		c.Status = ClusterStatusHealthy
	}
}

// GetAggregatedView returns the multi-cluster overview.
func (m *Manager) GetAggregatedView() AggregatedView {
	m.mu.RLock()
	defer m.mu.RUnlock()

	view := AggregatedView{
		Clusters:  make([]ClusterInfo, 0, len(m.clusters)),
		UpdatedAt: time.Now(),
	}

	totalScore := 0.0
	for _, c := range m.clusters {
		// Mark clusters as unreachable if no heartbeat in 5 minutes.
		info := *c
		if time.Since(c.LastHeartbeat) > 5*time.Minute {
			info.Status = ClusterStatusUnreachable
		}

		view.Clusters = append(view.Clusters, info)
		view.TotalClusters++
		view.TotalViolations += info.ViolationCount
		totalScore += float64(info.SecurityScore)

		if info.Status == ClusterStatusHealthy {
			view.HealthyClusters++
		}
	}

	if view.TotalClusters > 0 {
		view.AverageSecurityScore = totalScore / float64(view.TotalClusters)
	}

	return view
}

// Deregister removes a cluster from the federation.
func (m *Manager) Deregister(clusterID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clusters, clusterID)
}
