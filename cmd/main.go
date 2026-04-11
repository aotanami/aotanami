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

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"strconv"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/anomaly"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner"
	"github.com/zelyo-ai/zelyo-operator/internal/controller"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	"github.com/zelyo-ai/zelyo-operator/internal/dashboard"
	gitopscontroller "github.com/zelyo-ai/zelyo-operator/internal/gitops/controller"
	"github.com/zelyo-ai/zelyo-operator/internal/gitops/source"
	_ "github.com/zelyo-ai/zelyo-operator/internal/metrics" // Auto-register custom Prometheus metrics.
	"github.com/zelyo-ai/zelyo-operator/internal/remediation"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
	"github.com/zelyo-ai/zelyo-operator/internal/version"
	webhookv1alpha1 "github.com/zelyo-ai/zelyo-operator/internal/webhook/v1alpha1"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(zelyov1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

//nolint:gocyclo
func main() {
	var metricsAddr string
	var metricsCertPath, metricsCertName, metricsCertKey string
	var webhookCertPath, webhookCertName, webhookCertKey string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Log version information on startup.
	setupLog.Info("Starting Zelyo Operator",
		"version", version.Version,
		"commit", version.Commit,
		"buildDate", version.Date)

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("Disabling HTTP/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	// Initial webhook TLS options
	webhookTLSOpts := tlsOpts
	webhookServerOptions := webhook.Options{
		TLSOpts: webhookTLSOpts,
	}

	if len(webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName, "webhook-cert-key", webhookCertKey)

		webhookServerOptions.CertDir = webhookCertPath
		webhookServerOptions.CertName = webhookCertName
		webhookServerOptions.KeyName = webhookCertKey
	}

	webhookServer := webhook.NewServer(webhookServerOptions)

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	// If the certificate is not specified, controller-runtime will automatically
	// generate self-signed certificates for the metrics server. While convenient for development and testing,
	// this setup is not recommended for production.
	if len(metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName, "metrics-cert-key", metricsCertKey)

		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "zelyo.ai",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// Initialize the scanner registry with all built-in K8s scanners.
	scannerRegistry := scanner.DefaultRegistry()
	setupLog.Info("Scanner registry initialized", "registeredScanners", scannerRegistry.List())

	// Initialize the cloud scanner registry with all 48 cloud security checks.
	cloudScannerRegistry := cloudscanner.DefaultRegistry()
	setupLog.Info("Cloud scanner registry initialized",
		"registeredCloudScanners", cloudScannerRegistry.Count())

	// ── Initialize the Agentic Pipeline (shared brain instances) ──
	//
	// These are the core intelligence components that connect
	// Detect (SecurityPolicy/MonitoringPolicy) → Correlate (Correlator/LLM) → Fix (Remediation)
	correlatorEngine := correlator.NewEngine(&correlator.Config{
		CorrelationWindow: 5 * time.Minute,
	})
	anomalyDetector := anomaly.NewDetector(anomaly.DefaultConfig())
	// Remediation engine starts in dry-run mode for safety. Configurable via ZelyoConfig.
	remediationEngine := remediation.NewEngine(
		nil, // LLM client — injected when ZelyoConfig is reconciled.
		nil, // GitOps engine — injected when GitHub App is configured.
		remediation.EngineConfig{
			Strategy:       remediation.StrategyDryRun,
			MaxBlastRadius: 10,
		},
		ctrl.Log.WithName("remediation"),
	)
	setupLog.Info("Agentic pipeline initialized",
		"correlatorWindow", "5m",
		"anomalySensitivity", anomaly.DefaultConfig().Sensitivity,
		"remediationStrategy", "dry-run")

	if err := (&controller.SecurityPolicyReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		Recorder:         mgr.GetEventRecorderFor("securitypolicy-controller"), //nolint:staticcheck,nolintlint
		ScannerRegistry:  scannerRegistry,
		CorrelatorEngine: correlatorEngine,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "SecurityPolicy")
		os.Exit(1)
	}
	if err := (&controller.RemediationPolicyReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Recorder:          mgr.GetEventRecorderFor("remediationpolicy-controller"), //nolint:staticcheck,nolintlint
		CorrelatorEngine:  correlatorEngine,
		RemediationEngine: remediationEngine,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "RemediationPolicy")
		os.Exit(1)
	}
	if err := (&controller.ClusterScanReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Recorder:        mgr.GetEventRecorderFor("clusterscan-controller"), //nolint:staticcheck,nolintlint
		ScannerRegistry: scannerRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "ClusterScan")
		os.Exit(1)
	}
	if err := (&controller.ScanReportReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("scanreport-controller"), //nolint:staticcheck,nolintlint
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "ScanReport")
		os.Exit(1)
	}
	if err := (&controller.CostPolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("costpolicy-controller"), //nolint:staticcheck,nolintlint
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "CostPolicy")
		os.Exit(1)
	}
	if err := (&controller.MonitoringPolicyReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		Recorder:         mgr.GetEventRecorderFor("monitoringpolicy-controller"), //nolint:staticcheck,nolintlint
		AnomalyDetector:  anomalyDetector,
		CorrelatorEngine: correlatorEngine,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "MonitoringPolicy")
		os.Exit(1)
	}
	if err := (&controller.NotificationChannelReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("notificationchannel-controller"), //nolint:staticcheck,nolintlint
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "NotificationChannel")
		os.Exit(1)
	}
	if err := (&controller.ZelyoConfigReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Recorder:          mgr.GetEventRecorderFor("zelyoconfig-controller"), //nolint:staticcheck,nolintlint
		RemediationEngine: remediationEngine,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "ZelyoConfig")
		os.Exit(1)
	}
	if err := (&controller.CloudAccountConfigReconciler{
		Client:               mgr.GetClient(),
		Scheme:               mgr.GetScheme(),
		Recorder:             mgr.GetEventRecorderFor("cloudaccountconfig-controller"), //nolint:staticcheck,nolintlint
		CloudScannerRegistry: cloudScannerRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "CloudAccountConfig")
		os.Exit(1)
	}
	if err := (&controller.GitOpsRepositoryReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Recorder:           mgr.GetEventRecorderFor("gitopsrepository-controller"), //nolint:staticcheck,nolintlint
		SourceRegistry:     source.DefaultRegistry(),
		ControllerRegistry: gitopscontroller.DefaultRegistry(mgr.GetClient()),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "Failed to create controller", "controller", "GitOpsRepository")
		os.Exit(1)
	}

	if os.Getenv("ENABLE_WEBHOOKS") != "false" {
		if err := webhookv1alpha1.SetupSecurityPolicyWebhookWithManager(mgr); err != nil {
			setupLog.Error(err, "Failed to create webhook", "webhook", "SecurityPolicy")
			os.Exit(1)
		}
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up health check")
		os.Exit(1)
	}
	// ── Dashboard Server ──
	if os.Getenv("ZELYO_OPERATOR_DASHBOARD_ENABLED") != "false" {
		dashPort := 8080
		if p, err := strconv.Atoi(os.Getenv("ZELYO_OPERATOR_DASHBOARD_PORT")); err == nil && p > 0 {
			dashPort = p
		}
		dashBasePath := os.Getenv("ZELYO_OPERATOR_DASHBOARD_BASE_PATH")
		if dashBasePath == "" {
			dashBasePath = "/"
		}
		dashSrv := dashboard.NewServer(&dashboard.Config{
			Port:     dashPort,
			BasePath: dashBasePath,
			Enabled:  true,
		}, ctrl.Log.WithName("dashboard"))
		if err := mgr.Add(dashSrv); err != nil {
			setupLog.Error(err, "Failed to add dashboard server to manager")
			os.Exit(1)
		}
		setupLog.Info("Dashboard server registered", "port", dashPort, "basePath", dashBasePath)
	}

	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
