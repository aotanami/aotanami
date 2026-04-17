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
	"fmt"
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
	"github.com/zelyo-ai/zelyo-operator/internal/events"
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

// cliFlags holds all command-line flag values parsed at startup.
type cliFlags struct {
	metricsAddr          string
	probeAddr            string
	enableLeaderElection bool
	secureMetrics        bool
	enableHTTP2          bool
	metricsCertPath      string
	metricsCertName      string
	metricsCertKey       string
	webhookCertPath      string
	webhookCertName      string
	webhookCertKey       string
}

// parseFlags registers all CLI flags and returns a pointer to the struct.
// The caller must call flag.Parse() before using the returned values.
func parseFlags() *cliFlags {
	f := &cliFlags{}
	flag.StringVar(&f.metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&f.probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&f.enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&f.secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.StringVar(&f.webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	flag.StringVar(&f.webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	flag.StringVar(&f.webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	flag.StringVar(&f.metricsCertPath, "metrics-cert-path", "",
		"The directory that contains the metrics server certificate.")
	flag.StringVar(&f.metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	flag.StringVar(&f.metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	flag.BoolVar(&f.enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	return f
}

// buildTLSOpts returns TLS configuration functions based on the HTTP/2 flag.
func buildTLSOpts(enableHTTP2 bool) []func(*tls.Config) {
	if enableHTTP2 {
		return nil
	}
	return []func(*tls.Config){
		func(c *tls.Config) {
			setupLog.Info("Disabling HTTP/2")
			c.NextProtos = []string{"http/1.1"}
		},
	}
}

// buildWebhookServer creates the webhook server with TLS configuration.
func buildWebhookServer(f *cliFlags, tlsOpts []func(*tls.Config)) webhook.Server {
	opts := webhook.Options{
		TLSOpts: tlsOpts,
	}
	if len(f.webhookCertPath) > 0 {
		setupLog.Info("Initializing webhook certificate watcher using provided certificates",
			"webhook-cert-path", f.webhookCertPath, "webhook-cert-name", f.webhookCertName, "webhook-cert-key", f.webhookCertKey)
		opts.CertDir = f.webhookCertPath
		opts.CertName = f.webhookCertName
		opts.KeyName = f.webhookCertKey
	}
	return webhook.NewServer(opts)
}

// buildMetricsServerOptions creates the metrics server options with TLS and auth.
func buildMetricsServerOptions(f *cliFlags, tlsOpts []func(*tls.Config)) metricsserver.Options {
	opts := metricsserver.Options{
		BindAddress:   f.metricsAddr,
		SecureServing: f.secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if f.secureMetrics {
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	if len(f.metricsCertPath) > 0 {
		setupLog.Info("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", f.metricsCertPath, "metrics-cert-name", f.metricsCertName, "metrics-cert-key", f.metricsCertKey)
		opts.CertDir = f.metricsCertPath
		opts.CertName = f.metricsCertName
		opts.KeyName = f.metricsCertKey
	}
	return opts
}

// controllerDeps holds shared dependencies injected into controllers.
type controllerDeps struct {
	scannerRegistry      *scanner.Registry
	cloudScannerRegistry *cloudscanner.Registry
	correlatorEngine     *correlator.Engine
	anomalyDetector      *anomaly.Detector
	remediationEngine    *remediation.Engine
}

// setupControllers registers all Zelyo controllers with the manager.
func setupControllers(mgr ctrl.Manager, deps *controllerDeps) error {
	controllers := []struct {
		name       string
		reconciler interface{ SetupWithManager(ctrl.Manager) error }
	}{
		{"SecurityPolicy", &controller.SecurityPolicyReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:         mgr.GetEventRecorderFor("securitypolicy-controller"), //nolint:staticcheck,nolintlint
			ScannerRegistry:  deps.scannerRegistry,
			CorrelatorEngine: deps.correlatorEngine,
		}},
		{"RemediationPolicy", &controller.RemediationPolicyReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:          mgr.GetEventRecorderFor("remediationpolicy-controller"), //nolint:staticcheck,nolintlint
			CorrelatorEngine:  deps.correlatorEngine,
			RemediationEngine: deps.remediationEngine,
		}},
		{"ClusterScan", &controller.ClusterScanReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:        mgr.GetEventRecorderFor("clusterscan-controller"), //nolint:staticcheck,nolintlint
			ScannerRegistry: deps.scannerRegistry,
		}},
		{"ScanReport", &controller.ScanReportReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("scanreport-controller"), //nolint:staticcheck,nolintlint
		}},
		{"CostPolicy", &controller.CostPolicyReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("costpolicy-controller"), //nolint:staticcheck,nolintlint
		}},
		{"MonitoringPolicy", &controller.MonitoringPolicyReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:         mgr.GetEventRecorderFor("monitoringpolicy-controller"), //nolint:staticcheck,nolintlint
			AnomalyDetector:  deps.anomalyDetector,
			CorrelatorEngine: deps.correlatorEngine,
		}},
		{"NotificationChannel", &controller.NotificationChannelReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder: mgr.GetEventRecorderFor("notificationchannel-controller"), //nolint:staticcheck,nolintlint
		}},
		{"ZelyoConfig", &controller.ZelyoConfigReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:          mgr.GetEventRecorderFor("zelyoconfig-controller"), //nolint:staticcheck,nolintlint
			RemediationEngine: deps.remediationEngine,
		}},
		{"CloudAccountConfig", &controller.CloudAccountConfigReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:             mgr.GetEventRecorderFor("cloudaccountconfig-controller"), //nolint:staticcheck,nolintlint
			CloudScannerRegistry: deps.cloudScannerRegistry,
		}},
		{"GitOpsRepository", &controller.GitOpsRepositoryReconciler{
			Client: mgr.GetClient(), Scheme: mgr.GetScheme(),
			Recorder:           mgr.GetEventRecorderFor("gitopsrepository-controller"), //nolint:staticcheck,nolintlint
			SourceRegistry:     source.DefaultRegistry(),
			ControllerRegistry: gitopscontroller.DefaultRegistry(mgr.GetClient()),
		}},
	}

	for _, c := range controllers {
		if err := c.reconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("creating %s controller: %w", c.name, err)
		}
	}
	return nil
}

// startDashboard registers the dashboard HTTP server with the manager if enabled.
func startDashboard(mgr ctrl.Manager) (*dashboard.Server, error) {
	if os.Getenv("ZELYO_OPERATOR_DASHBOARD_ENABLED") == "false" {
		return nil, nil
	}
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
	}, mgr.GetClient(), ctrl.Log.WithName("dashboard"))
	if err := mgr.Add(dashSrv); err != nil {
		return nil, fmt.Errorf("adding dashboard server to manager: %w", err)
	}
	setupLog.Info("Dashboard server registered", "port", dashPort, "basePath", dashBasePath)
	return dashSrv, nil
}

func main() {
	f := parseFlags()
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	setupLog.Info("Starting Zelyo Operator",
		"version", version.Version, "commit", version.Commit, "buildDate", version.Date)

	tlsOpts := buildTLSOpts(f.enableHTTP2)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                buildMetricsServerOptions(f, tlsOpts),
		WebhookServer:          buildWebhookServer(f, tlsOpts),
		HealthProbeBindAddress: f.probeAddr,
		LeaderElection:         f.enableLeaderElection,
		LeaderElectionID:       "zelyo.ai",
	})
	if err != nil {
		setupLog.Error(err, "Failed to start manager")
		os.Exit(1)
	}

	// Initialize scanner registries.
	scannerRegistry := scanner.DefaultRegistry()
	setupLog.Info("Scanner registry initialized", "registeredScanners", scannerRegistry.List())
	cloudScannerRegistry := cloudscanner.DefaultRegistry()
	setupLog.Info("Cloud scanner registry initialized", "registeredCloudScanners", cloudScannerRegistry.Count())

	// Initialize the Agentic Pipeline.
	correlatorEngine := correlator.NewEngine(&correlator.Config{CorrelationWindow: 5 * time.Minute})
	anomalyDetector := anomaly.NewDetector(anomaly.DefaultConfig())
	remediationEngine := remediation.NewEngine(nil, nil,
		remediation.EngineConfig{Strategy: remediation.StrategyDryRun, MaxBlastRadius: 10},
		ctrl.Log.WithName("remediation"))
	setupLog.Info("Agentic pipeline initialized",
		"correlatorWindow", "5m",
		"anomalySensitivity", anomaly.DefaultConfig().Sensitivity,
		"remediationStrategy", "dry-run")

	if err := setupControllers(mgr, &controllerDeps{
		scannerRegistry:      scannerRegistry,
		cloudScannerRegistry: cloudScannerRegistry,
		correlatorEngine:     correlatorEngine,
		anomalyDetector:      anomalyDetector,
		remediationEngine:    remediationEngine,
	}); err != nil {
		setupLog.Error(err, "Failed to set up controllers")
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
	if _, err := startDashboard(mgr); err != nil {
		setupLog.Error(err, "Failed to start dashboard")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "Failed to set up ready check")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	// Demo mode: synthesize a realistic Scan→Correlate→Fix→Verify stream on
	// the pipeline event bus so the dashboard Pipeline view is never empty.
	// Real controller events interleave with these on the same bus.
	if os.Getenv("ZELYO_DEMO_MODE") == "true" {
		setupLog.Info("ZELYO_DEMO_MODE=true — starting synthetic pipeline event generator")
		go events.RunDemoSynthesizer(ctx)
	}

	setupLog.Info("Starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "Failed to run manager")
		os.Exit(1)
	}
}
