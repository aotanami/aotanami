/*
Copyright 2026 Zelyo AI

dashboard-demo is a standalone binary that runs the Zelyo Operator dashboard
against an in-memory fake Kubernetes client and drives the Pipeline view with
the synthetic event generator. It exists purely for local UX iteration and
investor demos — it does not scan anything, does not talk to a real cluster,
and must never be deployed to production.

Usage:

	go run ./cmd/dashboard-demo
	# open http://localhost:8080/#pipeline
*/
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/dashboard"
	"github.com/zelyo-ai/zelyo-operator/internal/events"
)

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	log := ctrl.Log.WithName("dashboard-demo")

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(zelyov1alpha1.AddToScheme(scheme))

	demoObjs := DemoObjects()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(demoObjs...).Build()
	log.Info("Seeded demo fake client", "objects", len(demoObjs))

	port := 8080
	if v := os.Getenv("ZELYO_OPERATOR_DASHBOARD_PORT"); v != "" {
		var p int
		if _, err := fmt.Sscanf(v, "%d", &p); err == nil && p > 0 {
			port = p
		}
	}

	srv := dashboard.NewServer(&dashboard.Config{
		Port:     port,
		BasePath: "/",
		Enabled:  true,
	}, fakeClient, log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Demo-only: synthesize pipeline events on the shared bus.
	go events.RunDemoSynthesizer(ctx)

	log.Info("Dashboard demo running",
		"url", fmt.Sprintf("http://localhost:%d/#pipeline", port),
		"mode", "standalone (fake client, synthetic events only)")

	if err := srv.Start(ctx); err != nil {
		log.Error(err, "dashboard server exited")
		cancel()
		os.Exit(1) //nolint:gocritic // orderly exit after explicit cancel.
	}
}
