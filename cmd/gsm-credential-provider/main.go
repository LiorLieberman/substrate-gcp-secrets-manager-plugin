// Command gsm-credential-provider is a substrate credential-provider plugin
// backed by Google Cloud Secret Manager. It serves substrate's
// CredentialProvider gRPC API, resolving ate-secret:// URIs of the
// secretmanager.googleapis.com provider to secret version payloads. The
// substrate egress gateway calls it when an install enables egress credential
// injection and points --credential-provider-address at it; it is the only
// component in that path with Secret Manager access.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"google.golang.org/grpc"

	"github.com/agent-substrate/substrate/pkg/proto/credproviderpb"

	"github.com/LiorLieberman/substrate-gcp-secrets-manager-plugin/internal/mtls"
	"github.com/LiorLieberman/substrate-gcp-secrets-manager-plugin/internal/provider"
)

// defaultInjectorIdentity is the SPIFFE ID substrate's egress gateway presents
// in a default install: the atenet-egress ServiceAccount in ate-system.
const defaultInjectorIdentity = "spiffe://cluster.local/ns/ate-system/sa/atenet-egress"

var (
	listenAddr       = flag.String("listen-address", ":50051", "gRPC listen address")
	healthAddr       = flag.String("health-address", ":9090", "HTTP listen address for /healthz and /readyz")
	serverBundle     = flag.String("server-cred-bundle", "", "credential bundle (PKCS#8 key and certificate chain) presented for serving TLS (required)")
	clientCAFile     = flag.String("client-ca-file", "", "trust bundle the caller's client certificate must chain to (required)")
	injectorIdentity = flag.String("injector-identity", defaultInjectorIdentity, "SPIFFE ID the caller's client certificate must carry; set it when substrate's egress gateway runs under another namespace or ServiceAccount")
	logLevel         = flag.String("log-level", "info", "one of debug, info, warn, error")
	drainGrace       = flag.Duration("drain-grace", 5*time.Second, "how long to wait for in-flight RPCs on shutdown before a hard stop")
)

// version is the release version, set at build time with
// -ldflags "-X main.version=v0.1.0".
var version string

func main() {
	flag.Parse()

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --log-level %q: %v\n", *logLevel, err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	slog.Info("starting gsm-credential-provider", slog.String("version", buildVersion()))
	if err := run(context.Background()); err != nil {
		slog.Error("gsm-credential-provider exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if *serverBundle == "" {
		return errors.New("--server-cred-bundle is required")
	}
	if *clientCAFile == "" {
		return errors.New("--client-ca-file is required")
	}
	creds, err := mtls.ServerCredentials(mtls.Config{
		ServerBundle:   *serverBundle,
		ClientCAFile:   *clientCAFile,
		CallerIdentity: *injectorIdentity,
	})
	if err != nil {
		return fmt.Errorf("server credentials: %w", err)
	}
	slog.Info("admitting callers", slog.String("client_ca", *clientCAFile), slog.String("required_san", *injectorIdentity))

	// Application Default Credentials: on GKE, Workload Identity Federation
	// for the pod's ServiceAccount is what grants Secret Manager access. The
	// client dials lazily, so a missing IAM grant surfaces on the first
	// FetchSecret as PermissionDenied rather than here.
	smClient, err := secretmanager.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("secret manager client: %w", err)
	}
	defer smClient.Close()

	srv := grpc.NewServer(grpc.Creds(creds))
	credproviderpb.RegisterCredentialProviderServer(srv, provider.NewServer(smClient))

	grpcLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddr, err)
	}
	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *healthAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *healthAddr, err)
	}
	var ready atomic.Bool
	healthSrv := &http.Server{Handler: healthHandler(&ready), ReadHeaderTimeout: 10 * time.Second}
	healthDone := make(chan error, 1)
	go func() { healthDone <- healthSrv.Serve(healthLis) }()

	shutdownCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		var err error
		select {
		case <-shutdownCtx.Done():
			slog.Info("shutting down")
		case err = <-healthDone:
			err = fmt.Errorf("health server: %w", err)
		}
		ready.Store(false)
		gracefulStop(srv, *drainGrace)
		_ = healthSrv.Close()
		shutdownErr <- err
	}()

	ready.Store(true)
	slog.Info("gsm-credential-provider listening", slog.String("address", grpcLis.Addr().String()), slog.String("health_address", healthLis.Addr().String()))
	if err := srv.Serve(grpcLis); err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	return <-shutdownErr
}

// gracefulStop lets in-flight RPCs finish for up to grace, then forces the
// server down.
func gracefulStop(srv *grpc.Server, grace time.Duration) {
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(grace):
		slog.Warn("graceful shutdown timed out; forcing stop", slog.Duration("grace", grace))
		srv.Stop()
	}
}

// healthHandler serves /healthz, which always succeeds so the liveness probe
// keeps passing while the server drains, and /readyz, which succeeds only
// while ready is set.
func healthHandler(ready *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// buildVersion describes the running binary: the release version when one was
// set or the module was installed at a tagged version, and the VCS revision
// when the build recorded one.
func buildVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if v == "" {
			return "dev"
		}
		return v
	}
	if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v = info.Main.Version
	}
	if v == "" {
		v = "dev"
	}
	var revision, modified string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision == "" {
		return v
	}
	if modified == "true" {
		revision += "-dirty"
	}
	return v + " commit=" + revision
}
