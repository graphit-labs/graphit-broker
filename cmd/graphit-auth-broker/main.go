package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/graphit-labs/graphit-broker/internal/broker"
)

var version = "dev"

func main() {
	configPath := flag.String("config", firstNonEmpty(os.Getenv("GRAPHIT_BROKER_CONFIG"), "/etc/graphit-broker/config.yaml"), "configuration YAML file")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	setupModels := flag.Bool("setup-models", false, "download and verify selected local model artifacts, then exit")
	healthcheck := flag.String("healthcheck", "", "GET a health endpoint and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	slog.SetDefault(logger)
	if err := broker.PrepareEmbeddedONNXRuntime(); err != nil {
		logger.Error("embedded ONNX Runtime preparation failed", "error", err)
		os.Exit(1)
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, version)
		return
	}

	if *healthcheck != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, *healthcheck, nil)
		if err == nil {
			resp, requestErr := http.DefaultClient.Do(req)
			err = requestErr
			if resp != nil {
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = errors.New(resp.Status)
				}
			}
		}
		if err != nil {
			logger.Error("healthcheck failed", "error", err)
			os.Exit(1)
		}
		return
	}
	cfg, err := broker.LoadConfig(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	if *check {
		logger.Info("configuration is valid", "path", *configPath)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *setupModels {
		if err := broker.SetupModels(ctx, cfg); err != nil {
			logger.Error("model setup failed", "error", err)
			os.Exit(1)
		}
		logger.Info("selected local models are installed", "directory", cfg.Models.Directory)
		return
	}
	service, err := broker.NewServer(ctx, cfg)
	if err != nil {
		logger.Error("broker initialization failed", "error", err)
		os.Exit(1)
	}
	defer service.Close()
	server := service.HTTPServer()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening", "address", server.Addr)
		errCh <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		logger.Info("broker stopped")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("broker stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
