package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/graphit-labs/graphit-broker/internal/broker"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	configPath := flag.String("config", firstNonEmpty(os.Getenv("GRAPHIT_BROKER_CONFIG"), "/etc/graphit-broker/config.yaml"), "configuration YAML file")
	check := flag.Bool("check-config", false, "validate configuration and exit")
	setupModels := flag.Bool("setup-models", false, "download and verify selected local model artifacts, then exit")
	healthcheck := flag.String("healthcheck", "", "GET a health endpoint and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	bootstrapAdmin := flag.Bool("bootstrap-admin", false, "create the first local administrator using a password read securely from the terminal")
	bootstrapAdminStdin := flag.Bool("bootstrap-admin-stdin", false, "create the first local administrator using a password read from standard input")
	flag.Parse()
	if *bootstrapAdmin && *bootstrapAdminStdin {
		fmt.Fprintln(os.Stderr, "choose either --bootstrap-admin or --bootstrap-admin-stdin")
		os.Exit(2)
	}
	if *bootstrapAdmin || *bootstrapAdminStdin {
		if flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "administrator bootstrap does not accept arguments")
			os.Exit(2)
		}
		cfg, err := broker.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "administrator bootstrap failed:", err)
			os.Exit(1)
		}
		var password []byte
		if *bootstrapAdmin {
			password, err = passwordFromTerminal(os.Stdin, os.Stderr)
		} else {
			password, err = passwordFromStdin(os.Stdin)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "administrator bootstrap failed:", err)
			os.Exit(1)
		}
		defer zeroBytes(password)
		if err := bootstrapLocalAdmin(context.Background(), cfg, password); err != nil {
			fmt.Fprintln(os.Stderr, "administrator bootstrap failed:", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "local administrator created")
		return
	}
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

func passwordFromStdin(input io.Reader) ([]byte, error) {
	const maximumInputBytes = 4096
	password, err := io.ReadAll(io.LimitReader(input, maximumInputBytes+2))
	if err != nil {
		return nil, fmt.Errorf("read password from standard input: %w", err)
	}
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
		if len(password) > 0 && password[len(password)-1] == '\r' {
			password = password[:len(password)-1]
		}
	}
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(password) > maximumInputBytes {
		zeroBytes(password)
		return nil, fmt.Errorf("password must not exceed %d bytes", maximumInputBytes)
	}
	return password, nil
}

func passwordFromTerminal(input *os.File, prompt io.Writer) ([]byte, error) {
	fd := int(input.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("interactive mode requires a terminal; use --bootstrap-admin-stdin for automation")
	}
	_, _ = fmt.Fprint(prompt, "Password: ")
	password, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(prompt)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	_, _ = fmt.Fprint(prompt, "Confirm password: ")
	confirmation, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(prompt)
	if err != nil {
		zeroBytes(password)
		return nil, fmt.Errorf("read password confirmation: %w", err)
	}
	defer zeroBytes(confirmation)
	if !bytes.Equal(password, confirmation) {
		zeroBytes(password)
		return nil, errors.New("password confirmation does not match")
	}
	return password, nil
}

func bootstrapLocalAdmin(ctx context.Context, cfg broker.Config, password []byte) error {
	pepper := []byte(cfg.Authentication.TokenPepper)
	defer zeroBytes(pepper)
	hash, err := broker.HashPassword(password, pepper)
	if err != nil {
		return err
	}
	store, err := broker.OpenControlStore(cfg.Database, cfg.Authentication.TokenPepper)
	if err != nil {
		return err
	}
	defer store.Close()
	return store.BootstrapLocalAdmin(ctx, hash)
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
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
