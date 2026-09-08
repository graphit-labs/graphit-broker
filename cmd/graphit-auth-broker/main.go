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
	"strings"
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
	hashPassword := flag.Bool("hash-password", false, "read a password securely from the terminal and print a peppered Argon2id PHC verifier")
	hashPasswordStdin := flag.Bool("hash-password-stdin", false, "read a password from standard input and print a peppered Argon2id PHC verifier")
	passwordPepperEnv := flag.String("password-pepper-env", "", "environment variable containing the password pepper (required with password hashing)")
	flag.Parse()
	if *hashPassword && *hashPasswordStdin {
		fmt.Fprintln(os.Stderr, "choose either --hash-password or --hash-password-stdin")
		os.Exit(2)
	}
	if *hashPassword || *hashPasswordStdin {
		if flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "password hashing does not accept password arguments")
			os.Exit(2)
		}
		pepper, err := passwordPepperFromEnvironment(*passwordPepperEnv, os.LookupEnv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "password hashing failed:", err)
			os.Exit(1)
		}
		defer zeroBytes(pepper)
		if *hashPassword {
			err = hashPasswordFromTerminal(os.Stdin, os.Stderr, os.Stdout, pepper)
		} else {
			err = hashPasswordFromStdin(os.Stdin, os.Stdout, pepper)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "password hashing failed:", err)
			os.Exit(1)
		}
		return
	}
	if *passwordPepperEnv != "" {
		fmt.Fprintln(os.Stderr, "--password-pepper-env requires --hash-password or --hash-password-stdin")
		os.Exit(2)
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

func hashPasswordFromStdin(input io.Reader, output io.Writer, pepper []byte) error {
	const maximumInputBytes = 4096
	password, err := io.ReadAll(io.LimitReader(input, maximumInputBytes+2))
	if err != nil {
		return fmt.Errorf("read password from standard input: %w", err)
	}
	defer zeroBytes(password)
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
		if len(password) > 0 && password[len(password)-1] == '\r' {
			password = password[:len(password)-1]
		}
	}
	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}
	if len(password) > maximumInputBytes {
		return fmt.Errorf("password must not exceed %d bytes", maximumInputBytes)
	}
	hash, err := broker.HashPassword(password, pepper)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, hash)
	return err
}

func hashPasswordFromTerminal(input *os.File, prompt, output io.Writer, pepper []byte) error {
	fd := int(input.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("interactive mode requires a terminal; use --hash-password-stdin for automation")
	}
	_, _ = fmt.Fprint(prompt, "Password: ")
	password, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(prompt)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	defer zeroBytes(password)
	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}
	_, _ = fmt.Fprint(prompt, "Confirm password: ")
	confirmation, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(prompt)
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	defer zeroBytes(confirmation)
	if !bytes.Equal(password, confirmation) {
		return errors.New("password confirmation does not match")
	}
	hash, err := broker.HashPassword(password, pepper)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, hash)
	return err
}

func passwordPepperFromEnvironment(name string, lookup func(string) (string, bool)) ([]byte, error) {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return nil, errors.New("--password-pepper-env must name an environment variable")
	}
	value, found := lookup(name)
	if !found || value == "" {
		return nil, fmt.Errorf("password pepper environment variable %q is not set or is empty", name)
	}
	pepper := []byte(value)
	if len(pepper) < 32 {
		zeroBytes(pepper)
		return nil, fmt.Errorf("password pepper environment variable %q must contain at least 32 bytes", name)
	}
	return pepper, nil
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
