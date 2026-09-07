package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestEnsureModelArtifactDownloadsOnceConcurrentlyAndCommitsVerifiedFile(t *testing.T) {
	content := []byte("verified model fixture")
	digest := sha256.Sum256(content)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(content)
	}))
	defer server.Close()
	artifact := modelArtifact{Name: "model.onnx", URL: server.URL, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}
	dir := t.TempDir()

	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ensureModelArtifact(context.Background(), dir, artifact)
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 1 {
		t.Fatalf("download requests=%d, want 1", requests.Load())
	}
	got, err := os.ReadFile(filepath.Join(dir, artifact.Name))
	if err != nil || string(got) != string(content) {
		t.Fatalf("cached artifact=%q err=%v", got, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary artifacts=%v err=%v", matches, err)
	}
}

func TestEnsureModelArtifactRejectsDigestMismatchWithoutCommitting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("corrupt"))
	}))
	defer server.Close()
	dir := t.TempDir()
	artifact := modelArtifact{Name: "model.onnx", URL: server.URL, SHA256: string(make([]byte, 64)), Size: 7}
	if _, err := ensureModelArtifact(context.Background(), dir, artifact); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, artifact.Name)); !os.IsNotExist(err) {
		t.Fatalf("corrupt artifact was committed: %v", err)
	}
}

func TestCUDADeviceAvailabilityOverride(t *testing.T) {
	t.Setenv("GRAPHIT_BROKER_CUDA_AVAILABLE", "true")
	if !cudaDeviceAvailable() {
		t.Fatal("explicit CUDA availability was ignored")
	}
	t.Setenv("GRAPHIT_BROKER_CUDA_AVAILABLE", "false")
	if cudaDeviceAvailable() {
		t.Fatal("explicit CPU-only override was ignored")
	}
}

func TestLocalDeviceCandidatePolicy(t *testing.T) {
	tests := []struct {
		device        string
		cudaAvailable bool
		want          string
	}{
		{device: "auto", cudaAvailable: true, want: "cuda,cpu"},
		{device: "auto", cudaAvailable: false, want: "cpu"},
		{device: "cpu", cudaAvailable: true, want: "cpu"},
		{device: "cuda", cudaAvailable: false, want: "cuda"},
	}
	for _, tc := range tests {
		if got := strings.Join(localDeviceCandidates(tc.device, tc.cudaAvailable), ","); got != tc.want {
			t.Errorf("device=%s cudaAvailable=%v candidates=%q want=%q", tc.device, tc.cudaAvailable, got, tc.want)
		}
	}
}

func TestResolveLocalModelBundleUsesOnlyOperatorArtifacts(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "custom.onnx")
	tokenizerPath := filepath.Join(dir, "tokenizer.json")
	model := []byte("custom model")
	tokenizer := []byte("custom tokenizer")
	if err := os.WriteFile(modelPath, model, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenizerPath, tokenizer, 0o600); err != nil {
		t.Fatal(err)
	}
	modelDigest := sha256.Sum256(model)
	tokenizerDigest := sha256.Sum256(tokenizer)

	paths, operatorProvided, err := resolveLocalModelBundle(context.Background(), LocalModelConfig{
		ModelPath:       modelPath,
		TokenizerPath:   tokenizerPath,
		ModelSHA256:     hex.EncodeToString(modelDigest[:]),
		TokenizerSHA256: hex.EncodeToString(tokenizerDigest[:]),
	}, modelArtifact{Name: "must-not-download", URL: "http://127.0.0.1:1/must-not-download"})
	if err != nil {
		t.Fatal(err)
	}
	if !operatorProvided || len(paths) != 2 || paths[0] != modelPath || paths[1] != tokenizerPath {
		t.Fatalf("paths=%v operatorProvided=%v", paths, operatorProvided)
	}
}

func TestResolveLocalModelBundleRejectsMissingAndMismatchedArtifacts(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "custom.onnx")
	tokenizerPath := filepath.Join(dir, "tokenizer.json")
	if err := os.WriteFile(modelPath, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveLocalModelBundle(context.Background(), LocalModelConfig{
		ModelPath: modelPath, TokenizerPath: tokenizerPath,
	}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing tokenizer error=%v", err)
	}
	if err := os.WriteFile(tokenizerPath, []byte("tokenizer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveLocalModelBundle(context.Background(), LocalModelConfig{
		ModelPath: modelPath, TokenizerPath: tokenizerPath, ModelSHA256: strings.Repeat("0", 64),
	}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("digest mismatch error=%v", err)
	}
}
