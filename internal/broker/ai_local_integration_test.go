package broker

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise the pinned production artifacts and are intentionally
// opt-in so the hermetic unit suite never downloads model weights.
func TestLocalEmbeddingRuntimeIntegration(t *testing.T) {
	if os.Getenv("GRAPHIT_BROKER_EMBEDDING_INTEGRATION") != "1" {
		t.Skip("set GRAPHIT_BROKER_EMBEDDING_INTEGRATION=1 to run the local model")
	}
	cacheDir := os.Getenv("GRAPHIT_BROKER_INTEGRATION_CACHE")
	if cacheDir == "" {
		cacheDir = filepath.Join(t.TempDir(), "coderankembed")
	}
	device := os.Getenv("GRAPHIT_BROKER_INTEGRATION_DEVICE")
	if device == "" {
		device = "cpu"
	}
	backend, err := newONNXEmbeddingBackend(context.Background(), LocalModelConfig{Device: device, CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("initialize embedding backend: %v", err)
	}
	defer backend.Close()
	if expected := os.Getenv("GRAPHIT_BROKER_EXPECT_DEVICE"); expected != "" && backend.(*onnxEmbeddingBackend).device != expected {
		t.Fatalf("selected device=%q, want %q", backend.(*onnxEmbeddingBackend).device, expected)
	}
	vectors, err := backend.Embed(context.Background(), []string{"graph traversal"}, "query")
	if err != nil {
		t.Fatalf("embed: %v", err)
	}
	if len(vectors) != 1 {
		t.Fatalf("embedding count=%d", len(vectors))
	}
	if len(vectors[0]) != localEmbeddingDimensions {
		t.Fatalf("embedding dimensions=%d", len(vectors[0]))
	}
	var norm float64
	for _, value := range vectors[0] {
		norm += float64(value) * float64(value)
	}
	if delta := math.Abs(math.Sqrt(norm) - 1); delta > 1e-4 {
		t.Fatalf("embedding norm delta=%g", delta)
	}
}

func TestLocalCUDARequirementIntegration(t *testing.T) {
	if os.Getenv("GRAPHIT_BROKER_CUDA_REJECTION_INTEGRATION") != "1" {
		t.Skip("set GRAPHIT_BROKER_CUDA_REJECTION_INTEGRATION=1 on a host without usable CUDA")
	}
	cacheDir := os.Getenv("GRAPHIT_BROKER_INTEGRATION_CACHE")
	if cacheDir == "" {
		t.Fatal("GRAPHIT_BROKER_INTEGRATION_CACHE must point to a verified CodeRankEmbed cache")
	}
	backend, err := newONNXEmbeddingBackend(context.Background(), LocalModelConfig{Device: "cuda", CacheDir: cacheDir})
	if backend != nil {
		_ = backend.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "CUDA device 0 was required but could not initialize") {
		t.Fatalf("strict CUDA initialization error=%v", err)
	}
}

func TestLocalRerankRuntimeIntegration(t *testing.T) {
	if os.Getenv("GRAPHIT_BROKER_RERANK_INTEGRATION") != "1" {
		t.Skip("set GRAPHIT_BROKER_RERANK_INTEGRATION=1 to run the local model")
	}
	cacheDir := os.Getenv("GRAPHIT_BROKER_INTEGRATION_CACHE")
	if cacheDir == "" {
		cacheDir = filepath.Join(t.TempDir(), "bge-reranker-base")
	}
	backend, err := newONNXRerankBackend(context.Background(), LocalModelConfig{Device: "cpu", CacheDir: cacheDir})
	if err != nil {
		t.Fatalf("initialize rerank backend: %v", err)
	}
	defer backend.Close()
	scores, err := backend.Score(context.Background(), "graph traversal", []string{"breadth first search", "banana bread"})
	if err != nil {
		t.Fatalf("rerank: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("scores=%v", scores)
	}
}
