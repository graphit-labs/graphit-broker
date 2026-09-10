package broker

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ort "github.com/yalue/onnxruntime_go"
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
	local := integrationLocalModel(t, "embedding", cacheDir, device)
	backend, err := newONNXEmbeddingBackend(context.Background(), local)
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
	local := integrationLocalModel(t, "embedding", cacheDir, "cuda")
	backend, err := newONNXEmbeddingBackend(context.Background(), local)
	if backend != nil {
		_ = backend.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "local device cuda was required but could not initialize") {
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
	device := os.Getenv("GRAPHIT_BROKER_INTEGRATION_DEVICE")
	if device == "" {
		device = "cpu"
	}
	local := integrationLocalModel(t, "rerank", cacheDir, device)
	backend, err := newONNXRerankBackend(context.Background(), local)
	if err != nil {
		t.Fatalf("initialize rerank backend: %v", err)
	}
	defer backend.Close()
	if expected := os.Getenv("GRAPHIT_BROKER_EXPECT_DEVICE"); expected != "" && backend.(*onnxRerankBackend).device != expected {
		t.Fatalf("selected device=%q, want %q", backend.(*onnxRerankBackend).device, expected)
	}
	scores, err := backend.Score(context.Background(), "graph traversal", []string{"breadth first search", "banana bread"})
	if err != nil {
		t.Fatalf("rerank: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("scores=%v", scores)
	}
}

func TestLocalCoreMLRuntimeIntegration(t *testing.T) {
	if os.Getenv("GRAPHIT_BROKER_COREML_INTEGRATION") != "1" {
		t.Skip("set GRAPHIT_BROKER_COREML_INTEGRATION=1 to run the CoreML smoke model")
	}
	if runtime.GOOS != "darwin" {
		t.Fatalf("CoreML integration requires macOS, running on %s", runtime.GOOS)
	}
	modelPath := os.Getenv("GRAPHIT_BROKER_COREML_SMOKE_MODEL")
	if modelPath == "" {
		t.Fatal("GRAPHIT_BROKER_COREML_SMOKE_MODEL must point to the CoreML smoke ONNX model")
	}
	if err := initializeONNXRuntime(); err != nil {
		t.Fatalf("initialize ONNX Runtime: %v", err)
	}
	session, device, err := newLocalONNXSession(modelPath, []string{"in"}, []string{"out"}, UpstreamConfig{Device: "coreml"})
	if err != nil {
		t.Fatalf("initialize CoreML session: %v", err)
	}
	defer session.Destroy()
	if device != "coreml" {
		t.Fatalf("selected device=%q, want coreml", device)
	}
	input, err := ort.NewTensor(ort.NewShape(1, 2), []int32{12, 21})
	if err != nil {
		t.Fatalf("create CoreML smoke input: %v", err)
	}
	defer input.Destroy()
	output, err := ort.NewEmptyTensor[int32](ort.NewShape(1))
	if err != nil {
		t.Fatalf("create CoreML smoke output: %v", err)
	}
	defer output.Destroy()
	if err := session.Run([]ort.Value{input}, []ort.Value{output}); err != nil {
		t.Fatalf("run CoreML smoke inference: %v", err)
	}
	if got := output.GetData()[0]; got != 33 {
		t.Fatalf("CoreML smoke output=%d, want 33", got)
	}
}

func integrationLocalModel(t *testing.T, task, bundleDir, device string) UpstreamConfig {
	t.Helper()
	upstream := UpstreamConfig{Protocol: "onnx", Directory: filepath.Dir(bundleDir), Model: filepath.Base(bundleDir), Device: device}
	model, err := NewModelCatalog().Resolve(context.Background(), task, upstream, resolveForRuntime)
	if err != nil {
		t.Fatalf("resolve %s model: %v", task, err)
	}
	model.Inspection, err = inspectONNX(model.ModelPath)
	if err != nil {
		t.Fatalf("inspect %s model: %v", task, err)
	}
	if err := resolveModelSemantics(model); err != nil {
		t.Fatalf("resolve %s semantics: %v", task, err)
	}
	return UpstreamConfig{Device: device, resolvedModel: model}
}
