package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	ort "github.com/yalue/onnxruntime_go"
)

func TestModelCatalogOnDemandDownloadsOnceWithAuthAndStablePaths(t *testing.T) {
	modelData, tokenizerData := []byte("onnx"), []byte("tokenizer")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/model") {
			_, _ = w.Write(modelData)
		} else {
			_, _ = w.Write(tokenizerData)
		}
	}))
	defer server.Close()
	t.Setenv("GRAPHIT_BROKER_MODEL_AUTH_PRIVATE_HF", "secret-token")
	root := t.TempDir()
	manifest := testManifest("custom", "embedding", "on_demand", []ModelArtifact{
		testRemoteArtifact("model", "model.onnx", server.URL+"/model", "private-hf", modelData),
		testRemoteArtifact("tokenizer", "tokenizer.json", server.URL+"/tokenizer", "private-hf", tokenizerData),
	})
	writeTestManifest(t, root, manifest)
	catalog := NewModelCatalog()
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolved, err := catalog.Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "custom"}, resolveForRuntime)
			if err == nil && (resolved.ModelPath != filepath.Join(root, "custom", "model.onnx") || resolved.TokenizerPath == "") {
				err = fmtError("unexpected resolved paths")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d, want one per artifact", requests.Load())
	}
	temporary, err := filepath.Glob(filepath.Join(root, "custom", "*.tmp"))
	if err != nil || len(temporary) != 0 {
		t.Fatalf("partial files=%v err=%v", temporary, err)
	}
	persisted, err := os.ReadFile(filepath.Join(root, "custom", "manifest.json"))
	if err != nil || strings.Contains(string(persisted), "secret-token") {
		t.Fatalf("credential leaked to manifest: err=%v", err)
	}
}

func TestModelCatalogLoadsInstalledNeverBundleWithoutNetwork(t *testing.T) {
	root := t.TempDir()
	manifest := testManifest("installed", "embedding", "never", []ModelArtifact{
		{Role: "model", Path: "model.onnx", Required: true},
		{Role: "tokenizer", Format: "huggingface-json", Path: "tokenizer.json", Required: true},
	})
	writeTestManifest(t, root, manifest)
	bundle := filepath.Join(root, "installed")
	if err := os.WriteFile(filepath.Join(bundle, "model.onnx"), []byte("local-model"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "tokenizer.json"), []byte("local-tokenizer"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := NewModelCatalog()
	catalog.artifacts.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("installed never bundle attempted network access")
		return nil, nil
	})}
	resolved, err := catalog.Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "installed"}, resolveForRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.ArtifactSHA["model"] == "" || resolved.ArtifactSHA["tokenizer"] == "" {
		t.Fatalf("hashes=%v", resolved.ArtifactSHA)
	}
}

func TestModelCatalogFetchPoliciesAndValidation(t *testing.T) {
	content := []byte("artifact")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(content)
	}))
	defer server.Close()
	for _, tc := range []struct {
		name         string
		policy       string
		mode         modelResolveMode
		wantError    string
		wantRequests int32
	}{
		{"never", "never", resolveForSetup, "fetch_policy=never", 0},
		{"setup-runtime", "setup", resolveForRuntime, "--setup-models", 0},
		{"setup-command", "setup", resolveForSetup, "", 2},
		{"on-demand", "on_demand", resolveForRuntime, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests.Store(0)
			root := t.TempDir()
			manifest := testManifest("custom", "embedding", tc.policy, []ModelArtifact{
				testRemoteArtifact("model", "model.onnx", server.URL, "", content),
				testRemoteArtifact("tokenizer", "tokenizer.json", server.URL, "", content),
			})
			writeTestManifest(t, root, manifest)
			_, err := NewModelCatalog().Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "custom"}, tc.mode)
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error=%v, want %q", err, tc.wantError)
			}
			if tc.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if requests.Load() != tc.wantRequests {
				t.Fatalf("requests=%d, want %d", requests.Load(), tc.wantRequests)
			}
		})
	}

	root := t.TempDir()
	missingSHA := testManifest("bad", "embedding", "on_demand", []ModelArtifact{
		{Role: "model", Path: "model.onnx", Sources: []ModelArtifactSource{{URL: server.URL}}, Required: true},
		{Role: "tokenizer", Path: "tokenizer.json", Required: true},
	})
	writeTestManifest(t, root, missingSHA)
	if _, err := NewModelCatalog().Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "bad"}, resolveForRuntime); err == nil || !strings.Contains(err.Error(), "no sha256") {
		t.Fatalf("remote source without sha256 error=%v", err)
	}
}

func TestSetupModelsAcquiresSelectedLocalBundlesWithoutRuntimeInitialization(t *testing.T) {
	content := []byte("setup-artifact")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(content)
	}))
	defer server.Close()
	root := t.TempDir()
	manifest := testManifest("setup-embedding", "embedding", "setup", []ModelArtifact{
		testRemoteArtifact("model", "model.onnx", server.URL, "", content),
		testRemoteArtifact("tokenizer", "tokenizer.json", server.URL, "", content),
	})
	writeTestManifest(t, root, manifest)
	cfg := Config{Services: ServicesConfig{
		Embeddings: EmbeddingServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "onnx", Directory: root, Model: "setup-embedding"}},
	}}
	if err := SetupModels(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d", requests.Load())
	}
	if _, err := os.Stat(filepath.Join(root, "setup-embedding", "model.onnx")); err != nil {
		t.Fatal(err)
	}
}

func TestModelCatalogConfinesPathsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	absolute := testManifest("absolute", "embedding", "never", []ModelArtifact{
		{Role: "model", Path: "/tmp/outside.onnx", Required: true},
		{Role: "tokenizer", Path: "tokenizer.json", Required: true},
	})
	absolute.Runtime.Entrypoints["model"] = "/tmp/outside.onnx"
	writeTestManifest(t, root, absolute)
	if _, err := NewModelCatalog().Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "absolute"}, resolveForRuntime); err == nil || !strings.Contains(err.Error(), "relative") {
		t.Fatalf("absolute path error=%v", err)
	}

	escape := testManifest("escape", "embedding", "never", []ModelArtifact{
		{Role: "model", Path: "../outside.onnx", Required: true},
		{Role: "tokenizer", Path: "tokenizer.json", Required: true},
	})
	escape.Runtime.Entrypoints["model"] = "../outside.onnx"
	writeTestManifest(t, root, escape)
	if _, err := NewModelCatalog().Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "escape"}, resolveForRuntime); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("path escape error=%v", err)
	}

	outside := t.TempDir()
	bundle := filepath.Join(root, "symlink")
	if err := os.MkdirAll(bundle, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(bundle, "linked")); err != nil {
		t.Fatal(err)
	}
	symlink := testManifest("symlink", "embedding", "never", []ModelArtifact{
		{Role: "model", Path: "linked/model.onnx", Required: true},
		{Role: "tokenizer", Path: "tokenizer.json", Required: true},
	})
	symlink.Runtime.Entrypoints["model"] = "linked/model.onnx"
	writeTestManifest(t, root, symlink)
	if _, err := NewModelCatalog().Resolve(context.Background(), "embedding", UpstreamConfig{Protocol: "onnx", Directory: root, Model: "symlink"}, resolveForRuntime); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink escape error=%v", err)
	}
}

func TestModelIdentityIncludesSemanticConfigurationAndArtifactHashes(t *testing.T) {
	model := &ResolvedModel{Manifest: testManifest("m", "embedding", "never", nil), ArtifactSHA: map[string]string{"model": "a", "tokenizer": "b"},
		InputSemantic: map[string]string{"ids": "input_ids"}, OutputName: "embedding", Dimensions: 3}
	if err := finalizeModelIdentity(model); err != nil {
		t.Fatal(err)
	}
	first := model.Identity
	if err := finalizeModelIdentity(model); err != nil || model.Identity != first {
		t.Fatalf("identity is unstable: %v", err)
	}
	model.Manifest.Text.QueryPrefix = "query: "
	if err := finalizeModelIdentity(model); err != nil {
		t.Fatal(err)
	}
	if model.Identity == first {
		t.Fatal("semantic change did not invalidate identity")
	}
}

func TestONNXWireInspectorReadsOpsetMetadataAndExternalWeights(t *testing.T) {
	opset := wireMessage(wireString(1, "ai.onnx"), wireVarintField(2, 18))
	metadata := wireMessage(wireString(1, "producer"), wireString(2, "fixture"))
	external := wireMessage(wireString(1, "location"), wireString(2, "weights/model.data"))
	tensor := wireMessage(wireBytes(13, external), wireVarintField(14, 1))
	graph := wireMessage(wireBytes(5, tensor))
	model := wireMessage(wireBytes(8, opset), wireBytes(14, metadata), wireBytes(7, graph))
	path := filepath.Join(t.TempDir(), "fixture.onnx")
	if err := os.WriteFile(path, model, 0o600); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectONNXWire(path)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Opsets["ai.onnx"] != 18 || inspection.Metadata["producer"] != "fixture" || len(inspection.ExternalData) != 1 || inspection.ExternalData[0] != "weights/model.data" {
		t.Fatalf("inspection=%#v", inspection)
	}
}

func TestSemanticResolutionPoolingNormalizationAndRerankTransforms(t *testing.T) {
	floatType := ort.TensorElementDataType(ort.TensorElementDataTypeFloat).String()
	int64Type := ort.TensorElementDataType(ort.TensorElementDataTypeInt64).String()
	model := &ResolvedModel{Manifest: testManifest("custom", "embedding", "never", nil), ArtifactSHA: map[string]string{}, Inspection: ONNXInspection{
		Inputs:  []ONNXTensorInfo{{"ids", int64Type, []int64{-1, -1}}, {"mask", int64Type, []int64{-1, -1}}},
		Outputs: []ONNXTensorInfo{{"tokens", floatType, []int64{-1, -1, 2}}},
	}}
	model.Manifest.Inference.Inputs = ModelInputManifest{InputIDs: "ids", AttentionMask: "mask"}
	model.Manifest.Inference.Output = "tokens"
	model.Manifest.Inference.Pooling = "mean"
	if err := resolveModelSemantics(model); err != nil {
		t.Fatal(err)
	}
	if model.Dimensions != 2 || model.InputSemantic["ids"] != "input_ids" {
		t.Fatalf("resolved=%#v", model)
	}

	vectors, err := poolEmbeddingOutput([]float32{3, 4, 0, 0}, ort.Shape{1, 2, 2}, "mean", true, 1, 2, 2, []int64{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(float64(vectors[0][0])-0.6) > 1e-6 || math.Abs(float64(vectors[0][1])-0.8) > 1e-6 {
		t.Fatalf("vectors=%v", vectors)
	}
	column := 1
	scores, err := transformRerankOutput([]float32{0, 2, 2, 0}, 2, "softmax", &column)
	if err != nil {
		t.Fatal(err)
	}
	if scores[0] <= scores[1] || scores[0] <= 0.8 {
		t.Fatalf("scores=%v", scores)
	}
}

func TestManifestAndSemanticValidationRejectIncompatibleModels(t *testing.T) {
	artifacts := []ModelArtifact{
		{Role: "model", Path: "model.onnx", Required: true},
		{Role: "tokenizer", Format: "huggingface-json", Path: "tokenizer.json", Required: true},
	}
	for _, tc := range []struct {
		name string
		edit func(*ModelManifest)
		want string
	}{
		{"task", func(m *ModelManifest) { m.Task = "rerank" }, "does not match"},
		{"tokenizer", func(m *ModelManifest) { m.Artifacts[1].Format = "sentencepiece-binary" }, "tokenizer format"},
		{"embedding-score", func(m *ModelManifest) { m.Inference.ScoreTransform = "sigmoid" }, "do not accept rerank"},
		{"explicit-inputs", func(m *ModelManifest) { m.Inference.Inputs = ModelInputManifest{Specified: true, InputIDs: "ids"} }, "requires input_ids and attention_mask"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := testManifest("model", "embedding", "never", append([]ModelArtifact(nil), artifacts...))
			tc.edit(&manifest)
			manifest.applyTaskProfile()
			if err := manifest.validate("model", "embedding"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}

	model := &ResolvedModel{BundleDir: t.TempDir(), ArtifactSHA: map[string]string{}, Manifest: testManifest("model", "embedding", "never", artifacts), Inspection: ONNXInspection{ExternalData: []string{"missing.data"}}}
	if err := resolveModelSemantics(model); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("external data error=%v", err)
	}
}

func testManifest(id, task, policy string, artifacts []ModelArtifact) ModelManifest {
	return ModelManifest{SchemaVersion: 1, ID: id, Task: task, Runtime: ModelRuntimeManifest{Engine: "onnx", Entrypoints: map[string]string{"model": "model.onnx"}},
		FetchPolicy: policy, Artifacts: artifacts, Text: ModelTextManifest{MaxTokens: 512, Truncation: "longest-first", Padding: "longest"},
		Inference: InferenceManifest{Inputs: ModelInputManifest{Auto: true}, Output: "auto", Pooling: "none", ScoreTransform: "identity"}}
}

func testRemoteArtifact(role, path, url, authRef string, content []byte) ModelArtifact {
	digest := sha256.Sum256(content)
	return ModelArtifact{Role: role, Path: path, Sources: []ModelArtifactSource{{URL: url, AuthRef: authRef}}, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), Required: true}
}

func writeTestManifest(t *testing.T, root string, manifest ModelManifest) {
	t.Helper()
	bundle := filepath.Join(root, manifest.ID)
	if err := os.MkdirAll(bundle, 0o750); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

type testError string

func (e testError) Error() string { return string(e) }
func fmtError(value string) error { return testError(value) }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func wireMessage(parts ...[]byte) []byte {
	var result []byte
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func wireBytes(field int, value []byte) []byte {
	result := append(wireVarint(uint64(field<<3|2)), wireVarint(uint64(len(value)))...)
	return append(result, value...)
}

func wireString(field int, value string) []byte { return wireBytes(field, []byte(value)) }
func wireVarintField(field int, value uint64) []byte {
	return append(wireVarint(uint64(field<<3)), wireVarint(value)...)
}
func wireVarint(value uint64) []byte {
	var result []byte
	for value >= 0x80 {
		result = append(result, byte(value)|0x80)
		value >>= 7
	}
	return append(result, byte(value))
}

func TestSetupModelsUsesIndependentUpstreamSelections(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte("artifact"))
	}))
	defer server.Close()
	roots := []string{t.TempDir(), t.TempDir()}
	ids := []string{"custom-embedding", "custom-rerank"}
	for i, task := range []string{"embedding", "rerank"} {
		writeTestManifest(t, roots[i], testManifest(ids[i], task, "setup", []ModelArtifact{
			testRemoteArtifact("model", "model.onnx", server.URL, "", []byte("artifact")),
			testRemoteArtifact("tokenizer", "tokenizer.json", server.URL, "", []byte("artifact")),
		}))
	}
	cfg := Config{Services: ServicesConfig{
		Embeddings: EmbeddingServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "onnx", Model: ids[0], Directory: roots[0]}},
		Rerank:     RerankServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "onnx", Model: ids[1], Directory: roots[1]}},
	}}
	if err := SetupModels(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 4 {
		t.Fatalf("requests=%d, want 4", requests.Load())
	}
	for i := range roots {
		if _, err := os.Stat(filepath.Join(roots[i], ids[i], "model.onnx")); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(roots[i], ids[1-i])); !os.IsNotExist(err) {
			t.Fatalf("model resolved in the wrong directory: %v", err)
		}
	}
	if err := SetupModels(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 4 {
		t.Fatalf("installed artifacts fetched again: %d", requests.Load())
	}
}

func TestSetupModelsSkipsDisabledAndHTTPServices(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "untouched")
		protocol := "onnx"
		if enabled {
			protocol = "openai"
		}
		// A catalog touch would create this directory and fail on the missing manifest.
		cfg := Config{Services: ServicesConfig{
			Embeddings: EmbeddingServiceConfig{Enabled: enabled, Upstream: UpstreamConfig{Protocol: protocol, Directory: root, Model: "missing"}},
			Rerank:     RerankServiceConfig{Enabled: enabled, Upstream: UpstreamConfig{Protocol: protocol, Directory: root, Model: "missing"}},
		}}
		if err := SetupModels(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(root); !os.IsNotExist(err) {
			t.Fatalf("inactive ONNX catalog was accessed: %v", err)
		}
	}
}
