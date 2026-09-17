package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPersistentEmbeddingCacheReusesDistinctInputsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "broker.db")
	store, err := OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	var requests [][]string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Input []string `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		requests = append(requests, body.Input)
		data := make([]EmbeddingData, len(body.Input))
		for i, text := range body.Input {
			data[i] = EmbeddingData{Index: i, Embedding: []float32{float32(len(text)), float32(i)}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer upstream.Close()
	cfg := ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "rev-1", Dimensions: 2,
		Upstream: UpstreamConfig{Protocol: "openai-embeddings-v1", Model: "model-a", URL: upstream.URL, Timeout: time.Second}}}
	principal := Principal{Issuer: "i", Subject: "s"}
	service := NewAIService(cfg, store)
	first, cached, err := service.Embed(ctx, principal, []string{"alpha", "beta", "alpha"})
	if err != nil || cached || !reflect.DeepEqual(requests, [][]string{{"alpha", "beta"}}) {
		t.Fatalf("first response=%v cached=%v requests=%v err=%v", first, cached, requests, err)
	}
	if first.Data[0].Index != 0 || first.Data[1].Index != 1 || first.Data[2].Index != 2 || !reflect.DeepEqual(first.Data[0].Embedding, first.Data[2].Embedding) {
		t.Fatalf("incorrect batch order: %#v", first.Data)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenControlStore(testDatabase(path), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service = NewAIService(cfg, store)
	second, cached, err := service.Embed(ctx, principal, []string{"beta", "gamma", "alpha", "gamma"})
	if err != nil || cached || !reflect.DeepEqual(requests, [][]string{{"alpha", "beta"}, {"gamma"}}) {
		t.Fatalf("second response=%v cached=%v requests=%v err=%v", second, cached, requests, err)
	}
	if len(second.Data) != 4 || second.Data[0].Embedding[0] != 4 || second.Data[1].Embedding[0] != 5 || second.Data[2].Embedding[0] != 5 || !reflect.DeepEqual(second.Data[1].Embedding, second.Data[3].Embedding) {
		t.Fatalf("incorrect mixed batch: %#v", second.Data)
	}
	_, cached, err = NewAIService(cfg, store).Embed(ctx, Principal{Issuer: "i", Subject: "other"}, []string{"alpha", "beta"})
	if err != nil || !cached || len(requests) != 2 {
		t.Fatalf("database hit across service and principal: cached=%v requests=%v err=%v", cached, requests, err)
	}
	var rows int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM embedding_cache`).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("persisted rows=%d err=%v", rows, err)
	}
}

func TestPersistentEmbeddingCacheSeparatesCompatibilityAndHasIndexedHashes(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var indexSQL string
	if err := store.db.QueryRowContext(ctx, `SELECT sql FROM sqlite_master WHERE type='table' AND name='embedding_cache'`).Scan(&indexSQL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(indexSQL, "PRIMARY KEY(compatibility_hash, input_hash)") || strings.Contains(indexSQL, "input_text") {
		t.Fatalf("cache table lacks indexed hashes or stores raw input: %s", indexSQL)
	}
	var selectID, parentID, unused int
	var plan string
	if err := store.db.QueryRowContext(ctx, `EXPLAIN QUERY PLAN SELECT embedding_json FROM embedding_cache WHERE compatibility_hash=? AND input_hash=?`, "a", "b").Scan(&selectID, &parentID, &unused, &plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "USING INDEX") || !strings.Contains(plan, "compatibility_hash=? AND input_hash=?") {
		t.Fatalf("cache lookup does not use the composite index: %s", plan)
	}
	var calls int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []EmbeddingData{{Index: 0, Embedding: []float32{float32(calls)}}}})
	}))
	defer upstream.Close()
	base := EmbeddingServiceConfig{Enabled: true, Revision: "v1", Dimensions: 1,
		Upstream: UpstreamConfig{Protocol: "openai-embeddings-v1", Model: "a", URL: upstream.URL, Timeout: time.Second}}
	configs := []EmbeddingServiceConfig{base}
	changed := base
	changed.Revision = "v2"
	configs = append(configs, changed)
	changed = base
	changed.Upstream.Model = "b"
	configs = append(configs, changed)
	changed = base
	changed.Upstream.Protocol = "openai-compatible"
	configs = append(configs, changed)
	for _, cfg := range configs {
		service := NewAIService(ServicesConfig{Embeddings: cfg}, store)
		for _, inputType := range []string{"document", "query"} {
			if _, cached, err := service.Embed(ctx, Principal{}, []string{"same text"}, inputType); err != nil || cached {
				t.Fatalf("unexpected compatibility hit cfg=%+v type=%s cached=%v err=%v", cfg, inputType, cached, err)
			}
		}
	}
	if calls != 8 {
		t.Fatalf("provider called %d times, want 8", calls)
	}
	var hash, vector string
	if err := store.db.QueryRowContext(ctx, `SELECT input_hash, embedding_json FROM embedding_cache LIMIT 1`).Scan(&hash, &vector); err != nil {
		t.Fatal(err)
	}
	if hash != sha256Hex([]byte("same text")) || strings.Contains(vector, "same text") {
		t.Fatalf("cache stored wrong hash or raw text: hash=%q vector=%q", hash, vector)
	}
}

func TestPersistentEmbeddingCacheAlsoCoversLocalModel(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &fakeLocalEmbeddingBackend{}
	cfg := ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "local", Dimensions: localEmbeddingDimensions,
		Upstream: UpstreamConfig{Protocol: "onnx", Model: "local-model", Device: "cpu"}}}
	makeService := func(identity string) *AIService {
		service := NewAIService(cfg, store)
		service.prepareModel = func(context.Context, string, UpstreamConfig) (*ResolvedModel, error) {
			return &ResolvedModel{Manifest: ModelManifest{ID: "local-model"}, Identity: identity, Dimensions: localEmbeddingDimensions}, nil
		}
		service.newLocalEmbedding = func(context.Context, UpstreamConfig) (localEmbeddingBackend, error) { return backend, nil }
		if err := service.InitializeLocal(ctx); err != nil {
			t.Fatal(err)
		}
		return service
	}
	first := makeService("identity-a")
	if _, cached, err := first.Embed(ctx, Principal{}, []string{"local text"}, "document"); err != nil || cached {
		t.Fatalf("first local: %v %v", cached, err)
	}
	if _, cached, err := makeService("identity-a").Embed(ctx, Principal{}, []string{"local text"}, "document"); err != nil || !cached {
		t.Fatalf("local database hit: %v %v", cached, err)
	}
	if _, cached, err := makeService("identity-b").Embed(ctx, Principal{}, []string{"local text"}, "document"); err != nil || cached {
		t.Fatalf("changed local model: %v %v", cached, err)
	}
	if backend.calls != 2 {
		t.Fatalf("local model calls=%d, want 2", backend.calls)
	}
}

func TestPersistentEmbeddingCacheKeepsValidVectorsWhenBatchIsIncomplete(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		data := []EmbeddingData{{Index: 0, Embedding: []float32{1}}}
		if len(body.Input) == 3 {
			data = append(data, EmbeddingData{Index: 2, Embedding: []float32{3}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer upstream.Close()
	cfg := ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "v1", Dimensions: 1,
		Upstream: UpstreamConfig{Protocol: "openai-embeddings-v1", Model: "model", URL: upstream.URL, Timeout: time.Second}}}
	service := NewAIService(cfg, store)
	if _, _, err := service.Embed(ctx, Principal{}, []string{"good-a", "missing", "good-c"}); err == nil {
		t.Fatal("incomplete upstream batch accepted")
	}
	response, cached, err := NewAIService(cfg, store).Embed(ctx, Principal{}, []string{"good-a", "good-c"})
	if err != nil || !cached || requests != 1 || response.Data[0].Embedding[0] != 1 || response.Data[1].Embedding[0] != 3 {
		t.Fatalf("valid vectors not retained: response=%#v cached=%v requests=%d err=%v", response, cached, requests, err)
	}
}

func TestPersistentEmbeddingCacheSalvagesSuccessfulInputsAfterBatchFailure(t *testing.T) {
	ctx := context.Background()
	store, err := OpenControlStore(testDatabase(":memory:"), testTokenPepper)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	requests := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(body.Input) > 1 || body.Input[0] == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []EmbeddingData{{Index: 0, Embedding: []float32{float32(len(body.Input[0]))}}}})
	}))
	defer upstream.Close()
	cfg := ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "v1", Dimensions: 1,
		Upstream: UpstreamConfig{Protocol: "openai-embeddings-v1", Model: "model", URL: upstream.URL, Timeout: time.Second}}}
	if _, _, err := NewAIService(cfg, store).Embed(ctx, Principal{}, []string{"good-a", "bad", "good-c"}); err == nil {
		t.Fatal("failed input accepted")
	}
	_, cached, err := NewAIService(cfg, store).Embed(ctx, Principal{}, []string{"good-a", "good-c"})
	if err != nil || !cached || requests != 4 {
		t.Fatalf("individual successes not saved: cached=%v requests=%d err=%v", cached, requests, err)
	}
}
