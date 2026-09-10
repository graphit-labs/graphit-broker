package broker

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLocalEmbeddingBackend struct {
	mu        sync.Mutex
	inputType string
	calls     int
}

func (f *fakeLocalEmbeddingBackend) Embed(_ context.Context, input []string, inputType string) ([][]float32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.inputType = inputType
	vectors := make([][]float32, len(input))
	for i := range vectors {
		vectors[i] = make([]float32, localEmbeddingDimensions)
	}
	return vectors, nil
}

func (*fakeLocalEmbeddingBackend) Close() error { return nil }

type fakeLocalRerankBackend struct{}

func (*fakeLocalRerankBackend) Score(_ context.Context, _ string, documents []string) ([]float64, error) {
	scores := make([]float64, len(documents))
	for i := range scores {
		scores[i] = float64(i)
	}
	return scores, nil
}

func (*fakeLocalRerankBackend) Close() error { return nil }

func TestAIServiceEmbeddingsUsesBrokerModelValidatesDimensionsAndCachesPerPrincipal(t *testing.T) {
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-secret" {
			t.Errorf("Authorization = %q", got)
		}
		var request struct {
			Model string   `json:"model"`
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Model != "internal-model" {
			t.Errorf("upstream model = %q", request.Model)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []any{
			map[string]any{"index": 0, "embedding": []float32{1, 2, 3}}, map[string]any{"index": 1, "embedding": []float32{4, 5, 6}},
		}, "usage": map[string]any{"total_tokens": 2}})
	}))
	defer upstream.Close()
	cfg := ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Route: "graphit-default", Revision: "rev-1", Dimensions: 3,
		Upstream: UpstreamConfig{URL: upstream.URL, Protocol: "openai-embeddings-v1", Model: "internal-model", APIKey: "upstream-secret", Timeout: time.Second},
		Cache:    CacheConfig{TTL: time.Minute, MaxEntries: 10}}}
	service := NewAIService(cfg)
	principal := Principal{Issuer: "i", Subject: "s", Organization: "acme"}
	response, cached, err := service.Embed(context.Background(), principal, []string{"a", "b"})
	if err != nil || cached {
		t.Fatalf("first Embed cached=%v err=%v", cached, err)
	}
	if response.Model != "graphit-default" || response.Graphit.Revision != "rev-1" {
		t.Fatalf("response = %#v", response)
	}
	_, cached, err = service.Embed(context.Background(), principal, []string{"a", "b"})
	if err != nil || !cached || calls != 1 {
		t.Fatalf("second Embed cached=%v calls=%d err=%v", cached, calls, err)
	}
	_, _, _ = service.Embed(context.Background(), Principal{Issuer: "i", Subject: "other", Organization: "acme"}, []string{"a", "b"})
	if calls != 2 {
		t.Fatalf("cache leaked across principals; calls=%d", calls)
	}
}

func TestAIServiceRejectsWrongEmbeddingWidth(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"index": 0, "embedding": []float32{1, 2}}}})
	}))
	defer upstream.Close()
	service := NewAIService(ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "r", Dimensions: 3, Upstream: UpstreamConfig{URL: upstream.URL, Protocol: "openai-embeddings-v1", Model: "m", Timeout: time.Second}}})
	if _, _, err := service.Embed(context.Background(), Principal{Issuer: "i", Subject: "s"}, []string{"x"}); err == nil {
		t.Fatal("wrong vector width accepted")
	}
}

func TestAIServiceNormalizesRerankProtocols(t *testing.T) {
	for _, tc := range []struct{ name, protocol, responseField, topField string }{
		{"cohere", "cohere-v2", "results", "top_n"}, {"jina", "jina-v1", "results", "top_n"}, {"graphit", "graphit-rerank-v1", "results", "top_n"}, {"voyage", "voyage-v1", "data", "top_k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if _, ok := body[tc.topField]; !ok {
					t.Errorf("missing %s", tc.topField)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{tc.responseField: []any{map[string]any{"index": 1, "relevance_score": 0.9}}})
			}))
			defer upstream.Close()
			service := NewAIService(ServicesConfig{Rerank: RerankServiceConfig{Enabled: true, Route: "default", Revision: "r1", Upstream: UpstreamConfig{URL: upstream.URL, Protocol: tc.protocol, Model: "internal", Timeout: time.Second}}})
			response, _, err := service.Rerank(context.Background(), Principal{Issuer: "i", Subject: "s"}, "q", []string{"a", "b"}, 1)
			if err != nil || len(response.Results) != 1 || response.Results[0].Index != 1 {
				t.Fatalf("response=%#v err=%v", response, err)
			}
		})
	}
}

func TestAIServiceSimulatesRerankWithEmbeddingProviders(t *testing.T) {
	tests := []struct {
		name, protocol, model string
		assert                func(*testing.T, int, *http.Request, map[string]any)
		response              func(int) map[string]any
	}{
		{
			name: "openai", protocol: "openai-embeddings-v1", model: "text-embedding-3-small",
			assert: func(t *testing.T, call int, _ *http.Request, body map[string]any) {
				inputs := body["input"].([]any)
				if body["model"] != "text-embedding-3-small" || len(inputs) != []int{1, 3}[call] {
					t.Errorf("call %d OpenAI body=%#v", call, body)
				}
			},
			response: indexedEmbeddingResponse,
		},
		{
			name: "cohere embed", protocol: "cohere-embed-v2", model: "embed-v4.0",
			assert: func(t *testing.T, call int, _ *http.Request, body map[string]any) {
				texts := body["texts"].([]any)
				inputType := []string{"search_query", "search_document"}[call]
				if body["input_type"] != inputType || len(texts) != []int{1, 3}[call] {
					t.Errorf("call %d Cohere Embed body=%#v", call, body)
				}
			},
			response: func(call int) map[string]any {
				return map[string]any{"embeddings": map[string]any{"float": embeddingVectors(call)}}
			},
		},
		{
			name: "voyage embeddings", protocol: "voyage-embeddings-v1", model: "voyage-3.5",
			assert: func(t *testing.T, call int, _ *http.Request, body map[string]any) {
				inputs := body["input"].([]any)
				inputType := []string{"query", "document"}[call]
				if body["input_type"] != inputType || len(inputs) != []int{1, 3}[call] {
					t.Errorf("call %d Voyage Embeddings body=%#v", call, body)
				}
			},
			response: indexedEmbeddingResponse,
		},
		{
			name: "gemini", protocol: "gemini", model: "gemini-embedding-2",
			assert: func(t *testing.T, call int, request *http.Request, body map[string]any) {
				if request.Header.Get("x-goog-api-key") != "secret" || !strings.HasSuffix(request.URL.Path, "/models/gemini-embedding-2:batchEmbedContents") {
					t.Errorf("call %d Gemini request path=%q headers=%v", call, request.URL.Path, request.Header)
				}
				requests := body["requests"].([]any)
				if len(requests) != []int{1, 3}[call] {
					t.Fatalf("call %d Gemini requests=%#v", call, requests)
				}
				first := requests[0].(map[string]any)
				if _, exists := first["embedContentConfig"]; exists {
					t.Errorf("Gemini Embedding 2 request contains unsupported task type: %#v", first)
				}
				text := first["content"].(map[string]any)["parts"].([]any)[0].(map[string]any)["text"].(string)
				prefix := []string{"task: search result | query: ", "title: none | text: "}[call]
				if !strings.HasPrefix(text, prefix) {
					t.Errorf("call %d Gemini text=%q", call, text)
				}
			},
			response: func(call int) map[string]any {
				data := indexedEmbeddingResponse(call)["data"].([]any)
				embeddings := make([]any, len(data))
				for i, item := range data {
					embeddings[i] = map[string]any{"values": item.(map[string]any)["embedding"]}
				}
				return map[string]any{"embeddings": embeddings}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				call := calls
				calls++
				tc.assert(t, call, r, body)
				_ = json.NewEncoder(w).Encode(tc.response(call))
			}))
			defer upstream.Close()

			service := NewAIService(ServicesConfig{Rerank: RerankServiceConfig{
				Enabled: true, Route: "default", Revision: "r1",
				Upstream: UpstreamConfig{URL: upstream.URL, Protocol: tc.protocol, Model: tc.model, APIKey: "secret", Timeout: time.Second},
			}})
			response, _, err := service.Rerank(context.Background(), Principal{Issuer: "i", Subject: "s"}, "query", []string{"orthogonal", "same", "related"}, 2)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || len(response.Results) != 2 || response.Results[0].Index != 1 || response.Results[1].Index != 2 || response.Results[0].RelevanceScore != 1 || response.Results[1].RelevanceScore <= 0 || response.Results[1].RelevanceScore >= 1 {
				t.Fatalf("calls=%d response=%#v", calls, response)
			}
		})
	}
}

func indexedEmbeddingResponse(call int) map[string]any {
	vectors := embeddingVectors(call)
	data := make([]any, len(vectors))
	for i, vector := range vectors {
		data[i] = map[string]any{"index": i, "embedding": vector}
	}
	return map[string]any{"data": data}
}

func embeddingVectors(call int) [][]float32 {
	return [][][]float32{
		{{1, 0}},
		{{0, 1}, {1, 0}, {1, 1}},
	}[call]
}

func TestAIServiceRejectsMalformedEmbeddingRerankResponses(t *testing.T) {
	tests := []struct {
		name      string
		responses []map[string]any
	}{
		{name: "missing query vector", responses: []map[string]any{{"data": []any{}}}},
		{name: "duplicate document index", responses: []map[string]any{
			indexedEmbeddingResponse(0),
			{"data": []any{
				map[string]any{"index": 0, "embedding": []float32{1, 0}},
				map[string]any{"index": 0, "embedding": []float32{0, 1}},
			}},
		}},
		{name: "incompatible dimensions", responses: []map[string]any{
			indexedEmbeddingResponse(0),
			{"data": []any{
				map[string]any{"index": 0, "embedding": []float32{1}},
				map[string]any{"index": 1, "embedding": []float32{1}},
			}},
		}},
		{name: "zero magnitude", responses: []map[string]any{
			{"data": []any{map[string]any{"index": 0, "embedding": []float32{0, 0}}}},
			{"data": []any{
				map[string]any{"index": 0, "embedding": []float32{1, 0}},
				map[string]any{"index": 1, "embedding": []float32{0, 1}},
			}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				response := tc.responses[min(calls, len(tc.responses)-1)]
				calls++
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer upstream.Close()
			service := NewAIService(ServicesConfig{Rerank: RerankServiceConfig{
				Enabled: true, Revision: "r1",
				Upstream: UpstreamConfig{URL: upstream.URL, Protocol: "openai", Model: "embedding", Timeout: time.Second},
			}})
			if _, _, err := service.Rerank(context.Background(), Principal{Issuer: "i", Subject: "s"}, "query", []string{"a", "b"}, 2); err == nil {
				t.Fatal("malformed embedding rerank response accepted")
			}
		})
	}
}

func TestEmbeddingRerankRejectsNonFiniteVectorValues(t *testing.T) {
	for name, value := range map[string]float32{"NaN": float32(math.NaN()), "infinity": float32(math.Inf(1))} {
		t.Run(name, func(t *testing.T) {
			response := embeddingBackendResponse{Data: []EmbeddingData{{Index: 0, Embedding: []float32{value}}}}
			if _, err := orderedEmbeddingVectors(response, 1); err == nil {
				t.Fatal("non-finite embedding value accepted")
			}
		})
	}
}

func TestAIServiceTranslatesEmbeddingProvidersAndInputType(t *testing.T) {
	tests := []struct {
		name, protocol string
		assert         func(*testing.T, http.Header, map[string]any)
		response       map[string]any
	}{
		{
			name: "cohere", protocol: "cohere",
			assert: func(t *testing.T, header http.Header, body map[string]any) {
				if body["input_type"] != "search_query" || len(body["texts"].([]any)) != 2 {
					t.Errorf("cohere body=%#v", body)
				}
				if header.Get("Authorization") != "Bearer secret" {
					t.Errorf("cohere authorization=%q", header.Get("Authorization"))
				}
			},
			response: map[string]any{"embeddings": map[string]any{"float": [][]float32{{1, 2, 3}, {4, 5, 6}}}},
		},
		{
			name: "voyage", protocol: "voyage",
			assert: func(t *testing.T, _ http.Header, body map[string]any) {
				if body["input_type"] != "query" || len(body["input"].([]any)) != 2 {
					t.Errorf("voyage body=%#v", body)
				}
			},
			response: map[string]any{"data": []any{
				map[string]any{"index": 0, "embedding": []float32{1, 2, 3}},
				map[string]any{"index": 1, "embedding": []float32{4, 5, 6}},
			}},
		},
		{
			name: "google", protocol: "google",
			assert: func(t *testing.T, header http.Header, body map[string]any) {
				if header.Get("x-goog-api-key") != "secret" {
					t.Errorf("google key=%q", header.Get("x-goog-api-key"))
				}
				requests := body["requests"].([]any)
				config := requests[0].(map[string]any)["embedContentConfig"].(map[string]any)
				if config["taskType"] != "RETRIEVAL_QUERY" {
					t.Errorf("google requests=%#v", requests)
				}
			},
			response: map[string]any{"embeddings": []any{
				map[string]any{"values": []float32{1, 2, 3}},
				map[string]any{"values": []float32{4, 5, 6}},
			}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				tc.assert(t, r.Header, body)
				_ = json.NewEncoder(w).Encode(tc.response)
			}))
			defer upstream.Close()
			service := NewAIService(ServicesConfig{Embeddings: EmbeddingServiceConfig{
				Enabled: true, Route: "default", Revision: "r", Dimensions: 3,
				Upstream: UpstreamConfig{URL: upstream.URL, Protocol: tc.protocol, Model: "model", APIKey: "secret", Timeout: time.Second},
			}})
			response, _, err := service.Embed(context.Background(), Principal{Issuer: "i", Subject: "s"}, []string{"a", "b"}, "query")
			if err != nil || len(response.Data) != 2 {
				t.Fatalf("response=%#v err=%v", response, err)
			}
		})
	}
}

func TestAIServiceChunksProviderEmbeddingRequestsAndRestoresGlobalIndexes(t *testing.T) {
	tests := []struct {
		protocol string
		limit    int
		count    func(map[string]any) int
		response func(int) map[string]any
	}{
		{
			protocol: "cohere", limit: cohereEmbeddingBatchLimit,
			count: func(body map[string]any) int { return len(body["texts"].([]any)) },
			response: func(n int) map[string]any {
				vectors := make([][]float32, n)
				for i := range vectors {
					vectors[i] = []float32{float32(i), 2, 3}
				}
				return map[string]any{"embeddings": map[string]any{"float": vectors}}
			},
		},
		{
			protocol: "voyage", limit: voyageEmbeddingBatchLimit,
			count: func(body map[string]any) int { return len(body["input"].([]any)) },
			response: func(n int) map[string]any {
				data := make([]map[string]any, n)
				for i := range data {
					data[i] = map[string]any{"index": i, "embedding": []float32{float32(i), 2, 3}}
				}
				return map[string]any{"object": "list", "data": data}
			},
		},
		{
			protocol: "google", limit: googleEmbeddingBatchLimit,
			count: func(body map[string]any) int { return len(body["requests"].([]any)) },
			response: func(n int) map[string]any {
				embeddings := make([]map[string]any, n)
				for i := range embeddings {
					embeddings[i] = map[string]any{"values": []float32{float32(i), 2, 3}}
				}
				return map[string]any{"embeddings": embeddings}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.protocol, func(t *testing.T) {
			calls := 0
			largest := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
					return
				}
				n := tc.count(body)
				if n > largest {
					largest = n
				}
				_ = json.NewEncoder(w).Encode(tc.response(n))
			}))
			defer upstream.Close()

			input := make([]string, tc.limit+5)
			for i := range input {
				input[i] = "text"
			}
			service := NewAIService(ServicesConfig{Embeddings: EmbeddingServiceConfig{
				Enabled: true, Route: "default", Revision: "r", Dimensions: 3,
				Upstream: UpstreamConfig{URL: upstream.URL, Protocol: tc.protocol, Model: "model", Timeout: time.Second},
			}})
			response, _, err := service.Embed(context.Background(), Principal{Issuer: "i", Subject: "s"}, input, "document")
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 || largest > tc.limit || len(response.Data) != len(input) {
				t.Fatalf("calls=%d largest=%d vectors=%d", calls, largest, len(response.Data))
			}
			for i, item := range response.Data {
				if item.Index != i {
					t.Fatalf("data[%d].index=%d", i, item.Index)
				}
			}
		})
	}
}

func TestAIServiceChunksCohereRerankAndSelectsGlobalTopN(t *testing.T) {
	calls := 0
	largest := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		documents := body["documents"].([]any)
		if len(documents) > largest {
			largest = len(documents)
		}
		if int(body["top_n"].(float64)) != len(documents) {
			t.Errorf("top_n=%v documents=%d", body["top_n"], len(documents))
		}
		score := 1.0
		if calls == 1 {
			score = 100
		}
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []any{
			map[string]any{"index": 0, "relevance_score": score},
		}})
	}))
	defer upstream.Close()

	documents := make([]string, cohereRerankBatchLimit+5)
	service := NewAIService(ServicesConfig{Rerank: RerankServiceConfig{
		Enabled: true, Route: "default", Revision: "r",
		Upstream: UpstreamConfig{URL: upstream.URL, Protocol: "cohere-v2", Model: "model", Timeout: time.Second},
	}})
	response, _, err := service.Rerank(context.Background(), Principal{Issuer: "i", Subject: "s"}, "query", documents, 1)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || largest != cohereRerankBatchLimit || len(response.Results) != 1 || response.Results[0].Index != cohereRerankBatchLimit {
		t.Fatalf("calls=%d largest=%d results=%v", calls, largest, response.Results)
	}
}

func TestAIServiceInitializesEnabledLocalBackendsAtStartupAndCachesByInputType(t *testing.T) {
	embedding := &fakeLocalEmbeddingBackend{}
	var embeddingInitializations atomic.Int32
	var rerankInitializations atomic.Int32
	service := NewAIService(ServicesConfig{
		Embeddings: EmbeddingServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "onnx", Model: "custom-embedding", Directory: "/embedding-models", Device: "cpu"}, Revision: "e1", Dimensions: localEmbeddingDimensions, Cache: CacheConfig{TTL: time.Minute, MaxEntries: 10}},
		Rerank:     RerankServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "onnx", Model: "custom-rerank", Directory: "/rerank-models", Device: "cuda", DeviceID: 2}, Revision: "r1", Cache: CacheConfig{TTL: time.Minute, MaxEntries: 10}},
	})
	service.newLocalEmbedding = func(_ context.Context, cfg UpstreamConfig) (localEmbeddingBackend, error) {
		if cfg.Device != "cpu" || cfg.Model != "custom-embedding" || cfg.resolvedModel == nil {
			t.Fatalf("embedding config=%#v", cfg)
		}
		embeddingInitializations.Add(1)
		return embedding, nil
	}
	service.newLocalRerank = func(_ context.Context, cfg UpstreamConfig) (localRerankBackend, error) {
		if cfg.Device != "cuda" || cfg.DeviceID != 2 || cfg.Model != "custom-rerank" || cfg.resolvedModel == nil {
			t.Fatalf("rerank config=%#v", cfg)
		}
		rerankInitializations.Add(1)
		return &fakeLocalRerankBackend{}, nil
	}
	service.prepareModel = func(_ context.Context, task string, cfg UpstreamConfig) (*ResolvedModel, error) {
		if cfg.Model != "custom-"+task || cfg.Directory != "/"+task+"-models" {
			t.Fatalf("model selection=%#v task=%s", cfg, task)
		}
		model := &ResolvedModel{Manifest: ModelManifest{ID: "fake-" + task, Task: task}, Identity: task + "-identity"}
		if task == "embedding" {
			model.Dimensions = localEmbeddingDimensions
		}
		return model, nil
	}
	if embeddingInitializations.Load() != 0 || rerankInitializations.Load() != 0 {
		t.Fatal("local backend initialized during service construction")
	}
	if err := service.InitializeLocal(context.Background()); err != nil {
		t.Fatalf("InitializeLocal: %v", err)
	}
	if embeddingInitializations.Load() != 1 || rerankInitializations.Load() != 1 {
		t.Fatalf("startup initializations: embedding=%d rerank=%d", embeddingInitializations.Load(), rerankInitializations.Load())
	}
	effective := service.EffectiveServices()
	if !strings.Contains(effective.Embeddings.Revision, "embedding-identity") || !strings.Contains(effective.Rerank.Revision, "rerank-identity") || effective.Embeddings.Dimensions != localEmbeddingDimensions {
		t.Fatalf("effective local service configuration=%#v", effective)
	}
	principal := Principal{Issuer: "i", Subject: "s"}
	if _, cached, err := service.Embed(context.Background(), principal, []string{"text"}, "document"); err != nil || cached {
		t.Fatalf("first local embed cached=%v err=%v", cached, err)
	}
	if _, cached, err := service.Embed(context.Background(), principal, []string{"text"}, "document"); err != nil || !cached {
		t.Fatalf("cached local embed cached=%v err=%v", cached, err)
	}
	if _, cached, err := service.Embed(context.Background(), principal, []string{"text"}, "query"); err != nil || cached {
		t.Fatalf("query local embed cached=%v err=%v", cached, err)
	}
	if embeddingInitializations.Load() != 1 || embedding.calls != 2 || embedding.inputType != "query" {
		t.Fatalf("embedding initializations=%d calls=%d input_type=%q", embeddingInitializations.Load(), embedding.calls, embedding.inputType)
	}
	response, _, err := service.Rerank(context.Background(), principal, "q", []string{"a", "b"}, 1)
	if err != nil || len(response.Results) != 1 || response.Results[0].Index != 1 || rerankInitializations.Load() != 1 {
		t.Fatalf("rerank response=%#v initializations=%d err=%v", response, rerankInitializations.Load(), err)
	}
}

func TestAIServiceStartupSkipsDisabledAndUpstreamModels(t *testing.T) {
	var embeddingInitializations atomic.Int32
	var rerankInitializations atomic.Int32
	service := NewAIService(ServicesConfig{
		Embeddings: EmbeddingServiceConfig{Enabled: false, Upstream: UpstreamConfig{Protocol: "onnx"}},
		Rerank:     RerankServiceConfig{Enabled: true, Upstream: UpstreamConfig{Protocol: "cohere-v2"}},
	})
	service.prepareModel = func(context.Context, string, UpstreamConfig) (*ResolvedModel, error) {
		t.Fatal("inactive ONNX catalog was accessed")
		return nil, nil
	}
	service.newLocalEmbedding = func(context.Context, UpstreamConfig) (localEmbeddingBackend, error) {
		embeddingInitializations.Add(1)
		return &fakeLocalEmbeddingBackend{}, nil
	}
	service.newLocalRerank = func(context.Context, UpstreamConfig) (localRerankBackend, error) {
		rerankInitializations.Add(1)
		return &fakeLocalRerankBackend{}, nil
	}
	if err := service.InitializeLocal(context.Background()); err != nil {
		t.Fatalf("InitializeLocal: %v", err)
	}
	if embeddingInitializations.Load() != 0 || rerankInitializations.Load() != 0 {
		t.Fatalf("unexpected initializations: embedding=%d rerank=%d", embeddingInitializations.Load(), rerankInitializations.Load())
	}
}
