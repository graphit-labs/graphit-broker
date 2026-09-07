package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
		Upstream: HTTPUpstreamConfig{URL: upstream.URL, Protocol: "openai-embeddings-v1", Model: "internal-model", APIKey: "upstream-secret", Timeout: time.Second},
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
	service := NewAIService(ServicesConfig{Embeddings: EmbeddingServiceConfig{Enabled: true, Revision: "r", Dimensions: 3, Upstream: HTTPUpstreamConfig{URL: upstream.URL, Protocol: "openai-embeddings-v1", Model: "m", Timeout: time.Second}}})
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
			service := NewAIService(ServicesConfig{Rerank: RerankServiceConfig{Enabled: true, Route: "default", Revision: "r1", Upstream: HTTPUpstreamConfig{URL: upstream.URL, Protocol: tc.protocol, Model: "internal", Timeout: time.Second}}})
			response, _, err := service.Rerank(context.Background(), Principal{Issuer: "i", Subject: "s"}, "q", []string{"a", "b"}, 1)
			if err != nil || len(response.Results) != 1 || response.Results[0].Index != 1 {
				t.Fatalf("response=%#v err=%v", response, err)
			}
		})
	}
}
