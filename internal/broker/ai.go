package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

type UpstreamError struct {
	Service string
	Status  int
	Message string
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("%s upstream returned HTTP %d: %s", e.Service, e.Status, e.Message)
}

type EmbeddingData struct {
	Object    string    `json:"object,omitempty"`
	Embedding []float32 `json:"embedding"`
	Index     int       `json:"index"`
}

type EmbeddingMetadata struct {
	Revision   string `json:"revision"`
	Dimensions int    `json:"dimensions"`
}

type EmbeddingResponse struct {
	Object  string            `json:"object,omitempty"`
	Data    []EmbeddingData   `json:"data"`
	Model   string            `json:"model"`
	Usage   json.RawMessage   `json:"usage,omitempty"`
	Graphit EmbeddingMetadata `json:"graphit"`
}

type RerankResult struct {
	Index          int     `json:"index"`
	RelevanceScore float64 `json:"relevance_score"`
}

type RerankResponse struct {
	Results []RerankResult `json:"results"`
	Graphit struct {
		Revision string `json:"revision"`
	} `json:"graphit"`
}

type AIService struct {
	embeddingCfg   EmbeddingServiceConfig
	rerankCfg      RerankServiceConfig
	embeddingHTTP  *http.Client
	rerankHTTP     *http.Client
	embeddingCache *responseCache
	rerankCache    *responseCache
}

func NewAIService(cfg ServicesConfig) *AIService {
	return &AIService{
		embeddingCfg: cfg.Embeddings, rerankCfg: cfg.Rerank,
		embeddingHTTP:  &http.Client{Timeout: cfg.Embeddings.Upstream.Timeout},
		rerankHTTP:     &http.Client{Timeout: cfg.Rerank.Upstream.Timeout},
		embeddingCache: newResponseCache(cfg.Embeddings.Cache),
		rerankCache:    newResponseCache(cfg.Rerank.Cache),
	}
}

func (s *AIService) Embed(ctx context.Context, principal Principal, input []string) (EmbeddingResponse, bool, error) {
	cfg := s.embeddingCfg
	key := scopedCacheKey(principal, cfg.Revision, input)
	if cached, ok := s.embeddingCache.Get(key); ok {
		var response EmbeddingResponse
		if json.Unmarshal(cached, &response) == nil {
			return response, true, nil
		}
	}
	body := map[string]any{"model": cfg.Upstream.Model, "input": input}
	if cfg.Upstream.SendDimensions {
		body["dimensions"] = cfg.Dimensions
	}
	var upstream struct {
		Object string          `json:"object"`
		Data   []EmbeddingData `json:"data"`
		Usage  json.RawMessage `json:"usage"`
	}
	if err := doUpstreamJSON(ctx, s.embeddingHTTP, "embeddings", cfg.Upstream, body, &upstream); err != nil {
		return EmbeddingResponse{}, false, err
	}
	if len(upstream.Data) != len(input) {
		return EmbeddingResponse{}, false, fmt.Errorf("embedding upstream returned %d vectors for %d inputs", len(upstream.Data), len(input))
	}
	seen := make([]bool, len(input))
	for _, item := range upstream.Data {
		if item.Index < 0 || item.Index >= len(input) || seen[item.Index] {
			return EmbeddingResponse{}, false, errors.New("embedding upstream returned an invalid or duplicate index")
		}
		if len(item.Embedding) != cfg.Dimensions {
			return EmbeddingResponse{}, false, fmt.Errorf("embedding upstream returned %d dimensions, expected %d", len(item.Embedding), cfg.Dimensions)
		}
		seen[item.Index] = true
	}
	sort.Slice(upstream.Data, func(i, j int) bool { return upstream.Data[i].Index < upstream.Data[j].Index })
	response := EmbeddingResponse{Object: firstNonEmpty(upstream.Object, "list"), Data: upstream.Data, Model: cfg.Route, Usage: upstream.Usage,
		Graphit: EmbeddingMetadata{Revision: cfg.Revision, Dimensions: cfg.Dimensions}}
	if encoded, err := json.Marshal(response); err == nil {
		s.embeddingCache.Put(key, encoded)
	}
	return response, false, nil
}

func (s *AIService) Rerank(ctx context.Context, principal Principal, query string, documents []string, topN int) (RerankResponse, bool, error) {
	cfg := s.rerankCfg
	key := scopedCacheKey(principal, cfg.Revision, struct {
		Query     string
		Documents []string
		TopN      int
	}{query, documents, topN})
	if cached, ok := s.rerankCache.Get(key); ok {
		var response RerankResponse
		if json.Unmarshal(cached, &response) == nil {
			return response, true, nil
		}
	}
	request := map[string]any{"model": cfg.Upstream.Model, "query": query, "documents": documents}
	if cfg.Upstream.Protocol == "voyage-v1" {
		request["top_k"] = topN
	} else {
		request["top_n"] = topN
	}
	var results []RerankResult
	switch cfg.Upstream.Protocol {
	case "cohere-v2", "jina-v1", "graphit-rerank-v1":
		var response struct {
			Results []RerankResult `json:"results"`
		}
		if err := doUpstreamJSON(ctx, s.rerankHTTP, "rerank", cfg.Upstream, request, &response); err != nil {
			return RerankResponse{}, false, err
		}
		results = response.Results
	case "voyage-v1":
		var response struct {
			Data []RerankResult `json:"data"`
		}
		if err := doUpstreamJSON(ctx, s.rerankHTTP, "rerank", cfg.Upstream, request, &response); err != nil {
			return RerankResponse{}, false, err
		}
		results = response.Data
	default:
		return RerankResponse{}, false, fmt.Errorf("unsupported rerank protocol %q", cfg.Upstream.Protocol)
	}
	if len(results) > topN {
		return RerankResponse{}, false, errors.New("rerank upstream returned more results than requested")
	}
	seen := map[int]struct{}{}
	for _, result := range results {
		if result.Index < 0 || result.Index >= len(documents) {
			return RerankResponse{}, false, errors.New("rerank upstream returned an out-of-range index")
		}
		if _, exists := seen[result.Index]; exists {
			return RerankResponse{}, false, errors.New("rerank upstream returned a duplicate index")
		}
		seen[result.Index] = struct{}{}
	}
	response := RerankResponse{Results: results}
	response.Graphit.Revision = cfg.Revision
	if encoded, err := json.Marshal(response); err == nil {
		s.rerankCache.Put(key, encoded)
	}
	return response, false, nil
}

func doUpstreamJSON(ctx context.Context, client *http.Client, service string, cfg HTTPUpstreamConfig, input, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode %s request: %w", service, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create %s request: %w", service, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if cfg.APIKey != "" {
		header := firstNonEmpty(cfg.APIKeyHeader, "Authorization")
		value := cfg.APIKey
		if scheme := firstNonEmpty(cfg.APIKeyScheme, "Bearer"); scheme != "" {
			value = scheme + " " + value
		}
		req.Header.Set(header, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call %s upstream: %w", service, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &UpstreamError{Service: service, Status: resp.StatusCode, Message: "upstream request failed"}
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode %s upstream response: %w", service, err)
	}
	return nil
}

func scopedCacheKey(principal Principal, revision string, value any) string {
	encoded, _ := json.Marshal(value)
	h := sha256.New()
	_, _ = io.WriteString(h, principal.CanonicalSubject())
	_, _ = io.WriteString(h, "\x00"+principal.Organization+"\x00"+revision+"\x00")
	_, _ = h.Write(encoded)
	return hex.EncodeToString(h.Sum(nil))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
