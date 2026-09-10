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
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
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
	embeddingCfg      EmbeddingServiceConfig
	rerankCfg         RerankServiceConfig
	s3Cfg             S3ServiceConfig
	embeddingHTTP     *http.Client
	rerankHTTP        *http.Client
	embeddingCache    *responseCache
	rerankCache       *responseCache
	localMu           sync.Mutex
	localEmbedding    localEmbeddingBackend
	localRerank       localRerankBackend
	newLocalEmbedding func(context.Context, UpstreamConfig) (localEmbeddingBackend, error)
	newLocalRerank    func(context.Context, UpstreamConfig) (localRerankBackend, error)
	modelCatalog      *ModelCatalog
	prepareModel      func(context.Context, string, UpstreamConfig) (*ResolvedModel, error)
}

func NewAIService(cfg ServicesConfig) *AIService {
	cfg.Embeddings.setDefaults()
	cfg.Rerank.setDefaults()
	return &AIService{
		embeddingCfg: cfg.Embeddings, rerankCfg: cfg.Rerank, s3Cfg: cfg.S3,
		embeddingHTTP:     &http.Client{Timeout: cfg.Embeddings.Upstream.Timeout},
		rerankHTTP:        &http.Client{Timeout: cfg.Rerank.Upstream.Timeout},
		embeddingCache:    newResponseCache(cfg.Embeddings.Cache),
		rerankCache:       newResponseCache(cfg.Rerank.Cache),
		newLocalEmbedding: newONNXEmbeddingBackend,
		newLocalRerank:    newONNXRerankBackend,
		modelCatalog:      NewModelCatalog(),
	}
}

func (s *AIService) Close() error {
	if s == nil {
		return nil
	}
	s.localMu.Lock()
	defer s.localMu.Unlock()
	var firstErr error
	if s.localEmbedding != nil {
		firstErr = s.localEmbedding.Close()
		s.localEmbedding = nil
	}
	if s.localRerank != nil {
		if err := s.localRerank.Close(); firstErr == nil {
			firstErr = err
		}
		s.localRerank = nil
	}
	return firstErr
}

// InitializeLocal loads only the enabled local backends. Constructors perform
// verified on-demand acquisition, so upstream and disabled services never touch
// the model cache while a local service is fully ready before the server listens.
func (s *AIService) InitializeLocal(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.embeddingCfg.Enabled && s.embeddingCfg.Upstream.isONNX() {
		model, err := s.prepareLocalModel(ctx, "embedding", s.embeddingCfg.Upstream)
		if err != nil {
			return fmt.Errorf("prepare local embeddings: %w", err)
		}
		if s.embeddingCfg.Dimensions > 0 && s.embeddingCfg.Dimensions != model.Dimensions {
			return fmt.Errorf("services.embeddings.dimensions %d conflicts with model %q dimensions %d", s.embeddingCfg.Dimensions, model.Manifest.ID, model.Dimensions)
		}
		s.embeddingCfg.Dimensions = model.Dimensions
		s.embeddingCfg.Revision = effectiveModelRevision(s.embeddingCfg.Revision, model)
		s.embeddingCfg.Upstream.resolvedModel = model
		if _, err := s.ensureLocalEmbedding(ctx); err != nil {
			return fmt.Errorf("initialize local embeddings: %w", err)
		}
	}
	if s.rerankCfg.Enabled && s.rerankCfg.Upstream.isONNX() {
		model, err := s.prepareLocalModel(ctx, "rerank", s.rerankCfg.Upstream)
		if err != nil {
			_ = s.Close()
			return fmt.Errorf("prepare local rerank: %w", err)
		}
		s.rerankCfg.Revision = effectiveModelRevision(s.rerankCfg.Revision, model)
		s.rerankCfg.Upstream.resolvedModel = model
		if _, err := s.ensureLocalRerank(ctx); err != nil {
			_ = s.Close()
			return fmt.Errorf("initialize local rerank: %w", err)
		}
	}
	return nil
}

func (s *AIService) prepareLocalModel(ctx context.Context, task string, local UpstreamConfig) (*ResolvedModel, error) {
	if s.prepareModel != nil {
		return s.prepareModel(ctx, task, local)
	}
	model, err := s.modelCatalog.Resolve(ctx, task, local, resolveForRuntime)
	if err != nil {
		return nil, err
	}
	model.Inspection, err = inspectONNX(model.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("inspect model %q: %w", model.Manifest.ID, err)
	}
	if err := resolveModelSemantics(model); err != nil {
		return nil, fmt.Errorf("resolve model %q semantics: %w", model.Manifest.ID, err)
	}
	return model, nil
}

func effectiveModelRevision(configured string, model *ResolvedModel) string {
	prefix := strings.TrimSpace(configured)
	if prefix == "" {
		prefix = model.Manifest.ID
	}
	return prefix + "@sha256:" + model.Identity
}

func (s *AIService) EffectiveServices() ServicesConfig {
	if s == nil {
		return ServicesConfig{}
	}
	return ServicesConfig{Embeddings: s.embeddingCfg, Rerank: s.rerankCfg, S3: s.s3Cfg}
}

func (s *AIService) Embed(ctx context.Context, principal Principal, input []string, requestedType ...string) (EmbeddingResponse, bool, error) {
	cfg := s.embeddingCfg
	inputType := "document"
	if len(requestedType) > 0 && requestedType[0] != "" {
		inputType = requestedType[0]
	}
	key := scopedCacheKey(principal, cfg.Revision, struct {
		InputType string
		Input     []string
	}{inputType, input})
	if cached, ok := s.embeddingCache.Get(key); ok {
		var response EmbeddingResponse
		if json.Unmarshal(cached, &response) == nil {
			return response, true, nil
		}
	}
	var upstream embeddingBackendResponse
	var err error
	if cfg.Upstream.isONNX() {
		upstream, err = s.embedLocal(ctx, input, inputType)
	} else {
		upstream, err = embedUpstream(ctx, s.embeddingHTTP, cfg, input, inputType)
	}
	if err != nil {
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

type embeddingBackendResponse struct {
	Object string
	Data   []EmbeddingData
	Usage  json.RawMessage
}

const (
	cohereEmbeddingBatchLimit = 96
	voyageEmbeddingBatchLimit = 128
	googleEmbeddingBatchLimit = 100
	cohereRerankBatchLimit    = 200
)

func (s *AIService) embedLocal(ctx context.Context, input []string, inputType string) (embeddingBackendResponse, error) {
	backend, err := s.ensureLocalEmbedding(ctx)
	if err != nil {
		return embeddingBackendResponse{}, err
	}
	vectors, err := backend.Embed(ctx, input, inputType)
	if err != nil {
		return embeddingBackendResponse{}, err
	}
	data := make([]EmbeddingData, len(vectors))
	for i, vector := range vectors {
		data[i] = EmbeddingData{Object: "embedding", Embedding: vector, Index: i}
	}
	return embeddingBackendResponse{Object: "list", Data: data}, nil
}

func (s *AIService) ensureLocalEmbedding(ctx context.Context) (localEmbeddingBackend, error) {
	s.localMu.Lock()
	defer s.localMu.Unlock()
	backend := s.localEmbedding
	if backend == nil {
		var err error
		backend, err = s.newLocalEmbedding(ctx, s.embeddingCfg.Upstream)
		if err != nil {
			return nil, err
		}
		s.localEmbedding = backend
	}
	return backend, nil
}

func embedUpstream(ctx context.Context, client *http.Client, cfg EmbeddingServiceConfig, input []string, inputType string) (embeddingBackendResponse, error) {
	protocol := strings.ToLower(strings.TrimSpace(cfg.Upstream.Protocol))
	switch protocol {
	case "openai", "openai-compatible", "openai-embeddings-v1":
		body := map[string]any{"model": cfg.Upstream.Model, "input": input}
		if cfg.Upstream.SendDimensions {
			body["dimensions"] = cfg.Dimensions
		}
		var response struct {
			Object string          `json:"object"`
			Data   []EmbeddingData `json:"data"`
			Usage  json.RawMessage `json:"usage"`
		}
		if err := doUpstreamJSON(ctx, client, "embeddings", cfg.Upstream, body, &response); err != nil {
			return embeddingBackendResponse{}, err
		}
		return embeddingBackendResponse{Object: response.Object, Data: response.Data, Usage: response.Usage}, nil
	case "cohere", "cohere-embed-v2":
		providerType := "search_document"
		if inputType == "query" {
			providerType = "search_query"
		}
		data := make([]EmbeddingData, 0, len(input))
		for start := 0; start < len(input); start += cohereEmbeddingBatchLimit {
			end := min(start+cohereEmbeddingBatchLimit, len(input))
			body := map[string]any{"model": cfg.Upstream.Model, "texts": input[start:end], "input_type": providerType, "embedding_types": []string{"float"}}
			var response struct {
				Embeddings struct {
					Float [][]float32 `json:"float"`
				} `json:"embeddings"`
			}
			if err := doUpstreamJSON(ctx, client, "embeddings", cfg.Upstream, body, &response); err != nil {
				return embeddingBackendResponse{}, err
			}
			for i, vector := range response.Embeddings.Float {
				data = append(data, EmbeddingData{Object: "embedding", Embedding: vector, Index: start + i})
			}
		}
		return embeddingBackendResponse{Object: "list", Data: data}, nil
	case "voyage", "voyage-embeddings-v1":
		providerType := "document"
		if inputType == "query" {
			providerType = "query"
		}
		result := embeddingBackendResponse{Object: "list", Data: make([]EmbeddingData, 0, len(input))}
		for start := 0; start < len(input); start += voyageEmbeddingBatchLimit {
			end := min(start+voyageEmbeddingBatchLimit, len(input))
			body := map[string]any{"model": cfg.Upstream.Model, "input": input[start:end], "input_type": providerType}
			var response struct {
				Object string          `json:"object"`
				Data   []EmbeddingData `json:"data"`
				Usage  json.RawMessage `json:"usage"`
			}
			if err := doUpstreamJSON(ctx, client, "embeddings", cfg.Upstream, body, &response); err != nil {
				return embeddingBackendResponse{}, err
			}
			result.Object = firstNonEmpty(response.Object, result.Object)
			result.Usage = response.Usage
			for _, item := range response.Data {
				item.Index += start
				result.Data = append(result.Data, item)
			}
		}
		return result, nil
	case "google", "google-embed-content-v1beta", "gemini", "gemini-embed-content-v1beta":
		taskType := "RETRIEVAL_DOCUMENT"
		if inputType == "query" {
			taskType = "RETRIEVAL_QUERY"
		}
		modelName := strings.TrimPrefix(cfg.Upstream.Model, "models/")
		modelPath := "models/" + modelName
		geminiEmbedding2 := strings.HasPrefix(strings.ToLower(modelName), "gemini-embedding-2")
		googleCfg := cfg.Upstream
		googleCfg.URL = googleEmbeddingURL(googleCfg.URL, cfg.Upstream.Model)
		data := make([]EmbeddingData, 0, len(input))
		for start := 0; start < len(input); start += googleEmbeddingBatchLimit {
			end := min(start+googleEmbeddingBatchLimit, len(input))
			requests := make([]map[string]any, end-start)
			for i, text := range input[start:end] {
				if geminiEmbedding2 {
					switch inputType {
					case "query":
						text = "task: search result | query: " + text
					case "document":
						text = "title: none | text: " + text
					}
				}
				item := map[string]any{
					"model":   modelPath,
					"content": map[string]any{"parts": []map[string]string{{"text": text}}},
				}
				if !geminiEmbedding2 {
					item["embedContentConfig"] = map[string]any{"taskType": taskType}
				}
				if cfg.Upstream.SendDimensions {
					if geminiEmbedding2 {
						item["outputDimensionality"] = cfg.Dimensions
					} else {
						item["embedContentConfig"].(map[string]any)["outputDimensionality"] = cfg.Dimensions
					}
				}
				requests[i] = item
			}
			var response struct {
				Embeddings []struct {
					Values []float32 `json:"values"`
				} `json:"embeddings"`
			}
			if err := doUpstreamJSON(ctx, client, "embeddings", googleCfg, map[string]any{"requests": requests}, &response); err != nil {
				return embeddingBackendResponse{}, err
			}
			for i := range response.Embeddings {
				data = append(data, EmbeddingData{Object: "embedding", Embedding: response.Embeddings[i].Values, Index: start + i})
			}
		}
		return embeddingBackendResponse{Object: "list", Data: data}, nil
	default:
		return embeddingBackendResponse{}, fmt.Errorf("unsupported embedding protocol %q", cfg.Upstream.Protocol)
	}
}

func googleEmbeddingURL(base, model string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.Contains(base, ":batchEmbedContents") {
		return base
	}
	return base + "/models/" + url.PathEscape(strings.TrimPrefix(model, "models/")) + ":batchEmbedContents"
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
	var results []RerankResult
	if cfg.Upstream.isONNX() {
		var err error
		results, err = s.rerankLocal(ctx, query, documents)
		if err != nil {
			return RerankResponse{}, false, err
		}
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].RelevanceScore == results[j].RelevanceScore {
				return results[i].Index < results[j].Index
			}
			return results[i].RelevanceScore > results[j].RelevanceScore
		})
		if len(results) > topN {
			results = results[:topN]
		}
	} else {
		var err error
		results, err = rerankUpstream(ctx, s.rerankHTTP, cfg, query, documents, topN)
		if err != nil {
			return RerankResponse{}, false, err
		}
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

func (s *AIService) rerankLocal(ctx context.Context, query string, documents []string) ([]RerankResult, error) {
	backend, err := s.ensureLocalRerank(ctx)
	if err != nil {
		return nil, err
	}
	scores, err := backend.Score(ctx, query, documents)
	if err != nil {
		return nil, err
	}
	if len(scores) != len(documents) {
		return nil, fmt.Errorf("local reranker returned %d scores for %d documents", len(scores), len(documents))
	}
	results := make([]RerankResult, len(scores))
	for i, score := range scores {
		results[i] = RerankResult{Index: i, RelevanceScore: score}
	}
	return results, nil
}

func (s *AIService) ensureLocalRerank(ctx context.Context) (localRerankBackend, error) {
	s.localMu.Lock()
	defer s.localMu.Unlock()
	backend := s.localRerank
	if backend == nil {
		var err error
		backend, err = s.newLocalRerank(ctx, s.rerankCfg.Upstream)
		if err != nil {
			return nil, err
		}
		s.localRerank = backend
	}
	return backend, nil
}

func rerankUpstream(ctx context.Context, client *http.Client, cfg RerankServiceConfig, query string, documents []string, topN int) ([]RerankResult, error) {
	request := map[string]any{"model": cfg.Upstream.Model, "query": query, "documents": documents}
	protocol := strings.ToLower(strings.TrimSpace(cfg.Upstream.Protocol))
	if protocol == "voyage" || protocol == "voyage-v1" {
		request["top_k"] = topN
	} else {
		request["top_n"] = topN
	}
	var results []RerankResult
	switch protocol {
	case "openai", "openai-compatible", "openai-embeddings-v1", "cohere-embed-v2", "voyage-embeddings-v1", "google", "google-embed-content-v1beta", "gemini", "gemini-embed-content-v1beta":
		return rerankWithEmbeddings(ctx, client, cfg, query, documents, topN)
	case "cohere", "cohere-v2":
		results = make([]RerankResult, 0, len(documents))
		for start := 0; start < len(documents); start += cohereRerankBatchLimit {
			end := min(start+cohereRerankBatchLimit, len(documents))
			chunkRequest := map[string]any{
				"model": cfg.Upstream.Model, "query": query, "documents": documents[start:end], "top_n": end - start,
			}
			var response struct {
				Results []RerankResult `json:"results"`
			}
			if err := doUpstreamJSON(ctx, client, "rerank", cfg.Upstream, chunkRequest, &response); err != nil {
				return nil, err
			}
			for _, result := range response.Results {
				result.Index += start
				results = append(results, result)
			}
		}
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].RelevanceScore == results[j].RelevanceScore {
				return results[i].Index < results[j].Index
			}
			return results[i].RelevanceScore > results[j].RelevanceScore
		})
		if len(results) > topN {
			results = results[:topN]
		}
	case "jina", "jina-v1", "graphit-rerank-v1":
		var response struct {
			Results []RerankResult `json:"results"`
		}
		if err := doUpstreamJSON(ctx, client, "rerank", cfg.Upstream, request, &response); err != nil {
			return nil, err
		}
		results = response.Results
	case "voyage", "voyage-v1":
		var response struct {
			Data []RerankResult `json:"data"`
		}
		if err := doUpstreamJSON(ctx, client, "rerank", cfg.Upstream, request, &response); err != nil {
			return nil, err
		}
		results = response.Data
	default:
		return nil, fmt.Errorf("unsupported rerank protocol %q", cfg.Upstream.Protocol)
	}
	return results, nil
}

func rerankWithEmbeddings(ctx context.Context, client *http.Client, cfg RerankServiceConfig, query string, documents []string, topN int) ([]RerankResult, error) {
	embeddingCfg := EmbeddingServiceConfig{Upstream: cfg.Upstream}
	queryResponse, err := embedUpstream(ctx, client, embeddingCfg, []string{query}, "query")
	if err != nil {
		return nil, err
	}
	queryVectors, err := orderedEmbeddingVectors(queryResponse, 1)
	if err != nil {
		return nil, fmt.Errorf("rerank query embeddings: %w", err)
	}
	documentResponse, err := embedUpstream(ctx, client, embeddingCfg, documents, "document")
	if err != nil {
		return nil, err
	}
	documentVectors, err := orderedEmbeddingVectors(documentResponse, len(documents))
	if err != nil {
		return nil, fmt.Errorf("rerank document embeddings: %w", err)
	}
	if len(queryVectors[0]) != len(documentVectors[0]) {
		return nil, fmt.Errorf("rerank embedding dimensions differ: query has %d and documents have %d", len(queryVectors[0]), len(documentVectors[0]))
	}
	results := make([]RerankResult, len(documentVectors))
	for i, vector := range documentVectors {
		score, err := cosineSimilarity(queryVectors[0], vector)
		if err != nil {
			return nil, fmt.Errorf("rerank document %d: %w", i, err)
		}
		results[i] = RerankResult{Index: i, RelevanceScore: score}
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].RelevanceScore == results[j].RelevanceScore {
			return results[i].Index < results[j].Index
		}
		return results[i].RelevanceScore > results[j].RelevanceScore
	})
	if len(results) > topN {
		results = results[:topN]
	}
	return results, nil
}

func orderedEmbeddingVectors(response embeddingBackendResponse, expected int) ([][]float32, error) {
	if len(response.Data) != expected {
		return nil, fmt.Errorf("provider returned %d vectors for %d inputs", len(response.Data), expected)
	}
	vectors := make([][]float32, expected)
	width := 0
	for _, item := range response.Data {
		if item.Index < 0 || item.Index >= expected || vectors[item.Index] != nil {
			return nil, errors.New("provider returned an invalid or duplicate embedding index")
		}
		if len(item.Embedding) == 0 {
			return nil, errors.New("provider returned an empty embedding")
		}
		if width == 0 {
			width = len(item.Embedding)
		} else if len(item.Embedding) != width {
			return nil, errors.New("provider returned inconsistent embedding dimensions")
		}
		for _, value := range item.Embedding {
			if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
				return nil, errors.New("provider returned a non-finite embedding value")
			}
		}
		vectors[item.Index] = item.Embedding
	}
	return vectors, nil
}

func cosineSimilarity(a, b []float32) (float64, error) {
	if len(a) == 0 || len(a) != len(b) {
		return 0, errors.New("embedding vectors must have the same non-zero dimensions")
	}
	var dot, normA, normB float64
	for i := range a {
		av := float64(a[i])
		bv := float64(b[i])
		dot += av * bv
		normA += av * av
		normB += bv * bv
	}
	if normA == 0 || normB == 0 {
		return 0, errors.New("embedding vectors must have non-zero magnitude")
	}
	score := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, errors.New("embedding similarity is not finite")
	}
	if score > 1 {
		score = 1
	} else if score < -1 {
		score = -1
	}
	return score, nil
}

func doUpstreamJSON(ctx context.Context, client *http.Client, service string, cfg UpstreamConfig, input, output any) error {
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
		header := cfg.APIKeyHeader
		scheme := cfg.APIKeyScheme
		protocol := strings.ToLower(strings.TrimSpace(cfg.Protocol))
		google := protocol == "google" || protocol == "google-embed-content-v1beta" || protocol == "gemini" || protocol == "gemini-embed-content-v1beta"
		if header == "" {
			if google {
				header = "x-goog-api-key"
			} else {
				header = "Authorization"
			}
		}
		if scheme == "" && !google {
			scheme = "Bearer"
		}
		value := cfg.APIKey
		if scheme = strings.TrimSpace(scheme); scheme != "" {
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
