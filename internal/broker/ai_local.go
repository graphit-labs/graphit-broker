package broker

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	tokenizer "github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	ort "github.com/yalue/onnxruntime_go"
)

const (
	localEmbeddingDimensions = 768
	localEmbeddingMaxLength  = 512
	localRerankMaxLength     = 512
	localRerankBatchSize     = 16
	localQueryPrefix         = "Represent this query for searching relevant code: "
)

var (
	embeddingModelArtifact = modelArtifact{
		Name: "model.onnx", URL: "https://huggingface.co/mrsladoje/CodeRankEmbed-onnx-int8/resolve/main/onnx/model.onnx",
		SHA256: "4eae31d09b1843103a1ebd5e2b2e24b5a5cad441a33906b35b12b1e2ed91d1db", Size: 138619279,
	}
	embeddingTokenizerArtifact = modelArtifact{
		Name: "tokenizer.json", URL: "https://huggingface.co/mrsladoje/CodeRankEmbed-onnx-int8/resolve/main/tokenizer.json",
		SHA256: "91f1def9b9391fdabe028cd3f3fcc4efd34e5d1f08c3bf2de513ebb5911a1854", Size: 711649,
	}
	rerankModelArtifact = modelArtifact{
		Name: "model.onnx", URL: "https://huggingface.co/BAAI/bge-reranker-base/resolve/main/onnx/model.onnx",
		SHA256: "15b9a8c3da82eddf263df571281166e00e9308fe19d077084b642ebfcaf06d2b", Size: 1112459588,
	}
	rerankTokenizerArtifact = modelArtifact{
		Name: "tokenizer.json", URL: "https://huggingface.co/BAAI/bge-reranker-base/resolve/main/tokenizer.json",
		SHA256: "9eb652ac4e40cc093272bbbe0f55d521cf67570060227109b5cdc20945a4489e", Size: 17098107,
	}
)

type localEmbeddingBackend interface {
	Embed(context.Context, []string, string) ([][]float32, error)
	Close() error
}

type localRerankBackend interface {
	Score(context.Context, string, []string) ([]float64, error)
	Close() error
}

type textEncoder interface {
	EncodeSingle(string, ...bool) (*tokenizer.Encoding, error)
}

type pairEncoder interface {
	EncodePair(string, string, ...bool) (*tokenizer.Encoding, error)
}

type onnxEmbeddingBackend struct {
	tokenizer   textEncoder
	session     *ort.DynamicAdvancedSession
	inputNames  []string
	device      string
	dimensions  int
	maxLength   int
	queryPrefix string
	mu          sync.Mutex
}

type onnxRerankBackend struct {
	tokenizer  pairEncoder
	session    *ort.DynamicAdvancedSession
	inputNames []string
	device     string
	maxLength  int
	mu         sync.Mutex
}

var (
	onnxInitOnce sync.Once
	onnxInitErr  error
)

func initializeONNXRuntime() error {
	onnxInitOnce.Do(func() {
		path := strings.TrimSpace(os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH"))
		if path == "" {
			for _, candidate := range onnxRuntimeCandidates() {
				if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
					path = candidate
					break
				}
			}
		}
		if path == "" {
			onnxInitErr = fmt.Errorf("ONNX Runtime shared library is unavailable; set ONNXRUNTIME_SHARED_LIBRARY_PATH")
			return
		}
		ort.SetSharedLibraryPath(path)
		if err := ort.InitializeEnvironment(); err != nil {
			onnxInitErr = fmt.Errorf("initialize ONNX Runtime from %s: %w", path, err)
		}
	})
	return onnxInitErr
}

func onnxRuntimeCandidates() []string {
	names := []string{"libonnxruntime.so.1.29.0", "libonnxruntime.so"}
	system := []string{
		"/opt/onnxruntime/lib/libonnxruntime.so.1.29.0",
		"/opt/onnxruntime/lib/libonnxruntime.so",
		"/usr/local/lib/libonnxruntime.so",
	}
	switch runtime.GOOS {
	case "darwin":
		names = []string{"libonnxruntime.1.29.0.dylib", "libonnxruntime.dylib"}
		system = []string{"/usr/local/lib/libonnxruntime.dylib", "/opt/homebrew/lib/libonnxruntime.dylib"}
	case "windows":
		names = []string{"onnxruntime.dll"}
		system = nil
	}
	if executable, err := os.Executable(); err == nil {
		dir := filepath.Dir(executable)
		candidates := make([]string, 0, len(names)*2+len(system))
		for _, name := range names {
			candidates = append(candidates, filepath.Join(dir, "lib", name), filepath.Join(dir, name))
		}
		return append(candidates, system...)
	}
	return system
}

func newONNXEmbeddingBackend(ctx context.Context, cfg LocalModelConfig) (localEmbeddingBackend, error) {
	paths, operatorProvided, err := resolveLocalModelBundle(ctx, cfg, embeddingModelArtifact, embeddingTokenizerArtifact)
	if err != nil {
		return nil, fmt.Errorf("prepare local embedding model: %w", err)
	}
	if err := initializeONNXRuntime(); err != nil {
		return nil, err
	}
	tk, err := pretrained.FromFile(paths[1])
	if err != nil {
		return nil, fmt.Errorf("load local embedding tokenizer: %w", err)
	}
	inputs, outputs, err := ort.GetInputOutputInfo(paths[0])
	if err != nil {
		return nil, fmt.Errorf("read local embedding model signature: %w", err)
	}
	if len(outputs) == 0 {
		return nil, fmt.Errorf("local embedding model declares no output")
	}
	inputNames := make([]string, len(inputs))
	for i := range inputs {
		switch inputs[i].Name {
		case "input_ids", "attention_mask", "token_type_ids":
			inputNames[i] = inputs[i].Name
		default:
			return nil, fmt.Errorf("local embedding model requires unsupported input %q", inputs[i].Name)
		}
	}
	outputName := strings.TrimSpace(cfg.OutputName)
	if outputName == "" {
		if operatorProvided {
			outputName = outputs[0].Name
		} else {
			outputName = "sentence_embedding"
		}
	}
	session, device, err := newLocalONNXSession(paths[0], inputNames, []string{outputName}, cfg)
	if err != nil {
		return nil, fmt.Errorf("create local embedding session: %w", err)
	}
	maxLength := cfg.MaxLength
	if maxLength == 0 {
		maxLength = localEmbeddingMaxLength
	}
	queryPrefix := cfg.QueryPrefix
	dimensions := cfg.Dimensions
	if dimensions == 0 {
		dimensions = localEmbeddingDimensions
	}
	modelName := paths[0]
	if !operatorProvided {
		modelName = "CodeRankEmbed-137M-INT8"
		if queryPrefix == "" {
			queryPrefix = localQueryPrefix
		}
	}
	slog.Info("local embedding model ready", "model", modelName, "device", device)
	return &onnxEmbeddingBackend{tokenizer: tk, session: session, inputNames: inputNames, device: device, dimensions: dimensions, maxLength: maxLength, queryPrefix: queryPrefix}, nil
}

func newONNXRerankBackend(ctx context.Context, cfg LocalModelConfig) (localRerankBackend, error) {
	paths, operatorProvided, err := resolveLocalModelBundle(ctx, cfg, rerankModelArtifact, rerankTokenizerArtifact)
	if err != nil {
		return nil, fmt.Errorf("prepare local rerank model: %w", err)
	}
	if err := initializeONNXRuntime(); err != nil {
		return nil, err
	}
	tk, err := pretrained.FromFile(paths[1])
	if err != nil {
		return nil, fmt.Errorf("load local rerank tokenizer: %w", err)
	}
	inputs, outputs, err := ort.GetInputOutputInfo(paths[0])
	if err != nil {
		return nil, fmt.Errorf("read local rerank model signature: %w", err)
	}
	if len(outputs) == 0 {
		return nil, fmt.Errorf("local rerank model declares no output")
	}
	inputNames := make([]string, len(inputs))
	for i := range inputs {
		inputNames[i] = inputs[i].Name
	}
	session, device, err := newLocalONNXSession(paths[0], inputNames, []string{outputs[0].Name}, cfg)
	if err != nil {
		return nil, fmt.Errorf("create local rerank session: %w", err)
	}
	maxLength := cfg.MaxLength
	if maxLength == 0 {
		maxLength = localRerankMaxLength
	}
	modelName := paths[0]
	if !operatorProvided {
		modelName = "bge-reranker-base"
	}
	slog.Info("local rerank model ready", "model", modelName, "device", device)
	return &onnxRerankBackend{tokenizer: tk, session: session, inputNames: inputNames, device: device, maxLength: maxLength}, nil
}

func newLocalONNXSession(modelPath string, inputNames, outputNames []string, cfg LocalModelConfig) (*ort.DynamicAdvancedSession, string, error) {
	devices := localDeviceCandidates(cfg.Device, cudaDeviceAvailable())
	var firstErr error
	for _, device := range devices {
		opts, err := ort.NewSessionOptions()
		if err != nil {
			return nil, "", err
		}
		_ = opts.SetInterOpNumThreads(1)
		_ = opts.SetIntraOpNumThreads(max(1, runtime.GOMAXPROCS(0)))
		if device == "cuda" {
			err = appendCUDAProvider(opts, cfg.DeviceID)
		}
		if err == nil {
			var session *ort.DynamicAdvancedSession
			session, err = ort.NewDynamicAdvancedSession(modelPath, inputNames, outputNames, opts)
			_ = opts.Destroy()
			if err == nil {
				return session, device, nil
			}
		} else {
			_ = opts.Destroy()
		}
		if firstErr == nil {
			firstErr = err
		}
		if cfg.Device == "auto" && device == "cuda" {
			slog.Warn("CUDA local inference unavailable; falling back to CPU", "error", err)
		}
	}
	if cfg.Device == "cuda" {
		return nil, "", fmt.Errorf("CUDA device %d was required but could not initialize: %w", cfg.DeviceID, firstErr)
	}
	return nil, "", firstErr
}

func localDeviceCandidates(device string, cudaAvailable bool) []string {
	switch device {
	case "cuda":
		return []string{"cuda"}
	case "auto":
		if cudaAvailable {
			return []string{"cuda", "cpu"}
		}
	}
	return []string{"cpu"}
}

func appendCUDAProvider(opts *ort.SessionOptions, deviceID int) error {
	cuda, err := ort.NewCUDAProviderOptions()
	if err != nil {
		return err
	}
	defer cuda.Destroy()
	if err := cuda.Update(map[string]string{"device_id": strconv.Itoa(deviceID)}); err != nil {
		return err
	}
	return opts.AppendExecutionProviderCUDA(cuda)
}

func cudaDeviceAvailable() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GRAPHIT_BROKER_CUDA_AVAILABLE"))) {
	case "1", "true", "yes":
		return true
	case "0", "false", "no":
		return false
	}
	for _, path := range []string{"/dev/nvidiactl", "/proc/driver/nvidia/version"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func (b *onnxEmbeddingBackend) Embed(ctx context.Context, texts []string, inputType string) ([][]float32, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	allIDs := make([][]int, len(texts))
	allMasks := make([][]int, len(texts))
	allTypes := make([][]int, len(texts))
	maxLen := 0
	for i, text := range texts {
		if inputType == "query" {
			text = b.queryPrefix + text
		}
		encoding, err := safeEncodeSingle(b.tokenizer, text)
		if err != nil {
			return nil, fmt.Errorf("tokenize embedding input %d: %w", i, err)
		}
		ids, mask, types := encoding.GetIds(), encoding.GetAttentionMask(), encoding.TypeIds
		if len(ids) > b.maxLength {
			ids = ids[:b.maxLength]
		}
		if len(mask) > len(ids) {
			mask = mask[:len(ids)]
		}
		if len(types) > len(ids) {
			types = types[:len(ids)]
		}
		allIDs[i], allMasks[i], allTypes[i] = ids, mask, types
		if len(ids) > maxLen {
			maxLen = len(ids)
		}
	}
	if maxLen == 0 {
		return nil, fmt.Errorf("local embedding tokenizer produced empty input")
	}
	flatIDs := make([]int64, len(texts)*maxLen)
	flatMasks := make([]int64, len(texts)*maxLen)
	flatTypes := make([]int64, len(texts)*maxLen)
	for i := range texts {
		for j := 0; j < len(allIDs[i]) && j < len(allMasks[i]); j++ {
			flatIDs[i*maxLen+j] = int64(allIDs[i][j])
			flatMasks[i*maxLen+j] = int64(allMasks[i][j])
			if j < len(allTypes[i]) {
				flatTypes[i*maxLen+j] = int64(allTypes[i][j])
			}
		}
	}
	shape := ort.Shape{int64(len(texts)), int64(maxLen)}
	values := make(map[string]ort.Value, len(b.inputNames))
	defer func() {
		for _, value := range values {
			_ = value.Destroy()
		}
	}()
	for _, name := range b.inputNames {
		var data []int64
		switch name {
		case "input_ids":
			data = flatIDs
		case "attention_mask":
			data = flatMasks
		case "token_type_ids":
			data = flatTypes
		default:
			return nil, fmt.Errorf("local embedding model requires unsupported input %q", name)
		}
		tensor, err := ort.NewTensor(shape, data)
		if err != nil {
			return nil, fmt.Errorf("create embedding %s tensor: %w", name, err)
		}
		values[name] = tensor
	}
	inputs := make([]ort.Value, len(b.inputNames))
	for i, name := range b.inputNames {
		inputs[i] = values[name]
	}
	outputs := []ort.Value{nil}
	b.mu.Lock()
	err := b.session.Run(inputs, outputs)
	b.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("local embedding inference: %w", err)
	}
	if outputs[0] == nil {
		return nil, fmt.Errorf("local embedding model produced no output")
	}
	defer outputs[0].Destroy()
	tensor, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("local embedding output is %T, want float32", outputs[0])
	}
	data := tensor.GetData()
	if len(data) != len(texts)*b.dimensions {
		return nil, fmt.Errorf("local embedding output has %d values, want %d", len(data), len(texts)*b.dimensions)
	}
	vectors := make([][]float32, len(texts))
	for i := range texts {
		vector := append([]float32(nil), data[i*b.dimensions:(i+1)*b.dimensions]...)
		var norm float64
		for _, value := range vector {
			norm += float64(value) * float64(value)
		}
		norm = math.Sqrt(norm)
		if norm > 0 {
			for j := range vector {
				vector[j] = float32(float64(vector[j]) / norm)
			}
		}
		vectors[i] = vector
	}
	return vectors, nil
}

func safeEncodeSingle(encoder textEncoder, text string) (encoding *tokenizer.Encoding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("tokenizer panic: %v", recovered)
		}
	}()
	return encoder.EncodeSingle(text, true)
}

func (b *onnxEmbeddingBackend) Close() error {
	if b == nil || b.session == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session.Destroy()
}

func (b *onnxRerankBackend) Score(ctx context.Context, query string, documents []string) ([]float64, error) {
	scores := make([]float64, len(documents))
	for start := 0; start < len(documents); start += localRerankBatchSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+localRerankBatchSize, len(documents))
		batch, err := b.scoreBatch(query, documents[start:end])
		if err != nil {
			return nil, err
		}
		copy(scores[start:end], batch)
	}
	return scores, nil
}

func (b *onnxRerankBackend) scoreBatch(query string, documents []string) ([]float64, error) {
	ids := make([][]int, len(documents))
	masks := make([][]int, len(documents))
	types := make([][]int, len(documents))
	maxLen := 1
	for i, document := range documents {
		encoding, err := safeEncodePair(b.tokenizer, query, document)
		if err != nil {
			return nil, fmt.Errorf("tokenize rerank document %d: %w", i, err)
		}
		ids[i], masks[i], types[i] = encoding.Ids, encoding.AttentionMask, encoding.TypeIds
		if len(ids[i]) > b.maxLength {
			ids[i] = ids[i][:b.maxLength]
			masks[i] = masks[i][:min(len(masks[i]), b.maxLength)]
			types[i] = types[i][:min(len(types[i]), b.maxLength)]
		}
		maxLen = max(maxLen, len(ids[i]))
	}
	flatIDs := make([]int64, len(documents)*maxLen)
	flatMasks := make([]int64, len(documents)*maxLen)
	flatTypes := make([]int64, len(documents)*maxLen)
	for i := range documents {
		for j := 0; j < len(ids[i]); j++ {
			flatIDs[i*maxLen+j] = int64(ids[i][j])
			if j < len(masks[i]) {
				flatMasks[i*maxLen+j] = int64(masks[i][j])
			}
			if j < len(types[i]) {
				flatTypes[i*maxLen+j] = int64(types[i][j])
			}
		}
	}
	shape := ort.Shape{int64(len(documents)), int64(maxLen)}
	values := make(map[string]ort.Value, len(b.inputNames))
	defer func() {
		for _, value := range values {
			_ = value.Destroy()
		}
	}()
	for _, name := range b.inputNames {
		var data []int64
		switch name {
		case "input_ids":
			data = flatIDs
		case "attention_mask":
			data = flatMasks
		case "token_type_ids":
			data = flatTypes
		default:
			return nil, fmt.Errorf("local rerank model requires unsupported input %q", name)
		}
		tensor, err := ort.NewTensor(shape, data)
		if err != nil {
			return nil, fmt.Errorf("create rerank %s tensor: %w", name, err)
		}
		values[name] = tensor
	}
	inputs := make([]ort.Value, len(b.inputNames))
	for i, name := range b.inputNames {
		inputs[i] = values[name]
	}
	outputs := []ort.Value{nil}
	b.mu.Lock()
	err := b.session.Run(inputs, outputs)
	b.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("local rerank inference: %w", err)
	}
	if outputs[0] == nil {
		return nil, fmt.Errorf("local rerank model produced no output")
	}
	defer outputs[0].Destroy()
	tensor, ok := outputs[0].(*ort.Tensor[float32])
	if !ok {
		return nil, fmt.Errorf("local rerank output is %T, want float32", outputs[0])
	}
	data := tensor.GetData()
	if len(data) < len(documents) || len(data)%len(documents) != 0 {
		return nil, fmt.Errorf("local rerank returned %d logits for %d documents", len(data), len(documents))
	}
	stride := len(data) / len(documents)
	scores := make([]float64, len(documents))
	for i := range documents {
		column := 0
		if stride == 2 {
			column = 1
		}
		scores[i] = float64(data[i*stride+column])
	}
	return scores, nil
}

func safeEncodePair(encoder pairEncoder, query, document string) (encoding *tokenizer.Encoding, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("tokenizer panic: %v", recovered)
		}
	}()
	return encoder.EncodePair(query, document, true)
}

func (b *onnxRerankBackend) Close() error {
	if b == nil || b.session == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.session.Destroy()
}
