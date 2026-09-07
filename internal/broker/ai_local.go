package broker

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/exec"
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
	tokenizer      textEncoder
	session        *ort.DynamicAdvancedSession
	inputNames     []string
	inputSemantic  map[string]string
	device         string
	dimensions     int
	maxLength      int
	queryPrefix    string
	documentPrefix string
	pooling        string
	normalize      bool
	mu             sync.Mutex
}

type onnxRerankBackend struct {
	tokenizer      pairEncoder
	session        *ort.DynamicAdvancedSession
	inputNames     []string
	inputSemantic  map[string]string
	device         string
	maxLength      int
	queryPrefix    string
	documentPrefix string
	scoreTransform string
	scoreColumn    *int
	mu             sync.Mutex
}

var (
	onnxInitOnce sync.Once
	onnxInitErr  error
)

func initializeONNXRuntime() error {
	onnxInitOnce.Do(func() {
		path, err := resolveONNXRuntimeLibraryPath()
		if err != nil {
			onnxInitErr = err
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
	_ = ctx
	model := cfg.resolvedModel
	if model == nil || model.Manifest.Task != "embedding" {
		return nil, fmt.Errorf("local embedding model was not resolved through the model catalog")
	}
	if err := initializeONNXRuntime(); err != nil {
		return nil, err
	}
	tk, err := pretrained.FromFile(model.TokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("load local embedding tokenizer: %w", err)
	}
	session, device, err := newLocalONNXSession(model.ModelPath, model.InputNames, []string{model.OutputName}, cfg)
	if err != nil {
		return nil, fmt.Errorf("create local embedding session: %w", err)
	}
	slog.Info("local embedding model ready", "model", model.Manifest.ID, "identity", model.Identity, "device", device)
	return &onnxEmbeddingBackend{tokenizer: tk, session: session, inputNames: model.InputNames, inputSemantic: model.InputSemantic,
		device: device, dimensions: model.Dimensions, maxLength: model.Manifest.Text.MaxTokens,
		queryPrefix: model.Manifest.Text.QueryPrefix, documentPrefix: model.Manifest.Text.DocumentPrefix,
		pooling: model.Manifest.Inference.Pooling, normalize: model.Manifest.Inference.Normalize}, nil
}

func newONNXRerankBackend(ctx context.Context, cfg LocalModelConfig) (localRerankBackend, error) {
	_ = ctx
	model := cfg.resolvedModel
	if model == nil || model.Manifest.Task != "rerank" {
		return nil, fmt.Errorf("local rerank model was not resolved through the model catalog")
	}
	if err := initializeONNXRuntime(); err != nil {
		return nil, err
	}
	tk, err := pretrained.FromFile(model.TokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("load local rerank tokenizer: %w", err)
	}
	session, device, err := newLocalONNXSession(model.ModelPath, model.InputNames, []string{model.OutputName}, cfg)
	if err != nil {
		return nil, fmt.Errorf("create local rerank session: %w", err)
	}
	slog.Info("local rerank model ready", "model", model.Manifest.ID, "identity", model.Identity, "device", device)
	return &onnxRerankBackend{tokenizer: tk, session: session, inputNames: model.InputNames, inputSemantic: model.InputSemantic,
		device: device, maxLength: model.Manifest.Text.MaxTokens, queryPrefix: model.Manifest.Text.QueryPrefix,
		documentPrefix: model.Manifest.Text.DocumentPrefix, scoreTransform: model.Manifest.Inference.ScoreTransform,
		scoreColumn: model.Manifest.Inference.ScoreColumn}, nil
}

func newLocalONNXSession(modelPath string, inputNames, outputNames []string, cfg LocalModelConfig) (*ort.DynamicAdvancedSession, string, error) {
	if err := validateLocalDevicePlatform(cfg.Device, runtime.GOOS); err != nil {
		return nil, "", err
	}
	devices := localDeviceCandidates(cfg.Device, cudaDeviceAvailable(), runtime.GOOS == "darwin")
	var firstErr error
	for _, device := range devices {
		opts, err := ort.NewSessionOptions()
		if err != nil {
			return nil, "", err
		}
		_ = opts.SetInterOpNumThreads(1)
		_ = opts.SetIntraOpNumThreads(max(1, runtime.GOMAXPROCS(0)))
		switch device {
		case "cuda":
			err = appendCUDAProvider(opts, cfg.DeviceID)
		case "coreml":
			err = appendCoreMLProvider(opts)
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
		if cfg.Device == "auto" && device != "cpu" {
			slog.Warn("accelerated local inference provider unavailable; trying next provider", "provider", device, "error", err)
		}
	}
	if cfg.Device != "auto" && cfg.Device != "cpu" {
		return nil, "", fmt.Errorf("local device %s was required but could not initialize: %w", cfg.Device, firstErr)
	}
	return nil, "", firstErr
}

func validateLocalDevicePlatform(device, goos string) error {
	if device == "coreml" && goos != "darwin" {
		return fmt.Errorf("local device coreml is supported only on macOS, running on %s", goos)
	}
	return nil
}

func localDeviceCandidates(device string, cudaAvailable, coreMLAvailable bool) []string {
	switch device {
	case "cuda":
		return []string{"cuda"}
	case "coreml":
		return []string{"coreml"}
	case "auto":
		devices := make([]string, 0, 3)
		if coreMLAvailable {
			devices = append(devices, "coreml")
		}
		if cudaAvailable {
			devices = append(devices, "cuda")
		}
		return append(devices, "cpu")
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

func appendCoreMLProvider(opts *ort.SessionOptions) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("CoreML execution provider is supported only on macOS, running on %s", runtime.GOOS)
	}
	return opts.AppendExecutionProviderCoreMLV2(map[string]string{
		"MLComputeUnits":           "ALL",
		"RequireStaticInputShapes": "0",
	})
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
	if _, err := exec.LookPath("nvidia-smi"); err == nil {
		return true
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
		} else {
			text = b.documentPrefix + text
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
		switch b.inputSemantic[name] {
		case "input_ids":
			data = flatIDs
		case "attention_mask":
			data = flatMasks
		case "token_type_ids":
			data = flatTypes
		default:
			return nil, fmt.Errorf("local embedding model input %q has no runtime semantic", name)
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
	outputShape := tensor.GetShape()
	return poolEmbeddingOutput(data, outputShape, b.pooling, b.normalize, len(texts), maxLen, b.dimensions, flatMasks)
}

func poolEmbeddingOutput(data []float32, outputShape ort.Shape, pooling string, normalize bool, batch, inputSequence, dimensions int, attentionMask []int64) ([][]float32, error) {
	vectors := make([][]float32, batch)
	switch pooling {
	case "none":
		if len(outputShape) != 2 || len(data) != batch*dimensions {
			return nil, fmt.Errorf("local embedding output shape %v is incompatible with batch=%d dimensions=%d and pooling=none", outputShape, batch, dimensions)
		}
		for i := range batch {
			vectors[i] = append([]float32(nil), data[i*dimensions:(i+1)*dimensions]...)
		}
	case "cls", "mean":
		if len(outputShape) != 3 || int(outputShape[0]) != batch || int(outputShape[2]) != dimensions {
			return nil, fmt.Errorf("local embedding output shape %v is incompatible with pooling=%s", outputShape, pooling)
		}
		sequence := int(outputShape[1])
		if len(data) != batch*sequence*dimensions {
			return nil, fmt.Errorf("local embedding output has %d values, expected %d", len(data), batch*sequence*dimensions)
		}
		for i := range batch {
			vector := make([]float32, dimensions)
			if pooling == "cls" {
				copy(vector, data[(i*sequence)*dimensions:(i*sequence+1)*dimensions])
			} else {
				count := 0
				for token := 0; token < sequence && token < inputSequence; token++ {
					if attentionMask[i*inputSequence+token] == 0 {
						continue
					}
					count++
					base := (i*sequence + token) * dimensions
					for j := range vector {
						vector[j] += data[base+j]
					}
				}
				if count == 0 {
					return nil, fmt.Errorf("local embedding attention mask contains no tokens for input %d", i)
				}
				for j := range vector {
					vector[j] /= float32(count)
				}
			}
			vectors[i] = vector
		}
	default:
		return nil, fmt.Errorf("unsupported embedding pooling %q", pooling)
	}
	if normalize {
		for i, vector := range vectors {
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
		encoding, err := safeEncodePair(b.tokenizer, b.queryPrefix+query, b.documentPrefix+document)
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
		switch b.inputSemantic[name] {
		case "input_ids":
			data = flatIDs
		case "attention_mask":
			data = flatMasks
		case "token_type_ids":
			data = flatTypes
		default:
			return nil, fmt.Errorf("local rerank model input %q has no runtime semantic", name)
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
	return transformRerankOutput(data, len(documents), b.scoreTransform, b.scoreColumn)
}

func transformRerankOutput(data []float32, batch int, transform string, configuredColumn *int) ([]float64, error) {
	if batch <= 0 || len(data) < batch || len(data)%batch != 0 {
		return nil, fmt.Errorf("local rerank returned %d logits for %d documents", len(data), batch)
	}
	stride := len(data) / batch
	scores := make([]float64, batch)
	for i := range batch {
		column := 0
		if stride == 2 {
			column = 1
		}
		if configuredColumn != nil {
			column = *configuredColumn
		}
		if column < 0 || column >= stride {
			return nil, fmt.Errorf("rerank score_column %d is outside output width %d", column, stride)
		}
		score := float64(data[i*stride+column])
		switch transform {
		case "identity":
		case "sigmoid":
			score = 1 / (1 + math.Exp(-score))
		case "softmax":
			maxLogit := float64(data[i*stride])
			for j := 1; j < stride; j++ {
				maxLogit = math.Max(maxLogit, float64(data[i*stride+j]))
			}
			var denominator float64
			for j := 0; j < stride; j++ {
				denominator += math.Exp(float64(data[i*stride+j]) - maxLogit)
			}
			score = math.Exp(score-maxLogit) / denominator
		default:
			return nil, fmt.Errorf("unsupported rerank score transform %q", transform)
		}
		scores[i] = score
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
