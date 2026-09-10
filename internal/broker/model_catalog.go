package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type modelResolveMode int

const (
	resolveForRuntime modelResolveMode = iota
	resolveForSetup
)

type ResolvedModel struct {
	Manifest      ModelManifest
	BundleDir     string
	ModelPath     string
	TokenizerPath string
	ArtifactPaths map[string]string
	ArtifactSHA   map[string]string
	Inspection    ONNXInspection
	InputNames    []string
	InputSemantic map[string]string
	OutputName    string
	Dimensions    int
	Identity      string
}

type ModelCatalog struct {
	artifacts *ArtifactResolver
}

// ArtifactResolver owns policy enforcement, authenticated acquisition,
// integrity validation, locking, and atomic installation.
type ArtifactResolver struct {
	getenv     func(string) string
	httpClient *http.Client
}

var modelArtifactLocks sync.Map

func NewModelCatalog() *ModelCatalog {
	return &ModelCatalog{artifacts: &ArtifactResolver{getenv: os.Getenv, httpClient: http.DefaultClient}}
}

// SetupModels acquires selected local model artifacts without starting the
// HTTP server or initializing ONNX sessions.
func SetupModels(ctx context.Context, cfg Config) error {
	catalog := NewModelCatalog()
	for _, selected := range []struct {
		task     string
		enabled  bool
		upstream UpstreamConfig
	}{
		{"embedding", cfg.Services.Embeddings.Enabled, cfg.Services.Embeddings.Upstream},
		{"rerank", cfg.Services.Rerank.Enabled, cfg.Services.Rerank.Upstream},
	} {
		selected.upstream.setDefaults(selected.task)
		if !selected.enabled || !selected.upstream.isONNX() {
			continue
		}
		if _, err := catalog.Resolve(ctx, selected.task, selected.upstream, resolveForSetup); err != nil {
			return fmt.Errorf("setup %s model: %w", selected.task, err)
		}
	}
	return nil
}

func (c *ModelCatalog) Resolve(ctx context.Context, task string, upstream UpstreamConfig, mode modelResolveMode) (*ResolvedModel, error) {
	upstream.setDefaults(task)
	if !upstream.isONNX() {
		return nil, errors.New("model catalog requires upstream.protocol onnx")
	}
	if err := upstream.validateONNX("upstream"); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(upstream.Directory, 0o750); err != nil {
		return nil, fmt.Errorf("create models directory: %w", err)
	}
	id := upstream.Model
	bundleDir, err := secureBundlePath(upstream.Directory, id)
	if err != nil {
		return nil, fmt.Errorf("resolve model %q bundle: %w", id, err)
	}
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		return nil, fmt.Errorf("create model %q bundle: %w", id, err)
	}
	manifest, err := c.loadManifest(bundleDir, id, task)
	if err != nil {
		return nil, err
	}
	resolved := &ResolvedModel{Manifest: manifest, BundleDir: bundleDir, ArtifactPaths: map[string]string{}, ArtifactSHA: map[string]string{}}
	for _, artifact := range manifest.Artifacts {
		path, err := secureBundlePath(bundleDir, artifact.Path)
		if err != nil {
			return nil, fmt.Errorf("model %q artifact %q: %w", id, artifact.Role, err)
		}
		digest, available, err := c.artifacts.Resolve(ctx, path, artifact, manifest.FetchPolicy, mode)
		if err != nil {
			return nil, fmt.Errorf("model %q artifact %q: %w", id, artifact.Role, err)
		}
		if !available {
			continue
		}
		resolved.ArtifactPaths[artifact.Role] = path
		resolved.ArtifactSHA[artifact.Role] = digest
	}
	resolved.ModelPath = resolved.ArtifactPaths["model"]
	resolved.TokenizerPath = resolved.ArtifactPaths["tokenizer"]
	if mode == resolveForRuntime && (resolved.ModelPath == "" || resolved.TokenizerPath == "") {
		return nil, fmt.Errorf("model %q does not have its required runtime artifacts", id)
	}
	return resolved, nil
}

func (c *ModelCatalog) loadManifest(bundleDir, id, task string) (ModelManifest, error) {
	manifestPath, err := secureBundlePath(bundleDir, "manifest.json")
	if err != nil {
		return ModelManifest{}, err
	}
	data, err := os.ReadFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		preset, ok := builtinModelManifest(id)
		if !ok {
			return ModelManifest{}, fmt.Errorf("model %q manifest is missing at %s", id, manifestPath)
		}
		preset.applyTaskProfile()
		data, err = json.MarshalIndent(preset, "", "  ")
		if err == nil {
			data = append(data, '\n')
			err = writeFileAtomic(manifestPath, data, 0o640)
		}
	}
	if err != nil {
		return ModelManifest{}, fmt.Errorf("load model %q manifest: %w", id, err)
	}
	var manifest ModelManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return ModelManifest{}, fmt.Errorf("decode model %q manifest: %w", id, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values are not allowed")
		}
		return ModelManifest{}, fmt.Errorf("decode model %q manifest: %w", id, err)
	}
	manifest.applyTaskProfile()
	if err := manifest.validate(id, task); err != nil {
		return ModelManifest{}, fmt.Errorf("validate model %q manifest: %w", id, err)
	}
	return manifest, nil
}

func builtinModelManifest(id string) (ModelManifest, bool) {
	switch id {
	case "coderankembed":
		dimensions := localEmbeddingDimensions
		return ModelManifest{SchemaVersion: 1, ID: id, Task: "embedding", Runtime: ModelRuntimeManifest{Engine: "onnx", Entrypoints: map[string]string{"model": "model.onnx"}}, FetchPolicy: "on_demand",
			Artifacts: []ModelArtifact{
				{Role: "model", Path: "model.onnx", Sources: []ModelArtifactSource{{URL: "https://huggingface.co/mrsladoje/CodeRankEmbed-onnx-int8/resolve/main/onnx/model.onnx"}}, SHA256: "4eae31d09b1843103a1ebd5e2b2e24b5a5cad441a33906b35b12b1e2ed91d1db", Size: 138619279, Required: true},
				{Role: "tokenizer", Format: "huggingface-json", Path: "tokenizer.json", Sources: []ModelArtifactSource{{URL: "https://huggingface.co/mrsladoje/CodeRankEmbed-onnx-int8/resolve/main/tokenizer.json"}}, SHA256: "91f1def9b9391fdabe028cd3f3fcc4efd34e5d1f08c3bf2de513ebb5911a1854", Size: 711649, Required: true},
			}, Text: ModelTextManifest{MaxTokens: 512, QueryPrefix: localQueryPrefix, Truncation: "longest-first", Padding: "longest"},
			Inference: InferenceManifest{Inputs: ModelInputManifest{Auto: true}, Output: "sentence_embedding", Pooling: "none", Normalize: true, Dimensions: &dimensions}}, true
	case "bge-reranker-base":
		return ModelManifest{SchemaVersion: 1, ID: id, Task: "rerank", Runtime: ModelRuntimeManifest{Engine: "onnx", Entrypoints: map[string]string{"model": "model.onnx"}}, FetchPolicy: "on_demand",
			Artifacts: []ModelArtifact{
				{Role: "model", Path: "model.onnx", Sources: []ModelArtifactSource{{URL: "https://huggingface.co/BAAI/bge-reranker-base/resolve/main/onnx/model.onnx"}}, SHA256: "15b9a8c3da82eddf263df571281166e00e9308fe19d077084b642ebfcaf06d2b", Size: 1112459588, Required: true},
				{Role: "tokenizer", Format: "huggingface-json", Path: "tokenizer.json", Sources: []ModelArtifactSource{{URL: "https://huggingface.co/BAAI/bge-reranker-base/resolve/main/tokenizer.json"}}, SHA256: "9eb652ac4e40cc093272bbbe0f55d521cf67570060227109b5cdc20945a4489e", Size: 17098107, Required: true},
			}, Text: ModelTextManifest{MaxTokens: 512, Truncation: "longest-first", Padding: "longest"},
			Inference: InferenceManifest{Inputs: ModelInputManifest{Auto: true}, Output: "auto", Pooling: "none", ScoreTransform: "identity"}}, true
	default:
		return ModelManifest{}, false
	}
}

var authRefCleaner = regexp.MustCompile(`[^A-Za-z0-9]+`)

func (r *ArtifactResolver) Resolve(ctx context.Context, destination string, artifact ModelArtifact, policy string, mode modelResolveMode) (string, bool, error) {
	lockValue, _ := modelArtifactLocks.LoadOrStore(destination, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	if digest, valid := validateInstalledArtifact(destination, artifact); valid {
		return digest, true, nil
	}
	allowDownload := policy == "on_demand" || (policy == "setup" && mode == resolveForSetup)
	if !allowDownload || len(artifact.Sources) == 0 {
		if !artifact.Required {
			return "", false, nil
		}
		hint := "install it in the model volume"
		if policy == "setup" && mode == resolveForRuntime {
			hint = "run graphit-broker --setup-models first"
		}
		return "", false, fmt.Errorf("required file %s is missing or invalid; %s (fetch_policy=%s)", destination, hint, policy)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return "", false, fmt.Errorf("create artifact directory: %w", err)
	}
	var sourceErrors []string
	for _, source := range artifact.Sources {
		if err := r.download(ctx, destination, artifact, source); err == nil {
			digest, valid := validateInstalledArtifact(destination, artifact)
			if !valid {
				return "", false, errors.New("download committed an invalid artifact")
			}
			return digest, true, nil
		} else {
			sourceErrors = append(sourceErrors, err.Error())
		}
	}
	if !artifact.Required {
		return "", false, nil
	}
	return "", false, fmt.Errorf("all artifact sources failed: %s", strings.Join(sourceErrors, "; "))
}

func (r *ArtifactResolver) download(ctx context.Context, destination string, artifact ModelArtifact, source ModelArtifactSource) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return err
	}
	if source.AuthRef != "" {
		name := "GRAPHIT_BROKER_MODEL_AUTH_" + strings.ToUpper(strings.Trim(authRefCleaner.ReplaceAllString(source.AuthRef, "_"), "_"))
		token := strings.TrimSpace(r.getenv(name))
		if token == "" {
			return fmt.Errorf("auth_ref %q requires environment variable %s", source.AuthRef, name)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, source.URL)
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	hash := sha256.New()
	reader := io.Reader(resp.Body)
	if artifact.Size > 0 {
		reader = io.LimitReader(resp.Body, artifact.Size+1)
	}
	written, err := io.Copy(io.MultiWriter(tmp, hash), reader)
	if err != nil {
		return err
	}
	if artifact.Size > 0 && written != artifact.Size {
		return fmt.Errorf("downloaded %d bytes, expected %d", written, artifact.Size)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, artifact.SHA256) {
		return fmt.Errorf("SHA-256 %s does not match pinned digest", actual)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	committed = true
	if dir, err := os.Open(filepath.Dir(destination)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func validateInstalledArtifact(path string, artifact ModelArtifact) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (artifact.Size > 0 && info.Size() != artifact.Size) {
		return "", false
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return "", false
	}
	return digest, artifact.SHA256 == "" || strings.EqualFold(digest, artifact.SHA256)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSHA256(value, role string) error {
	if value == "" {
		return nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("manifest artifact %q sha256 must be 64 hexadecimal characters", role)
	}
	return nil
}

func secureBundlePath(root, relative string) (string, error) {
	if strings.TrimSpace(relative) == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path %q must be relative", relative)
	}
	clean := filepath.Clean(relative)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes its bundle", relative)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(rootAbs, clean)
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes its bundle", relative)
	}
	rootReal := rootAbs
	if evaluated, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootReal = evaluated
	}
	probe := target
	for {
		if _, err := os.Lstat(probe); err == nil {
			evaluated, err := filepath.EvalSymlinks(probe)
			if err != nil {
				return "", err
			}
			realRel, err := filepath.Rel(rootReal, evaluated)
			if err != nil || realRel == ".." || strings.HasPrefix(realRel, ".."+string(filepath.Separator)) {
				return "", fmt.Errorf("path %q escapes its bundle through a symlink", relative)
			}
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	return target, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func finalizeModelIdentity(model *ResolvedModel) error {
	payload := struct {
		Manifest   ModelManifest     `json:"manifest"`
		Artifacts  map[string]string `json:"artifacts"`
		Inspection ONNXInspection    `json:"inspection"`
		Inputs     map[string]string `json:"inputs"`
		Output     string            `json:"output"`
		Dimensions int               `json:"dimensions"`
	}{model.Manifest, model.ArtifactSHA, model.Inspection, model.InputSemantic, model.OutputName, model.Dimensions}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	model.Identity = hex.EncodeToString(digest[:])
	return nil
}
