package broker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const modelManifestSchemaVersion = 1

type ModelManifest struct {
	SchemaVersion int                  `json:"schema_version"`
	ID            string               `json:"id"`
	Task          string               `json:"task"`
	Runtime       ModelRuntimeManifest `json:"runtime"`
	FetchPolicy   string               `json:"fetch_policy"`
	Artifacts     []ModelArtifact      `json:"artifacts"`
	Text          ModelTextManifest    `json:"text"`
	Inference     InferenceManifest    `json:"inference"`
}

type ModelRuntimeManifest struct {
	Engine      string            `json:"engine"`
	Entrypoints map[string]string `json:"entrypoints"`
}

type ModelArtifact struct {
	Role     string                `json:"role"`
	Format   string                `json:"format,omitempty"`
	Path     string                `json:"path"`
	Sources  []ModelArtifactSource `json:"sources,omitempty"`
	SHA256   string                `json:"sha256,omitempty"`
	Size     int64                 `json:"size,omitempty"`
	Required bool                  `json:"required"`
}

type ModelArtifactSource struct {
	URL     string `json:"url"`
	AuthRef string `json:"auth_ref,omitempty"`
}

type ModelTextManifest struct {
	MaxTokens      int    `json:"max_tokens"`
	QueryPrefix    string `json:"query_prefix"`
	DocumentPrefix string `json:"document_prefix"`
	Truncation     string `json:"truncation"`
	Padding        string `json:"padding"`
}

// ModelInputManifest accepts either the string "auto" or an explicit
// semantic-to-tensor mapping. The semantic keys deliberately remain small:
// adapters, rather than arbitrary manifests, own task behavior.
type ModelInputManifest struct {
	Auto          bool   `json:"-"`
	Specified     bool   `json:"-"`
	InputIDs      string `json:"input_ids,omitempty"`
	AttentionMask string `json:"attention_mask,omitempty"`
	TokenTypeIDs  string `json:"token_type_ids,omitempty"`
}

func (m *ModelInputManifest) UnmarshalJSON(data []byte) error {
	var auto string
	if err := json.Unmarshal(data, &auto); err == nil {
		if auto != "auto" {
			return fmt.Errorf("inference.inputs string must be %q", "auto")
		}
		*m = ModelInputManifest{Auto: true, Specified: true}
		return nil
	}
	type plain ModelInputManifest
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("inference.inputs must be \"auto\" or a semantic mapping: %w", err)
	}
	*m = ModelInputManifest(value)
	m.Specified = true
	return nil
}

func (m ModelInputManifest) MarshalJSON() ([]byte, error) {
	if m.Auto || (m.InputIDs == "" && m.AttentionMask == "" && m.TokenTypeIDs == "") {
		return json.Marshal("auto")
	}
	type plain ModelInputManifest
	return json.Marshal(plain(m))
}

type InferenceManifest struct {
	Inputs         ModelInputManifest `json:"inputs"`
	Output         string             `json:"output"`
	Pooling        string             `json:"pooling"`
	Normalize      bool               `json:"normalize"`
	Dimensions     *int               `json:"dimensions"`
	ScoreTransform string             `json:"score_transform,omitempty"`
	ScoreColumn    *int               `json:"score_column,omitempty"`
}

func (m *ModelManifest) applyTaskProfile() {
	m.Runtime.Engine = strings.ToLower(strings.TrimSpace(m.Runtime.Engine))
	m.Task = strings.ToLower(strings.TrimSpace(m.Task))
	m.FetchPolicy = strings.ToLower(strings.TrimSpace(m.FetchPolicy))
	if m.FetchPolicy == "" {
		m.FetchPolicy = "never"
	}
	if m.Text.MaxTokens == 0 {
		m.Text.MaxTokens = 512
	}
	if m.Text.Truncation == "" {
		m.Text.Truncation = "longest-first"
	}
	if m.Text.Padding == "" {
		m.Text.Padding = "longest"
	}
	if m.Inference.Output == "" {
		m.Inference.Output = "auto"
	}
	if m.Inference.Pooling == "" {
		m.Inference.Pooling = "none"
	}
	if m.Inference.ScoreTransform == "" {
		m.Inference.ScoreTransform = "identity"
	}
	if !m.Inference.Inputs.Specified && !m.Inference.Inputs.Auto {
		m.Inference.Inputs.Auto = true
	}
}

func (m ModelManifest) validate(expectedID, expectedTask string) error {
	if m.SchemaVersion != modelManifestSchemaVersion {
		return fmt.Errorf("manifest schema_version must be %d", modelManifestSchemaVersion)
	}
	if m.ID != expectedID {
		return fmt.Errorf("manifest id %q does not match selected directory %q", m.ID, expectedID)
	}
	if m.Task != expectedTask {
		return fmt.Errorf("manifest task %q does not match selected task %q", m.Task, expectedTask)
	}
	if m.Runtime.Engine != "onnx" {
		return fmt.Errorf("manifest runtime.engine %q is unsupported (use onnx)", m.Runtime.Engine)
	}
	entrypoint := strings.TrimSpace(m.Runtime.Entrypoints["model"])
	if entrypoint == "" {
		return errors.New("manifest runtime.entrypoints.model is required")
	}
	switch m.FetchPolicy {
	case "setup", "on_demand", "never":
	default:
		return fmt.Errorf("manifest fetch_policy %q is unsupported", m.FetchPolicy)
	}
	if m.Text.MaxTokens < 1 || m.Text.MaxTokens > 8192 {
		return errors.New("manifest text.max_tokens must be between 1 and 8192")
	}
	if m.Text.Truncation != "longest-first" {
		return fmt.Errorf("manifest text.truncation %q is unsupported", m.Text.Truncation)
	}
	if m.Text.Padding != "longest" {
		return fmt.Errorf("manifest text.padding %q is unsupported", m.Text.Padding)
	}
	switch m.Inference.Pooling {
	case "none", "cls", "mean":
	default:
		return fmt.Errorf("manifest inference.pooling %q is unsupported", m.Inference.Pooling)
	}
	switch m.Inference.ScoreTransform {
	case "identity", "sigmoid", "softmax":
	default:
		return fmt.Errorf("manifest inference.score_transform %q is unsupported", m.Inference.ScoreTransform)
	}
	if m.Inference.Dimensions != nil && *m.Inference.Dimensions <= 0 {
		return errors.New("manifest inference.dimensions must be positive or null")
	}
	if !m.Inference.Inputs.Auto && (m.Inference.Inputs.InputIDs == "" || m.Inference.Inputs.AttentionMask == "") {
		return errors.New("explicit inference.inputs requires input_ids and attention_mask mappings")
	}
	if m.Task == "embedding" && (m.Inference.ScoreTransform != "identity" || m.Inference.ScoreColumn != nil) {
		return errors.New("embedding manifests do not accept rerank score configuration")
	}
	if m.Task == "rerank" && (m.Inference.Pooling != "none" || m.Inference.Normalize || m.Inference.Dimensions != nil) {
		return errors.New("rerank manifests require pooling none, normalize false, and dimensions null")
	}
	roles := map[string]bool{}
	paths := map[string]bool{}
	for i, artifact := range m.Artifacts {
		if strings.TrimSpace(artifact.Role) == "" || strings.TrimSpace(artifact.Path) == "" {
			return fmt.Errorf("manifest artifacts[%d] requires role and path", i)
		}
		if roles[artifact.Role] {
			return fmt.Errorf("manifest has duplicate artifact role %q", artifact.Role)
		}
		if paths[artifact.Path] {
			return fmt.Errorf("manifest has duplicate artifact path %q", artifact.Path)
		}
		roles[artifact.Role], paths[artifact.Path] = true, true
		if artifact.Role == "model" && artifact.Path != entrypoint {
			return fmt.Errorf("manifest model artifact path %q must match runtime entrypoint %q", artifact.Path, entrypoint)
		}
		if artifact.Role == "tokenizer" && artifact.Format != "" && artifact.Format != "huggingface-json" {
			return fmt.Errorf("manifest tokenizer format %q is unsupported", artifact.Format)
		}
		if (artifact.Role == "model" || artifact.Role == "tokenizer") && !artifact.Required {
			return fmt.Errorf("manifest artifact %q must be required", artifact.Role)
		}
		if len(artifact.Sources) > 0 && artifact.SHA256 == "" {
			return fmt.Errorf("manifest artifact %q has remote sources but no sha256", artifact.Role)
		}
		if err := validateSHA256(artifact.SHA256, artifact.Role); err != nil {
			return err
		}
		for j, source := range artifact.Sources {
			if strings.TrimSpace(source.URL) == "" {
				return fmt.Errorf("manifest artifact %q sources[%d].url is required", artifact.Role, j)
			}
			if err := validateHTTPURL(source.URL, fmt.Sprintf("manifest artifact %q source URL", artifact.Role)); err != nil {
				return err
			}
			if source.AuthRef != "" && strings.Trim(authRefCleaner.ReplaceAllString(source.AuthRef, ""), "_") == "" {
				return fmt.Errorf("manifest artifact %q sources[%d].auth_ref is invalid", artifact.Role, j)
			}
		}
	}
	if !roles["model"] || !roles["tokenizer"] {
		return errors.New("manifest requires model and tokenizer artifacts")
	}
	if !paths[entrypoint] {
		return fmt.Errorf("manifest model entrypoint %q is not declared as an artifact", entrypoint)
	}
	return nil
}
