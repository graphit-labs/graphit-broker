package broker

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// embeddingCompatibilityHash changes whenever a vector could have different semantics.
// Do not include credentials or the input text in the persisted metadata.
func embeddingCompatibilityHash(cfg EmbeddingServiceConfig, inputType string) string {
	identity, _ := json.Marshal(struct {
		CacheFormat    int
		Protocol       string
		URL            string
		Model          string
		Revision       string
		Dimensions     int
		SendDimensions bool
		InputType      string
	}{1, cfg.Upstream.Protocol, cfg.Upstream.URL, cfg.Upstream.Model, cfg.Revision,
		cfg.Dimensions, cfg.Upstream.SendDimensions, inputType})
	return sha256Hex(identity)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (s *ControlStore) CachedEmbedding(ctx context.Context, compatibilityHash, inputHash string, dimensions int) ([]float32, bool, error) {
	var encoded string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT embedding_json FROM embedding_cache WHERE compatibility_hash=? AND input_hash=?`), compatibilityHash, inputHash).Scan(&encoded)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read embedding cache: %w", err)
	}
	var vector []float32
	if err := json.Unmarshal([]byte(encoded), &vector); err != nil || len(vector) != dimensions {
		return nil, false, fmt.Errorf("invalid cached embedding for hash %s", inputHash)
	}
	return vector, true, nil
}

func (s *ControlStore) SaveEmbedding(ctx context.Context, cfg EmbeddingServiceConfig, inputType, compatibilityHash, inputHash string, vector []float32) error {
	encoded, err := json.Marshal(vector)
	if err != nil || len(vector) != cfg.Dimensions {
		return fmt.Errorf("invalid embedding for cache: dimensions=%d expected=%d: %v", len(vector), cfg.Dimensions, err)
	}
	query := s.bind(s.dialect.InsertIgnore(`INSERT INTO embedding_cache(compatibility_hash, input_hash, provider, revision, model, input_type, embedding_json) VALUES(?, ?, ?, ?, ?, ?, ?)`))
	if _, err := s.db.ExecContext(ctx, query, compatibilityHash, inputHash, cfg.Upstream.Protocol,
		cfg.Revision, cfg.Upstream.Model, inputType, string(encoded)); err != nil {
		return fmt.Errorf("save embedding cache: %w", err)
	}
	return nil
}
