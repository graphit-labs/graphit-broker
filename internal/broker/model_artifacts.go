package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type modelArtifact struct {
	Name   string
	URL    string
	SHA256 string
	Size   int64
}

var modelArtifactLocks sync.Map

func ensureModelBundle(ctx context.Context, cacheDir string, artifacts ...modelArtifact) ([]string, error) {
	paths := make([]string, len(artifacts))
	for i, artifact := range artifacts {
		path, err := ensureModelArtifact(ctx, cacheDir, artifact)
		if err != nil {
			return nil, err
		}
		paths[i] = path
	}
	return paths, nil
}

func resolveLocalModelBundle(ctx context.Context, cfg LocalModelConfig, artifacts ...modelArtifact) ([]string, bool, error) {
	if !cfg.operatorProvided() {
		paths, err := ensureModelBundle(ctx, cfg.CacheDir, artifacts...)
		return paths, false, err
	}
	paths := []string{cfg.ModelPath, cfg.TokenizerPath}
	digests := []string{cfg.ModelSHA256, cfg.TokenizerSHA256}
	for i, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return nil, true, fmt.Errorf("operator-provided local artifact %s is unavailable: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil, true, fmt.Errorf("operator-provided local artifact %s is not a regular file", path)
		}
		if digests[i] != "" {
			artifact := modelArtifact{Name: filepath.Base(path), SHA256: digests[i], Size: info.Size()}
			if !validModelArtifact(path, artifact) {
				return nil, true, fmt.Errorf("operator-provided local artifact %s does not match its configured SHA-256", path)
			}
		}
	}
	return paths, true, nil
}

func ensureModelArtifact(ctx context.Context, cacheDir string, artifact modelArtifact) (string, error) {
	path := filepath.Join(cacheDir, artifact.Name)
	lockValue, _ := modelArtifactLocks.LoadOrStore(path, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	if validModelArtifact(path, artifact) {
		return path, nil
	}
	if err := os.MkdirAll(cacheDir, 0o750); err != nil {
		return "", fmt.Errorf("create model cache %s: %w", cacheDir, err)
	}
	if err := downloadModelArtifact(ctx, path, artifact); err != nil {
		return "", err
	}
	return path, nil
}

func validModelArtifact(path string, artifact modelArtifact) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (artifact.Size > 0 && info.Size() != artifact.Size) {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), artifact.SHA256)
}

func downloadModelArtifact(ctx context.Context, destination string, artifact modelArtifact) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return fmt.Errorf("create model download request for %s: %w", artifact.Name, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download model artifact %s: %w", artifact.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("download model artifact %s: HTTP %d", artifact.Name, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(destination), "."+filepath.Base(destination)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary model artifact %s: %w", artifact.Name, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if copyErr != nil {
		return fmt.Errorf("write model artifact %s: %w", artifact.Name, copyErr)
	}
	if artifact.Size > 0 && written != artifact.Size {
		return fmt.Errorf("verify model artifact %s: got %d bytes, want %d", artifact.Name, written, artifact.Size)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, artifact.SHA256) {
		return fmt.Errorf("verify model artifact %s: SHA-256 %s does not match pinned digest", artifact.Name, actual)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync model artifact %s: %w", artifact.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close model artifact %s: %w", artifact.Name, err)
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return fmt.Errorf("secure model artifact %s: %w", artifact.Name, err)
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return fmt.Errorf("commit model artifact %s: %w", artifact.Name, err)
	}
	committed = true
	if dir, err := os.Open(filepath.Dir(destination)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
