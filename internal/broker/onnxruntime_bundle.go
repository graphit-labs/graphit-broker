package broker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	onnxRuntimeBundleSchema = "1"
	maxONNXRuntimeFileSize  = int64(2 << 30)
)

var brokerProcessStartDir, _ = os.Getwd()

// These values are filled by release builds with -X. Keeping them in the
// common file makes malformed tagged builds fail clearly instead of silently
// behaving like development builds.
var (
	embeddedONNXRuntimeVersion       string
	embeddedONNXRuntimePlatform      string
	embeddedONNXRuntimeLibrary       string
	embeddedONNXRuntimeRequiredFiles string
	embeddedONNXRuntimeBundleSHA256  string
)

type onnxRuntimeBundle struct {
	version       string
	platform      string
	library       string
	requiredFiles []string
	sha256        string
	payload       []byte
}

// PrepareEmbeddedONNXRuntime performs the cheap installation check on every
// packaged-binary execution. Development binaries without an embedded payload
// remain able to use ONNXRUNTIME_SHARED_LIBRARY_PATH or an adjacent runtime.
func PrepareEmbeddedONNXRuntime() error {
	if strings.TrimSpace(os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH")) != "" {
		return nil
	}
	bundle, ok, err := platformEmbeddedONNXRuntimeBundle()
	if err != nil || !ok {
		return err
	}
	_, err = installONNXRuntimeBundle(graphitGlobalDir(), bundle)
	return err
}

func graphitGlobalDir() string {
	if override := strings.TrimSpace(os.Getenv("GRAPHIT_GLOBAL_DIR")); override != "" {
		if filepath.IsAbs(override) {
			return filepath.Clean(override)
		}
		return filepath.Join(brokerProcessStartDir, override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".graphit")
}

func resolveONNXRuntimeLibraryPath() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("ONNXRUNTIME_SHARED_LIBRARY_PATH")); explicit != "" {
		return explicit, nil
	}
	bundle, ok, err := platformEmbeddedONNXRuntimeBundle()
	if err != nil {
		return "", err
	}
	if ok {
		globalDir := graphitGlobalDir()
		if globalDir == "" {
			return "", errors.New("resolve Graphit global directory: user home is unavailable and GRAPHIT_GLOBAL_DIR is unset")
		}
		return installONNXRuntimeBundle(globalDir, bundle)
	}
	for _, candidate := range onnxRuntimeCandidates() {
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", errors.New("ONNX Runtime shared library is unavailable; use an official embedded release or set ONNXRUNTIME_SHARED_LIBRARY_PATH")
}

func installONNXRuntimeBundle(globalDir string, bundle onnxRuntimeBundle) (string, error) {
	if err := validateONNXRuntimeBundle(bundle); err != nil {
		return "", err
	}
	if strings.TrimSpace(globalDir) == "" {
		return "", errors.New("Graphit global directory is empty")
	}
	runtimeDir := filepath.Join(globalDir, "broker", "runtime", "onnxruntime", bundle.version, bundle.platform, bundle.sha256)
	if runtimeInstallComplete(runtimeDir, bundle) {
		return filepath.Join(runtimeDir, bundle.library), nil
	}
	parent := filepath.Dir(runtimeDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create embedded ONNX Runtime directory: %w", err)
	}
	tmpDir, err := os.MkdirTemp(parent, "."+bundle.sha256+".tmp-")
	if err != nil {
		return "", fmt.Errorf("create embedded ONNX Runtime temporary directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmpDir)
		}
	}()
	if err := extractONNXRuntimeBundle(tmpDir, bundle); err != nil {
		return "", err
	}
	if runtimeInstallComplete(runtimeDir, bundle) {
		return filepath.Join(runtimeDir, bundle.library), nil
	}
	if err := publishRuntimeDirectory(tmpDir, runtimeDir, bundle); err != nil {
		return "", err
	}
	committed = true
	_ = os.RemoveAll(tmpDir)
	return filepath.Join(runtimeDir, bundle.library), nil
}

func validateONNXRuntimeBundle(bundle onnxRuntimeBundle) error {
	currentPlatform := runtime.GOOS + "-" + runtime.GOARCH
	if bundle.platform != currentPlatform {
		return fmt.Errorf("embedded ONNX Runtime is for %s, running on %s", bundle.platform, currentPlatform)
	}
	if strings.TrimSpace(bundle.version) == "" || !safeSegment(bundle.version) {
		return errors.New("embedded ONNX Runtime version metadata is invalid")
	}
	digest, err := hex.DecodeString(bundle.sha256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("embedded ONNX Runtime bundle SHA-256 metadata is invalid")
	}
	if len(bundle.payload) == 0 {
		return errors.New("embedded ONNX Runtime payload is empty")
	}
	seen := map[string]bool{}
	for _, name := range bundle.requiredFiles {
		if name == "" || filepath.Base(name) != name || name == "." || seen[name] {
			return fmt.Errorf("embedded ONNX Runtime required file %q is invalid", name)
		}
		seen[name] = true
	}
	if len(seen) == 0 || !seen[bundle.library] {
		return errors.New("embedded ONNX Runtime main library is not in the required file set")
	}
	return nil
}

func runtimeInstallComplete(runtimeDir string, bundle onnxRuntimeBundle) bool {
	marker, err := os.Open(filepath.Join(runtimeDir, ".complete"))
	if err != nil {
		return false
	}
	expected := runtimeBundleMarker(bundle)
	data, readErr := io.ReadAll(io.LimitReader(marker, int64(len(expected)+1)))
	closeErr := marker.Close()
	if readErr != nil || closeErr != nil || string(data) != expected {
		return false
	}
	for _, name := range bundle.requiredFiles {
		info, statErr := os.Stat(filepath.Join(runtimeDir, name))
		if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return false
		}
	}
	return true
}

func runtimeBundleMarker(bundle onnxRuntimeBundle) string {
	files := append([]string(nil), bundle.requiredFiles...)
	sort.Strings(files)
	return "schema=" + onnxRuntimeBundleSchema + "\n" +
		"bundle=" + bundle.sha256 + "\n" +
		"version=" + bundle.version + "\n" +
		"platform=" + bundle.platform + "\n" +
		"files=" + strings.Join(files, ",") + "\n"
}

func extractONNXRuntimeBundle(destination string, bundle onnxRuntimeBundle) error {
	digest := sha256.Sum256(bundle.payload)
	if actual := hex.EncodeToString(digest[:]); !strings.EqualFold(actual, bundle.sha256) {
		return fmt.Errorf("embedded ONNX Runtime payload SHA-256 %s does not match build metadata", actual)
	}
	gz, err := gzip.NewReader(bytes.NewReader(bundle.payload))
	if err != nil {
		return fmt.Errorf("open embedded ONNX Runtime payload: %w", err)
	}
	defer gz.Close()
	required := make(map[string]bool, len(bundle.requiredFiles))
	for _, name := range bundle.requiredFiles {
		required[name] = false
	}
	reader := tar.NewReader(gz)
	var total int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read embedded ONNX Runtime payload: %w", nextErr)
		}
		name := strings.TrimPrefix(filepath.ToSlash(header.Name), "./")
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(name) != name {
			return fmt.Errorf("embedded ONNX Runtime payload has unsafe entry %q", header.Name)
		}
		found, expected := required[name]
		if !expected || found {
			return fmt.Errorf("embedded ONNX Runtime payload has unexpected or duplicate file %q", name)
		}
		if header.Size <= 0 || header.Size > maxONNXRuntimeFileSize || total > maxONNXRuntimeFileSize-header.Size {
			return fmt.Errorf("embedded ONNX Runtime file %q has invalid size %d", name, header.Size)
		}
		total += header.Size
		path := filepath.Join(destination, name)
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
		if createErr != nil {
			return fmt.Errorf("create embedded ONNX Runtime file %q: %w", name, createErr)
		}
		written, copyErr := io.CopyN(file, reader, header.Size)
		syncErr := file.Sync()
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("extract embedded ONNX Runtime file %q: %w", name, copyErr)
		}
		if written != header.Size {
			return fmt.Errorf("extract embedded ONNX Runtime file %q: wrote %d bytes, expected %d", name, written, header.Size)
		}
		if syncErr != nil {
			return fmt.Errorf("sync embedded ONNX Runtime file %q: %w", name, syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close embedded ONNX Runtime file %q: %w", name, closeErr)
		}
		required[name] = true
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("embedded ONNX Runtime payload is missing %q", name)
		}
	}
	if err := os.WriteFile(filepath.Join(destination, ".complete"), []byte(runtimeBundleMarker(bundle)), 0o400); err != nil {
		return fmt.Errorf("write embedded ONNX Runtime completion marker: %w", err)
	}
	if dir, openErr := os.Open(destination); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func publishRuntimeDirectory(tmpDir, runtimeDir string, bundle onnxRuntimeBundle) error {
	if err := os.Rename(tmpDir, runtimeDir); err == nil {
		return nil
	}
	if runtimeInstallComplete(runtimeDir, bundle) {
		return nil
	}
	staleDir, err := os.MkdirTemp(filepath.Dir(runtimeDir), ".stale-")
	if err != nil {
		return fmt.Errorf("reserve stale ONNX Runtime path: %w", err)
	}
	if err := os.Remove(staleDir); err != nil {
		return fmt.Errorf("prepare stale ONNX Runtime path: %w", err)
	}
	if err := os.Rename(runtimeDir, staleDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		if runtimeInstallComplete(runtimeDir, bundle) {
			return nil
		}
		return fmt.Errorf("replace incomplete embedded ONNX Runtime: %w", err)
	}
	defer os.RemoveAll(staleDir)
	if err := os.Rename(tmpDir, runtimeDir); err != nil {
		if runtimeInstallComplete(runtimeDir, bundle) {
			return nil
		}
		return fmt.Errorf("publish embedded ONNX Runtime: %w", err)
	}
	return nil
}
