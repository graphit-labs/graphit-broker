package broker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmbeddedONNXRuntimeInstallAndCheapFastPath(t *testing.T) {
	bundle := testONNXRuntimeBundle(t)
	globalDir := t.TempDir()
	path, err := installONNXRuntimeBundle(globalDir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(globalDir, "broker", "runtime", "onnxruntime", bundle.version, bundle.platform, bundle.sha256, bundle.library)
	if path != wantPath {
		t.Fatalf("installed runtime path=%q, want %q", path, wantPath)
	}
	if _, err := os.Stat(filepath.Join(globalDir, "runtime", "onnxruntime")); !os.IsNotExist(err) {
		t.Fatalf("legacy unnamespaced runtime path exists or cannot be checked: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "runtime" {
		t.Fatalf("installed main library data=%q err=%v", data, err)
	}
	runtimeDir := filepath.Dir(path)
	if !runtimeInstallComplete(runtimeDir, bundle) {
		t.Fatal("fresh installation is not complete")
	}

	// A deliberately unreadable payload still succeeds: the completed fast path
	// only reads the small marker and stats required files.
	cheap := bundle
	cheap.payload = []byte("not a gzip stream")
	if second, err := installONNXRuntimeBundle(globalDir, cheap); err != nil || second != path {
		t.Fatalf("cheap second resolution path=%q err=%v", second, err)
	}
}

func TestEmbeddedONNXRuntimeReplacesIncompleteInstallation(t *testing.T) {
	bundle := testONNXRuntimeBundle(t)
	globalDir := t.TempDir()
	path, err := installONNXRuntimeBundle(globalDir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), "provider.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), ".complete")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), ".complete"), []byte("another build\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced, err := installONNXRuntimeBundle(globalDir, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if replaced != path || !runtimeInstallComplete(filepath.Dir(path), bundle) {
		t.Fatalf("replacement path=%q complete=%v", replaced, runtimeInstallComplete(filepath.Dir(path), bundle))
	}
}

func TestEmbeddedONNXRuntimeConcurrentInstallConverges(t *testing.T) {
	bundle := testONNXRuntimeBundle(t)
	globalDir := t.TempDir()
	const workers = 8
	paths := make(chan string, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			path, err := installONNXRuntimeBundle(globalDir, bundle)
			paths <- path
			errors <- err
		}()
	}
	group.Wait()
	close(paths)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	want := ""
	for path := range paths {
		if want == "" {
			want = path
		}
		if path != want {
			t.Fatalf("concurrent path=%q, want %q", path, want)
		}
	}
	parent := filepath.Dir(filepath.Dir(want))
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") || strings.HasPrefix(entry.Name(), ".stale-") {
			t.Fatalf("temporary directory remained after concurrent install: %s", entry.Name())
		}
	}
}

func TestGraphitGlobalDirectoryAndExplicitONNXOverride(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "global")
	t.Setenv("GRAPHIT_GLOBAL_DIR", absolute)
	if got := graphitGlobalDir(); got != absolute {
		t.Fatalf("absolute global directory=%q, want %q", got, absolute)
	}
	t.Setenv("GRAPHIT_GLOBAL_DIR", "relative-global")
	if got, want := graphitGlobalDir(), filepath.Join(brokerProcessStartDir, "relative-global"); got != want {
		t.Fatalf("relative global directory=%q, want %q", got, want)
	}
	override := filepath.Join(t.TempDir(), "onnxruntime.override")
	if err := os.WriteFile(override, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ONNXRUNTIME_SHARED_LIBRARY_PATH", override)
	if got, err := resolveONNXRuntimeLibraryPath(); err != nil || got != override {
		t.Fatalf("explicit runtime path=%q err=%v", got, err)
	}
}

func testONNXRuntimeBundle(t *testing.T) onnxRuntimeBundle {
	t.Helper()
	var payload bytes.Buffer
	gz, err := gzip.NewWriterLevel(&payload, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gz.Header.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(gz)
	for _, file := range []struct{ name, body string }{{"runtime.bin", "runtime"}, {"provider.bin", "provider"}} {
		if err := tw.WriteHeader(&tar.Header{Name: file.name, Mode: 0o500, Size: int64(len(file.body)), ModTime: time.Unix(0, 0)}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(file.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload.Bytes())
	return onnxRuntimeBundle{
		version:       "test-1",
		platform:      runtime.GOOS + "-" + runtime.GOARCH,
		library:       "runtime.bin",
		requiredFiles: []string{"runtime.bin", "provider.bin"},
		sha256:        hex.EncodeToString(digest[:]),
		payload:       payload.Bytes(),
	}
}
