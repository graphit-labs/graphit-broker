package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testArchive(t *testing.T, entry, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: entry, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestUpdateVerifiedArchiveAndFailurePaths(t *testing.T) {
	platform := runtime.GOOS + "-" + runtime.GOARCH
	archiveName := "graphit-broker-" + platform + ".tar.gz"
	checksumName := "graphit-broker-" + platform + ".sha256"
	bin := "graphit-broker"
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	archive := testArchive(t, "graphit-broker-"+platform+"/"+bin, "new binary")
	sum := sha256.Sum256(archive)
	checksum := []byte(fmt.Sprintf("%x  %s\n", sum, archiveName))
	badChecksum := []byte(strings.Repeat("0", 64) + "  " + archiveName + "\n")
	for _, tc := range []struct {
		name, version         string
		badHash, missingAsset bool
		wantChange, wantError bool
	}{
		{"update", "v1.0.0", false, false, true, false},
		{"same version", "v1.2.0", false, false, false, false},
		{"downgrade refused", "v2.0.0", false, false, false, false},
		{"checksum mismatch", "v1.0.0", true, false, false, true},
		{"missing checksum asset", "v1.0.0", false, true, false, true},
		{"development build", "dev", false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := filepath.Join(t.TempDir(), bin)
			if err := os.WriteFile(current, []byte("old binary"), 0o755); err != nil {
				t.Fatal(err)
			}
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/release":
					assets := []map[string]string{{"name": archiveName, "browser_download_url": server.URL + "/archive"}}
					if !tc.missingAsset {
						assets = append(assets, map[string]string{"name": checksumName, "browser_download_url": server.URL + "/checksum"})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.0", "assets": assets})
				case "/archive":
					_, _ = w.Write(archive)
				case "/checksum":
					if tc.badHash {
						_, _ = w.Write(badChecksum)
					} else {
						_, _ = w.Write(checksum)
					}
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			_, err := Update(context.Background(), tc.version, current, server.Client(), server.URL+"/release")
			if (err != nil) != tc.wantError {
				t.Fatalf("Update error = %v, wantError %t", err, tc.wantError)
			}
			got, err := os.ReadFile(current)
			if err != nil {
				t.Fatal(err)
			}
			want := "old binary"
			if tc.wantChange {
				want = "new binary"
			}
			if string(got) != want {
				t.Fatalf("installed executable = %q, want %q", got, want)
			}
		})
	}
}

func TestExtractRejectsSymlinkAndWrongEntry(t *testing.T) {
	archive := testArchive(t, "other/executable", "content")
	var dst bytes.Buffer
	if err := extract(bytes.NewReader(archive), "expected/executable", &dst); err == nil {
		t.Fatal("wrong archive entry accepted")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "expected/executable", Typeflag: tar.TypeSymlink, Linkname: "../../evil"}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()
	if err := extract(bytes.NewReader(buf.Bytes()), "expected/executable", &dst); err == nil {
		t.Fatal("symlink executable accepted")
	}
}

func TestCompareVersionsDoesNotOverflow(t *testing.T) {
	if got := compareVersions("v1.999999999999999999999999999999.0", "v2.0.0"); got >= 0 {
		t.Fatalf("major version comparison = %d", got)
	}
	if got := compareVersions("v01.002.3", "v1.2.3"); got != 0 {
		t.Fatalf("leading-zero comparison = %d", got)
	}
}
