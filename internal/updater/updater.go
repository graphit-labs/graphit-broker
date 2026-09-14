package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const latestURL = "https://api.github.com/repos/graphit-labs/graphit-broker/releases/latest"

var releaseVersion = regexp.MustCompile(`^v([0-9]+)\.([0-9]+)\.([0-9]+)$`)

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Update replaces only the executable, never the broker configuration or state.
// The client and API URL arguments permit hermetic release tests.
func Update(ctx context.Context, currentVersion, executable string, client *http.Client, apiURL string) (string, error) {
	if currentVersion == "dev" {
		return "", errors.New("development builds cannot self-update; install a tagged release first")
	}
	if !releaseVersion.MatchString(currentVersion) {
		return "", fmt.Errorf("unrecognized installed version %q", currentVersion)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	if apiURL == "" {
		apiURL = latestURL
	}
	data, err := fetch(ctx, client, apiURL, 2<<20)
	if err != nil {
		return "", fmt.Errorf("fetch latest release: %w", err)
	}
	var rel release
	if err := json.Unmarshal(data, &rel); err != nil {
		return "", fmt.Errorf("decode latest release: %w", err)
	}
	if !releaseVersion.MatchString(rel.TagName) {
		return "", fmt.Errorf("invalid release tag %q", rel.TagName)
	}
	if compareVersions(currentVersion, rel.TagName) >= 0 {
		return fmt.Sprintf("Already up to date (%s); latest release is %s", currentVersion, rel.TagName), nil
	}
	platform := runtime.GOOS + "-" + runtime.GOARCH
	archiveName := "graphit-broker-" + platform + ".tar.gz"
	checksumName := "graphit-broker-" + platform + ".sha256"
	var archiveURL, checksumURL string
	for _, asset := range rel.Assets {
		switch asset.Name {
		case archiveName:
			archiveURL = asset.URL
		case checksumName:
			checksumURL = asset.URL
		}
	}
	if archiveURL == "" || checksumURL == "" {
		return "", fmt.Errorf("release %s has no archive and checksum for %s", rel.TagName, platform)
	}
	archive, err := os.CreateTemp("", "graphit-broker-release-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create temporary archive: %w", err)
	}
	defer os.Remove(archive.Name())
	defer archive.Close()
	if err := download(ctx, client, archiveURL, 1<<30, archive); err != nil {
		return "", fmt.Errorf("download archive: %w", err)
	}
	checksum, err := fetch(ctx, client, checksumURL, 4096)
	if err != nil {
		return "", fmt.Errorf("download checksum: %w", err)
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if err := verify(archive, checksum, archiveName); err != nil {
		return "", err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	// Stage on the executable's filesystem so replacement is a rename, not a partial copy.
	staged, err := os.CreateTemp(filepath.Dir(executable), ".graphit-broker-update-*")
	if err != nil {
		return "", fmt.Errorf("stage executable beside %s: %w", executable, err)
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	defer staged.Close()
	binName := "graphit-broker"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	if err := extract(archive, "graphit-broker-"+platform+"/"+binName, staged); err != nil {
		return "", err
	}
	if err := staged.Chmod(0o755); err != nil {
		return "", err
	}
	if err := staged.Sync(); err != nil {
		return "", err
	}
	if err := staged.Close(); err != nil {
		return "", err
	}
	if err := replace(stagedPath, executable); err != nil {
		return "", err
	}
	return fmt.Sprintf("Updated graphit-broker from %s to %s. Restart any running broker service to use it.", currentVersion, rel.TagName), nil
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	var buf bytes.Buffer
	if err := download(ctx, client, url, limit, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func download(ctx context.Context, client *http.Client, url string, limit int64, dest io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "graphit-broker-self-update/1")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", url, resp.StatusCode)
	}
	n, err := io.Copy(dest, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("download exceeds %d bytes", limit)
	}
	return nil
}

func verify(archive io.Reader, checksum []byte, archiveName string) error {
	for _, line := range strings.Split(string(checksum), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == archiveName {
			want, err := hex.DecodeString(fields[0])
			if err != nil || len(want) != sha256.Size {
				return errors.New("invalid release checksum")
			}
			h := sha256.New()
			if _, err := io.Copy(h, archive); err != nil {
				return err
			}
			if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
				return errors.New("archive SHA-256 mismatch")
			}
			return nil
		}
	}
	return fmt.Errorf("checksum for %s not found", archiveName)
}

func extract(archive io.Reader, entry string, target io.Writer) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Name != entry {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return errors.New("release executable is not a regular file")
		}
		if hdr.Size <= 0 || hdr.Size > 1<<30 {
			return errors.New("invalid release executable size")
		}
		_, err = io.CopyN(target, tr, hdr.Size)
		return err
	}
	return fmt.Errorf("release executable %s not found", entry)
}

func replace(staged, current string) error {
	// Unique backup avoids overwriting a previous interrupted update.
	backup := current + ".bak-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if err := os.Rename(current, backup); err != nil {
		return fmt.Errorf("backup installed executable: %w", err)
	}
	if err := os.Rename(staged, current); err != nil {
		if restoreErr := os.Rename(backup, current); restoreErr != nil {
			return fmt.Errorf("install updated executable: %v; restore original from %s failed: %w", err, backup, restoreErr)
		}
		return fmt.Errorf("install updated executable: %w", err)
	}
	// On Windows the running old executable may remain locked until this process exits.
	_ = os.Remove(backup)
	return nil
}

func compareVersions(a, b string) int {
	aa, bb := releaseVersion.FindStringSubmatch(a), releaseVersion.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		av := strings.TrimLeft(aa[i], "0")
		bv := strings.TrimLeft(bb[i], "0")
		if len(av) < len(bv) || len(av) == len(bv) && av < bv {
			return -1
		}
		if len(av) > len(bv) || len(av) == len(bv) && av > bv {
			return 1
		}
	}
	return 0
}
