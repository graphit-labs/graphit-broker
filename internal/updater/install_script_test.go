package updater

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUnixInstallScriptOffline(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("Unix release fixture exercises Linux amd64")
	}
	for _, badHash := range []bool{false, true} {
		t.Run(fmt.Sprintf("badHash=%t", badHash), func(t *testing.T) {
			root := t.TempDir()
			fixture := filepath.Join(root, "fixtures")
			binDir := filepath.Join(root, "bin")
			shimDir := filepath.Join(root, "shims")
			for _, dir := range []string{fixture, binDir, shimDir} {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			archiveName := "graphit-broker-linux-amd64.tar.gz"
			archive := testArchive(t, "graphit-broker-linux-amd64/graphit-broker", "new executable")
			if err := os.WriteFile(filepath.Join(fixture, "archive"), archive, 0o644); err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(archive)
			if badHash {
				sum = sha256.Sum256([]byte("wrong"))
			}
			if err := os.WriteFile(filepath.Join(fixture, "checksum"), []byte(fmt.Sprintf("%x  %s\n", sum, archiveName)), 0o644); err != nil {
				t.Fatal(err)
			}
			installed := filepath.Join(binDir, "graphit-broker")
			if err := os.WriteFile(installed, []byte("old executable"), 0o755); err != nil {
				t.Fatal(err)
			}
			shim := `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *.tar.gz) cp "$TEST_FIXTURE_DIR/archive" "$out" ;;
  *.sha256) cp "$TEST_FIXTURE_DIR/checksum" "$out" ;;
  *) exit 1 ;;
esac
`
			if err := os.WriteFile(filepath.Join(shimDir, "curl"), []byte(shim), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("sh", "../../install.sh", "--dir", binDir, "--version", "v1.2.0")
			cmd.Env = append(os.Environ(), "PATH="+shimDir+":"+os.Getenv("PATH"), "TEST_FIXTURE_DIR="+fixture)
			out, err := cmd.CombinedOutput()
			if (err != nil) != badHash {
				t.Fatalf("install err=%v output=%s", err, out)
			}
			got, err := os.ReadFile(installed)
			if err != nil {
				t.Fatal(err)
			}
			want := "new executable"
			if badHash {
				want = "old executable"
			}
			if strings.TrimSpace(string(got)) != want {
				t.Fatalf("installed %q, want %q; output=%s", got, want, out)
			}
		})
	}
}
