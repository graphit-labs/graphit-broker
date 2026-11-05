#!/usr/bin/env python3
"""Exercise the public Unix installer with local, checksum-verified release fixtures."""
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import subprocess
import tarfile
import tempfile
import textwrap
import unittest

REPO = Path(__file__).resolve().parents[1]
CPU = ["graphit-broker", "graphit-runtime/licenses/broker/LICENSE",
       "graphit-runtime/licenses/broker/ggml/LICENSE", "graphit-runtime/licenses/broker/ggml/LICENSE-MIT", "graphit-runtime/licenses/broker/ggml/LICENSE-APACHE", "graphit-runtime/licenses/broker/nvidia/LICENSE",
       "graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp"]
LINUX = ["graphit-runtime/broker/linux-libraries.json", "graphit-runtime/broker/lib/libstdc++.so.6",
         "graphit-runtime/broker/lib/libgcc_s.so.1", "graphit-runtime/licenses/broker/linux/libstdc++.so.6.copyright",
         "graphit-runtime/licenses/broker/linux/libgcc_s.so.1.copyright", "graphit-runtime/licenses/broker/linux/GPL-3"] + [
    "graphit-runtime/broker/lib/" + name for name in
    ["libllama.so", "libggml.so", "libggml-base.so", "libggml-cpu.so", "libggml-cuda.so",
     "libcudart.so.12", "libcublas.so.12", "libcublasLt.so.12"]]



class Installer(unittest.TestCase):
    def test_package_switch_and_rejection_preserve_unrelated_files(self):
        self.install_case(local=False)

    def test_local_archive_and_make_install_use_the_same_validated_payload(self):
        self.install_case(local=True)

    def test_cuda_13_local_archive_keeps_notices_and_installation_boundaries(self):
        self.install_case(local=True, cuda_major=13)

    def install_case(self, local, cuda_major=12):
        with tempfile.TemporaryDirectory(prefix="broker-install-") as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            (tools / "curl").write_text('''#!/bin/sh
set -eu
url=
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    https:*) url=$1; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  *.tar.gz) cp "$FIXTURE_ARCHIVE" "$output" ;;
  *.sha256) cp "$FIXTURE_CHECKSUM" "$output" ;;
  *) exit 1 ;;
esac
''')
            if local:
                (tools / "curl").write_text("#!/bin/sh\nexit 99\n")
            (tools / "curl").chmod(0o755)
            (tools / "uname").write_text('#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; *) exit 1 ;; esac\n')
            (tools / "uname").chmod(0o755)
            destination = root / "bin"
            destination.mkdir()
            (destination / "unrelated-product").write_text("keep")
            other_runtime = destination / "graphit-runtime/lib/unrelated.so"
            other_runtime.parent.mkdir(parents=True)
            other_runtime.write_text("keep")
            archive = root / "graphit-broker-linux-amd64.tar.gz"
            checksum = root / "graphit-broker-linux-amd64.sha256"
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                               FIXTURE_ARCHIVE=str(archive), FIXTURE_CHECKSUM=str(checksum))
            environment.pop("VERSION", None)
            for index, invalid in enumerate([None, "digest", "missing-notice", "missing-engine-notice", "missing-nvidia-notice", None]):
                with tarfile.open(archive, "w:gz") as output:
                    for name in CPU + [name.replace(".so.12", f".so.{cuda_major}") for name in LINUX]:
                        missing = {"missing-notice": CPU[-1],
                                   "missing-engine-notice": "graphit-runtime/licenses/broker/ggml/LICENSE-MIT",
                                   "missing-nvidia-notice": "graphit-runtime/licenses/broker/nvidia/LICENSE"}
                        if name == missing.get(invalid):
                            continue
                        data = f"release {index}: {name}\n".encode()
                        entry = tarfile.TarInfo("graphit-broker-linux-amd64/" + name)
                        entry.size = len(data)
                        entry.mode = 0o755 if name == "graphit-broker" else 0o644
                        output.addfile(entry, io.BytesIO(data))
                digest = hashlib.sha256(archive.read_bytes()).hexdigest() if invalid != "digest" else "0" * 64
                checksum.write_text(digest + "  " + archive.name + "\n")
                before = {path.relative_to(destination): path.read_bytes()
                          for path in destination.rglob("*") if path.is_file()}
                selection = ["--archive", str(archive)] if local else ["--version", "v1.2.0"]
                result = subprocess.run(["sh", str(REPO / "install.sh"), "--dir", str(destination)] + selection,
                                        env=environment, capture_output=True, text=True)
                if invalid:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("SHA-256 mismatch" if invalid == "digest" else "required native license missing", result.stderr)
                    self.assertEqual(before, {path.relative_to(destination): path.read_bytes()
                                            for path in destination.rglob("*") if path.is_file()})
                    continue
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((destination / "graphit-broker").read_text(), f"release {index}: graphit-broker\n")
                self.assertEqual((destination / "unrelated-product").read_text(), "keep")
                self.assertEqual(other_runtime.read_text(), "keep")

            if local:
                # The Make target packages its existing binary, then invokes this same
                # real installer. Only the producer is controlled; no network is usable.
                shutil.copyfile(REPO / "Makefile", root / "Makefile")
                shutil.copyfile(REPO / "install.sh", root / "install.sh")
                record = root / "package-context"
                (tools / "cargo").write_text("""#!/bin/sh
set -eu
case "$*" in
  'run --release --locked --offline --quiet -p xtask -- package --binary ./graphit-broker --output '*) ;;
  *) exit 31 ;;
esac
for arg do output=$arg; done
mkdir "$output"
cp "$FIXTURE_ARCHIVE" "$output/graphit-broker-linux-amd64.tar.gz"
cp "$FIXTURE_CHECKSUM" "$output/graphit-broker-linux-amd64.sha256"
printf '%s' "$output" > "$FIXTURE_PACKAGE_RECORD"
""")
                (tools / "cargo").chmod(0o755)
                environment["FIXTURE_PACKAGE_RECORD"] = str(record)
                make_destination = root / "make-bin"
                result = subprocess.run(["make", "-o", "build", "install", "PREFIX=" + str(make_destination)],
                                        cwd=root, env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((make_destination / "graphit-broker").read_bytes(),
                                 (destination / "graphit-broker").read_bytes())
                self.assertFalse(Path(record.read_text()).parent.exists(), "owned package context must be removed")

    def test_make_container_uses_owned_package_context_and_cleans_up(self):
        with tempfile.TemporaryDirectory(prefix="broker-make-container-") as directory:
            root = Path(directory)
            for name in ["Makefile", "Dockerfile", ".dockerignore", "docker-entrypoint.sh"]:
                shutil.copyfile(REPO / name, root / name)
            tools = root / "tools"
            tools.mkdir()
            (tools / "cargo").write_text("""#!/bin/sh
set -eu
[ "$*" != "" ]
case "$*" in
  'run --release --locked --offline --quiet -p xtask -- package --binary ./graphit-broker --output '*) ;;
  *) exit 31 ;;
esac
for arg do output=$arg; done
mkdir "$output"
printf 'controlled package input' > "$output/graphit-broker-linux-amd64.tar.gz"
""")
            (tools / "docker").write_text("""#!/bin/sh
set -eu
[ "$1 $2 $3" = 'build -t graphit-broker:dev' ]
context=$4
for file in Dockerfile .dockerignore docker-entrypoint.sh installer-package/graphit-broker-linux-amd64.tar.gz; do
  [ -s "$context/$file" ]
done
printf '%s' "$context" > "$FIXTURE_CONTEXT_RECORD"
exit "$FIXTURE_DOCKER_STATUS"
""")
            for tool in tools.iterdir():
                tool.chmod(0o755)
            record = root / "context-record"
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"],
                               FIXTURE_CONTEXT_RECORD=str(record))
            for status in ["0", "23"]:
                environment["FIXTURE_DOCKER_STATUS"] = status
                result = subprocess.run(["make", "-o", "build", "docker-build"], cwd=root,
                                        env=environment, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, status == "0", result.stderr)
                self.assertFalse(Path(record.read_text()).exists(), "owned context must be removed")
                self.assertTrue((root / "Makefile").exists())

    def test_windows_make_selects_complete_powershell_installer(self):
        with tempfile.TemporaryDirectory(prefix="broker-windows-make-") as directory:
            root = Path(directory)
            shutil.copyfile(REPO / "Makefile", root / "Makefile")
            tools = root / "tools"
            tools.mkdir()
            (tools / "cargo").write_text("""#!/bin/sh
set -eu
case "$*" in
 'run --release --locked --offline --quiet -p xtask -- package --binary ./graphit-broker.exe --output '*) ;;
 *) exit 31 ;;
esac
for arg do output=$arg; done
mkdir "$output"
printf 'controlled package' > "$output/graphit-broker-windows-amd64.tar.gz"
""")
            (tools / "powershell.exe").write_text("""#!/bin/sh
set -eu
[ "$1 $2 $3 $4 $5" = '-NoProfile -ExecutionPolicy Bypass -File install.ps1' ]
[ "$6" = '-Archive' ] && [ -f "$7" ]
[ "$8" = '-Dir' ] && [ "$9" = "$EXPECTED_DESTINATION" ]
printf '%s' "$7" > "$WINDOWS_INSTALL_RECORD"
""")
            for tool in tools.iterdir(): tool.chmod(0o755)
            record = root / "record"
            appdata = root / "Local AppData"
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], OS="Windows_NT",
                               LOCALAPPDATA=str(appdata), WINDOWS_INSTALL_RECORD=str(record),
                               EXPECTED_DESTINATION=str(appdata / "Programs/graphit-broker"))
            result = subprocess.run(["make", "-o", "build", "install"], cwd=root, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(Path(record.read_text()).parent.parent.exists())

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell parser/runtime unavailable on this host")
    def test_powershell_installer_contract_on_linux_fixture(self):
        if os.name == "nt": self.skipTest("Windows CI exercises the real native package separately")
        with tempfile.TemporaryDirectory(prefix="broker-powershell-contract-") as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            (tools / "tar.exe").write_text('#!/bin/sh\nexec /usr/bin/tar "$@"\n')
            (tools / "tar.exe").chmod(0o755)
            names = ["graphit-broker.exe"] + CPU[1:] + ["vcruntime140.dll", "graphit-runtime/broker/licenses/windows-amd64/Microsoft-VC-REDIST-NOTICE.txt"]
            payloads = {name: b"controlled installer fixture\n" for name in names}
            # A shell fixture exercises installer IO/control flow only, never PE/DLL loading.
            payloads["graphit-broker.exe"] = b'#!/bin/sh\nprintf "graphit-broker 0.1.0\\n"\n'
            manifest = {"platform": "windows-amd64", "executables": [{"file": "graphit-broker.exe", "sha256": hashlib.sha256(payloads["graphit-broker.exe"]).hexdigest()}],
                        "libraries": [{"file": "vcruntime140.dll", "sha256": hashlib.sha256(payloads["vcruntime140.dll"]).hexdigest()}]}
            payloads["graphit-runtime/broker/windows-libraries.json"] = json.dumps(manifest).encode()
            archive = root / "graphit-broker-windows-amd64.tar.gz"
            with tarfile.open(archive, "w:gz") as output:
                for name, data in payloads.items():
                    entry = tarfile.TarInfo("graphit-broker-windows-amd64/" + name)
                    entry.size, entry.mode = len(data), 0o755 if name.endswith(".exe") else 0o644
                    output.addfile(entry, io.BytesIO(data))
            archive.with_name("graphit-broker-windows-amd64.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
            environment = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], PROCESSOR_ARCHITECTURE="AMD64")
            environment.pop("VERSION", None)
            result = subprocess.run([shutil.which("pwsh"), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(REPO / "scripts/test-install.ps1"), "-Archive", str(archive)], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_release_validator_accepts_complete_cpu_and_rejects_invalid_layouts(self):
        self.release_validator_case(cuda_major=12)

    def test_release_validator_cuda_13_retains_license_and_layout_rejections(self):
        self.release_validator_case(cuda_major=13)

    def release_validator_case(self, cuda_major):
        workflow = (REPO / ".github/workflows/release.yml").read_text()
        step = workflow.split("- name: Verify every native pair before release mutation", 1)[1]
        code = textwrap.dedent(step.split("python3 - <<'PY'\n", 1)[1].split("          PY\n", 1)[0])
        with tempfile.TemporaryDirectory(prefix="broker-release-contract-") as directory:
            root = Path(directory)
            environment = dict(os.environ, BROKER_COMMIT="broker-fixture", CODE_REPOSITORY="fixture/code",
                               CODE_COMMIT="code-fixture", GITHUB_REF_NAME="v1.2.0")
            for issue in [None, "missing-notice", "missing-nvidia-notice", "unknown", "escape",
                          "duplicate", "symlink", "wrong-mode", "wrong-platform",
                          "windows-missing-dll", "windows-missing-notice", "windows-digest", "windows-case-duplicate", "macos-manifest"]:
                for platform in ["linux-amd64", "darwin-arm64", "windows-amd64"]:
                    package = root / "release-assets" / platform / "installer-package"
                    package.mkdir(parents=True, exist_ok=True)
                    (package.parent / "code-source.txt").write_text(
                        "broker_commit=broker-fixture\ncode_repository=fixture/code\ncode_commit=code-fixture\n"
                        f"platform={platform}\nversion=1.2.0\ncode_ref=fixture-ref\n")
                    archive = package / f"graphit-broker-{platform}.tar.gz"
                    executable = "graphit-broker.exe" if platform == "windows-amd64" else "graphit-broker"
                    names = [executable] + CPU[1:]
                    if platform == "linux-amd64": names += [name.replace(".so.12", f".so.{cuda_major}") for name in LINUX]
                    elif platform == "darwin-arm64": names += ["graphit-runtime/broker/macos-libraries.json", "graphit-runtime/broker/lib/libcrypto.3.dylib", "graphit-runtime/broker/licenses/darwin-arm64/OpenSSL-LICENSE.txt"]
                    else: names += ["graphit-runtime/broker/windows-libraries.json", "vcruntime140.dll", "msvcp140.dll", "graphit-runtime/broker/licenses/windows-amd64/Microsoft-VC-REDIST-NOTICE.txt"]
                    payloads = {name: b"controlled release fixture\n" for name in names}
                    if platform != "linux-amd64":
                        manifest_name = "graphit-runtime/broker/" + ("macos" if platform == "darwin-arm64" else "windows") + "-libraries.json"
                        manifest = {"platform": "linux-amd64" if issue == "macos-manifest" and platform == "darwin-arm64" else platform,
                                    "executables": [{"file": executable, "sha256": hashlib.sha256(payloads[executable]).hexdigest()}],
                                    "libraries": [{"file": name, "sha256": hashlib.sha256(payloads[name]).hexdigest()} for name in names if name.endswith((".dll", ".dylib"))]}
                        payloads[manifest_name] = json.dumps(manifest).encode()
                    affected = platform == "linux-amd64"
                    if affected:
                        if issue == "missing-notice": names.remove(CPU[-1])
                        if issue == "missing-nvidia-notice": names.remove("graphit-runtime/licenses/broker/nvidia/LICENSE")
                        if issue == "unknown": names += ["unrecognized.so"]
                        if issue == "escape": names += ["../outside"]
                        if issue == "duplicate": names += [CPU[-1]]
                    if platform == "windows-amd64":
                        if issue == "windows-missing-dll": names.remove("vcruntime140.dll")
                        if issue == "windows-missing-notice": names.remove("graphit-runtime/broker/licenses/windows-amd64/Microsoft-VC-REDIST-NOTICE.txt")
                        if issue == "windows-digest": payloads[executable] = b"wrong executable"
                        if issue == "windows-case-duplicate": names += ["VCRUNTIME140.dll"]
                    with tarfile.open(archive, "w:gz") as output:
                        for name in names:
                            selected = "darwin-arm64" if affected and issue == "wrong-platform" else platform
                            entry = tarfile.TarInfo(f"graphit-broker-{selected}/" + name)
                            data = payloads.get(name, b"unrecognized fixture\n")
                            entry.size = len(data)
                            entry.mode = 0o755 if name == executable else 0o644
                            if affected and issue == "wrong-mode" and name == CPU[-1]: entry.mode = 0o777
                            if affected and issue == "symlink" and name == CPU[-1]:
                                entry.type, entry.linkname, entry.size = tarfile.SYMTYPE, "/outside", 0
                                output.addfile(entry)
                            else:
                                output.addfile(entry, io.BytesIO(data))
                    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                    (package / f"graphit-broker-{platform}.sha256").write_text(digest + "  " + archive.name + "\n")
                result = subprocess.run(["python3", "-c", code], cwd=root, env=environment,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, issue is None, f"{issue}: {result.stderr}")

    def test_container_copies_the_complete_installer_payload(self):
        dockerfile = (REPO / "Dockerfile").read_text()
        self.assertIn("COPY installer-package/graphit-broker-linux-amd64.tar.gz", dockerfile)
        self.assertIn("/package/graphit-broker-linux-amd64/ /usr/local/bin/", dockerfile)
        self.assertIn("!installer-package/graphit-broker-linux-amd64.tar.gz", (REPO / ".dockerignore").read_text())


if __name__ == "__main__":
    unittest.main()
