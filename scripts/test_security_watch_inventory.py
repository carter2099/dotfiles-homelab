import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import inventory  # noqa: E402
from security_watch.config import ComponentSpec  # noqa: E402
from security_watch.model import Package  # noqa: E402

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
IMAGE_ID = "sha256:" + "ab" * 32

UBUNTU_OS = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\nID_LIKE=debian\n'
DEBIAN13_OS = 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nNAME="Debian GNU/Linux"\nVERSION_ID="13"\nID=debian\n'
ALPINE_OS = 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.24.2\n'
VOID_OS = 'NAME="Void"\nID="void"\nPRETTY_NAME="Void Linux"\n'
DISTROLESS_OS = 'PRETTY_NAME="Distroless"\nNAME="Debian GNU/Linux"\nID="debian"\nVERSION_ID="12"\n'


def proc(stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def dpkg_row(status, source, source_version, binary, version):
    return "\t".join([status, source, source_version, binary, version]) + "\n"


class FakeRun:
    """argv-prefix tuple -> CompletedProcess or callable(argv) -> CompletedProcess."""

    def __init__(self, table):
        self.table = {tuple(k): v for k, v in table.items()}
        self.calls = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        best = None
        for prefix in self.table:
            if tuple(argv[:len(prefix)]) == prefix and (best is None or len(prefix) > len(best)):
                best = prefix
        if best is None:
            return subprocess.CompletedProcess(argv, 127, "", "not faked")
        value = self.table[best]
        return value(argv) if callable(value) else value


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def fetch_rig(state):
    def fetch(url, **kwargs):
        return FakeResponse({"rig_os": state, "status": "down"})
    return fetch


def spec(id, collector, **extra):
    return ComponentSpec(id=id, kind="test", collector=collector, exposure="none", owner="alert",
                         lock=id, extra=extra)


def inspect_out(running=True, status="running", image="example:1"):
    return proc('{"image_id":"%s","image":"%s","running":%s,"status":"%s"}\n'
                % (IMAGE_ID, image, "true" if running else "false", status))


def docker_cp_writer(files):
    """Fake `docker cp -L C:path dest`: files maps in-container path -> bytes | dict(name -> str)."""
    def run(argv):
        src = argv[3].split(":", 1)[1]
        dest = Path(argv[4])
        content = files.get(src)
        if content is None:
            return proc(rc=1, stderr="no such file")
        if isinstance(content, dict):
            dest.mkdir()
            for name, text in content.items():
                (dest / name).write_text(text)
        else:
            dest.write_bytes(content)
        return proc()
    return run


GO_VERSION_M = (
    "{path}: go1.27.3 X:nocoverageredesign\n"
    "\tpath\tgithub.com/carter2099/demo\n"
    "\tmod\tgithub.com/carter2099/demo\t(devel)\t\n"
    "\tdep\tgithub.com/gorilla/websocket\tv1.5.3\th1:abc=\n"
    "\tdep\tgolang.org/x/net\tv0.40.0\th1:def=\n"
    "\t=>\tgolang.org/x/net\tv0.47.0\th1:ghi=\n"
    "\tdep\texample.com/local\tv1.0.0\n"
    "\t=>\t../local\t\n"
    "\tbuild\t-compiler=gc\n"
    "\tbuild\tvcs.revision=0123abc\n"
)


def go_version_m(argv):
    return proc(GO_VERSION_M.format(path=argv[-1]))


class HomeTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        patcher = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)
        self.go = str(inventory.go_bin())


class EcosystemTests(unittest.TestCase):
    def test_ubuntu_even_april_release_is_lts(self):
        self.assertEqual(inventory.os_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.04"}), "Ubuntu:24.04:LTS")

    def test_ubuntu_non_lts_releases_have_no_lts_suffix(self):
        self.assertEqual(inventory.os_ecosystem({"ID": "ubuntu", "VERSION_ID": "24.10"}), "Ubuntu:24.10")
        self.assertEqual(inventory.os_ecosystem({"ID": "ubuntu", "VERSION_ID": "25.04"}), "Ubuntu:25.04")

    def test_debian_alpine_and_void(self):
        self.assertEqual(inventory.os_ecosystem({"ID": "debian", "VERSION_ID": "13"}), "Debian:13")
        self.assertEqual(inventory.os_ecosystem({"ID": "alpine", "VERSION_ID": "3.24.2"}), "Alpine:v3.24")
        self.assertIsNone(inventory.os_ecosystem({"ID": "void"}))

    def test_os_release_quotes_are_stripped(self):
        osr = inventory.parse_os_release(VOID_OS)
        self.assertEqual(osr["ID"], "void")
        self.assertEqual(osr["PRETTY_NAME"], "Void Linux")


class HostTests(HomeTestCase):
    def test_host_dpkg_and_running_kernel(self):
        rows = (dpkg_row("ii ", "brotli", "1.1.0-2ubuntu0.1", "libbrotli1:amd64", "1.1.0-2ubuntu0.1")
                + dpkg_row("ii ", "brotli", "1.1.0-2ubuntu0.1", "brotli", "1.1.0-2ubuntu0.1")
                + dpkg_row("rc ", "oldpkg", "1.0-1", "oldpkg", "1.0-1")
                + dpkg_row("ii ", "", "", "plainpkg:amd64", "2.0-1"))
        run = FakeRun({
            ("cat", "/etc/os-release"): proc(UBUNTU_OS),
            ("dpkg-query", "-W", "-f", inventory.DPKG_FORMAT): proc(rows),
            ("cat", "/proc/version_signature"): proc("Ubuntu 6.8.0-147.147-generic 6.8.12\n"),
            ("stat",): proc("1700418 1793678400\n"),
        })
        inv = inventory.collect(spec("host", "host-dpkg"), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        eco = "Ubuntu:24.04:LTS"
        self.assertEqual(inv.meta["ecosystem"], eco)
        self.assertEqual(inv.meta["kernel"], "Ubuntu 6.8.0-147.147-generic 6.8.12")
        idents = {(p.ecosystem, p.name, p.version) for p in inv.packages}
        self.assertEqual(idents, {(eco, "brotli", "1.1.0-2ubuntu0.1"), (eco, "plainpkg", "2.0-1"),
                                  (eco, "linux", "6.8.0-147.147")})
        brotli = next(p for p in inv.packages if p.name == "brotli")
        self.assertEqual(brotli.binary, "brotli,libbrotli1:amd64")
        self.assertIn(Package(eco, "linux", "6.8.0-147.147", binary="running-kernel"), inv.packages)
        self.assertTrue(inv.fingerprint)
        self.assertEqual(inv.fingerprint, inventory.fingerprint(spec("host", "host-dpkg"), run=run))

    def test_host_drops_installed_kernel_sources_but_keeps_running_kernel(self):
        rows = (dpkg_row("ii ", "linux", "6.8.0-146.146", "linux-image-6.8.0-146-generic", "6.8.0-146.146")
                + dpkg_row("ii ", "linux", "6.8.0-146.146", "linux-headers-6.8.0-146", "6.8.0-146.146")
                + dpkg_row("ii ", "linux", "6.8.0-147.147", "linux-libc-dev:amd64", "6.8.0-147.147")
                + dpkg_row("ii ", "linux-signed", "6.8.0-146.146", "linux-image-6.8.0-146-generic", "6.8.0-146.146")
                + dpkg_row("ii ", "linux-meta", "6.8.0-147.147", "linux-generic", "6.8.0-147.147")
                + dpkg_row("ii ", "linux-hwe-6.8", "6.8.0-146.146~22.04.1", "linux-hwe-6.8-headers", "6.8.0-146.146~22.04.1")
                + dpkg_row("ii ", "linux-firmware", "20240318.git3b128b60-0ubuntu2.20", "linux-firmware", "20240318.git3b128b60-0ubuntu2.20")
                + dpkg_row("ii ", "linux-base", "4.5ubuntu9", "linux-base", "4.5ubuntu9"))
        run = FakeRun({
            ("cat", "/etc/os-release"): proc(UBUNTU_OS),
            ("dpkg-query", "-W", "-f", inventory.DPKG_FORMAT): proc(rows),
            ("cat", "/proc/version_signature"): proc("Ubuntu 6.8.0-147.147-generic 6.8.12\n"),
            ("stat",): proc("1 2\n"),
        })
        inv = inventory.collect(spec("host", "host-dpkg"), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        eco = "Ubuntu:24.04:LTS"
        kernel = [p for p in inv.packages if p.name == "linux"]
        self.assertEqual(kernel, [Package(eco, "linux", "6.8.0-147.147", binary="running-kernel")])
        self.assertEqual({p.name for p in inv.packages}, {"linux", "linux-firmware", "linux-base"})
        self.assertEqual(inv.meta["kernel_rows_dropped"], 6)

    def test_kernel_source_classification(self):
        for source in ("linux", "linux-signed", "linux-meta-hwe-6.8", "linux-hwe-6.8", "linux-aws-6.8",
                       "linux-restricted-modules", "linux-oem-6.11"):
            self.assertTrue(inventory.is_kernel_source(source), source)
        for source in ("linux-firmware", "linux-base", "linux-atm", "linux-sound-base", "util-linux", "linuxdoc-tools"):
            self.assertFalse(inventory.is_kernel_source(source), source)

    def test_host_fingerprint_changes_with_kernel(self):
        base = {("stat",): proc("1 2\n"), ("cat", "/proc/version_signature"): proc("Ubuntu 6.8.0-147.147-generic 6.8.12")}
        other = dict(base)
        other[("cat", "/proc/version_signature")] = proc("Ubuntu 6.8.0-148.148-generic 6.8.12")
        s = spec("host", "host-dpkg")
        self.assertNotEqual(inventory.fingerprint(s, run=FakeRun(base)), inventory.fingerprint(s, run=FakeRun(other)))

    def test_host_dpkg_failure_is_unknown(self):
        run = FakeRun({("cat", "/etc/os-release"): proc(UBUNTU_OS),
                       ("dpkg-query",): proc(rc=2, stderr="boom")})
        inv = inventory.collect(spec("host", "host-dpkg"), run=run, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertIn("dpkg-query", inv.reason)


class ContainerTests(HomeTestCase):
    def test_debian_container_maps_binnmu_binary_to_source_version(self):
        rows = (dpkg_row("ii ", "brotli", "1.1.0-2", "libbrotli1:amd64", "1.1.0-2+b7")
                + dpkg_row("ii ", "curl", "8.14.1-2", "libcurl4t64:amd64", "8.14.1-2"))
        run = FakeRun({
            ("docker", "inspect"): inspect_out(image="freshrss/freshrss:1.27"),
            ("docker", "exec", "freshrss", "cat", "/etc/os-release"): proc(DEBIAN13_OS),
            ("docker", "exec", "freshrss", "dpkg-query"): proc(rows),
            ("docker", "exec", "freshrss", "php"): proc("8.4.27"),
        })
        s = spec("freshrss", "container", container="freshrss", runtimes={"php": ["php", "-r", "echo PHP_VERSION;"]})
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual(inv.fingerprint, IMAGE_ID)
        self.assertEqual(inv.meta["image"], "freshrss/freshrss:1.27")
        self.assertEqual(inv.meta["image_id"], IMAGE_ID)
        self.assertEqual(inv.meta["ecosystem"], "Debian:13")
        self.assertEqual(inv.meta["os"], {"id": "debian", "version_id": "13"})
        self.assertIn(Package("Debian:13", "brotli", "1.1.0-2", binary="libbrotli1:amd64"), inv.packages)
        self.assertIn(Package("runtime", "php", "8.4.27", location="freshrss"), inv.packages)
        self.assertEqual(inventory.fingerprint(s, run=run), IMAGE_ID)

    def test_container_drops_linux_libc_dev(self):
        rows = (dpkg_row("ii ", "linux", "6.12.48-1", "linux-libc-dev:amd64", "6.12.48-1")
                + dpkg_row("ii ", "brotli", "1.1.0-2", "libbrotli1:amd64", "1.1.0-2+b7"))
        run = FakeRun({
            ("docker", "inspect"): inspect_out(),
            ("docker", "exec", "open-webui", "cat", "/etc/os-release"): proc(DEBIAN13_OS),
            ("docker", "exec", "open-webui", "dpkg-query"): proc(rows),
        })
        inv = inventory.collect(spec("open-webui", "container", container="open-webui"), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual([p.name for p in inv.packages], ["brotli"])
        self.assertEqual(inv.meta["kernel_rows_dropped"], 1)

    def test_status_d_drops_kernel_sources(self):
        stats = {}
        packages = inventory.parse_status_d(
            ["Package: linux-libc-dev\nSource: linux (6.1.153-1)\nVersion: 6.1.153-1\n",
             "Package: tzdata\nVersion: 2026b-0+deb12u1\n"], "Debian:12", stats=stats)
        self.assertEqual([p.name for p in packages], ["tzdata"])
        self.assertEqual(stats["kernel_rows_dropped"], 1)

    def test_alpine_apk_packages_use_origin(self):
        apk = ("alpine-baselayout-3.7.2-r1 x86_64 {alpine-baselayout} (GPL-2.0-only) [installed]\n"
               "alpine-baselayout-data-3.7.2-r1 x86_64 {alpine-baselayout} (GPL-2.0-only) [installed]\n"
               "brotli-libs-1.2.0-r1 x86_64 {brotli} (MIT) [installed]\n"
               "libfoo-2-1.0-r0 x86_64 {libfoo} (MIT) [installed]\n"
               "WARNING: ignore me\n")
        run = FakeRun({
            ("docker", "inspect"): inspect_out(),
            ("docker", "exec", "carter-news", "cat", "/etc/os-release"): proc(ALPINE_OS),
            ("docker", "exec", "carter-news", "apk", "list", "--installed"): proc(apk),
        })
        inv = inventory.collect(spec("news", "container", container="carter-news"), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        idents = {(p.ecosystem, p.name, p.version) for p in inv.packages}
        self.assertEqual(idents, {("Alpine:v3.24", "alpine-baselayout", "3.7.2-r1"),
                                  ("Alpine:v3.24", "brotli", "1.2.0-r1"),
                                  ("Alpine:v3.24", "libfoo", "1.0-r0")})
        brotli = next(p for p in inv.packages if p.name == "brotli")
        self.assertEqual(brotli.binary, "brotli-libs")

    def test_void_container_is_partial_with_python_packages(self):
        py = "/usr/local/searxng/.venv/bin/python"
        run = FakeRun({
            ("docker", "inspect"): inspect_out(),
            ("docker", "exec", "searxng", "cat", "/etc/os-release"): proc(VOID_OS),
            ("docker", "exec", "searxng", py, "-c"): proc('[["PyYAML", "6.0.3"], ["curl_cffi", "0.16.3"], ["Flask", "3.1.3"]]\n'),
        })
        inv = inventory.collect(spec("searxng", "container", container="searxng", python=[py]), run=run, now=NOW)
        self.assertEqual(inv.status, "partial")
        self.assertIn("os void has no OSV ecosystem", inv.reason)
        names = {(p.ecosystem, p.name, p.version) for p in inv.packages}
        self.assertEqual(names, {("PyPI", "pyyaml", "6.0.3"), ("PyPI", "curl-cffi", "0.16.3"), ("PyPI", "flask", "3.1.3")})

    def test_os_release_falls_back_to_docker_cp(self):
        run = FakeRun({
            ("docker", "inspect"): inspect_out(),
            ("docker", "exec", "c1", "cat"): proc(rc=126, stderr="exec failed"),
            ("docker", "cp"): docker_cp_writer({"/etc/os-release": VOID_OS.encode()}),
        })
        inv = inventory.collect(spec("c1", "container", container="c1"), run=run, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertEqual(inv.meta["os"], {"id": "void", "version_id": ""})
        self.assertIn("os void has no OSV ecosystem", inv.reason)

    def test_distroless_status_d_and_go_binary(self):
        status_d = {
            "base-files": "Package: base-files\nVersion: 12.4+deb12u15\nArchitecture: amd64\n"
                          "Description: Debian base\n continuation line\n",
            "base-files.md5sums": "d41d8cd9  etc/issue\n",
            "libbrotli1": "Package: libbrotli1\nSource: brotli (1.0.9-2)\nVersion: 1.0.9-2+b6\n",
            "tzdata": "Package: tzdata\nSource: tzdata\nVersion: 2026b-0+deb12u1\n",
        }
        run = FakeRun({
            ("docker", "inspect"): inspect_out(image="carter-beatz:commit-1"),
            ("docker", "cp"): docker_cp_writer({"/etc/os-release": DISTROLESS_OS.encode(),
                                                "/var/lib/dpkg/status.d": status_d,
                                                "/beatz": b"\x7fELF fake beatz"}),
            (self.go, "version", "-m"): go_version_m,
        })
        s = spec("beatz", "container", container="carter-beatz", distroless=True, container_go_binaries=["/beatz"])
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertFalse([c for c in run.calls if c[:2] == ["docker", "exec"]])
        eco = "Debian:12"
        idents = {(p.ecosystem, p.name, p.version) for p in inv.packages}
        self.assertIn((eco, "brotli", "1.0.9-2"), idents)
        self.assertIn((eco, "base-files", "12.4+deb12u15"), idents)
        self.assertIn((eco, "tzdata", "2026b-0+deb12u1"), idents)
        self.assertIn(("Go", "stdlib", "1.27.3"), idents)
        self.assertIn(("Go", "golang.org/x/net", "0.47.0"), idents)
        self.assertFalse([p for p in inv.packages if p.name.endswith("md5sums")])
        [binary] = inv.meta["binaries"]
        self.assertEqual(binary["path"], "/beatz")
        self.assertEqual(binary["extracted_from"], "carter-beatz")
        self.assertEqual(binary["go_version"], "1.27.3")
        self.assertEqual(binary["vcs_revision"], "0123abc")
        self.assertEqual(len(binary["sha256"]), 64)

    def test_container_go_binaries_cmd_lists_paths(self):
        thrust = "/usr/local/bundle/ruby/3.4.0/gems/thruster-0.1.27-x86_64-linux/exe/x86_64-linux/thrust"
        lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.4)\n\nPLATFORMS\n  x86_64-linux\n"
        run = FakeRun({
            ("docker", "inspect"): inspect_out(),
            ("docker", "exec", "blog-web-1", "cat", "/etc/os-release"): proc(DEBIAN13_OS),
            ("docker", "exec", "blog-web-1", "dpkg-query"): proc(dpkg_row("ii ", "brotli", "1.0.9-2", "libbrotli1:amd64", "1.0.9-2+b6")),
            ("docker", "exec", "blog-web-1", "cat", "/rails/Gemfile.lock"): proc(lock),
            ("docker", "exec", "blog-web-1", "sh", "-c"): proc(thrust + "\n"),
            ("docker", "cp"): docker_cp_writer({thrust: b"\x7fELF thrust"}),
            (self.go, "version", "-m"): go_version_m,
        })
        s = spec("blog", "container", container="blog-web-1", gemfile_lock="/rails/Gemfile.lock",
                 container_go_binaries_cmd=["sh", "-c", "ls /x/thrust"])
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertIn(Package("RubyGems", "rack", "3.2.4", location="blog-web-1:/rails/Gemfile.lock"), inv.packages)
        self.assertEqual(inv.meta["binaries"][0]["path"], thrust)
        self.assertIn(Package("Go", "stdlib", "1.27.3", location=f"blog-web-1:{thrust}"), inv.packages)

    def test_stopped_container_is_unknown(self):
        run = FakeRun({("docker", "inspect"): inspect_out(running=False, status="exited")})
        s = spec("freshrss", "container", container="freshrss")
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertIn("exited", inv.reason)
        self.assertEqual(inventory.fingerprint(s, run=run), "")

    def test_missing_container_is_unknown(self):
        run = FakeRun({("docker", "inspect"): proc(rc=1, stderr="Error: No such container: x")})
        inv = inventory.collect(spec("x", "container", container="x"), run=run, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertTrue(inv.reason)

    def test_extract_container_file_returns_none_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = FakeRun({("docker", "cp"): proc(rc=1)})
            self.assertIsNone(inventory.extract_container_file("c", "/nope", Path(tmp), run=run))


class GemfileTests(unittest.TestCase):
    def test_gemfile_lock_strips_platform_and_ignores_dependencies(self):
        text = ("GIT\n  remote: https://example.invalid/x.git\n  specs:\n    localgem (0.1.0)\n\n"
                "GEM\n  remote: https://rubygems.org/\n  specs:\n"
                "    actioncable (8.1.4)\n      actionpack (= 8.1.4)\n      nio4r (~> 2.0)\n"
                "    nokogiri (1.19.4-aarch64-linux-gnu)\n      racc (~> 1.4)\n"
                "    nokogiri (1.19.4-x86_64-linux-gnu)\n"
                "    thruster (0.1.27-x86_64-linux)\n"
                "    rails (8.1.0.rc1)\n\n"
                "PLATFORMS\n  x86_64-linux\n\nBUNDLED WITH\n   2.6.9\n")
        gems = {(p.name, p.version) for p in inventory.parse_gemfile_lock(text)}
        self.assertEqual(gems, {("actioncable", "8.1.4"), ("nokogiri", "1.19.4"), ("thruster", "0.1.27"),
                                ("rails", "8.1.0.rc1")})
        self.assertTrue(all(p.ecosystem == "RubyGems" for p in inventory.parse_gemfile_lock(text)))


class GoTests(HomeTestCase):
    def test_go_version_m_parses_replacements_and_stdlib(self):
        packages, info = inventory.parse_go_version_m(GO_VERSION_M.format(path="/x/demo"), "/x/demo")
        idents = [(p.name, p.version) for p in packages]
        self.assertEqual(idents, [("stdlib", "1.27.3"), ("github.com/gorilla/websocket", "1.5.3"),
                                  ("golang.org/x/net", "0.47.0")])
        self.assertEqual(info, {"go_version": "1.27.3", "vcs_revision": "0123abc",
                                "module": "github.com/carter2099/demo"})

    def test_go_stdlib_version_strips_prefix_and_experiments(self):
        self.assertEqual(inventory.go_stdlib_version("go1.26.10"), "1.26.10")
        self.assertEqual(inventory.go_stdlib_version("go1.27.3 X:nocoverageredesign"), "1.27.3")
        self.assertEqual(inventory.go_stdlib_version("devel go1.28-abc"), "")

    def test_go_binary_collector(self):
        binary = self.home / ".local/bin/demo"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELF demo")
        run = FakeRun({(self.go, "version", "-m"): go_version_m})
        s = spec("demo", "go-binary", binaries=["~/.local/bin/demo"])
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        [entry] = inv.meta["binaries"]
        self.assertEqual(entry["path"], str(binary))
        self.assertNotIn("extracted_from", entry)
        self.assertIn(Package("Go", "stdlib", "1.27.3", location=str(binary)), inv.packages)
        self.assertTrue(inv.fingerprint)
        self.assertEqual(inv.fingerprint, inventory.fingerprint(s, run=run))

    def test_missing_binary_is_unknown(self):
        run = FakeRun({(self.go, "version", "-m"): go_version_m})
        s = spec("demo", "go-binary", binaries=["~/.local/bin/absent"])
        inv = inventory.collect(s, run=run, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertIn("missing", inv.reason)
        self.assertEqual(inventory.fingerprint(s, run=run), "")

    def test_go_toolchain(self):
        run = FakeRun({(self.go, "version"): proc("go version go1.27.3 linux/amd64\n")})
        inv = inventory.collect(spec("go-user", "go-toolchain", cmd=["~/.local/go/bin/go", "version"]), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual(inv.packages, [Package("Go", "stdlib", "1.27.3", binary="toolchain", location=self.go)])


class RuntimeVenvTests(HomeTestCase):
    def test_runtime_version_token(self):
        node = str(self.home / ".local/share/fnm/aliases/default/bin/node")
        run = FakeRun({(node, "--version"): proc("v26.13.0\n")})
        inv = inventory.collect(spec("node", "runtime", runtime="node",
                                     cmd=["~/.local/share/fnm/aliases/default/bin/node", "--version"]),
                                run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual([(p.ecosystem, p.name, p.version) for p in inv.packages], [("runtime", "node", "26.13.0")])

    def test_runtime_failure_is_unknown(self):
        inv = inventory.collect(spec("bun", "runtime", runtime="bun", cmd=["~/.bun/bin/bun", "--version"]),
                                run=FakeRun({}), now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertTrue(inv.reason)

    def test_venv_packages(self):
        python = self.home / "venv/bin/python3"
        python.parent.mkdir(parents=True)
        python.write_text("")
        run = FakeRun({(str(python), "-c"): proc('[["Transformers", "4.57.1"], ["torch", "2.9.0"]]\n')})
        inv = inventory.collect(spec("pg", "venv", python="~/venv/bin/python3"), run=run, now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertEqual({(p.ecosystem, p.name) for p in inv.packages}, {("PyPI", "transformers"), ("PyPI", "torch")})

    def test_missing_venv_is_unknown(self):
        inv = inventory.collect(spec("pg", "venv", python="~/venv/bin/python3"), run=FakeRun({}), now=NOW)
        self.assertEqual(inv.status, "unknown")


class RigTests(HomeTestCase):
    def test_rig_offline_is_unknown_without_ssh(self):
        run = FakeRun({})
        inv = inventory.collect(spec("rig", "rig"), run=run, fetch=fetch_rig("offline"), now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertEqual(inv.reason, "rig is offline; not scanned")
        self.assertEqual(run.calls, [])

    def test_rig_os_failure_is_unknown(self):
        def broken(url, **kwargs):
            raise OSError("connection refused")
        self.assertEqual(inventory.rig_os(broken), "unknown")
        self.assertEqual(inventory.rig_os(fetch_rig("windows")), "windows")

    def test_rig_linux_scans_over_ssh(self):
        base = tuple(inventory.RIG_SSH)
        run = FakeRun({
            base + ("cat /etc/os-release",): proc(UBUNTU_OS),
            base: proc(dpkg_row("ii ", "openssl", "3.0.13-0ubuntu3.6", "libssl3t64:amd64", "3.0.13-0ubuntu3.6")),
        })
        inv = inventory.collect(spec("rig", "rig"), run=run, fetch=fetch_rig("linux"), now=NOW)
        self.assertEqual(inv.status, "ok", inv.reason)
        self.assertIn(("Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.6"),
                      {(p.ecosystem, p.name, p.version) for p in inv.packages})
        self.assertTrue(run.calls[-1][-1].startswith("dpkg-query -W -f '"))


class CollectTests(HomeTestCase):
    def test_collect_never_raises(self):
        def exploding(argv, **kwargs):
            raise RuntimeError("bug")
        inv = inventory.collect(spec("host", "host-dpkg"), run=exploding, now=NOW)
        self.assertEqual(inv.status, "unknown")
        self.assertIn("RuntimeError", inv.reason)

    def test_unknown_collector_is_unknown(self):
        inv = inventory.collect(spec("x", "nope"), run=FakeRun({}), now=NOW)
        self.assertEqual(inv.status, "unknown")

    def test_collect_all_honours_only(self):
        specs = [spec("a", "runtime", cmd=["/bin/a"]), spec("b", "runtime", cmd=["/bin/b"])]
        invs = inventory.collect_all(specs, run=FakeRun({}), fetch=fetch_rig("offline"), now=NOW, only={"b"})
        self.assertEqual([i.component_id for i in invs], ["b"])


if __name__ == "__main__":
    unittest.main()
