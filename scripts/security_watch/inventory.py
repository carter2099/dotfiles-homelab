"""Inventory of what is DEPLOYED: host dpkg + running kernel, container OS/pip/gem/Go
packages, host Go binaries, venvs, runtimes and the rig (when it runs Linux).

Every collector returns an ``Inventory``; failures yield status "unknown" (nothing
usable) or "partial" (some parts missing) with a non-empty reason.  ``collect``
never raises.  All subprocess calls go through an injectable ``run``.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Sequence

from security_watch import config, net
from security_watch.config import ComponentSpec
from security_watch.model import Inventory, Package, RUNTIME_ECOSYSTEM

Run = Callable[..., subprocess.CompletedProcess]

DPKG_FORMAT = r"${db:Status-Abbrev}\t${source:Package}\t${source:Version}\t${binary:Package}\t${Version}\n"
DPKG_STATUS = "/var/lib/dpkg/status"
KERNEL_SIGNATURE = "/proc/version_signature"
RIG_HEALTH_URL = "http://127.0.0.1:8081/health"
RIG_HOST = "gamingrig-linux"
RIG_SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1",
           "-o", "StrictHostKeyChecking=yes", RIG_HOST]

# Prints [[name, version], ...] for every installed distribution (works without pip).
PY_METADATA = (
    "import json, importlib.metadata as m\n"
    "out = []\n"
    "for d in m.distributions():\n"
    "    n = d.metadata['Name']\n"
    "    if n and d.version:\n"
    "        out.append([n, d.version])\n"
    "print(json.dumps(out))"
)

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_KERNEL_VERSION = re.compile(r"^(\d+\.\d+\.\d+-\d+(?:\.\d+)*)(?:-[A-Za-z].*)?$")
_APK_LINE = re.compile(r"^(?P<name>\S+)-(?P<version>\d[^-\s]*-r\d+)\s+\S+\s+(?:\{(?P<origin>[^}]*)\})?")
_GEM_SPEC = re.compile(r"^    (?P<name>[^\s(]+) \((?P<version>[^)]+)\)$")
_GEM_PLATFORM = re.compile(r"-[A-Za-z].*$")
_BINNMU = re.compile(r"\+b\d+$")


def _log(message: str) -> None:
    print(f"security-watch: inventory: {message}", file=sys.stderr)


# --- subprocess --------------------------------------------------------------

def default_run(argv: list[str], *, timeout: float = 120, input: str | None = None,
                env: dict | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run argv without a shell; never raises (timeout -> 124, exec failure -> 127)."""
    try:
        return subprocess.run(
            list(argv), input=input, stdin=None if input is not None else subprocess.DEVNULL,
            capture_output=True, text=True, errors="replace", timeout=timeout, env=env, cwd=cwd,
            check=False)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        return subprocess.CompletedProcess(list(argv), 124, out, f"timeout after {timeout}s")
    except (OSError, ValueError) as exc:
        return subprocess.CompletedProcess(list(argv), 127, "", f"{type(exc).__name__}: {exc}")


def _err(proc: subprocess.CompletedProcess) -> str:
    text = (proc.stderr or proc.stdout or "").strip().splitlines()
    tail = text[-1][:200] if text else ""
    return f"rc {proc.returncode}" + (f": {tail}" if tail else "")


def go_bin() -> Path:
    """Host Go toolchain used for ``go version -m``."""
    return config.expand("~/.local/go/bin/go")


def _sha256_file(path: Path) -> str:
    with path.open("rb") as fh:
        return hashlib.file_digest(fh, "sha256").hexdigest()


def _sha256_text(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


# --- parsers -----------------------------------------------------------------

def parse_os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def os_ecosystem(osr: dict[str, str]) -> str | None:
    """OSV ecosystem for an os-release mapping, or None when OSV has none."""
    os_id = osr.get("ID", "").lower()
    version = osr.get("VERSION_ID", "")
    if os_id == "debian":
        major = version.split(".")[0]
        return f"Debian:{major}" if major.isdigit() else None
    if os_id == "ubuntu":
        m = re.fullmatch(r"(\d+)\.(\d+)", version)
        if not m:
            return None
        lts = m.group(2) == "04" and int(m.group(1)) % 2 == 0
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if os_id == "alpine":
        parts = version.split(".")
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return f"Alpine:v{parts[0]}.{parts[1]}"
        return None
    return None


def _os_meta(osr: dict[str, str]) -> dict[str, str]:
    return {"id": osr.get("ID", ""), "version_id": osr.get("VERSION_ID", "")}


def _merge_source(found: dict[tuple[str, str], list[str]], source: str, version: str, binary: str) -> None:
    binaries = found.setdefault((source, version), [])
    if binary and binary not in binaries:
        binaries.append(binary)


def _source_packages(ecosystem: str, found: dict[tuple[str, str], list[str]], location: str = "") -> list[Package]:
    return [Package(ecosystem, src, ver, binary=",".join(sorted(bins)), location=location)
            for (src, ver), bins in sorted(found.items())]


_KERNEL_SOURCE = re.compile(
    r"^linux-(signed|meta|hwe|lowlatency|oem|restricted-modules|generic|aws|azure|gcp|oracle|ibm|kvm|"
    r"raspi|riscv|nvidia|intel|lts|realtime)(-[a-z0-9.+-]+)?$")


def is_kernel_source(source: str) -> bool:
    """Kernel source packages: installed-but-not-running kernels, headers and linux-libc-dev
    are irrelevant (containers share the host kernel; the host's running kernel is
    inventoried separately as the 'running-kernel' package).  linux-firmware/-base stay."""
    return source == "linux" or bool(_KERNEL_SOURCE.match(source))


def _drop_kernel(source: str, stats: dict | None) -> bool:
    if not is_kernel_source(source):
        return False
    if stats is not None:
        stats["kernel_rows_dropped"] = stats.get("kernel_rows_dropped", 0) + 1
    return True


def parse_dpkg_query(text: str, ecosystem: str, location: str = "", stats: dict | None = None) -> list[Package]:
    """Rows of DPKG_FORMAT -> source packages (installed 'ii' rows, deduped by source+version).
    Kernel source rows are dropped and counted in stats["kernel_rows_dropped"]."""
    found: dict[tuple[str, str], list[str]] = {}
    if stats is not None:
        stats["kernel_rows_dropped"] = 0
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) < 5 or cols[0].strip() != "ii":
            continue
        source, source_version, binary, version = (c.strip() for c in cols[1:5])
        if not source:
            source = binary.split(":")[0]
        if not source_version:
            source_version = _BINNMU.sub("", version)
        if source and source_version and not _drop_kernel(source, stats):
            _merge_source(found, source, source_version, binary)
    return _source_packages(ecosystem, found, location)


def parse_dpkg_stanzas(text: str) -> list[dict[str, str]]:
    stanzas: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                stanzas.append(current)
            current = {}
            continue
        if line[0] in " \t" or ":" not in line:
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()
    if current:
        stanzas.append(current)
    return stanzas


def parse_status_d(texts: Sequence[str], ecosystem: str, location: str = "", stats: dict | None = None) -> list[Package]:
    """Distroless /var/lib/dpkg/status.d stanzas -> source packages (kernel sources dropped)."""
    found: dict[tuple[str, str], list[str]] = {}
    if stats is not None:
        stats["kernel_rows_dropped"] = 0
    for text in texts:
        for st in parse_dpkg_stanzas(text):
            name, version = st.get("Package", ""), st.get("Version", "")
            if not name or not version:
                continue
            status = st.get("Status")
            if status and not status.endswith(" installed"):
                continue
            source, source_version = name, _BINNMU.sub("", version)
            if st.get("Source"):
                m = re.fullmatch(r"(\S+)(?:\s+\(([^)]+)\))?", st["Source"])
                if m:
                    source = m.group(1)
                    source_version = m.group(2) or source_version
            if not _drop_kernel(source, stats):
                _merge_source(found, source, source_version, name)
    return _source_packages(ecosystem, found, location)


def parse_apk_list(text: str, ecosystem: str, location: str = "") -> list[Package]:
    """`apk list --installed` -> (origin, version) packages."""
    found: dict[tuple[str, str], list[str]] = {}
    for line in text.splitlines():
        m = _APK_LINE.match(line.strip())
        if not m:
            continue
        name = m.group("name")
        _merge_source(found, m.group("origin") or name, m.group("version"), name)
    return _source_packages(ecosystem, found, location)


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_python_metadata(text: str, location: str = "") -> list[Package]:
    data = json.loads(text.strip().splitlines()[-1]) if text.strip() else None
    if not isinstance(data, list):
        raise ValueError("python metadata output is not a JSON list")
    seen: set[tuple[str, str]] = set()
    out: list[Package] = []
    for item in data:
        if not (isinstance(item, list) and len(item) == 2 and all(isinstance(x, str) for x in item)):
            continue
        key = (pep503(item[0]), item[1].strip())
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            out.append(Package("PyPI", key[0], key[1], location=location))
    return sorted(out, key=lambda p: (p.name, p.version))


def parse_gemfile_lock(text: str, location: str = "") -> list[Package]:
    """GEM section specs lines '    name (version[-platform])' -> RubyGems packages."""
    seen: set[tuple[str, str]] = set()
    out: list[Package] = []
    section = ""
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line and not line[0].isspace():
            section = line.strip()
            continue
        m = _GEM_SPEC.match(line) if section == "GEM" else None
        if not m:
            continue
        version = _GEM_PLATFORM.sub("", m.group("version").strip())
        key = (m.group("name"), version)
        if version and key not in seen:
            seen.add(key)
            out.append(Package("RubyGems", key[0], key[1], location=location))
    return out


def go_stdlib_version(raw: str) -> str:
    """'go1.27.3 X:nocoverageredesign' -> '1.27.3'; '' when not a release version."""
    token = raw.strip().split(" ")[0] if raw.strip() else ""
    if not token.startswith("go") or not token[2:3].isdigit():
        return ""
    return token[2:]


def parse_go_version_m(text: str, location: str = "") -> tuple[list[Package], dict[str, Any]]:
    """`go version -m <file>` -> (Go packages, {"go_version", "vcs_revision", "module"})."""
    lines = text.splitlines()
    if not lines or ": " not in lines[0]:
        raise ValueError("unexpected go version -m output")
    raw_go = lines[0].rsplit(": ", 1)[1].strip()
    go_version = go_stdlib_version(raw_go)
    if not go_version:
        raise ValueError(f"unrecognised Go version {raw_go[:40]!r}")
    info: dict[str, Any] = {"go_version": go_version, "vcs_revision": "", "module": ""}
    deps: list[tuple[str, str]] = []
    for line in lines[1:]:
        cols = line.strip().split("\t")
        kind = cols[0] if cols else ""
        if kind == "mod" and len(cols) >= 2:
            info["module"] = cols[1]
        elif kind == "dep" and len(cols) >= 3:
            deps.append((cols[1], cols[2]))
        elif kind == "=>" and deps:
            # Replacement of the preceding dep: the replacement is what is compiled in.
            # Local directory replacements carry no version and cannot be matched.
            deps.pop()
            if len(cols) >= 3 and cols[2] and cols[2] != "(devel)":
                deps.append((cols[1], cols[2]))
        elif kind == "build" and len(cols) >= 2 and cols[1].startswith("vcs.revision="):
            info["vcs_revision"] = cols[1].split("=", 1)[1]
    packages = [Package("Go", "stdlib", go_version, location=location)]
    seen: set[tuple[str, str]] = set()
    for module, version in deps:
        version = version[1:] if version.startswith("v") else version
        if version and version != "(devel)" and (module, version) not in seen:
            seen.add((module, version))
            packages.append(Package("Go", module, version, location=location))
    return packages, info


def version_token(text: str) -> str:
    m = _VERSION_RE.search(text or "")
    return m.group(0) if m else ""


def kernel_package(signature: str, ecosystem: str) -> Package | None:
    """'Ubuntu 6.8.0-147.147-generic 6.8.12' -> Package(eco, 'linux', '6.8.0-147.147')."""
    parts = signature.split()
    if len(parts) < 2:
        return None
    m = _KERNEL_VERSION.match(parts[1])
    if not m:
        return None
    return Package(ecosystem, "linux", m.group(1), binary="running-kernel")


# --- result helpers ----------------------------------------------------------

class _Builder:
    def __init__(self, spec: ComponentSpec, now: datetime):
        self.spec = spec
        self.now = now
        self.packages: list[Package] = []
        self.reasons: list[str] = []
        self.meta: dict[str, Any] = {}
        self.fingerprint = ""

    def fail(self, reason: str) -> None:
        self.reasons.append(reason)

    def build(self) -> Inventory:
        packages = list(dict.fromkeys(self.packages))
        if not self.reasons:
            status = "ok"
        else:
            status = "partial" if packages else "unknown"
        return Inventory(self.spec.id, self.now, status, self.fingerprint, packages,
                         "; ".join(self.reasons), self.meta)


def _unknown(spec: ComponentSpec, now: datetime, reason: str, *, fingerprint: str = "",
             meta: dict | None = None) -> Inventory:
    return Inventory(spec.id, now, "unknown", fingerprint, [], reason or "inventory failed", meta or {})


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else [str(v) for v in value]


# --- docker helpers ----------------------------------------------------------

_INSPECT_FORMAT = ('{"image_id":{{json .Image}},"image":{{json .Config.Image}},'
                   '"running":{{json .State.Running}},"status":{{json .State.Status}}}')


def _inspect(container: str, run: Run) -> tuple[dict | None, str]:
    proc = run(["docker", "inspect", "--type", "container", "--format", _INSPECT_FORMAT, container], timeout=30)
    if proc.returncode != 0:
        return None, f"docker inspect {container} failed ({_err(proc)})"
    try:
        data = json.loads(proc.stdout.strip().splitlines()[0])
    except (ValueError, IndexError):
        return None, f"docker inspect {container}: unparsable output"
    if not isinstance(data, dict):
        return None, f"docker inspect {container}: unparsable output"
    return data, ""


def extract_container_file(container: str, path: str, dest_dir: Path, *, run: Run = default_run) -> Path | None:
    """`docker cp -L container:path` into dest_dir; returns the local path or None."""
    name = Path(path).name or "root"
    dest = Path(dest_dir) / name
    n = 1
    while dest.exists():
        dest = Path(dest_dir) / f"{name}.{n}"
        n += 1
    proc = run(["docker", "cp", "-L", f"{container}:{path}", str(dest)], timeout=120)
    if proc.returncode != 0 or not dest.exists():
        return None
    return dest


def _container_cat(container: str, path: str, run: Run, tmp: Path, *, allow_exec: bool) -> str | None:
    if allow_exec:
        proc = run(["docker", "exec", container, "cat", path], timeout=30)
        if proc.returncode == 0:
            return proc.stdout
    local = extract_container_file(container, path, tmp, run=run)
    if local is None or not local.is_file():
        return None
    return local.read_text(errors="replace")


# --- collectors --------------------------------------------------------------

def _dpkg_status_stat(run: Run) -> str:
    proc = run(["stat", "-L", "-c", "%s %Y", DPKG_STATUS], timeout=15)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _kernel_signature(run: Run) -> str:
    proc = run(["cat", KERNEL_SIGNATURE], timeout=15)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _host_fingerprint(run: Run) -> str:
    stat = _dpkg_status_stat(run)
    return _sha256_text(stat, _kernel_signature(run)) if stat else ""


def _collect_host(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    proc = run(["cat", "/etc/os-release"], timeout=15)
    if proc.returncode != 0:
        return _unknown(spec, now, f"cannot read /etc/os-release ({_err(proc)})")
    osr = parse_os_release(proc.stdout)
    eco = os_ecosystem(osr)
    b = _Builder(spec, now)
    b.meta["os"] = _os_meta(osr)
    if eco is None:
        return _unknown(spec, now, f"os {osr.get('ID', '?')} has no OSV ecosystem", meta=b.meta)
    b.meta["ecosystem"] = eco
    proc = run(["dpkg-query", "-W", "-f", DPKG_FORMAT], timeout=120)
    if proc.returncode != 0:
        return _unknown(spec, now, f"dpkg-query failed ({_err(proc)})", meta=b.meta)
    b.packages = parse_dpkg_query(proc.stdout, eco, stats=b.meta)
    if not b.packages:
        return _unknown(spec, now, "dpkg-query listed no installed packages", meta=b.meta)
    signature = _kernel_signature(run)
    b.meta["kernel"] = signature
    kernel = kernel_package(signature, eco) if signature else None
    if kernel is None:
        b.fail("running kernel version unknown")
    else:
        b.packages.append(kernel)
    stat = _dpkg_status_stat(run)
    b.fingerprint = _sha256_text(stat, signature) if stat else ""
    return b.build()


def _python_packages(argv_prefix: list[str], python: str, run: Run, location: str) -> tuple[list[Package], str]:
    proc = run([*argv_prefix, python, "-c", PY_METADATA], timeout=120)
    if proc.returncode != 0:
        return [], f"python {python}: {_err(proc)}"
    try:
        return parse_python_metadata(proc.stdout, location), ""
    except ValueError as exc:
        return [], f"python {python}: {exc}"


def _go_binary_entry(local: Path, display_path: str, run: Run, location: str,
                     extracted_from: str = "") -> tuple[list[Package], dict | None, str]:
    proc = run([str(go_bin()), "version", "-m", str(local)], timeout=60)
    if proc.returncode != 0:
        return [], None, f"go version -m {display_path}: {_err(proc)}"
    try:
        packages, info = parse_go_version_m(proc.stdout, location)
    except ValueError as exc:
        return [], None, f"go version -m {display_path}: {exc}"
    entry = {"path": display_path, "sha256": _sha256_file(local), "go_version": info["go_version"],
             "vcs_revision": info["vcs_revision"], "module": info["module"]}
    if extracted_from:
        entry["extracted_from"] = extracted_from
    return packages, entry, ""


def _container_os_packages(b: _Builder, container: str, osr: dict[str, str], run: Run, tmp: Path,
                           *, distroless: bool) -> None:
    os_id = osr.get("ID", "").lower() or "?"
    eco = os_ecosystem(osr)
    if eco is None:
        b.fail(f"os {os_id} has no OSV ecosystem")
        return
    b.meta["ecosystem"] = eco
    if os_id == "alpine":
        proc = run(["docker", "exec", container, "apk", "list", "--installed"], timeout=120)
        packages = parse_apk_list(proc.stdout, eco) if proc.returncode == 0 else []
        if not packages:
            b.fail(f"apk list failed ({_err(proc)})" if proc.returncode else "apk list returned no packages")
        b.packages.extend(packages)
        return
    # debian / ubuntu
    if not distroless:
        proc = run(["docker", "exec", container, "dpkg-query", "-W", "-f", DPKG_FORMAT], timeout=120)
        packages = parse_dpkg_query(proc.stdout, eco, stats=b.meta) if proc.returncode == 0 else []
        if packages:
            b.packages.extend(packages)
            return
    status_d = extract_container_file(container, "/var/lib/dpkg/status.d", tmp, run=run)
    if status_d is None or not status_d.is_dir():
        b.fail("dpkg database unreadable")
        return
    texts = [p.read_text(errors="replace") for p in sorted(status_d.iterdir())
             if p.is_file() and not p.name.endswith(".md5sums")]
    packages = parse_status_d(texts, eco, stats=b.meta)
    if not packages:
        b.fail("dpkg status.d listed no packages")
    b.packages.extend(packages)


def _collect_container(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    container = spec.get("container") or spec.id
    info, err = _inspect(container, run)
    if info is None:
        return _unknown(spec, now, err)
    meta = {"image": info.get("image") or "", "image_id": info.get("image_id") or "", "container": container}
    if info.get("running") is not True:
        return _unknown(spec, now, f"container {container} is {info.get('status') or 'not running'}", meta=meta)
    b = _Builder(spec, now)
    b.meta.update(meta)
    b.fingerprint = meta["image_id"]
    distroless = bool(spec.get("distroless"))
    with tempfile.TemporaryDirectory(prefix="security-watch-inv-") as tmpname:
        tmp = Path(tmpname)
        text = _container_cat(container, "/etc/os-release", run, tmp, allow_exec=not distroless)
        if text is None:
            b.fail("os-release unreadable")
        else:
            osr = parse_os_release(text)
            b.meta["os"] = _os_meta(osr)
            _container_os_packages(b, container, osr, run, tmp, distroless=distroless)

        for python in _as_list(spec.get("python")):
            packages, err = _python_packages(["docker", "exec", container], python, run, f"{container}:{python}")
            b.packages.extend(packages)
            if err:
                b.fail(err)

        lock = spec.get("gemfile_lock")
        if lock:
            text = _container_cat(container, lock, run, tmp, allow_exec=not distroless)
            gems = parse_gemfile_lock(text, f"{container}:{lock}") if text is not None else []
            if not gems:
                b.fail(f"{lock} unreadable or empty")
            b.packages.extend(gems)

        paths = _as_list(spec.get("container_go_binaries"))
        cmd = spec.get("container_go_binaries_cmd")
        if cmd:
            proc = run(["docker", "exec", container, *_as_list(cmd)], timeout=60)
            listed = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()] if proc.returncode == 0 else []
            if not listed:
                b.fail(f"container Go binary listing failed ({_err(proc)})")
            paths.extend(listed)
        binaries: list[dict] = []
        for path in dict.fromkeys(paths):
            local = extract_container_file(container, path, tmp, run=run)
            if local is None or not local.is_file():
                b.fail(f"cannot extract {path}")
                continue
            packages, entry, err = _go_binary_entry(local, path, run, f"{container}:{path}", container)
            if err:
                b.fail(err)
                continue
            b.packages.extend(packages)
            binaries.append(entry)
        if binaries:
            b.meta["binaries"] = binaries

    for name, argv in (spec.get("runtimes") or {}).items():
        proc = run(["docker", "exec", container, *_as_list(argv)], timeout=30)
        version = version_token(proc.stdout) if proc.returncode == 0 else ""
        if version:
            b.packages.append(Package(RUNTIME_ECOSYSTEM, name, version, location=container))
        else:
            b.fail(f"runtime {name} version unknown ({_err(proc)})")
    return b.build()


def _collect_go_binary(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    b = _Builder(spec, now)
    binaries: list[dict] = []
    paths = _as_list(spec.get("binaries"))
    if not paths:
        return _unknown(spec, now, "no binaries configured")
    for raw in paths:
        path = config.expand(raw)
        if not path.is_file():
            b.fail(f"binary {raw} missing")
            continue
        packages, entry, err = _go_binary_entry(path, str(path), run, str(path))
        if err:
            b.fail(err)
            continue
        b.packages.extend(packages)
        binaries.append(entry)
    b.meta["binaries"] = binaries
    b.fingerprint = _sha256_text(*(e["sha256"] for e in binaries)) if binaries else ""
    return b.build()


def _venv_python(spec: ComponentSpec) -> Path | None:
    python = spec.get("python")
    return config.expand(python) if isinstance(python, str) and python else None


def _venv_fingerprint(spec: ComponentSpec) -> str:
    python = _venv_python(spec)
    if python is None or not python.exists():
        return ""
    venv = python.parent.parent.resolve()
    try:
        return _sha256_text(str(venv), str(venv.stat().st_mtime_ns))
    except OSError:
        return ""


def _collect_venv(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    python = _venv_python(spec)
    if python is None:
        return _unknown(spec, now, "no python configured")
    if not python.exists():
        return _unknown(spec, now, f"python {spec.get('python')} missing")
    packages, err = _python_packages([], str(python), run, str(python))
    if err or not packages:
        return _unknown(spec, now, err or "venv lists no packages")
    b = _Builder(spec, now)
    b.packages = packages
    b.meta["python"] = str(python)
    b.fingerprint = _venv_fingerprint(spec)
    return b.build()


def _cmd(spec: ComponentSpec) -> list[str]:
    argv = _as_list(spec.get("cmd"))
    return [str(config.expand(argv[0])), *argv[1:]] if argv else []


def _cmd_output(spec: ComponentSpec, run: Run) -> tuple[str, str]:
    argv = _cmd(spec)
    if not argv:
        return "", "no cmd configured"
    proc = run(argv, timeout=30)
    if proc.returncode != 0:
        return "", f"{spec.get('cmd')[0]} failed ({_err(proc)})"
    return proc.stdout.strip(), ""


def _collect_runtime(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    out, err = _cmd_output(spec, run)
    if err:
        return _unknown(spec, now, err)
    version = version_token(out)
    name = spec.get("runtime") or spec.id
    if not version:
        return _unknown(spec, now, f"no version in {name} output")
    b = _Builder(spec, now)
    b.packages = [Package(RUNTIME_ECOSYSTEM, name, version, location=_cmd(spec)[0])]
    b.fingerprint = _sha256_text(out)
    return b.build()


def _collect_go_toolchain(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    out, err = _cmd_output(spec, run)
    if err:
        return _unknown(spec, now, err)
    parts = out.split()
    version = go_stdlib_version(parts[2]) if len(parts) >= 3 and parts[:2] == ["go", "version"] else ""
    if not version:
        return _unknown(spec, now, "unrecognised go version output")
    b = _Builder(spec, now)
    b.packages = [Package("Go", "stdlib", version, binary="toolchain", location=_cmd(spec)[0])]
    b.fingerprint = _sha256_text(out)
    return b.build()


def rig_os(fetch=net.fetch) -> str:
    """'linux' | 'windows' | 'offline' | 'unknown' from llm-proxy /health."""
    try:
        data = fetch(RIG_HEALTH_URL, timeout=5).json()
    except Exception:  # noqa: BLE001 - any failure means we cannot tell
        return "unknown"
    state = data.get("rig_os") if isinstance(data, dict) else None
    return state if state in {"linux", "windows", "offline"} else "unknown"


def _collect_rig(spec: ComponentSpec, run: Run, fetch, now: datetime) -> Inventory:
    state = rig_os(fetch)
    if state != "linux":
        return _unknown(spec, now, f"rig is {state}; not scanned", meta={"rig_os": state})
    proc = run([*RIG_SSH, "cat /etc/os-release"], timeout=60)
    if proc.returncode != 0:
        return _unknown(spec, now, f"ssh {RIG_HOST} failed ({_err(proc)})", meta={"rig_os": state})
    osr = parse_os_release(proc.stdout)
    b = _Builder(spec, now)
    b.meta.update({"rig_os": state, "os": _os_meta(osr)})
    eco = os_ecosystem(osr)
    if eco is None or osr.get("ID", "").lower() not in {"debian", "ubuntu"}:
        return _unknown(spec, now, f"os {osr.get('ID', '?')} has no supported OSV package listing", meta=b.meta)
    b.meta["ecosystem"] = eco
    proc = run([*RIG_SSH, f"dpkg-query -W -f {shlex.quote(DPKG_FORMAT)}"], timeout=120)
    packages = parse_dpkg_query(proc.stdout, eco, RIG_HOST, stats=b.meta) if proc.returncode == 0 else []
    if not packages:
        return _unknown(spec, now, f"rig dpkg-query failed ({_err(proc)})", meta=b.meta)
    b.packages = packages
    b.fingerprint = _sha256_text(*(p.ident() for p in packages))
    return b.build()


_COLLECTORS: dict[str, Callable[[ComponentSpec, Run, Any, datetime], Inventory]] = {
    "host-dpkg": _collect_host,
    "container": _collect_container,
    "go-binary": _collect_go_binary,
    "venv": _collect_venv,
    "runtime": _collect_runtime,
    "go-toolchain": _collect_go_toolchain,
    "rig": _collect_rig,
}


# --- public API --------------------------------------------------------------

def collect(spec: ComponentSpec, *, run: Run = default_run, fetch=net.fetch, now: datetime) -> Inventory:
    collector = _COLLECTORS.get(spec.collector)
    if collector is None:
        return _unknown(spec, now, f"unknown collector {spec.collector!r}")
    try:
        inv = collector(spec, run, fetch, now)
    except Exception as exc:  # noqa: BLE001 - a collector bug must read as unknown, never clean
        _log(f"{spec.id}: {type(exc).__name__}: {exc}")
        return _unknown(spec, now, f"inventory error: {type(exc).__name__}: {exc}")
    if inv.status != "ok":
        _log(f"{spec.id}: {inv.status}: {inv.reason}")
    return inv


def collect_all(specs: Sequence[ComponentSpec], *, run: Run = default_run, fetch=net.fetch, now: datetime,
                only: set[str] | None = None) -> list[Inventory]:
    return [collect(spec, run=run, fetch=fetch, now=now)
            for spec in specs if only is None or spec.id in only]


def fingerprint(spec: ComponentSpec, *, run: Run = default_run) -> str:
    """Cheap artifact identity (image id, binary hashes, dpkg status stat); '' when unavailable."""
    try:
        if spec.collector == "host-dpkg":
            return _host_fingerprint(run)
        if spec.collector == "container":
            info, _ = _inspect(spec.get("container") or spec.id, run)
            return (info.get("image_id") or "") if info and info.get("running") is True else ""
        if spec.collector == "go-binary":
            hashes = []
            for raw in _as_list(spec.get("binaries")):
                path = config.expand(raw)
                if not path.is_file():
                    return ""
                hashes.append(_sha256_file(path))
            return _sha256_text(*hashes) if hashes else ""
        if spec.collector == "venv":
            return _venv_fingerprint(spec)
        if spec.collector in {"runtime", "go-toolchain"}:
            out, err = _cmd_output(spec, run)
            return "" if err else _sha256_text(out)
    except Exception as exc:  # noqa: BLE001
        _log(f"{spec.id}: fingerprint failed: {type(exc).__name__}: {exc}")
    return ""
