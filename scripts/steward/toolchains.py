"""Steward P1: same-line updates of the host's user toolchains.

Node (fnm default), Ruby (rbenv global), Go (~/.local/go and the root-owned
/usr/local/go) and Neovim (~/.local/nvim) move only to the newest release on
their installed line: same major for Node, same major.minor for the rest.  A
newer line is never applied here; the version-currency audit reports it.

Each update downloads and verifies its artifact (sha256 from the publisher's
index; ruby-build verifies its own), installs side by side, smoke-tests the
new version, switches (fnm default / rbenv global / atomic renameat2 tree
exchange), re-verifies the active version, and rolls back on any failure.
Nothing is changed before the switch, so a failed download, checksum, build
or smoke test leaves the host exactly as it was (a ``warning`` row).

Replaced Go/Neovim trees go to ``~/.local/state/toolchain-rollback/``
(gitignored) or ``/var/lib/steward-toolchain-rollback/`` for /usr/local/go,
never into the dotfiles work tree; replaced fnm/rbenv versions stay
installed.  ``state.json`` records every replacement; a later run removes a
replaced version once it is RETENTION_DAYS old and the current version passed
its smoke test.  Only versions this module replaced are ever removed, and
never a Ruby/Node a repo or script pins.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .config import HOME, STEWARD_PATH
from .runtime import write_json

STEP_NAMES = (
    "toolchain_node", "toolchain_ruby", "toolchain_go_user", "toolchain_go_root",
    "toolchain_nvim",
)
# Shared wall-clock budget for all toolchain steps in one P1 run (the unit's
# hard cap is TimeoutStartSec=7200).  A step that cannot finish in what is
# left skips with a warning and retries the next night.
BUDGET_S = 1800
RUBY_MIN_S = 900          # a Ruby build takes minutes; do not start one late
DEFAULT_MIN_S = 180
RUBY_BUILD_TIMEOUT = 1500
DOWNLOAD_TIMEOUT = 600
RETENTION_DAYS = 7
STATE_DIR = HOME / ".local" / "state" / "toolchain-rollback"
ROOT_ROLLBACK_DIR = Path("/var/lib/steward-toolchain-rollback")
ROOT_GO = Path("/usr/local/go")

GO_INDEX = "https://go.dev/dl/?mode=json&include=all"
GO_DL = "https://dl.google.com/go/"
NODE_DIST = "https://nodejs.org/dist"
NVIM_RELEASES = "https://api.github.com/repos/neovim/neovim/releases?per_page=30"
NVIM_ASSET = "nvim-linux-x86_64.tar.gz"
# Global npm packages bundled with every Node release (not carried over).
_NODE_BUNDLED = frozenset({"npm", "corepack"})

# renameat2(RENAME_EXCHANGE): swap two paths atomically, so the live tree is
# never missing.  Run as a child (under `sudo -n` for root-owned trees).
_EXCHANGE = (
    "import ctypes, os, sys\n"
    "libc = ctypes.CDLL(None, use_errno=True)\n"
    "if libc.renameat2(-100, os.fsencode(sys.argv[1]), -100, os.fsencode(sys.argv[2]), 2):\n"
    "    sys.exit('renameat2 exchange failed: ' + os.strerror(ctypes.get_errno()))\n"
)


class ToolchainError(Exception):
    """A problem found before anything was switched: no change was made."""


def _vt(version):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(version or "").strip())
    return tuple(int(part) for part in match.groups()) if match else None


def select_same_line(current, releases, width):
    """Newest release newer than ``current`` sharing its first ``width`` parts."""
    cur = _vt(current)
    if cur is None:
        return None
    candidates = [r for r in releases
                  if (v := _vt(r["version"])) and v[:width] == cur[:width] and v > cur]
    return max(candidates, key=lambda r: _vt(r["version"])) if candidates else None


def newest_other_line(current, releases, width):
    """Newest release on a newer line than ``current`` (audit information only)."""
    cur = _vt(current)
    if cur is None:
        return None
    newer = [r["version"] for r in releases
             if (v := _vt(r["version"])) and v[:width] > cur[:width]]
    return max(newer, key=_vt) if newer else None


def _http_get(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "homelab-steward"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _http_download(url, dest, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": "homelab-steward"})
    deadline = time.monotonic() + timeout
    with urllib.request.urlopen(request, timeout=60) as response, open(dest, "wb") as out:
        while chunk := response.read(1 << 20):
            if time.monotonic() > deadline:
                raise ToolchainError(f"download of {url} exceeded {timeout}s")
            out.write(chunk)


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _default_env():
    env = {key: value for key, value in os.environ.items()
           if key not in ("RBENV_VERSION", "GOROOT", "GEM_HOME", "GEM_PATH")}
    env["PATH"] = f"{STEWARD_PATH}:{os.environ.get('PATH', '')}"
    return env


def _tail(text, limit=400):
    return str(text or "").strip()[-limit:]


@dataclass
class Ctx:
    """Host, clock and network seams (tests replace the network and paths)."""
    home: Path = HOME
    state_dir: Path | None = None
    root_dir: Path = ROOT_ROLLBACK_DIR
    root_go: Path = ROOT_GO
    env: dict = field(default_factory=_default_env)
    fetch: Callable[[str], bytes] = _http_get
    download: Callable[[str, Path, float], None] = _http_download
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    monotonic: Callable[[], float] = time.monotonic
    deadline: float | None = None
    dry_run: bool = False

    def __post_init__(self):
        self.home = Path(self.home)
        self.state_dir = Path(self.state_dir or self.home / ".local/state/toolchain-rollback")

    def remaining(self):
        return float("inf") if self.deadline is None else self.deadline - self.monotonic()

    def run(self, argv, *, timeout=120, cwd=None, env=None, sudo=False):
        """(exit code, combined output); kills the whole process group on timeout."""
        argv = [str(a) for a in (["sudo", "-n", *argv] if sudo else argv)]
        limit = max(1.0, min(float(timeout), self.remaining()))
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, cwd=cwd, env=env or self.env,
                start_new_session=True)
        except OSError as error:
            return 127, str(error)
        try:
            out, _ = proc.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except OSError:
                    proc.kill()
                try:
                    proc.communicate(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    continue
            return 124, f"{argv[0]} timed out after {int(limit)}s"
        return proc.returncode, out

    def check(self, argv, what, **kwargs):
        code, out = self.run(argv, **kwargs)
        if code != 0:
            raise ToolchainError(f"{what} failed (exit {code}): {_tail(out)}")
        return out


# ── drivers ─────────────────────────────────────────────────────────────


class Driver:
    """One toolchain.  ``current`` reads the active version, ``stage`` installs
    a verified release side by side, ``switch``/``unswitch`` move the active
    pointer, ``remove_replaced`` prunes a version recorded in the state file."""
    key = label = ""
    width = 2
    min_seconds = DEFAULT_MIN_S

    def __init__(self, ctx):
        self.ctx = ctx
        self.notes = []

    def prepare(self, staged, cur):
        return {}

    def pinned(self):
        return set()

    def staging(self, name):
        wrapper = self.ctx.state_dir / "staging" / name
        shutil.rmtree(wrapper, ignore_errors=True)
        wrapper.mkdir(parents=True)
        return wrapper

    def fetch_verified(self, url, filename, sha256, dest_dir):
        archive = Path(dest_dir) / filename
        self.ctx.download(url, archive, min(DOWNLOAD_TIMEOUT, self.ctx.remaining()))
        digest = _sha256(archive)
        if digest != sha256.lower():
            raise ToolchainError(
                f"checksum mismatch for {filename}: got {digest[:16]}…, "
                f"published {sha256[:16]}…")
        return archive


def _pin_files(home, names):
    roots = [*sorted((home / "dev").glob("*/")), home / "blog" / "blog"]
    for root in roots:
        for name in names:
            path = root / name
            if path.is_file():
                yield path


class NodeDriver(Driver):
    key, label, width = "node", "Node.js", 1

    @property
    def fnm_dir(self):
        return self.ctx.home / ".local" / "share" / "fnm"

    def _fnm(self, *args, what):
        fnm = self.fnm_dir / "fnm"
        exe = str(fnm) if fnm.exists() else (shutil.which("fnm", path=self.ctx.env.get("PATH")) or "fnm")
        return self.ctx.check([exe, *args], what,
                              env={**self.ctx.env, "FNM_DIR": str(self.fnm_dir)})

    def current(self):
        target = (self.fnm_dir / "aliases" / "default").resolve()
        match = re.fullmatch(r"v(\d+\.\d+\.\d+)", target.parent.name)
        return match.group(1) if match and (target / "bin" / "node").exists() else ""

    def active(self):
        return self.fnm_dir / "aliases" / "default"

    def releases(self):
        index = json.loads(self.ctx.fetch(f"{NODE_DIST}/index.json"))
        return [{"version": r["version"].lstrip("v")} for r in index
                if "linux-x64" in (r.get("files") or [])]

    def _globals(self, install):
        """{name: version} of non-bundled global npm packages of one install."""
        found = {}
        modules = install / "lib" / "node_modules"
        for pkg in [*modules.glob("[!@.]*"), *modules.glob("@*/*")]:
            name = str(pkg.relative_to(modules))
            if name in _NODE_BUNDLED:
                continue
            try:
                found[name] = json.loads((pkg / "package.json").read_text())["version"]
            except (OSError, ValueError, KeyError):
                found[name] = "latest"
        return found

    def stage(self, rel):
        version = rel["version"]
        vdir = self.fnm_dir / "node-versions" / f"v{version}"
        install = vdir / "installation"
        staged = {"path": install, "dir": vdir, "created": False}
        if not (install / "bin" / "node").exists():
            if vdir.exists():
                raise ToolchainError(f"{vdir} exists without a node binary; left untouched")
            filename = f"node-v{version}-linux-x64.tar.xz"
            sums = self.ctx.fetch(f"{NODE_DIST}/v{version}/SHASUMS256.txt").decode()
            match = re.search(rf"^([0-9a-f]{{64}})\s+{re.escape(filename)}$", sums, re.M)
            if not match:
                raise ToolchainError(f"{filename} is not listed in SHASUMS256.txt")
            wrapper = self.staging(f"node-{version}")
            try:
                archive = self.fetch_verified(
                    f"{NODE_DIST}/v{version}/{filename}", filename, match.group(1), wrapper)
                self.ctx.check(["tar", "-C", wrapper, "-xJf", archive], f"extracting {filename}",
                               timeout=300)
                vdir.mkdir(parents=True)
                staged["created"] = True
                os.rename(wrapper / f"node-v{version}-linux-x64", install)
            except BaseException:
                if staged["created"]:
                    shutil.rmtree(vdir, ignore_errors=True)
                raise
            finally:
                shutil.rmtree(wrapper, ignore_errors=True)
        try:
            self._carry_globals(install)
        except BaseException:
            self.discard(staged)
            raise
        return staged

    def _carry_globals(self, install):
        old = self.active().resolve()
        missing = {name: ver for name, ver in self._globals(old).items()
                   if name not in self._globals(install)}
        if not missing:
            return
        env = {**self.ctx.env, "PATH": f"{install / 'bin'}:{self.ctx.env.get('PATH', '')}"}
        self.ctx.check(
            [install / "bin" / "npm", "install", "-g", "--no-fund", "--no-audit",
             *(f"{name}@{ver}" for name, ver in sorted(missing.items()))],
            "carrying global npm packages over", env=env, timeout=600)
        self.notes.append("global npm packages carried over: " + ", ".join(sorted(missing)))

    def smoke(self, install):
        env = {**self.ctx.env, "PATH": f"{Path(install) / 'bin'}:{self.ctx.env.get('PATH', '')}"}
        out = self.ctx.check([Path(install) / "bin" / "node", "-e",
                              "process.stdout.write(process.versions.node)"],
                             "node smoke test", env=env, timeout=60)
        self.ctx.check([Path(install) / "bin" / "npm", "-v"], "npm smoke test", env=env, timeout=60)
        return out.strip()

    def switch(self, staged, cur, record):
        self._fnm("default", f"v{record['installed']}", what="fnm default")

    def unswitch(self, staged, cur, record):
        self._fnm("default", f"v{cur}", what="fnm default (rollback)")

    def discard(self, staged):
        if staged.get("created"):
            shutil.rmtree(staged["dir"], ignore_errors=True)

    def undo(self, cur, record):
        return f"fnm default {cur}"

    def pinned(self):
        pins = {self.current()}
        for path in _pin_files(self.ctx.home, (".node-version", ".nvmrc")):
            pins.add(path.read_text(errors="replace").strip().lstrip("v"))
        return pins

    def remove_replaced(self, record):
        vdir = self.fnm_dir / "node-versions" / f"v{record['version']}"
        if not vdir.exists():
            return "already gone"
        aliases = self.fnm_dir / "aliases"
        for alias in aliases.iterdir() if aliases.is_dir() else ():
            if alias.resolve().parent == vdir.resolve():
                return f"kept: fnm alias {alias.name} points to it"
        self._fnm("uninstall", f"v{record['version']}", what="fnm uninstall")
        return "removed"


class RubyDriver(Driver):
    key, label, min_seconds = "ruby", "Ruby (rbenv global)", RUBY_MIN_S

    @property
    def root(self):
        return self.ctx.home / ".rbenv"

    @property
    def env(self):
        return {**self.ctx.env, "RBENV_ROOT": str(self.root)}

    def _rbenv(self, *args, what, timeout=120):
        exe = shutil.which("rbenv", path=self.ctx.env.get("PATH")) or "rbenv"
        return self.ctx.check([exe, *args], what, env=self.env, timeout=timeout, cwd="/")

    def current(self):
        out = self._rbenv("global", what="rbenv global").strip()
        return out if _vt(out) else ""

    def active(self):
        return self.root / "shims"

    def releases(self):
        plugin = self.root / "plugins" / "ruby-build"
        if not self.ctx.dry_run:
            code, out = self.ctx.run(["git", "-C", plugin, "pull", "--ff-only", "-q"], timeout=120)
            if code != 0:
                self.notes.append(f"ruby-build definitions not updated: {_tail(out, 200)}")
        out = self.ctx.check([plugin / "bin" / "ruby-build", "--definitions"],
                             "ruby-build --definitions", env=self.env)
        return [{"version": line.strip()} for line in out.splitlines()
                if _vt(line.strip())]

    def _bin(self, version):
        return self.root / "versions" / version / "bin"

    def _gems(self, bindir):
        out = self.ctx.check([bindir / "gem", "list", "--local", "--no-details"],
                             "gem list", env=self._prefix_env(bindir), timeout=120)
        gems = {}
        for line in out.splitlines():
            match = re.match(r"^(\S+) \((?:default: )?([^,)\s]+)", line.strip())
            if match:
                gems[match.group(1)] = match.group(2)
        return gems

    def _prefix_env(self, bindir):
        return {**self.env, "PATH": f"{bindir}:{self.ctx.env.get('PATH', '')}"}

    def stage(self, rel):
        version = rel["version"]
        staged = {"path": self._bin(version), "version": version,
                  "created": not (self._bin(version) / "ruby").exists()}
        try:
            if staged["created"]:
                budget = min(RUBY_BUILD_TIMEOUT, self.ctx.remaining() - 300)
                if budget < 300:
                    raise ToolchainError("not enough P1 time left to build Ruby")
                self._rbenv("install", "-s", version, what=f"rbenv install {version}",
                            timeout=budget)
            self._carry_gems(staged["path"])
        except BaseException:
            self.discard(staged)
            raise
        return staged

    def _carry_gems(self, new_bin):
        cur = self.current()
        old = self._gems(self._bin(cur))
        have = self._gems(new_bin)
        missing = {name: ver for name, ver in old.items() if name not in have}
        for name, ver in sorted(missing.items()):
            self.ctx.check([new_bin / "gem", "install", "--no-document", name, "-v", ver],
                           f"gem install {name} {ver}", env=self._prefix_env(new_bin),
                           timeout=300)
        if missing:
            self.notes.append("gems carried over: " + ", ".join(sorted(missing)))

    def smoke(self, bindir):
        env = self._prefix_env(bindir) if Path(bindir) != self.active() else self.env
        out = self.ctx.check(
            [Path(bindir) / "ruby", "-ropenssl", "-rpsych", "-rzlib", "-e",
             "OpenSSL::Digest::SHA256.hexdigest('x'); Psych.load('a: 1'); "
             "Zlib.crc32('x'); print RUBY_VERSION"],
            "ruby smoke test", env=env, timeout=60, cwd="/")
        self.ctx.check([Path(bindir) / "gem", "-v"], "gem smoke test", env=env, timeout=60, cwd="/")
        return out.strip()

    def switch(self, staged, cur, record):
        self._rbenv("global", record["installed"], what="rbenv global")
        self._rbenv("rehash", what="rbenv rehash")

    def unswitch(self, staged, cur, record):
        self._rbenv("global", cur, what="rbenv global (rollback)")
        self._rbenv("rehash", what="rbenv rehash")

    def discard(self, staged):
        if staged.get("created") and (self.root / "versions" / staged["version"]).exists():
            self.ctx.run([shutil.which("rbenv", path=self.ctx.env.get("PATH")) or "rbenv",
                          "uninstall", "-f", staged["version"]], env=self.env, timeout=300)

    def undo(self, cur, record):
        return f"rbenv global {cur}"

    def pinned(self):
        pins = {self.current()}
        for path in _pin_files(self.ctx.home, (".ruby-version",)):
            pins.add(path.read_text(errors="replace").strip().removeprefix("ruby-"))
        scripts = self.ctx.home / "scripts"
        for path in scripts.rglob("*") if scripts.is_dir() else ():
            if path.is_file() and "__pycache__" not in path.parts:
                try:
                    text = path.read_text(errors="replace")
                except OSError:
                    continue
                pins.update(re.findall(r"RBENV_VERSION[=:][\"']?(\d+\.\d+\.\d+)", text))
        return pins

    def remove_replaced(self, record):
        if not (self.root / "versions" / record["version"]).exists():
            return "already gone"
        self._rbenv("uninstall", "-f", record["version"], what="rbenv uninstall", timeout=300)
        return "removed"


class TreeDriver(Driver):
    """A toolchain installed as one directory tree (Go, Neovim)."""
    inner = ""
    sudo = False

    def __init__(self, ctx, key, label, target, rollback_dir, sudo=False):
        super().__init__(ctx)
        self.key, self.label, self.target = key, label, Path(target)
        self.rollback_dir, self.sudo = Path(rollback_dir), sudo

    def _sh(self, argv, what, **kwargs):
        return self.ctx.check(argv, what, sudo=self.sudo, **kwargs)

    def _exchange(self, a, b):
        self._sh(["/usr/bin/python3", "-c", _EXCHANGE, a, b], f"exchange {a} <-> {b}")

    def _within_rollback(self, path):
        path = Path(path)
        return path.parent == self.rollback_dir and path.name.startswith(f"{self.key}-")

    def current(self):
        return self.version_of(self.target)

    def active(self):
        return self.target

    def stage(self, rel):
        wrapper = self.rollback_dir / "staging" / f"{self.key}-{rel['version']}"
        staged = {"path": wrapper / self.inner, "wrapper": wrapper}
        self._sh(["rm", "-rf", wrapper], "clearing staging")
        self._sh(["mkdir", "-p", wrapper], "creating staging")
        try:
            sha256 = rel.get("sha256") or self.resolve_sha256(rel)
            downloads = self.ctx.state_dir / "downloads"
            downloads.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=downloads) as tmp:
                archive = self.fetch_verified(rel["url"], rel["filename"], sha256, tmp)
                self._sh(["tar", "-C", wrapper, "--no-same-owner", "-xzf", archive],
                         f"extracting {rel['filename']}", timeout=300)
            if not staged["path"].is_dir():
                raise ToolchainError(f"{rel['filename']} has no top-level {self.inner}/")
            self._sh(["chmod", "--reference", self.target, staged["path"]], "matching tree mode")
        except BaseException:
            self.discard(staged)
            raise
        return staged

    def resolve_sha256(self, rel):
        raise ToolchainError(f"no published sha256 for {rel['filename']}")

    def prepare(self, staged, cur):
        stamp = self.ctx.now().strftime("%Y%m%dT%H%M%SZ")
        return {"path": str(self.rollback_dir / f"{self.key}-{cur}-{stamp}")}

    def switch(self, staged, cur, record):
        self._exchange(staged["path"], self.target)
        self._sh(["mv", staged["path"], record["path"]], "keeping the replaced tree")
        self._sh(["rm", "-rf", staged["wrapper"]], "clearing staging")

    def unswitch(self, staged, cur, record):
        """Put the old tree back at target and delete the new one."""
        if self.version_of(self.target) == cur:
            return  # the exchange never happened
        old = Path(record["path"])
        if not old.exists():
            old = staged["path"]  # exchanged but not yet moved aside
        self._exchange(old, self.target)
        if self._within_rollback(old) or old == staged["path"]:
            self._sh(["rm", "-rf", old], "removing the rejected tree")

    def discard(self, staged):
        self.ctx.run(["rm", "-rf", staged["wrapper"]], sudo=self.sudo)

    def undo(self, cur, record):
        sudo = "sudo " if self.sudo else ""
        aside = self.rollback_dir / f"{self.key}-{record['installed']}-undone"
        return (f"{sudo}mv {shlex.quote(str(self.target))} {shlex.quote(str(aside))} && "
                f"{sudo}mv {shlex.quote(record['path'])} {shlex.quote(str(self.target))}")

    def remove_replaced(self, record):
        path = Path(record.get("path") or "")
        if not self._within_rollback(path):
            return f"kept: {path} is not a rollback tree of this step"
        if not path.exists():
            return "already gone"
        self._sh(["rm", "-rf", path], f"removing {path}", timeout=300)
        return "removed"


class GoDriver(TreeDriver):
    inner = "go"

    def version_of(self, root):
        try:
            first = (Path(root) / "VERSION").read_text().splitlines()[0]
        except (OSError, IndexError):
            return ""
        version = first.strip().removeprefix("go")
        return version if _vt(version) else ""

    def releases(self):
        out = []
        for release in json.loads(self.ctx.fetch(GO_INDEX)):
            if not release.get("stable"):
                continue
            for item in release.get("files") or []:
                if (item.get("os"), item.get("arch"), item.get("kind")) == ("linux", "amd64", "archive"):
                    out.append({"version": release["version"].removeprefix("go"),
                                "filename": item["filename"], "sha256": item["sha256"],
                                "url": GO_DL + item["filename"]})
        return out

    def smoke(self, root):
        with tempfile.TemporaryDirectory(prefix="steward-go-smoke-") as tmp:
            Path(tmp, "main.go").write_text(
                'package main\n\nimport (\n\t"crypto/sha256"\n\t"fmt"\n\t"runtime"\n)\n\n'
                'func main() {\n\t_ = sha256.Sum256([]byte("x"))\n\tfmt.Print(runtime.Version())\n}\n')
            env = {**self.ctx.env, "GOTOOLCHAIN": "local", "GOFLAGS": "", "GO111MODULE": ""}
            out = self.ctx.check([Path(root) / "bin" / "go", "run", "main.go"], "go smoke test",
                                 cwd=tmp, env=env, timeout=300)
        return out.strip().removeprefix("go")


class NvimDriver(TreeDriver):
    inner = "nvim-linux-x86_64"

    def version_of(self, root):
        code, out = self.ctx.run([Path(root) / "bin" / "nvim", "--version"], timeout=30)
        match = re.search(r"NVIM v(\d+\.\d+\.\d+)", out or "") if code == 0 else None
        return match.group(1) if match else ""

    def releases(self):
        out = []
        for release in json.loads(self.ctx.fetch(NVIM_RELEASES)):
            if release.get("draft") or release.get("prerelease"):
                continue
            version = str(release.get("tag_name") or "").removeprefix("v")
            assets = {a.get("name"): a for a in release.get("assets") or []}
            asset = assets.get(NVIM_ASSET)
            if not _vt(version) or not asset:
                continue
            digest = str(asset.get("digest") or "")
            out.append({
                "version": version, "filename": NVIM_ASSET,
                "url": asset["browser_download_url"],
                "sha256": digest.removeprefix("sha256:") if digest.startswith("sha256:") else "",
                "shasum_url": (assets.get("shasum.txt") or {}).get("browser_download_url", ""),
            })
        return out

    def resolve_sha256(self, rel):
        if rel.get("shasum_url"):
            text = self.ctx.fetch(rel["shasum_url"]).decode(errors="replace")
            match = re.search(rf"^([0-9a-f]{{64}})\s+\*?{re.escape(NVIM_ASSET)}$", text, re.M)
            if match:
                return match.group(1)
        return super().resolve_sha256(rel)

    def smoke(self, root):
        out = self.ctx.check(
            [Path(root) / "bin" / "nvim", "--headless", "--clean", "-c",
             "lua local v = vim.version() io.stdout:write(v.major..'.'..v.minor..'.'..v.patch)",
             "-c", "qa!"],
            "nvim smoke test", timeout=60)
        return out.strip()


def drivers(ctx):
    return {
        "toolchain_node": NodeDriver(ctx),
        "toolchain_ruby": RubyDriver(ctx),
        "toolchain_go_user": GoDriver(ctx, "go-user", "Go (~/.local/go)",
                                      ctx.home / ".local" / "go", ctx.state_dir),
        "toolchain_go_root": GoDriver(ctx, "go-root", f"Go ({ctx.root_go})", ctx.root_go,
                                      ctx.root_dir, sudo=True),
        "toolchain_nvim": NvimDriver(ctx, "nvim", "Neovim (~/.local/nvim)",
                                     ctx.home / ".local" / "nvim", ctx.state_dir),
    }


# ── state + engine ──────────────────────────────────────────────────────


def _state_path(ctx):
    return ctx.state_dir / "state.json"


def load_state(ctx):
    try:
        state = json.loads(_state_path(ctx).read_text())
    except (OSError, ValueError):
        state = {}
    if not isinstance(state, dict):
        state = {}
    state.setdefault("replaced", [])
    state.setdefault("last", {})
    return state


def _save_state(ctx, state):
    ctx.state_dir.mkdir(parents=True, exist_ok=True)
    write_json(_state_path(ctx), state)


def _reconcile_pending(driver, state):
    """A switch interrupted by a crash: keep it only if the new version is active."""
    for record in [r for r in state["replaced"]
                   if r.get("key") == driver.key and r.get("state") == "pending"]:
        if driver.current() == record.get("installed"):
            record["state"] = "replaced"
        else:
            state["replaced"].remove(record)


def _update(driver, state):
    ctx = driver.ctx
    cur = driver.current()
    if not cur:
        raise ToolchainError(f"cannot read the active {driver.label} version")
    out = {"pre_version": cur, "post_version": cur}
    try:
        releases = driver.releases()
    except ToolchainError:
        raise
    except Exception as error:
        raise ToolchainError(f"upstream release list unavailable: {error}") from error
    newer_line = newest_other_line(cur, releases, driver.width)
    if newer_line:
        out["newer_line"] = newer_line
    release = select_same_line(cur, releases, driver.width)
    line = ".".join(cur.split(".")[:driver.width])
    if release is None:
        return {**out, "status": "skipped", "reason": f"{cur} is the newest {line}.x release"}
    target = release["version"]
    out["target"] = target
    if ctx.dry_run:
        return {**out, "status": "available", "reason": f"dry run: would update {cur} → {target}"}
    if ctx.remaining() < driver.min_seconds:
        raise ToolchainError(f"{target} needs ~{driver.min_seconds}s; only "
                             f"{max(0, int(ctx.remaining()))}s of the toolchain budget left")
    staged = None
    try:
        staged = driver.stage(release)
        got = driver.smoke(staged["path"])
        if got != target:
            raise ToolchainError(f"smoke test of the new install reported {got!r}")
    except Exception as error:
        if staged is not None:
            driver.discard(staged)
        raise ToolchainError(f"{target} not installed; nothing changed: {error}") from error

    record = {"key": driver.key, "version": cur, "installed": target,
              "replaced_at": ctx.now().isoformat(), "state": "pending",
              **driver.prepare(staged, cur)}
    state["replaced"].append(record)
    _save_state(ctx, state)
    problem = ""
    try:
        driver.switch(staged, cur, record)
        active = driver.current()
        if active != target:
            problem = f"active version is {active or 'unreadable'} after the switch"
        else:
            got = driver.smoke(driver.active())
            if got != target:
                problem = f"active smoke test reported {got!r}"
    except Exception as error:
        problem = f"switch failed: {error}"
    if not problem:
        record["state"] = "replaced"
        _save_state(ctx, state)
        return {**out, "status": "ok", "post_version": target,
                "revert": driver.undo(cur, record)}

    rollback_error = ""
    try:
        driver.unswitch(staged, cur, record)
        back = driver.current()
        verified = back == cur and driver.smoke(driver.active()) == cur
        if not verified:
            rollback_error = f"active version after rollback is {back or 'unreadable'}"
    except Exception as error:
        verified, rollback_error = False, str(error)
    if verified:
        state["replaced"].remove(record)
        driver.discard(staged)
        _save_state(ctx, state)
        return {**out, "status": "reverted", "reverted_to": cur,
                "error": f"{target}: {problem}; rolled back to {cur}"}
    record["state"] = "rollback_unverified"
    _save_state(ctx, state)
    return {**out, "status": "failed", "post_version": driver.current() or "unknown",
            "revert": driver.undo(cur, record),
            "error": f"{target}: {problem}; rollback NOT verified: {rollback_error}"}


def _age_days(record, now):
    try:
        then = datetime.fromisoformat(str(record.get("replaced_at")))
    except ValueError:
        return 0.0
    return (now - then).total_seconds() / 86400


def _prune(driver, state):
    """Remove replaced versions this module recorded, once safe; returns (removed, notes)."""
    ctx = driver.ctx
    due = [r for r in state["replaced"]
           if r.get("key") == driver.key and r.get("state") == "replaced"
           and _age_days(r, ctx.now()) >= RETENTION_DAYS]
    if not due:
        return [], []
    cur = driver.current()
    try:
        healthy = bool(cur) and driver.smoke(driver.active()) == cur
    except ToolchainError:
        healthy = False
    if not healthy:
        return [], [f"kept replaced versions: current {cur or '?'} failed its smoke test"]
    pins = driver.pinned()
    removed, notes = [], []
    for record in due:
        version = record.get("version")
        if version == cur:
            notes.append(f"kept {version}: it is active again")
            continue
        if version in pins:
            notes.append(f"kept {version}: pinned")
            continue
        try:
            outcome = driver.remove_replaced(record)
        except ToolchainError as error:
            notes.append(f"could not remove {version}: {error}")
            continue
        if outcome in ("removed", "already gone"):
            state["replaced"].remove(record)
            if outcome == "removed":
                removed.append(version)
        else:
            notes.append(f"{version} {outcome}")
    return removed, notes


def p1_toolchain(step, *, dry_run=False, deadline=None, ctx=None):
    """One P1 toolchain step: same-line update, then retention pruning."""
    ctx = ctx or Ctx(dry_run=dry_run, deadline=deadline)
    driver = drivers(ctx)[step]
    print(f"  [toolchain] {driver.label}")
    state = load_state(ctx)
    packet = {"step": step, "toolchain": driver.label}
    try:
        if not ctx.dry_run:
            _reconcile_pending(driver, state)
        packet.update(_update(driver, state))
    except ToolchainError as error:
        packet.update(status="warning", error=str(error))
    except Exception as error:  # _update rolls back its own switch failures
        packet.update(status="warning", error=f"{type(error).__name__}: {error}")
    if not ctx.dry_run and packet.get("status") in ("ok", "skipped"):
        try:
            removed, notes = _prune(driver, state)
        except Exception as error:
            removed, notes = [], [f"retention check failed: {error}"]
        if removed:
            packet["pruned"] = removed
        if notes:
            packet["retention"] = notes
    if driver.notes:
        packet["notes"] = driver.notes
    if not ctx.dry_run:
        state["last"][driver.key] = {
            key: packet[key] for key in
            ("status", "pre_version", "post_version", "target", "newer_line", "error", "reason")
            if packet.get(key)
        } | {"at": ctx.now().isoformat()}
        _save_state(ctx, state)
    return packet


def evidence(ctx=None):
    """Live toolchain versions plus tonight's P1 outcomes, for the version audit."""
    ctx = ctx or Ctx(dry_run=True)
    live = {}
    for step, driver in drivers(ctx).items():
        try:
            live[step] = driver.current() or "unreadable"
        except ToolchainError as error:
            live[step] = f"unreadable: {_tail(error, 120)}"
    state = load_state(ctx)
    return {"active": live, "p1_last": state["last"],
            "rollback_kept": [{k: r.get(k) for k in ("key", "version", "installed", "replaced_at",
                                                      "state")} for r in state["replaced"]]}
