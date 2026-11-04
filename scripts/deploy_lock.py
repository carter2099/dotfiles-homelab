"""Deploy locks shared by the homelab steward and security-watch.

One ``flock`` per surface key under ``lock_dir()``.  ``surface_lock(key)``
takes the ``host`` lock shared and then ``key`` exclusive (always in that
order, so two surface locks never deadlock); ``host_lock()`` takes ``host``
exclusive and so excludes every surface at once (apt, docker daemon,
cloudflared).  Locks are never stale: the kernel drops an flock when the
holding process dies.  Each lock file holds one JSON line describing the
latest holder, for diagnostics only (``holders()``).

Within one process a key is re-entrant in the same mode (the count is shared
by every thread of the process); asking for the other mode while the process
holds a key raises ``RuntimeError`` rather than silently converting it.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

POLL_SECONDS = 0.5
HOST_KEY = "host"
_KEY_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")

# key -> [count, mode ("exclusive" | "shared"), fd]
_HELD: dict[str, list] = {}
_GUARD = threading.RLock()


class LockTimeout(Exception):
    """A deploy lock stayed held by someone else past the caller's timeout."""

    def __init__(self, key: str, info: dict | None = None):
        self.key = key
        self.info = dict(info or {})
        holder = str(self.info.get("holder") or "").strip()
        pid = self.info.get("pid")
        if holder and pid:
            holder = f"{holder} (pid {pid})"
        elif pid:
            holder = f"pid {pid}"
        self.holder = holder or "unknown"
        super().__init__(f"deploy lock {key} held by {self.holder}")


def lock_dir() -> Path:
    """``$DEPLOY_LOCK_DIR`` or ``~/.local/state/deploy-locks``; created 0700."""
    override = os.environ.get("DEPLOY_LOCK_DIR")
    path = Path(override) if override else Path.home() / ".local" / "state" / "deploy-locks"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.stat()
    if st.st_uid == os.getuid() and st.st_mode & 0o077:
        os.chmod(path, 0o700)
    return path


def _check_key(key: str) -> str:
    if not isinstance(key, str) or not _KEY_RE.fullmatch(key):
        raise ValueError(f"invalid deploy lock key: {key!r}")
    return key


def _lock_path(key: str) -> Path:
    return lock_dir() / f"{key}.lock"


def _read_info(fd: int) -> dict:
    try:
        raw = os.pread(fd, 4096, 0)
        value = json.loads(raw.decode("utf-8", errors="replace").splitlines()[0])
    except (OSError, ValueError, IndexError):
        return {}
    return value if isinstance(value, dict) else {}


def _read_info_path(path: Path) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        return {}
    try:
        return _read_info(fd)
    finally:
        os.close(fd)


def _default_holder() -> str:
    return Path(sys.argv[0]).name if sys.argv and sys.argv[0] else "python"


def _acquire_fd(key: str, mode: str, timeout: float | None) -> int:
    fd = os.open(
        _lock_path(key),
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    op = fcntl.LOCK_EX if mode == "exclusive" else fcntl.LOCK_SH
    try:
        if timeout is None:
            fcntl.flock(fd, op)
            return fd
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            try:
                fcntl.flock(fd, op | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise LockTimeout(key, _read_info(fd)) from None
                time.sleep(min(POLL_SECONDS, remaining))
    except BaseException:
        os.close(fd)
        raise


def _write_info(fd: int, mode: str, holder: str) -> None:
    line = json.dumps({
        "pid": os.getpid(),
        "holder": holder,
        "since": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mode": mode,
    }) + "\n"
    try:
        os.ftruncate(fd, 0)
        os.pwrite(fd, line.encode(), 0)
    except OSError:
        pass  # diagnostics only; the flock itself is what excludes


def _release(key: str) -> None:
    with _GUARD:
        entry = _HELD.get(key)
        if entry is None:
            return
        entry[0] -= 1
        if entry[0] > 0:
            return
        del _HELD[key]
        fd = entry[2]
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.contextmanager
def service_lock(key: str, *, timeout: float | None = None, shared: bool = False,
                 holder: str = ""):
    """Hold ``key`` (flock LOCK_EX, or LOCK_SH when ``shared``).

    ``timeout`` None blocks, 0 tries once, > 0 polls every 0.5 s; raises
    ``LockTimeout`` (with the recorded holder) when the lock stays busy.
    """
    _check_key(key)
    mode = "shared" if shared else "exclusive"
    with _GUARD:
        entry = _HELD.get(key)
        if entry is not None:
            if entry[1] != mode:
                raise RuntimeError(
                    f"deploy lock {key} already held {entry[1]} by this process; "
                    f"cannot re-enter it {mode}")
            entry[0] += 1
            reentered = True
        else:
            reentered = False
    if not reentered:
        fd = _acquire_fd(key, mode, timeout)
        with _GUARD:
            entry = _HELD.get(key)
            if entry is None:
                _HELD[key] = [1, mode, fd]
                _write_info(fd, mode, holder or _default_holder())
                fd = None
            elif entry[1] == mode:
                entry[0] += 1   # another thread took it in the same mode meanwhile
            else:
                os.close(fd)
                raise RuntimeError(
                    f"deploy lock {key} already held {entry[1]} by this process; "
                    f"cannot re-enter it {mode}")
        if fd is not None:
            os.close(fd)
    try:
        yield
    finally:
        _release(key)


@contextlib.contextmanager
def surface_lock(key: str, *, timeout: float | None = None, holder: str = ""):
    """``host`` shared, then ``key`` exclusive (fixed order); one shared budget."""
    _check_key(key)
    if key == HOST_KEY:
        raise ValueError("surface_lock key must not be 'host'; use host_lock()")
    deadline = None if timeout is None else time.monotonic() + max(0.0, float(timeout))
    with service_lock(HOST_KEY, timeout=timeout, shared=True, holder=holder):
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        with service_lock(key, timeout=remaining, holder=holder):
            yield


@contextlib.contextmanager
def host_lock(*, timeout: float | None = None, holder: str = ""):
    """``host`` exclusive: excludes every surface lock."""
    with service_lock(HOST_KEY, timeout=timeout, holder=holder):
        yield


def holders() -> dict[str, dict]:
    """Currently held keys -> ``{"pid", "holder", "since", "mode"}`` (diagnostics)."""
    result: dict[str, dict] = {}
    directory = lock_dir()
    for path in sorted(directory.glob("*.lock")):
        key = path.name[: -len(".lock")]
        if not _KEY_RE.fullmatch(key):
            continue
        with _GUARD:
            mine = key in _HELD
        if not mine:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            except OSError:
                continue
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    held = True
                else:
                    held = False
                    fcntl.flock(fd, fcntl.LOCK_UN)
                info = _read_info(fd) if held else {}
            finally:
                os.close(fd)
            if not held:
                continue
        else:
            info = _read_info_path(path)
        result[key] = {
            "pid": info.get("pid"),
            "holder": info.get("holder", ""),
            "since": info.get("since"),
            "mode": info.get("mode", ""),
        }
    return result


def _reset_after_fork() -> None:
    """A forked child does not hold its parent's locks; drop the inherited fds."""
    global _GUARD
    _GUARD = threading.RLock()
    for _count, _mode, fd in _HELD.values():
        with contextlib.suppress(OSError):
            os.close(fd)
    _HELD.clear()


os.register_at_fork(after_in_child=_reset_after_fork)
