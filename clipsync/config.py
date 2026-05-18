"""
clipsync.config
===============

Non-channel runtime settings (channels themselves live in core/channels.py).

Settings are deliberately simple and few: ClipSync's behaviour is dominated by
explicit user actions (publish, pull), not by tunable knobs. The values below
are the ones the transport and daemon layers actually consult at runtime.

Persisted alongside channels.json so a user override survives a restart.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import uuid
from dataclasses import dataclass, asdict, fields
from pathlib import Path

from .core.channels import default_config_path


# ---------------------------------------------------------------------------
# Defaults. These match the recommendations in PROJECT_STATUS.md item 1.
# ---------------------------------------------------------------------------

DEFAULT_RING_SIZE = 5                # items kept per channel ring buffer
DEFAULT_ANNOUNCE_INTERVAL = 3.0      # seconds between ANNOUNCE multicasts
DEFAULT_PEER_TIMEOUT = 10.0          # silent peer dropped after N seconds
DEFAULT_POLL_INTERVAL = 10.0         # slow safety-net POLL cadence
DEFAULT_MAX_PAYLOAD = 25 * 1024 * 1024   # bytes; rejects pathological items
DEFAULT_TCP_PORT = 0                 # 0 = let the OS pick an ephemeral port


# ---------------------------------------------------------------------------
# Settings record.
# ---------------------------------------------------------------------------


@dataclass
class Settings:
    """Daemon-wide runtime settings.

    ``origin`` and ``origin_name`` identify *this* machine to peers; they are
    not tunable but live here because they need to be stable across restarts
    (the origin UUID lets peers dedupe items by sender across reconnects).
    """

    ring_size: int = DEFAULT_RING_SIZE
    announce_interval: float = DEFAULT_ANNOUNCE_INTERVAL
    peer_timeout: float = DEFAULT_PEER_TIMEOUT
    poll_interval: float = DEFAULT_POLL_INTERVAL
    max_payload: int = DEFAULT_MAX_PAYLOAD
    tcp_port: int = DEFAULT_TCP_PORT
    origin: str = ""                 # stable daemon UUID
    origin_name: str = ""            # human-readable host label

    def __post_init__(self) -> None:
        # Fill in identity on first creation so callers do not need to.
        if not self.origin:
            self.origin = uuid.uuid4().hex
        if not self.origin_name:
            self.origin_name = socket.gethostname() or "clipsync-host"

    # -- persistence --------------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Settings":
        """Tolerant loader: unknown keys are dropped, missing keys default."""
        known = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)


def default_settings_path() -> Path:
    """``settings.json`` lives next to ``channels.json``."""
    return default_config_path().with_name("settings.json")


class SettingsStore:
    """Load / save :class:`Settings`. Thread-safe."""

    def __init__(self, path: Path | None = None):
        self._path = path or default_settings_path()
        self._lock = threading.Lock()
        self._settings: Settings = self._load()

    def get(self) -> Settings:
        with self._lock:
            return self._settings

    def update(self, **kwargs) -> Settings:
        """Patch fields and persist. Unknown keys raise ``KeyError``."""
        with self._lock:
            known = {f.name for f in fields(Settings)}
            for k in kwargs:
                if k not in known:
                    raise KeyError(f"unknown setting {k!r}")
            current = asdict(self._settings)
            current.update(kwargs)
            self._settings = Settings.from_dict(current)
            self._save_locked()
            return self._settings

    # -- io -----------------------------------------------------------------

    def _load(self) -> Settings:
        if not self._path.exists():
            # First run: materialize defaults to disk so identity is stable.
            settings = Settings()
            self._settings = settings
            self._save_locked()
            return settings
        try:
            raw = json.loads(self._path.read_text("utf-8"))
            return Settings.from_dict(raw)
        except (json.JSONDecodeError, OSError, TypeError):
            # Bad file: fall back to defaults rather than refusing to start.
            # Channels file is the load-bearing one; settings can be regen'd.
            return Settings()

    def _save_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._settings.to_dict(), fh, indent=2)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)
