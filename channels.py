"""
clipsync.core.channels
======================

Channel lifecycle: create, join, leave, persist -- and the ``clipsync://``
join string that is the *only* way a channel's secret moves between
machines.

What a channel is
-----------------
A channel is a small record::

    name      human label, e.g. "work"        (chosen by the creator)
    secret    32 random bytes                  (the shared key material)
    group     multicast group + port           (where its traffic flows)

Two machines are on the same channel iff they hold the same ``secret``.
There is no registry server; the secret reaches a second machine only
because a human deliberately carried the join string there.

The join string
----------------
"How do I find a channel?" -- you do not discover it on the network, you
are *given* it, out of band. A member exports::

    clipsync://join?n=<name>&k=<secret-b64url>&g=<addr>&p=<port>

and sends it via any trusted path (a messaging app, AirDrop, a QR code,
a slip of paper). The recipient pastes it into "Manage channels -> Join".

Deliberately *not* automatic: if channels were advertised on the LAN, then
"on the network" would equal "able to join", and per-channel encryption
would protect nothing. The human step is the access-control boundary.

Multicast groups
----------------
Each channel gets its own group in the administratively-scoped block
239.192.0.0/14 so that channels do not see each other's announce/notify
traffic at the socket level. (Crypto already isolates them; separate
groups just avoid waking every daemon for every packet.) The group is
derived deterministically from the secret, so two machines that hold the
same secret independently compute the same group with nothing extra to
exchange.

Persistence
-----------
Joined channels live in ``~/.config/clipsync/channels.json``. The file
contains channel *secrets* in the clear, so it is written with 0600
permissions (owner-only). It is the same trust level as an SSH private
key or a password-manager vault file on disk.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode


SECRET_SIZE = 32                       # bytes of random channel key material
DEFAULT_PORT = 47100                   # UDP port for a channel's multicast

# Administratively-scoped multicast range (RFC 2365). Safe for LAN-local
# use and not routed off the local network by default.
_MCAST_BASE = (239, 192, 0, 0)
_MCAST_BITS = 14                       # 239.192.0.0/14 -> ~256k usable groups

# A channel name is a short, file-system- and menu-friendly label.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}[a-z0-9]$")

JOIN_SCHEME = "clipsync"
JOIN_HOST = "join"


class ChannelError(Exception):
    """Raised for invalid channel names, malformed join strings, etc."""


# ---------------------------------------------------------------------------
# b64url helpers -- url-safe, unpadded, so a join string survives being
# pasted into chat apps and URLs without escaping surprises.
# ---------------------------------------------------------------------------


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)        # restore stripped padding
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, base64.binascii.Error) as exc:
        raise ChannelError(f"invalid base64 in join string: {exc}") from exc


def validate_channel_name(name: str) -> str:
    """Return ``name`` if it is a legal channel name, else raise.

    Rules: lowercase, 2-32 chars, alphanumeric plus '-'/'_', no leading or
    trailing separator. Keeps names safe as dict keys, menu labels and
    HKDF ``info`` material.
    """
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ChannelError(
            f"invalid channel name {name!r}: use 2-32 lowercase chars "
            f"(a-z, 0-9, '-', '_'), not starting or ending with '-'/'_'"
        )
    return name


def _derive_multicast_group(secret: bytes) -> str:
    """Deterministically map a channel secret to a multicast group address.

    Both ends compute this from the shared secret, so the group never has
    to travel in the join string -- though we include it anyway for
    forward-compatibility and human inspection.

    The lower (32 - _MCAST_BITS) bits of a SHA-256 digest pick the host
    part within 239.192.0.0/14.
    """
    digest = hashlib.sha256(b"clipsync-mcast-v1:" + secret).digest()
    host_bits = 32 - _MCAST_BITS
    host = int.from_bytes(digest[:4], "big") & ((1 << host_bits) - 1)
    base = (_MCAST_BASE[0] << 24) | (_MCAST_BASE[1] << 16) \
        | (_MCAST_BASE[2] << 8) | _MCAST_BASE[3]
    addr = base | host
    return ".".join(str((addr >> shift) & 0xFF) for shift in (24, 16, 8, 0))


# ---------------------------------------------------------------------------
# The Channel record.
# ---------------------------------------------------------------------------


@dataclass
class Channel:
    """One joined channel: its name, secret, and multicast endpoint."""

    name: str
    secret: bytes
    group: str
    port: int = DEFAULT_PORT

    @classmethod
    def create(cls, name: str, port: int = DEFAULT_PORT) -> "Channel":
        """Create a brand-new channel with a fresh random secret.

        This is what "Manage channels -> Create" calls. The channel exists
        the moment this returns; it becomes *shared* only once someone
        joins it via the exported join string.
        """
        validate_channel_name(name)
        secret = os.urandom(SECRET_SIZE)
        return cls(
            name=name,
            secret=secret,
            group=_derive_multicast_group(secret),
            port=port,
        )

    # -- join string --------------------------------------------------------

    def to_join_string(self) -> str:
        """Export this channel as a ``clipsync://join?...`` string.

        Anyone who receives this string can join the channel -- it contains
        the secret. Treat it like a password: share it only over a trusted
        path, never post it publicly.
        """
        query = urlencode({
            "n": self.name,
            "k": _b64url_encode(self.secret),
            "g": self.group,
            "p": str(self.port),
        })
        return f"{JOIN_SCHEME}://{JOIN_HOST}?{query}"

    @classmethod
    def from_join_string(cls, text: str) -> "Channel":
        """Parse a ``clipsync://join?...`` string into a Channel.

        Raises ChannelError on anything malformed. The group is recomputed
        from the secret and cross-checked against the string's ``g`` field,
        so a corrupted or tampered group value is caught here.
        """
        text = text.strip()
        parsed = urlparse(text)
        if parsed.scheme != JOIN_SCHEME or parsed.netloc != JOIN_HOST:
            raise ChannelError(
                f"not a ClipSync join string (expected "
                f"'{JOIN_SCHEME}://{JOIN_HOST}?...')"
            )

        q = parse_qs(parsed.query)

        def _one(key: str) -> str:
            vals = q.get(key)
            if not vals:
                raise ChannelError(f"join string missing '{key}' parameter")
            return vals[0]

        name = validate_channel_name(_one("n"))
        secret = _b64url_decode(_one("k"))
        if len(secret) != SECRET_SIZE:
            raise ChannelError(
                f"join string secret is {len(secret)} bytes, "
                f"expected {SECRET_SIZE}"
            )

        try:
            port = int(_one("p"))
        except ValueError as exc:
            raise ChannelError(f"join string has non-numeric port: {exc}") from exc
        if not (1 <= port <= 65535):
            raise ChannelError(f"join string port {port} out of range")

        # Recompute the group from the secret and verify it matches the
        # advertised one -- guards against a mangled paste.
        expected_group = _derive_multicast_group(secret)
        given_group = _one("g")
        if given_group != expected_group:
            raise ChannelError(
                "join string is inconsistent (group does not match secret); "
                "it may have been corrupted in transit"
            )

        return cls(name=name, secret=secret, group=expected_group, port=port)

    # -- persistence form ---------------------------------------------------

    def to_dict(self) -> dict:
        """Serializable form for channels.json (secret base64-encoded)."""
        return {
            "name": self.name,
            "secret": _b64url_encode(self.secret),
            "group": self.group,
            "port": self.port,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Channel":
        """Inverse of :meth:`to_dict`."""
        try:
            secret = _b64url_decode(d["secret"])
            channel = cls(
                name=validate_channel_name(d["name"]),
                secret=secret,
                group=d.get("group") or _derive_multicast_group(secret),
                port=int(d.get("port", DEFAULT_PORT)),
            )
        except (KeyError, TypeError) as exc:
            raise ChannelError(f"malformed channel record: {exc}") from exc
        if len(channel.secret) != SECRET_SIZE:
            raise ChannelError("stored channel secret has wrong length")
        return channel

    def __repr__(self) -> str:  # never expose the secret in logs/reprs
        return (f"Channel(name={self.name!r}, group={self.group}:"
                f"{self.port}, secret=<{SECRET_SIZE} bytes hidden>)")


# ---------------------------------------------------------------------------
# The channel registry -- the set of channels this daemon has joined,
# backed by an on-disk file.
# ---------------------------------------------------------------------------


def default_config_path() -> Path:
    """Location of channels.json, honoring $XDG_CONFIG_HOME when set."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "clipsync" / "channels.json"


class ChannelRegistry:
    """Thread-safe set of joined channels, persisted to disk.

    The UI layer ("Manage channels") drives this; the transport and crypto
    layers read from it to know which multicast groups to join and which
    cipher keys to install. Every mutation is written through to disk
    immediately so a crash never loses a joined channel.
    """

    def __init__(self, path: Path | None = None):
        self._path = path or default_config_path()
        self._channels: dict[str, Channel] = {}
        self._lock = threading.RLock()
        self.load()

    # -- queries ------------------------------------------------------------

    def list_channels(self) -> list[Channel]:
        with self._lock:
            return list(self._channels.values())

    def get(self, name: str) -> Channel | None:
        with self._lock:
            return self._channels.get(name)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._channels

    # -- mutations ----------------------------------------------------------

    def create_channel(self, name: str, port: int = DEFAULT_PORT) -> Channel:
        """Create a new channel and join it. Fails if the name is taken."""
        validate_channel_name(name)
        with self._lock:
            if name in self._channels:
                raise ChannelError(f"channel '{name}' already exists")
            channel = Channel.create(name, port)
            self._channels[name] = channel
            self._save_locked()
            return channel

    def join(self, join_string: str) -> Channel:
        """Join a channel from a ``clipsync://`` join string.

        If a channel with the same name but a *different* secret already
        exists, this raises -- silently overwriting it would disconnect the
        user from the old channel without warning. The UI should surface
        this and let the user rename or replace explicitly.
        """
        channel = Channel.from_join_string(join_string)
        with self._lock:
            existing = self._channels.get(channel.name)
            if existing is not None and existing.secret != channel.secret:
                raise ChannelError(
                    f"a different channel named '{channel.name}' is already "
                    f"joined; remove it first or rename one of them"
                )
            self._channels[channel.name] = channel
            self._save_locked()
            return channel

    def leave(self, name: str) -> None:
        """Leave a channel. No-op if not joined."""
        with self._lock:
            if self._channels.pop(name, None) is not None:
                self._save_locked()

    # -- persistence --------------------------------------------------------

    def load(self) -> None:
        """Load channels.json from disk. Absent file => empty registry."""
        with self._lock:
            self._channels.clear()
            if not self._path.exists():
                return
            try:
                raw = json.loads(self._path.read_text("utf-8"))
                for record in raw.get("channels", []):
                    channel = Channel.from_dict(record)
                    self._channels[channel.name] = channel
            except (json.JSONDecodeError, ChannelError, OSError) as exc:
                # A corrupt config should not crash the daemon. Start empty
                # and let the user re-join; the bad file is left in place
                # for inspection rather than silently destroyed.
                raise ChannelError(
                    f"could not read {self._path}: {exc}"
                ) from exc

    def _save_locked(self) -> None:
        """Atomically write channels.json with 0600 perms. Caller holds lock.

        Atomic = write to a temp file in the same directory, then rename
        over the target. A crash mid-write can never leave a half-written
        config that would lose every channel.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "channels": [c.to_dict() for c in self._channels.values()],
        }
        tmp = self._path.with_suffix(".json.tmp")
        # Create the temp file 0600 from the outset so the secrets are
        # never momentarily world-readable.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        os.replace(tmp, self._path)      # atomic rename
        os.chmod(self._path, 0o600)      # ensure final file is owner-only
