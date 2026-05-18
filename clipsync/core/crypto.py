"""
clipsync.core.crypto
====================

Per-channel authenticated encryption for ClipSync.

Why this layer exists
---------------------
A ClipSync channel *is* a shared secret. Two machines are "on the same
channel" precisely when they hold the same channel key -- there is no server
to ask. That makes the channel key do three jobs at once:

  1. Confidentiality -- a machine on the LAN that is not on the channel
     cannot read clipboard payloads.
  2. Authentication  -- it cannot forge or tamper with messages either;
     a modified ciphertext fails the AEAD tag check and is dropped.
  3. Access control  -- discovery itself is encrypted, so a non-member
     cannot even see that the channel's peers exist.

This module turns a channel's secret into a usable key and provides the
two operations the transport layer needs: ``seal`` (encrypt a Message blob)
and ``open`` (decrypt + verify, with replay rejection).

Cipher choice
-------------
AES-256-GCM. It is an AEAD cipher: one operation gives us both encryption
and an integrity tag, and it is hardware-accelerated on every modern Mac
and PC (AES-NI). ChaCha20-Poly1305 would be an equally fine choice; AES-GCM
is picked for ubiquity.

The 96-bit GCM nonce MUST never repeat under the same key -- a repeat is
catastrophic for GCM. We generate it from 12 fresh random bytes per message
(``os.urandom``). At 96 bits of randomness the birthday bound is large
enough that a clipboard-sharing tool will never approach it.

Key derivation
--------------
The join string carries a high-entropy random secret (see channels.py).
We still run it through HKDF-SHA256 rather than using it raw, so that:
  * the key is always exactly 32 bytes regardless of secret length, and
  * a per-channel ``info`` label domain-separates keys -- the same secret
    used for two channel names yields two unrelated keys.

Replay defense
--------------
AEAD stops tampering but not *replay* -- an attacker could re-send a
captured-but-valid ciphertext. Two guards, both keyed off the
authenticated header:

  * timestamp freshness -- messages older than REPLAY_WINDOW are rejected.
  * nonce/msg-id memory  -- a recently-seen msg_id is rejected as a dup.

Together they bound replay to a short window and forbid duplicates within
it. The seen-cache is time-bounded so it cannot grow without limit.
"""

from __future__ import annotations

import os
import time
import threading
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .protocol import Message, ProtocolError


# AES-256 -> 32-byte key. GCM standard nonce is 96 bits / 12 bytes.
KEY_SIZE = 32
NONCE_SIZE = 12

# A message whose authenticated timestamp is more than this many seconds
# away from local time (in either direction) is rejected. Generous enough
# to tolerate modest clock skew between machines on a LAN, tight enough
# that a captured ciphertext is only replayable very briefly.
REPLAY_WINDOW = 30.0

# How long a seen msg_id stays remembered. Must be >= REPLAY_WINDOW so that
# a duplicate cannot outlive the freshness check that would also catch it.
SEEN_TTL = 2 * REPLAY_WINDOW


class CryptoError(Exception):
    """Raised when decryption, authentication, or replay checks fail.

    Deliberately coarse: callers should treat any CryptoError as 'drop this
    packet silently' and never branch on the specific reason, so that the
    error path leaks nothing to an attacker probing the daemon.
    """


def derive_channel_key(secret: bytes, channel_name: str) -> bytes:
    """Derive a 32-byte AES key from a channel's raw secret.

    HKDF-SHA256 with the channel name as ``info`` so the same secret bound
    to two different channel names produces two cryptographically unrelated
    keys (domain separation). ``salt`` is intentionally empty: the secret is
    already high-entropy random material, not a human password, so HKDF's
    extract step needs no additional salt.
    """
    if not isinstance(secret, bytes) or len(secret) == 0:
        raise CryptoError("channel secret must be non-empty bytes")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=b"",
        info=b"clipsync-channel-v1:" + channel_name.encode("utf-8"),
    )
    return hkdf.derive(secret)


@dataclass
class _SeenEntry:
    """A remembered msg_id and the time it was first seen."""
    seen_at: float


class ChannelCipher:
    """Seals and opens messages for exactly one channel.

    One instance per joined channel. The transport layer keeps a dict of
    ``{channel_name: ChannelCipher}`` and routes each incoming packet to
    every cipher until one opens it (or none do, and the packet is dropped).

    Thread-safe: the replay cache is guarded by a lock because announces,
    notifies and fetch replies can all be opened from different threads.
    """

    def __init__(self, secret: bytes, channel_name: str):
        self.channel_name = channel_name
        self._key = derive_channel_key(secret, channel_name)
        self._aesgcm = AESGCM(self._key)
        # msg_id -> _SeenEntry, for duplicate rejection.
        self._seen: dict[str, _SeenEntry] = {}
        self._seen_lock = threading.Lock()

    # -- outbound -----------------------------------------------------------

    def seal(self, message: Message) -> bytes:
        """Encrypt a Message into a self-contained wire packet.

        Packet layout::

            [12-byte nonce][AES-GCM ciphertext + 16-byte tag]

        The plaintext is the full ``Message.encode()`` blob (framed header +
        body). We additionally bind the channel name into the GCM AAD: a
        packet sealed for channel X cannot be opened as channel Y even in
        the impossible event of a key collision, and it cross-checks the
        channel field that is also inside the encrypted header.
        """
        if message.channel != self.channel_name:
            raise CryptoError(
                f"cipher for '{self.channel_name}' cannot seal a message "
                f"for '{message.channel}'"
            )
        plaintext = message.encode()
        nonce = os.urandom(NONCE_SIZE)
        aad = self.channel_name.encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce + ciphertext

    # -- inbound ------------------------------------------------------------

    def open(self, packet: bytes) -> Message:
        """Decrypt + authenticate a wire packet back into a Message.

        Raises CryptoError if the packet was not sealed for this channel,
        was tampered with, is stale, or is a replay. The caller drops the
        packet on any CryptoError -- this is the normal, expected outcome
        for traffic belonging to other channels.
        """
        if len(packet) < NONCE_SIZE + 16:  # 16 = GCM tag length
            raise CryptoError("packet too short to contain nonce + tag")

        nonce, ciphertext = packet[:NONCE_SIZE], packet[NONCE_SIZE:]
        aad = self.channel_name.encode("utf-8")

        # AEAD decryption. Wrong key (i.e. another channel's traffic) or any
        # tampering fails here with InvalidTag -- this is how a cipher
        # silently ignores packets that are not its own.
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:  # cryptography raises InvalidTag here
            raise CryptoError("decryption/authentication failed") from exc

        # The plaintext is a framed Message. A malformed one after a *valid*
        # AEAD tag would be very strange, but treat it as a crypto-layer
        # failure all the same so the caller's single except suffices.
        try:
            message = Message.decode(plaintext)
        except ProtocolError as exc:
            raise CryptoError(f"authenticated plaintext is malformed: {exc}") from exc

        # The channel inside the encrypted header must match this cipher.
        # AAD already enforces this cryptographically; this is defence in
        # depth against a logic bug, not against an attacker.
        if message.channel != self.channel_name:
            raise CryptoError("channel field does not match cipher")

        self._check_replay(message)
        return message

    # -- replay defense -----------------------------------------------------

    def _check_replay(self, message: Message) -> None:
        """Reject stale or duplicate messages. Called only after AEAD passes,
        so every field read here is authenticated and trustworthy.
        """
        now = time.time()
        age = now - message.timestamp

        # Freshness: too old, or too far in the future (skewed/forged clock).
        if age > REPLAY_WINDOW:
            raise CryptoError(f"message is stale ({age:.1f}s old)")
        if age < -REPLAY_WINDOW:
            raise CryptoError(f"message timestamp is in the future ({-age:.1f}s)")

        with self._seen_lock:
            self._evict_expired(now)
            if message.msg_id in self._seen:
                raise CryptoError(f"duplicate message {message.msg_id} (replay)")
            self._seen[message.msg_id] = _SeenEntry(seen_at=now)

    def _evict_expired(self, now: float) -> None:
        """Drop seen-cache entries older than SEEN_TTL. Caller holds the lock.

        Keeps the cache bounded by *time*: on a quiet channel it empties out;
        on a busy one it holds only the last SEEN_TTL seconds of msg_ids.
        """
        cutoff = now - SEEN_TTL
        stale = [mid for mid, e in self._seen.items() if e.seen_at < cutoff]
        for mid in stale:
            del self._seen[mid]


class CipherRegistry:
    """The set of ciphers for all channels this daemon has joined.

    The transport layer holds one of these. Outbound: look up the cipher by
    channel name and ``seal``. Inbound: a packet arrives with no cleartext
    channel label (the label is *inside* the ciphertext), so we try each
    cipher's ``open`` until one succeeds. A packet no cipher can open
    belongs to a channel we have not joined -- it is dropped, which is
    exactly the access-control behaviour we want.
    """

    def __init__(self):
        self._ciphers: dict[str, ChannelCipher] = {}
        self._lock = threading.Lock()

    def add_channel(self, channel_name: str, secret: bytes) -> None:
        """Register (or replace) the cipher for a channel."""
        with self._lock:
            self._ciphers[channel_name] = ChannelCipher(secret, channel_name)

    def remove_channel(self, channel_name: str) -> None:
        """Forget a channel's cipher (called on 'leave channel')."""
        with self._lock:
            self._ciphers.pop(channel_name, None)

    def channels(self) -> list[str]:
        """Names of all currently-joined channels."""
        with self._lock:
            return list(self._ciphers)

    def seal(self, message: Message) -> bytes:
        """Seal a message using the cipher for its ``channel`` field."""
        with self._lock:
            cipher = self._ciphers.get(message.channel)
        if cipher is None:
            raise CryptoError(f"not joined to channel '{message.channel}'")
        return cipher.seal(message)

    def open(self, packet: bytes) -> Message:
        """Open a packet by trying every joined channel's cipher.

        Returns the Message from whichever cipher succeeds. Raises
        CryptoError only if *no* cipher can open it -- meaning the packet is
        for a channel we have not joined, or is noise. Either way the
        transport layer drops it.
        """
        with self._lock:
            ciphers = list(self._ciphers.values())
        for cipher in ciphers:
            try:
                return cipher.open(packet)
            except CryptoError:
                continue  # not this channel's packet; try the next cipher
        raise CryptoError("packet does not belong to any joined channel")
