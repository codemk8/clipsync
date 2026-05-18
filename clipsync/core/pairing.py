"""
clipsync.core.pairing
=====================

Short-lived pairing protocol that hands a channel's join string from one
machine ("giver") to another ("taker") over the LAN, so the user does not
have to copy/paste the ``clipsync://`` URL.

Flow
----
1. **Giver** enters share mode, generates an ephemeral X25519 keypair, listens
   on a random TCP port, and advertises ``_clipsync-pair._tcp`` via mDNS with
   TXT records ``role=giver``, ``display=<hostname>``, ``label=<#chan>``.
2. **Taker** browses the same service type and surfaces the list to the user.
3. The user picks a giver; taker opens TCP. Both sides exchange ``HELLO``
   carrying their X25519 public keys and 8-byte nonces.
4. Both sides derive ``session_key`` and a 4-digit ``SAS`` via HKDF-SHA256
   from ``(shared_secret, transcript)`` where the transcript fixes initiator
   (taker) first, then responder (giver), and includes both nonces.
5. Both UIs display ``SAS``. The user verifies the codes match. On confirm
   each side sends an AES-GCM-sealed ``CONFIRM`` (AAD=``b"confirm"``); on
   reject, the socket is closed.
6. After both confirms exchange successfully, the giver sends ``GIFT``
   (the join string sealed with AAD=``b"gift"``). The taker installs the
   channel, sends ``OK`` (AAD=``b"ok"``), and both sockets close.

Security argument
-----------------
The SAS verification step is what defeats a LAN MITM: an attacker who
proxies the two ECDHs computes a different ``session_key`` per leg, so the
SAS digits on the two screens differ. The user catches the mismatch and
rejects. AAD on each encrypted message prevents replay across types.
Ephemeral keypairs + nonces in the transcript mean each pairing session is
unique. Pairing windows open only on explicit user action and time out
after 2 minutes.

Threat model is unchanged from PROJECT_STATUS.md: LAN outsider in scope,
malicious channel member out (inherent to no-server keyed channels).

Discovery is delegated to :mod:`clipsync.core._mdns`, which picks the
right backend per OS: macOS shells out to ``dns-sd`` (so we coexist with
``mDNSResponder`` on port 5353); other platforms use ``python-zeroconf``.
The rest of this module is OS-agnostic.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _mdns


log = logging.getLogger(__name__)

# Service type sans the trailing ``.local.``; backends format the FQDN.
# (zeroconf needs the suffix; dns-sd doesn't.)
SERVICE_TYPE = "_clipsync-pair._tcp"
SESSION_TIMEOUT_S = 120.0   # hard cap on a full pairing session
HELLO_TIMEOUT_S = 30.0      # wait for HELLO once a socket is up
CONFIRM_WAIT_S = 90.0       # wait for user + peer confirm
MAX_FRAME = 65536           # any pairing frame larger than this is suspect


# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PairingPeer:
    """A discovered pairing-mode peer (shown in the taker's peer list)."""
    peer_id: str            # zeroconf instance name (unique on the network)
    display: str            # human-friendly machine name
    label: str              # what the giver is offering, e.g. "#work"
    address: str            # IPv4 address of the giver
    port: int               # TCP port to connect to


@dataclass
class PairingCallbacks:
    """Hooks the daemon installs to surface pairing events to the UI.

    All callbacks fire on background threads. UI layers must marshal back to
    their main thread (rumps Timer / Qt QTimer.singleShot).
    """
    on_peers_changed: Callable[[list[PairingPeer]], None] = field(
        default=lambda peers: None
    )
    on_sas_ready: Callable[[str, str], None] = field(
        default=lambda sas, peer_display: None
    )
    # Receive side: payload = the join string. Share side: payload = None.
    on_paired: Callable[[Optional[str]], None] = field(default=lambda payload: None)
    on_failed: Callable[[str], None] = field(default=lambda reason: None)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _ub64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _send(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError("pairing frame too large to send")
    sock.sendall(struct.pack(">I", len(data)) + data)


def _recv(sock: socket.socket) -> dict:
    header = _recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise ValueError(f"pairing frame too large to receive: {length}")
    body = _recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed pairing socket")
        buf.extend(chunk)
    return bytes(buf)


def _transcript(initiator_pub: bytes, responder_pub: bytes,
                initiator_nonce: bytes, responder_nonce: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(initiator_pub)
    h.update(responder_pub)
    h.update(initiator_nonce)
    h.update(responder_nonce)
    return h.digest()


def _derive(shared: bytes, transcript: bytes) -> tuple[bytes, str]:
    """Return (session_key, 4-digit SAS string)."""
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"clipsync-pair-session|" + transcript,
    ).derive(shared)
    sas_bytes = HKDF(
        algorithm=hashes.SHA256(), length=4, salt=None,
        info=b"clipsync-pair-sas|" + transcript,
    ).derive(shared)
    sas_int = int.from_bytes(sas_bytes, "big") % 10000
    return session_key, f"{sas_int:04d}"


def _seal(session_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ct = AESGCM(session_key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def _open(session_key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    return AESGCM(session_key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# PairingService
# ---------------------------------------------------------------------------

class PairingService:
    """One pairing session at a time -- giver OR taker, never both at once.

    Lifecycle methods (``start_share`` / ``start_receive``) spawn a worker
    thread and return immediately. The worker fires callbacks at significant
    points (peers updated, SAS ready, paired, failed). ``confirm`` / ``reject``
    / ``cancel`` are the only externally-visible state pokes during a session.
    """

    def __init__(self, display_name: str, callbacks: PairingCallbacks):
        self._display = display_name
        self._cb = callbacks
        self._lock = threading.Lock()
        self._state: str = "idle"
        # Stop flag the worker threads watch.
        self._stop = threading.Event()
        # User decision gates (set by confirm/reject).
        self._user_confirmed = threading.Event()
        self._user_rejected = threading.Event()
        # mDNS handles -- one register (giver) or one browse (taker) at a
        # time. The concrete backend is chosen by ``_mdns.get_backend()``.
        self._register_handle: Optional[_mdns.RegisterHandle] = None
        self._browse_handle: Optional[_mdns.BrowseHandle] = None
        self._peers: dict[str, PairingPeer] = {}
        self._peers_lock = threading.Lock()
        self._listen_sock: Optional[socket.socket] = None
        # Active session state.
        self._conn: Optional[socket.socket] = None
        self._priv: Optional[X25519PrivateKey] = None
        self._my_nonce: bytes = b""
        self._session_key: Optional[bytes] = None
        self._sas: Optional[str] = None
        self._peer_display: str = ""
        # Giver-only: the payload to deliver.
        self._payload: Optional[str] = None
        self._label: str = ""

    # -- public API --------------------------------------------------------

    def start_share(self, payload: str, label: str) -> None:
        """Begin advertising as giver and wait for a taker to connect.

        ``payload`` is the opaque string the taker should receive on success
        (the daemon hands in a ``clipsync://`` join string). ``label`` is the
        short text shown to the taker in their peer list.
        """
        with self._lock:
            if self._state != "idle":
                raise RuntimeError(f"pairing already in state {self._state!r}")
            self._payload = payload
            self._label = label
            self._reset_session_events()
            self._state = "share-advertising"
        threading.Thread(target=self._run_giver, daemon=True,
                         name="pair-giver").start()

    def start_receive(self) -> None:
        """Begin browsing as taker. The peer list arrives via on_peers_changed."""
        with self._lock:
            if self._state != "idle":
                raise RuntimeError(f"pairing already in state {self._state!r}")
            self._reset_session_events()
            self._state = "receive-browsing"
        threading.Thread(target=self._run_taker_browse, daemon=True,
                         name="pair-taker-browse").start()

    def pick_peer(self, peer_id: str) -> None:
        """Taker side: connect to a discovered peer."""
        with self._peers_lock:
            peer = self._peers.get(peer_id)
        if peer is None:
            self._fail(f"peer {peer_id!r} no longer available")
            return
        threading.Thread(
            target=self._run_taker_connect, args=(peer,), daemon=True,
            name="pair-taker-conn",
        ).start()

    def confirm(self) -> None:
        self._user_confirmed.set()

    def reject(self) -> None:
        self._user_rejected.set()

    def cancel(self) -> None:
        """Abandon any active session and tear everything down."""
        self._user_rejected.set()
        self._stop.set()
        self._teardown_discovery()
        self._teardown_session()

    def peers(self) -> list[PairingPeer]:
        with self._peers_lock:
            return list(self._peers.values())

    # -- giver -------------------------------------------------------------

    def _run_giver(self) -> None:
        try:
            self._priv = X25519PrivateKey.generate()
            self._my_nonce = secrets.token_bytes(8)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 0))
            sock.listen(1)
            sock.settimeout(SESSION_TIMEOUT_S)
            self._listen_sock = sock
            port = sock.getsockname()[1]
            log.info("pairing: sharing %s on port %d", self._label, port)

            self._advertise(port)

            try:
                conn, addr = sock.accept()
            except (socket.timeout, TimeoutError):
                self._fail("no taker connected within timeout")
                return
            log.info("pairing: taker connected from %s", addr)
            self._conn = conn
            # We no longer need to advertise; close mDNS so we don't draw
            # attention from anyone else once a session is in flight.
            self._teardown_discovery()

            self._handshake(role="giver")
            self._cb.on_sas_ready(self._sas, self._peer_display)

            if not self._run_confirm_round():
                return

            # Send the payload.
            nonce, ct = _seal(self._session_key,
                              self._payload.encode("utf-8"), aad=b"gift")
            _send(conn, {"type": "GIFT", "nonce": _b64(nonce), "ct": _b64(ct)})

            # Wait for OK.
            conn.settimeout(30.0)
            reply = _recv(conn)
            if reply.get("type") != "OK":
                self._fail(f"unexpected reply after GIFT: {reply.get('type')!r}")
                return
            _open(self._session_key, _ub64(reply["nonce"]),
                  _ub64(reply["ct"]), aad=b"ok")
            self._cb.on_paired(None)
        except Exception as exc:
            log.exception("pairing giver failed")
            self._fail(f"giver error: {exc}")
        finally:
            self._teardown_session()
            with self._lock:
                self._state = "idle"

    # -- taker -------------------------------------------------------------

    def _run_taker_browse(self) -> None:
        try:
            self._browse_handle = _mdns.get_backend(SERVICE_TYPE).browse(
                on_added=self._on_peer_discovered,
                on_removed=self._on_peer_lost,
            )
            # Browse until pick_peer / cancel / timeout.
            self._stop.wait(SESSION_TIMEOUT_S)
        except Exception as exc:
            log.exception("pairing browse failed")
            self._fail(f"browse error: {exc}")

    def _run_taker_connect(self, peer: PairingPeer) -> None:
        try:
            self._teardown_discovery()
            self._priv = X25519PrivateKey.generate()
            self._my_nonce = secrets.token_bytes(8)
            sock = socket.create_connection((peer.address, peer.port),
                                            timeout=HELLO_TIMEOUT_S)
            self._conn = sock

            self._handshake(role="taker")
            self._cb.on_sas_ready(self._sas, self._peer_display)

            if not self._run_confirm_round():
                return

            sock.settimeout(30.0)
            msg = _recv(sock)
            if msg.get("type") != "GIFT":
                self._fail(f"expected GIFT, got {msg.get('type')!r}")
                return
            payload = _open(self._session_key,
                            _ub64(msg["nonce"]), _ub64(msg["ct"]),
                            aad=b"gift").decode("utf-8")

            # Ack before notifying so the giver can close cleanly.
            ok_nonce, ok_ct = _seal(self._session_key, b"ok", aad=b"ok")
            _send(sock, {"type": "OK", "nonce": _b64(ok_nonce), "ct": _b64(ok_ct)})

            self._cb.on_paired(payload)
        except Exception as exc:
            log.exception("pairing taker failed")
            self._fail(f"taker error: {exc}")
        finally:
            self._teardown_session()
            with self._lock:
                self._state = "idle"

    # -- shared protocol pieces --------------------------------------------

    def _handshake(self, role: str) -> None:
        """Exchange HELLO, derive session_key + SAS. ``role`` is 'giver' or 'taker'."""
        my_pub_bytes = self._priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        my_hello = {
            "type": "HELLO",
            "pub": _b64(my_pub_bytes),
            "nonce": self._my_nonce.hex(),
            "display": self._display,
            "label": self._label,
        }
        self._conn.settimeout(HELLO_TIMEOUT_S)
        if role == "taker":
            _send(self._conn, my_hello)
            peer_hello = _recv(self._conn)
        else:
            peer_hello = _recv(self._conn)
            _send(self._conn, my_hello)

        if peer_hello.get("type") != "HELLO":
            raise ValueError(f"expected HELLO, got {peer_hello.get('type')!r}")
        peer_pub_bytes = _ub64(peer_hello["pub"])
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        peer_nonce = bytes.fromhex(peer_hello["nonce"])
        self._peer_display = peer_hello.get("display") or "(unknown)"

        shared = self._priv.exchange(peer_pub)
        # Transcript: initiator (taker) first, responder (giver) second.
        # Both sides reconstruct the same byte string.
        if role == "taker":
            tr = _transcript(my_pub_bytes, peer_pub_bytes,
                             self._my_nonce, peer_nonce)
        else:
            tr = _transcript(peer_pub_bytes, my_pub_bytes,
                             peer_nonce, self._my_nonce)
        self._session_key, self._sas = _derive(shared, tr)

    def _run_confirm_round(self) -> bool:
        """Wait for our user to confirm/reject, send our CONFIRM, then wait
        for the peer's CONFIRM. Returns True iff we should proceed to the
        data phase."""
        deadline = time.monotonic() + CONFIRM_WAIT_S
        while not (self._user_confirmed.is_set() or self._user_rejected.is_set()):
            if self._stop.is_set() or time.monotonic() > deadline:
                self._fail("user did not confirm in time")
                return False
            time.sleep(0.1)

        if self._user_rejected.is_set():
            try:
                self._conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._fail("rejected by user")
            return False

        nonce, ct = _seal(self._session_key, b"confirm", aad=b"confirm")
        _send(self._conn, {"type": "CONFIRM",
                           "nonce": _b64(nonce), "ct": _b64(ct)})

        remaining = max(1.0, deadline - time.monotonic())
        self._conn.settimeout(remaining)
        try:
            msg = _recv(self._conn)
        except (ConnectionError, TimeoutError, OSError) as exc:
            self._fail(f"peer did not confirm: {exc}")
            return False
        if msg.get("type") != "CONFIRM":
            self._fail(f"expected CONFIRM, got {msg.get('type')!r}")
            return False
        try:
            _open(self._session_key, _ub64(msg["nonce"]),
                  _ub64(msg["ct"]), aad=b"confirm")
        except Exception as exc:
            self._fail(f"peer CONFIRM failed authentication: {exc}")
            return False
        return True

    # -- mDNS advertise / browse -------------------------------------------

    def _advertise(self, port: int) -> None:
        instance = f"clipsync-{secrets.token_hex(4)}"
        self._register_handle = _mdns.get_backend(SERVICE_TYPE).register(
            instance=instance,
            port=port,
            txt={
                "role": "giver",
                "display": self._display,
                "label": self._label,
            },
        )

    def _teardown_discovery(self) -> None:
        if self._browse_handle is not None:
            try:
                self._browse_handle.stop()
            except Exception:
                log.exception("browse stop failed")
            self._browse_handle = None
        if self._register_handle is not None:
            try:
                self._register_handle.stop()
            except Exception:
                log.exception("register stop failed")
            self._register_handle = None

    def _teardown_session(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None
        if self._listen_sock is not None:
            try:
                self._listen_sock.close()
            except OSError:
                pass
            self._listen_sock = None

    def _reset_session_events(self) -> None:
        self._stop.clear()
        self._user_confirmed.clear()
        self._user_rejected.clear()
        with self._peers_lock:
            self._peers.clear()
        self._session_key = None
        self._sas = None
        self._peer_display = ""

    def _fail(self, reason: str) -> None:
        log.info("pairing failed: %s", reason)
        self._cb.on_failed(reason)

    # -- discovery callbacks (from the backend's threads) -----------------

    def _on_peer_discovered(self, found: _mdns.DiscoveredPeer) -> None:
        if found.txt.get("role") != "giver":
            return
        peer = PairingPeer(
            peer_id=found.name,
            display=found.txt.get("display", "") or "(unknown)",
            label=found.txt.get("label", "") or "",
            address=found.address,
            port=found.port,
        )
        with self._peers_lock:
            self._peers[found.name] = peer
        self._cb.on_peers_changed(self.peers())

    def _on_peer_lost(self, name: str) -> None:
        with self._peers_lock:
            self._peers.pop(name, None)
        self._cb.on_peers_changed(self.peers())


# ---------------------------------------------------------------------------
# CLI harness for two-terminal smoke testing (no UI required).
# ---------------------------------------------------------------------------

def _cli() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m clipsync.core.pairing",
        description="Two-terminal smoke test for the pairing protocol.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp_share = sub.add_parser("share", help="advertise a fake payload")
    sp_share.add_argument("--label", default="#test",
                          help="label shown to the receiver")
    sp_share.add_argument("--payload", default="clipsync://join?demo=1",
                          help="opaque string to deliver on success")
    sub.add_parser("receive", help="browse and accept a shared payload")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    done = threading.Event()
    result: dict = {}

    def on_peers(peers):
        names = ", ".join(f"{p.display} {p.label}" for p in peers) or "(none yet)"
        print(f"[peers] {names}")

    def on_sas(sas, who):
        print(f"\nVerify code: {sas}   (peer: {who})")
        ans = input("Confirm? [y/N] ").strip().lower()
        if ans == "y":
            svc.confirm()
        else:
            svc.reject()

    def on_paired(payload):
        result["payload"] = payload
        if payload is None:
            print("[paired] giver: payload delivered.")
        else:
            print(f"[paired] taker received: {payload}")
        done.set()

    def on_failed(reason):
        result["error"] = reason
        print(f"[failed] {reason}")
        done.set()

    cbs = PairingCallbacks(
        on_peers_changed=on_peers,
        on_sas_ready=on_sas,
        on_paired=on_paired,
        on_failed=on_failed,
    )
    svc = PairingService(display_name=socket.gethostname(), callbacks=cbs)

    if args.cmd == "share":
        svc.start_share(payload=args.payload, label=args.label)
    else:
        svc.start_receive()
        # Wait for a peer to appear, then pick the first one.
        for _ in range(60):
            peers = svc.peers()
            if peers:
                first = peers[0]
                print(f"[picking] {first.display} {first.label}")
                svc.pick_peer(first.peer_id)
                break
            time.sleep(1.0)
        else:
            print("[failed] no peers found in 60s")
            svc.cancel()
            return 2

    done.wait(SESSION_TIMEOUT_S + 30)
    return 0 if "payload" in result else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
