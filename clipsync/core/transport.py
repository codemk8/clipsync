"""
clipsync.core.transport
=======================

UDP multicast + TCP networking, wired through :class:`CipherRegistry`.

What this module owns
---------------------
* **UDP multicast**, one socket per channel, for :class:`MessageType.ANNOUNCE`
  (periodic) and :class:`MessageType.PUBLISH_NOTIFY` (one-shot).
* **TCP server + client** for :class:`MessageType.POLL` /
  :class:`MessageType.POLL_RESULT` and :class:`MessageType.FETCH` /
  :class:`MessageType.FETCH_RESULT`. TCP is used for these because POLL_RESULT
  can be large (every item in the ring buffer) and FETCH_RESULT can be a
  multi-MB image.
* **Sealing / opening** every packet through the :class:`CipherRegistry`. The
  registry is the access-control boundary: a packet no cipher can open is
  silently dropped.
* A **per-channel peer roster** built from incoming ANNOUNCE packets, with
  peers timed out after :attr:`Settings.peer_timeout`.

What this module does *not* own
-------------------------------
The ring buffer of published items, the clipboard itself, and the user-facing
decisions ("publish current", "pull seq N") live in :mod:`clipsync.daemon`.
Transport is the I/O layer; daemon is the business logic.

Threading
---------
There are three long-lived threads:

* a **UDP reader** that select()s on every channel's multicast socket and
  hands opened messages to the inbound dispatcher,
* a **TCP acceptor** that hands each incoming connection to a short-lived
  worker thread,
* an **announce loop** that broadcasts ANNOUNCE on each channel every
  :attr:`Settings.announce_interval`.

Callbacks fire on whichever thread received the triggering packet. The
daemon is responsible for being thread-safe; in practice it serializes work
through a lock around its per-channel ring buffers.
"""

from __future__ import annotations

import logging
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .channels import Channel, ChannelRegistry
from .crypto import CipherRegistry, CryptoError
from .protocol import (
    ItemMeta,
    Message,
    MessageType,
    ProtocolError,
    announce_fields,
    fetch_seq,
    make_announce,
    make_error,
    make_fetch,
    make_fetch_result,
    make_poll,
    make_poll_result,
    make_publish_notify,
    notify_item,
    poll_result_items,
    fetch_result_item,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Peer roster.
# ---------------------------------------------------------------------------


@dataclass
class Peer:
    """A live peer learned from ANNOUNCE packets on some channel.

    ``addr`` is the source IP from which the announce was received; ``tcp_port``
    is the TCP port that peer is listening on for POLL/FETCH (announced in the
    payload, not inferred from the UDP source -- different sockets).
    """

    origin: str
    origin_name: str
    addr: str
    tcp_port: int
    channel: str
    latest_seq: int = -1
    last_seen: float = field(default_factory=time.time)

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.addr, self.tcp_port


# ---------------------------------------------------------------------------
# Transport callbacks. The daemon wires these up.
# ---------------------------------------------------------------------------


@dataclass
class TransportCallbacks:
    """Hooks the daemon installs to react to network events.

    Every callback may be called from a transport-owned thread. Implementations
    must be thread-safe (or marshal back to a single worker).

    ``on_fetch`` is the only callback that synchronously *returns* data: it
    must return ``(ItemMeta, payload_bytes)`` for a known seq, or ``None`` if
    the requested seq is not in the local ring buffer.
    """

    on_announce: Callable[[Peer], None] = lambda peer: None
    on_peer_lost: Callable[[Peer], None] = lambda peer: None
    on_publish_notify: Callable[[str, ItemMeta, Peer], None] = (
        lambda channel, item, peer: None
    )
    on_poll: Callable[[str], list[ItemMeta]] = lambda channel: []
    on_poll_result: Callable[[str, list[ItemMeta], Peer], None] = (
        lambda channel, items, peer: None
    )
    on_fetch: Callable[[str, int], Optional[tuple[ItemMeta, bytes]]] = (
        lambda channel, seq: None
    )
    on_fetch_result: Callable[[str, ItemMeta, bytes, Peer], None] = (
        lambda channel, item, body, peer: None
    )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _length_prefixed_send(sock: socket.socket, blob: bytes) -> None:
    """Send a length-prefixed blob over a TCP socket."""
    if len(blob) > 0xFFFFFFFF:
        raise OSError("packet too large to frame")
    sock.sendall(len(blob).to_bytes(4, "big") + blob)


def _length_prefixed_recv(sock: socket.socket, max_size: int) -> bytes:
    """Receive a length-prefixed blob. Returns empty bytes on clean EOF."""
    prefix = _recvn(sock, 4)
    if not prefix:
        return b""
    n = int.from_bytes(prefix, "big")
    if n > max_size:
        raise OSError(f"incoming packet of {n} bytes exceeds max {max_size}")
    return _recvn(sock, n)


def _recvn(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise on short read."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            if not buf:
                return b""           # clean EOF before any bytes
            raise OSError("connection closed mid-message")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Transport.
# ---------------------------------------------------------------------------


# Max UDP payload that fits comfortably under the typical Ethernet MTU after
# IP+UDP overhead. PUBLISH_NOTIFY can hold a non-trivial ItemMeta but never a
# clipboard payload, so this is plenty.
UDP_BUFSIZE = 65535


class Transport:
    """The networking layer. One instance per daemon.

    Holds the UDP multicast sockets (one per joined channel), the shared TCP
    listener, the peer roster, and the announce/timeout loops. Outbound
    helpers (:meth:`publish_notify`, :meth:`poll`, :meth:`fetch`) are what the
    daemon calls when the user acts.
    """

    def __init__(
        self,
        channel_registry: ChannelRegistry,
        cipher_registry: CipherRegistry,
        callbacks: TransportCallbacks,
        origin: str,
        origin_name: str,
        announce_interval: float = 3.0,
        peer_timeout: float = 10.0,
        max_payload: int = 25 * 1024 * 1024,
        tcp_bind: tuple[str, int] = ("0.0.0.0", 0),
    ):
        self._channels = channel_registry
        self._ciphers = cipher_registry
        self._cb = callbacks
        self._origin = origin
        self._origin_name = origin_name
        self._announce_interval = announce_interval
        self._peer_timeout = peer_timeout
        # The TCP frame can carry an entire FETCH_RESULT, so the max payload
        # plus header+overhead bounds the frame size we will accept.
        self._tcp_max_frame = max_payload + (1 << 20)
        self._tcp_bind = tcp_bind

        # Per-channel UDP multicast sockets.
        self._udp_socks: dict[str, socket.socket] = {}
        self._udp_lock = threading.Lock()

        # Peer roster: {(channel, origin): Peer}. Indexed by origin so a peer
        # that changes IP between announces updates rather than duplicates.
        self._peers: dict[tuple[str, str], Peer] = {}
        self._peers_lock = threading.Lock()

        # Latest-seq we have published per channel, surfaced via ANNOUNCE.
        # The daemon sets this through :meth:`set_latest_seq`.
        self._latest_seq: dict[str, int] = {}
        self._latest_seq_lock = threading.Lock()

        # TCP listener.
        self._tcp_sock: socket.socket | None = None
        self._tcp_port: int = 0

        # Lifecycle.
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Bring the transport online and join every persisted channel."""
        self._open_tcp()
        for channel in self._channels.list_channels():
            self._add_channel_sockets(channel)

        # Spawn loops. Each loop owns its socket set via shared state under
        # the relevant lock.
        for target in (self._udp_loop, self._tcp_accept_loop,
                       self._announce_loop, self._peer_gc_loop):
            t = threading.Thread(target=target, name=target.__name__, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        """Tear down sockets and signal every loop to exit."""
        self._stop.set()
        # Closing sockets unblocks recv()/select(). We do not join() the loops
        # because they are daemon threads and may be sleeping; the process is
        # going away.
        with self._udp_lock:
            for sock in self._udp_socks.values():
                try:
                    sock.close()
                except OSError:
                    pass
            self._udp_socks.clear()
        if self._tcp_sock is not None:
            try:
                self._tcp_sock.close()
            except OSError:
                pass
            self._tcp_sock = None

    # -- channel membership wiring -----------------------------------------

    def add_channel(self, channel: Channel) -> None:
        """Hook a newly-joined channel into the transport (UDP socket up)."""
        self._add_channel_sockets(channel)

    def remove_channel(self, channel_name: str) -> None:
        """Tear down a left channel's UDP socket and forget its peers."""
        with self._udp_lock:
            sock = self._udp_socks.pop(channel_name, None)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        with self._peers_lock:
            for key in [k for k in self._peers if k[0] == channel_name]:
                self._peers.pop(key, None)
        with self._latest_seq_lock:
            self._latest_seq.pop(channel_name, None)

    def _add_channel_sockets(self, channel: Channel) -> None:
        """Open the per-channel UDP multicast socket and join its group."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                # macOS / Linux: harmless if the kernel does not support it.
                pass
        sock.bind(("", channel.port))

        # IP_ADD_MEMBERSHIP: req = group + interface ("0" = INADDR_ANY).
        mreq = struct.pack(
            "4s4s",
            socket.inet_aton(channel.group),
            socket.inet_aton("0.0.0.0"),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        # TTL=1 keeps multicast inside the local network (decision: LAN-only).
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        # Receive our own packets too so a one-host test still exercises the
        # full path. The crypto layer's msg_id dedupe takes care of the rest.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        with self._udp_lock:
            # Close any pre-existing socket for this channel (rejoin case).
            old = self._udp_socks.pop(channel.name, None)
            if old is not None:
                try:
                    old.close()
                except OSError:
                    pass
            self._udp_socks[channel.name] = sock

    # -- TCP setup ----------------------------------------------------------

    def _open_tcp(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(self._tcp_bind)
        sock.listen(8)
        self._tcp_sock = sock
        self._tcp_port = sock.getsockname()[1]

    @property
    def tcp_port(self) -> int:
        """Port the TCP listener bound to (advertised in ANNOUNCE)."""
        return self._tcp_port

    # -- outbound API -------------------------------------------------------

    def set_latest_seq(self, channel: str, seq: int) -> None:
        """Daemon tells us the newest seq it has published on a channel.

        Surfaced in the next ANNOUNCE so peers can catch up after missing a
        PUBLISH_NOTIFY.
        """
        with self._latest_seq_lock:
            self._latest_seq[channel] = int(seq)

    def publish_notify(self, channel: str, item: ItemMeta) -> None:
        """Multicast PUBLISH_NOTIFY so peers' menus update immediately."""
        msg = make_publish_notify(channel, self._origin, self._origin_name, item)
        self._send_multicast(channel, msg)
        # The new item becomes the latest_seq we advertise.
        self.set_latest_seq(channel, item.seq)

    def poll(self, peer: Peer) -> Optional[list[ItemMeta]]:
        """Unicast POLL to ``peer``, returning the items list it reports.

        Returns ``None`` on any failure (connection refused, timeout, crypto
        error). Failures are normal -- peers come and go.
        """
        req = make_poll(peer.channel, self._origin, self._origin_name)
        reply = self._tcp_request(peer, req, expected_type=MessageType.POLL_RESULT)
        if reply is None:
            return None
        try:
            items = poll_result_items(reply)
        except ProtocolError:
            return None
        # Surface to the daemon's callback too, so a poll triggered elsewhere
        # also flows through the standard dispatch.
        try:
            self._cb.on_poll_result(peer.channel, items, peer)
        except Exception:
            log.exception("on_poll_result callback raised")
        return items

    def fetch(self, peer: Peer, seq: int) -> Optional[tuple[ItemMeta, bytes]]:
        """Unicast FETCH to ``peer`` for ``seq``. Returns ``(meta, body)``."""
        req = make_fetch(peer.channel, self._origin, self._origin_name, seq)
        reply = self._tcp_request(peer, req, expected_type=MessageType.FETCH_RESULT)
        if reply is None:
            return None
        try:
            meta = fetch_result_item(reply)
        except ProtocolError:
            return None
        try:
            self._cb.on_fetch_result(peer.channel, meta, reply.body, peer)
        except Exception:
            log.exception("on_fetch_result callback raised")
        return meta, reply.body

    # -- peer roster --------------------------------------------------------

    def peers(self, channel: str) -> list[Peer]:
        """Snapshot of currently-known peers on ``channel``."""
        with self._peers_lock:
            return [p for (ch, _), p in self._peers.items() if ch == channel]

    # -- inbound dispatch loops --------------------------------------------

    def _udp_loop(self) -> None:
        """select() over every channel's UDP socket; dispatch opened messages."""
        while not self._stop.is_set():
            with self._udp_lock:
                socks = list(self._udp_socks.values())
            if not socks:
                # No joined channels: idle long. Channels only appear by
                # explicit user action ("Manage channels..."); a UI thread
                # calls add_channel and the next iteration of this loop picks
                # the new socket up. There is no need to wake at 2 Hz.
                self._stop.wait(5.0)
                continue

            try:
                # 1s timeout is short enough that add_channel / remove_channel
                # picks up the new socket set within a second, and long
                # enough that an idle daemon sees ~one wakeup per second per
                # process instead of two.
                readable, _, _ = select.select(socks, [], [], 1.0)
            except (OSError, ValueError):
                # A socket got closed under us during a leave -- retry.
                continue

            for sock in readable:
                try:
                    data, src = sock.recvfrom(UDP_BUFSIZE)
                except OSError:
                    continue
                self._handle_udp_packet(data, src)

    def _handle_udp_packet(self, data: bytes, src) -> None:
        try:
            msg = self._ciphers.open(data)
        except CryptoError:
            # Wrong key, replay, tampered, or just noise. Silently drop.
            return

        if msg.sender == self._origin:
            # Looped-back from our own multicast. The crypto-layer dedupe
            # would also catch this if we relied on it, but skipping the
            # roster update saves a lock acquire.
            return

        if msg.type is MessageType.ANNOUNCE:
            try:
                tcp_port, latest_seq = announce_fields(msg)
            except ProtocolError:
                return
            # ANNOUNCE is authoritative: it reflects the peer's current
            # top-of-ring, which can go DOWN (unpublish) as well as up.
            peer = self._upsert_peer(
                channel=msg.channel,
                origin=msg.sender,
                origin_name=msg.sender_name,
                addr=src[0],
                tcp_port=tcp_port,
                latest_seq=latest_seq,
                seq_mode="set",
            )
            try:
                self._cb.on_announce(peer)
            except Exception:
                log.exception("on_announce callback raised")

        elif msg.type is MessageType.PUBLISH_NOTIFY:
            try:
                item = notify_item(msg)
            except ProtocolError:
                return
            # Best-effort upsert so the menu shows the sender even if we
            # have not yet caught an ANNOUNCE from them. NOTIFY can arrive
            # out of order relative to ANNOUNCE, so only raise the seq --
            # the next ANNOUNCE will reconcile.
            peer = self._upsert_peer(
                channel=msg.channel,
                origin=msg.sender,
                origin_name=msg.sender_name,
                addr=src[0],
                tcp_port=0,            # unknown until their next announce
                latest_seq=item.seq,
                seq_mode="raise",
                touch_endpoint_only=True,
            )
            try:
                self._cb.on_publish_notify(msg.channel, item, peer)
            except Exception:
                log.exception("on_publish_notify callback raised")

        else:
            # POLL/FETCH/ERROR are TCP-only; ignore if they arrive over UDP.
            log.debug("ignoring %s over UDP", msg.type.value)

    def _tcp_accept_loop(self) -> None:
        """Accept TCP requests and hand each to a short-lived worker."""
        while not self._stop.is_set():
            try:
                if self._tcp_sock is None:
                    return
                conn, addr = self._tcp_sock.accept()
            except OSError:
                if self._stop.is_set():
                    return
                continue
            t = threading.Thread(
                target=self._tcp_worker,
                args=(conn, addr),
                name="tcp-worker",
                daemon=True,
            )
            t.start()

    def _tcp_worker(self, conn: socket.socket, addr) -> None:
        """Handle one TCP request: read frame, dispatch, write response."""
        try:
            conn.settimeout(15.0)
            blob = _length_prefixed_recv(conn, self._tcp_max_frame)
            if not blob:
                return
            try:
                msg = self._ciphers.open(blob)
            except CryptoError:
                return

            if msg.type is MessageType.POLL:
                reply = self._handle_poll(msg)
            elif msg.type is MessageType.FETCH:
                reply = self._handle_fetch(msg)
            else:
                reply = make_error(
                    channel=msg.channel,
                    sender=self._origin,
                    sender_name=self._origin_name,
                    reason=f"unsupported request type: {msg.type.value}",
                    ref_msg_id=msg.msg_id,
                )

            try:
                sealed = self._ciphers.seal(reply)
            except CryptoError:
                return
            _length_prefixed_send(conn, sealed)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_poll(self, msg: Message) -> Message:
        try:
            items = self._cb.on_poll(msg.channel)
        except Exception:
            log.exception("on_poll callback raised")
            items = []
        return make_poll_result(msg.channel, self._origin, self._origin_name, items)

    def _handle_fetch(self, msg: Message) -> Message:
        try:
            seq = fetch_seq(msg)
        except ProtocolError as exc:
            return make_error(
                msg.channel, self._origin, self._origin_name,
                reason=str(exc), ref_msg_id=msg.msg_id,
            )
        try:
            result = self._cb.on_fetch(msg.channel, seq)
        except Exception:
            log.exception("on_fetch callback raised")
            result = None
        if result is None:
            return make_error(
                msg.channel, self._origin, self._origin_name,
                reason=f"seq {seq} not available", ref_msg_id=msg.msg_id,
            )
        item, body = result
        return make_fetch_result(
            msg.channel, self._origin, self._origin_name, item, body,
        )

    # -- announce + GC loops -----------------------------------------------

    def _announce_loop(self) -> None:
        """Multicast ANNOUNCE on every joined channel every interval."""
        while not self._stop.is_set():
            for channel in self._channels.list_channels():
                with self._latest_seq_lock:
                    latest = self._latest_seq.get(channel.name, -1)
                msg = make_announce(
                    channel=channel.name,
                    sender=self._origin,
                    sender_name=self._origin_name,
                    tcp_port=self._tcp_port,
                    latest_seq=latest,
                )
                self._send_multicast(channel.name, msg)
            self._stop.wait(self._announce_interval)

    def _peer_gc_loop(self) -> None:
        """Drop peers we have not heard from for ``peer_timeout``."""
        while not self._stop.is_set():
            self._stop.wait(self._peer_timeout / 2)
            if self._stop.is_set():
                return
            cutoff = time.time() - self._peer_timeout
            lost: list[Peer] = []
            with self._peers_lock:
                for key in list(self._peers):
                    peer = self._peers[key]
                    if peer.last_seen < cutoff:
                        lost.append(peer)
                        self._peers.pop(key, None)
            for peer in lost:
                try:
                    self._cb.on_peer_lost(peer)
                except Exception:
                    log.exception("on_peer_lost callback raised")

    # -- internals ---------------------------------------------------------

    def _send_multicast(self, channel_name: str, msg: Message) -> None:
        """Seal ``msg`` and send it on ``channel_name``'s multicast socket."""
        channel = self._channels.get(channel_name)
        if channel is None:
            return
        with self._udp_lock:
            sock = self._udp_socks.get(channel_name)
        if sock is None:
            return
        try:
            blob = self._ciphers.seal(msg)
        except CryptoError:
            return
        try:
            sock.sendto(blob, (channel.group, channel.port))
        except OSError:
            log.debug("multicast send failed on channel %s", channel_name)

    def _tcp_request(
        self,
        peer: Peer,
        request: Message,
        expected_type: MessageType,
    ) -> Optional[Message]:
        """One-shot TCP round-trip to ``peer``. Returns the opened reply or None."""
        try:
            sealed = self._ciphers.seal(request)
        except CryptoError:
            return None
        try:
            with socket.create_connection(peer.endpoint, timeout=15.0) as conn:
                _length_prefixed_send(conn, sealed)
                blob = _length_prefixed_recv(conn, self._tcp_max_frame)
        except (OSError, ValueError):
            return None
        if not blob:
            return None
        try:
            reply = self._ciphers.open(blob)
        except CryptoError:
            return None
        if reply.type is MessageType.ERROR:
            return None
        if reply.type is not expected_type:
            return None
        return reply

    def _upsert_peer(
        self,
        channel: str,
        origin: str,
        origin_name: str,
        addr: str,
        tcp_port: int,
        latest_seq: int,
        seq_mode: str = "raise",
        touch_endpoint_only: bool = False,
    ) -> Peer:
        """Insert or refresh a peer in the roster. Returns the live :class:`Peer`.

        ``seq_mode`` controls how ``latest_seq`` is merged into the existing
        record. ``"set"`` overwrites unconditionally (ANNOUNCE: authoritative
        current state, allows unpublishes to be reflected downward).
        ``"raise"`` updates only if the new value is greater (PUBLISH_NOTIFY:
        best-effort, can arrive out of order).
        """
        key = (channel, origin)
        with self._peers_lock:
            peer = self._peers.get(key)
            now = time.time()
            if peer is None:
                peer = Peer(
                    origin=origin,
                    origin_name=origin_name or origin[:8],
                    addr=addr,
                    tcp_port=tcp_port,
                    channel=channel,
                    latest_seq=latest_seq,
                    last_seen=now,
                )
                self._peers[key] = peer
            else:
                peer.addr = addr
                peer.origin_name = origin_name or peer.origin_name
                # PUBLISH_NOTIFY does not carry a TCP port; preserve whatever
                # the last ANNOUNCE established.
                if not touch_endpoint_only and tcp_port:
                    peer.tcp_port = tcp_port
                if seq_mode == "set":
                    peer.latest_seq = latest_seq
                elif latest_seq > peer.latest_seq:
                    peer.latest_seq = latest_seq
                peer.last_seen = now
            return peer
