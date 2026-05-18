"""
clipsync.daemon
===============

The entry point. Wires the registry, transport, clipboard, and per-channel
ring buffers together and exposes the API the UI layer calls:

    publish_current(channel)          read the OS clipboard, broadcast notify
    unpublish_last(channel)            drop the newest item from the ring
    pull(channel, seq)                 fetch a peer's item -> write clipboard
    available_items(channel)           list known items across all peers
    peers(channel)                     live peer roster
    create_channel / join_channel / leave_channel    channel management

Design fidelity (PROJECT_STATUS.md):
  * Sharing is opt-in push, manual pull -- the OS clipboard is not watched.
  * Sender holds a small ring buffer per channel; pulled items stay published.
  * Receivers learn of new items via PUBLISH_NOTIFY and via ANNOUNCE's
    ``latest_seq`` (a quiet poll loop is the safety net for missed notifies).

State model
-----------
* **Outgoing ring buffer**: per channel, the last N items we have published,
  oldest evicted on overflow. Each item has metadata + payload kept in
  memory (clipboard items are typically small; max bounded by max_payload).
* **Inbound catalog**: per channel, the ItemMetas we have learned from
  peers, keyed by ``(origin, seq)`` so we never confuse two items even if
  two daemons happen to pick the same seq. The catalog is *menu data*; it
  is repopulated by POLL on demand and trimmed on peer loss.
"""

from __future__ import annotations

import hashlib
import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from .config import SettingsStore
from .core.channels import Channel, ChannelRegistry, ChannelError
from .core.clipboard import Clipboard, ClipboardError, get_clipboard
from .core.crypto import CipherRegistry
from .core.pairing import PairingCallbacks, PairingPeer, PairingService
from .core.protocol import (
    CONTENT_IMAGE,
    CONTENT_TEXT,
    ItemMeta,
)
from .core.transport import Peer, Transport, TransportCallbacks

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Catalog entries (what populates the "Available on #channel" submenu).
# ---------------------------------------------------------------------------


@dataclass
class CatalogEntry:
    """An item *some* peer holds, as we currently understand it."""

    channel: str
    item: ItemMeta            # metadata only -- payload pulled on demand
    peer: Peer                 # who to FETCH from


# ---------------------------------------------------------------------------
# Ring buffer of published items, per channel.
# ---------------------------------------------------------------------------


@dataclass
class _PublishedItem:
    meta: ItemMeta
    body: bytes


class _PublishRing:
    """In-memory ring buffer of recently published items for one channel."""

    def __init__(self, size: int):
        self._size = max(1, int(size))
        self._items: deque[_PublishedItem] = deque(maxlen=self._size)
        self._next_seq: int = 1
        self._lock = threading.Lock()

    def push(self, meta: ItemMeta, body: bytes) -> None:
        with self._lock:
            self._items.append(_PublishedItem(meta=meta, body=body))
            self._next_seq = max(self._next_seq, meta.seq + 1)

    def allocate_seq(self) -> int:
        with self._lock:
            seq = self._next_seq
            self._next_seq += 1
            return seq

    def latest_seq(self) -> int:
        with self._lock:
            return self._items[-1].meta.seq if self._items else -1

    def get(self, seq: int) -> Optional[_PublishedItem]:
        with self._lock:
            for entry in self._items:
                if entry.meta.seq == seq:
                    return entry
            return None

    def items(self) -> list[ItemMeta]:
        with self._lock:
            return [e.meta for e in self._items]

    def pop_latest(self) -> Optional[_PublishedItem]:
        with self._lock:
            if not self._items:
                return None
            return self._items.pop()

    def remove(self, seq: int) -> Optional[_PublishedItem]:
        """Remove a specific seq from anywhere in the ring. ``None`` if absent.

        ``deque`` does not have an efficient remove-by-predicate, but the ring
        is small (default 5) so a rebuild is O(ring_size) and negligible.
        """
        with self._lock:
            for idx, entry in enumerate(self._items):
                if entry.meta.seq == seq:
                    # Rebuild the deque to drop this one item. maxlen is
                    # preserved by passing it through.
                    items = list(self._items)
                    del items[idx]
                    self._items = deque(items, maxlen=self._items.maxlen)
                    return entry
            return None


# ---------------------------------------------------------------------------
# Daemon.
# ---------------------------------------------------------------------------


def _make_preview(content_type: str, data: bytes) -> str:
    """Short human preview for menu display."""
    if content_type == CONTENT_TEXT:
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            text = ""
        snippet = text.replace("\n", " ").replace("\r", " ").strip()
        if len(snippet) > 60:
            snippet = snippet[:57] + "..."
        return f'"{snippet}"' if snippet else "(empty text)"
    if content_type == CONTENT_IMAGE:
        return f"image · {_human_bytes(len(data))}"
    return f"{content_type} · {_human_bytes(len(data))}"


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


class Daemon:
    """The single object the UI layer talks to."""

    def __init__(
        self,
        channel_registry: ChannelRegistry | None = None,
        settings_store: SettingsStore | None = None,
        clipboard: Clipboard | None = None,
    ):
        self._channels = channel_registry or ChannelRegistry()
        self._settings_store = settings_store or SettingsStore()
        self._settings = self._settings_store.get()
        self._clipboard = clipboard or get_clipboard()

        # Sync toggle. When False, publish/pull become no-ops at the daemon
        # level; the transport keeps running so ANNOUNCE still works.
        self._sync_enabled = True
        self._sync_lock = threading.Lock()

        # Crypto. One cipher per joined channel.
        self._ciphers = CipherRegistry()
        for ch in self._channels.list_channels():
            self._ciphers.add_channel(ch.name, ch.secret)

        # Per-channel publish rings.
        self._rings: dict[str, _PublishRing] = {}
        self._rings_lock = threading.Lock()
        for ch in self._channels.list_channels():
            self._rings[ch.name] = _PublishRing(self._settings.ring_size)

        # Inbound catalog, indexed by channel so per-channel queries are O(items
        # in that channel) instead of O(total items across all channels). The
        # inner dict is keyed by (origin, seq) so two daemons that happen to
        # pick the same seq never collide.
        self._catalog: dict[str, dict[tuple[str, int], CatalogEntry]] = {}
        self._catalog_lock = threading.Lock()

        # Per-channel hide set: (origin, seq) tuples the user has chosen to
        # suppress from their own "Available" view. Local-only -- unpublishing
        # would affect everyone, hiding affects only this machine's menu. Kept
        # in memory: hides do not persist across restarts. A naturally-stale
        # entry (peer unpublished it for real) is harmless since the catalog
        # entry is also gone.
        self._hidden: dict[str, set[tuple[str, int]]] = {}
        self._hidden_lock = threading.Lock()

        # Wire callbacks. The transport calls these from its own threads.
        cbs = TransportCallbacks(
            on_announce=self._on_announce,
            on_peer_lost=self._on_peer_lost,
            on_publish_notify=self._on_publish_notify,
            on_poll=self._on_poll,
            on_poll_result=self._on_poll_result,
            on_fetch=self._on_fetch,
            on_fetch_result=self._on_fetch_result,
        )
        self._transport = Transport(
            channel_registry=self._channels,
            cipher_registry=self._ciphers,
            callbacks=cbs,
            origin=self._settings.origin,
            origin_name=self._settings.origin_name,
            announce_interval=self._settings.announce_interval,
            peer_timeout=self._settings.peer_timeout,
            max_payload=self._settings.max_payload,
            tcp_bind=("0.0.0.0", self._settings.tcp_port),
        )

        # Single background worker for outbound polls. We deliberately do NOT
        # spawn a thread per poll: with N peers across M channels and
        # announces every few seconds, that adds up to a continuous churn of
        # OS thread creation. A single worker draining a deduping queue keeps
        # the cost flat regardless of peer count.
        self._poll_queue: queue.Queue[tuple[str, str] | None] = queue.Queue()
        self._poll_inflight: set[tuple[str, str]] = set()
        self._poll_inflight_lock = threading.Lock()
        self._poll_stop = threading.Event()
        self._poll_worker: threading.Thread | None = None
        self._slow_poll_thread: threading.Thread | None = None

        # Hooks the UI installs to know when to redraw the menu. The daemon
        # never assumes a particular UI toolkit -- it just fires the bare
        # callback on the thread that produced the change.
        self.on_catalog_changed: callable = lambda channel: None
        self.on_peers_changed: callable = lambda channel: None

        # Pairing service. Wraps PairingCallbacks so the UI sees a single
        # set of hooks on the daemon (matching the on_catalog_changed style).
        # The taker path joins the received channel automatically before
        # firing on_pairing_paired -- so the UI just gets the Channel.
        self.on_pairing_peers_changed: callable = lambda peers: None
        self.on_pairing_sas_ready: callable = lambda sas, peer_display: None
        self.on_pairing_paired: callable = lambda channel: None
        self.on_pairing_failed: callable = lambda reason: None
        self._pairing = PairingService(
            display_name=self._settings.origin_name,
            callbacks=PairingCallbacks(
                on_peers_changed=lambda peers: self.on_pairing_peers_changed(peers),
                on_sas_ready=lambda sas, who: self.on_pairing_sas_ready(sas, who),
                on_paired=self._handle_pairing_done,
                on_failed=lambda reason: self.on_pairing_failed(reason),
            ),
        )

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        self._transport.start()
        self._poll_stop.clear()
        self._poll_worker = threading.Thread(
            target=self._poll_worker_loop, name="poll-worker", daemon=True,
        )
        self._poll_worker.start()
        self._slow_poll_thread = threading.Thread(
            target=self._slow_poll_loop, name="slow-poll", daemon=True,
        )
        self._slow_poll_thread.start()

    def stop(self) -> None:
        self._poll_stop.set()
        # Wake the worker so it exits promptly instead of waiting for an item.
        self._poll_queue.put_nowait(None)
        try:
            self._pairing.cancel()
        except Exception:
            log.exception("pairing cancel during stop")
        self._transport.stop()

    @property
    def origin(self) -> str:
        return self._settings.origin

    @property
    def origin_name(self) -> str:
        return self._settings.origin_name

    # -- sync toggle --------------------------------------------------------

    def set_sync_enabled(self, enabled: bool) -> None:
        with self._sync_lock:
            self._sync_enabled = bool(enabled)

    def sync_enabled(self) -> bool:
        with self._sync_lock:
            return self._sync_enabled

    # -- OS clipboard helpers (used by UI for join-string copy/paste) ------

    def copy_text_to_clipboard(self, text: str) -> None:
        """Place ``text`` on the OS clipboard as UTF-8."""
        self._clipboard.write(CONTENT_TEXT, text.encode("utf-8"))

    def read_clipboard_text(self) -> Optional[str]:
        """Return the OS clipboard as text, or None if it isn't text."""
        item = self._clipboard.read()
        if item is None:
            return None
        content_type, data = item
        if content_type != CONTENT_TEXT:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return None

    # -- pairing (UI passthrough) ------------------------------------------

    def start_pairing_share(self, channel_name: str) -> None:
        """Advertise ``channel_name`` for pairing. UI gets on_pairing_sas_ready
        once a taker connects and the HELLO round completes."""
        channel = next(
            (c for c in self._channels.list_channels() if c.name == channel_name),
            None,
        )
        if channel is None:
            raise ChannelError(f"unknown channel {channel_name!r}")
        self._pairing.start_share(
            payload=channel.to_join_string(),
            label=f"#{channel.name}",
        )

    def start_pairing_receive(self) -> None:
        """Browse for nearby pairing peers. UI gets on_pairing_peers_changed
        as discoveries come in, then calls :meth:`pick_pairing_peer`."""
        self._pairing.start_receive()

    def pick_pairing_peer(self, peer_id: str) -> None:
        self._pairing.pick_peer(peer_id)

    def confirm_pairing(self) -> None:
        self._pairing.confirm()

    def reject_pairing(self) -> None:
        self._pairing.reject()

    def cancel_pairing(self) -> None:
        self._pairing.cancel()

    def pairing_peers(self) -> list[PairingPeer]:
        return self._pairing.peers()

    def _handle_pairing_done(self, payload: Optional[str]) -> None:
        """Pairing completion glue. Giver side: payload is None, just notify.
        Taker side: payload is the join string -- install the channel here
        so the UI just gets the resulting :class:`Channel`."""
        if payload is None:
            self.on_pairing_paired(None)
            return
        try:
            channel = self.join_channel(payload)
        except ChannelError as exc:
            log.warning("pairing received channel but join failed: %s", exc)
            self.on_pairing_failed(f"received channel but could not install: {exc}")
            return
        self.on_pairing_paired(channel)

    # -- channel management (UI passthrough) -------------------------------

    def list_channels(self) -> list[Channel]:
        return self._channels.list_channels()

    def create_channel(self, name: str) -> Channel:
        channel = self._channels.create_channel(name)
        self._wire_channel(channel)
        return channel

    def join_channel(self, join_string: str) -> Channel:
        channel = self._channels.join(join_string)
        self._wire_channel(channel)
        return channel

    def leave_channel(self, name: str) -> None:
        self._channels.leave(name)
        self._ciphers.remove_channel(name)
        self._transport.remove_channel(name)
        with self._rings_lock:
            self._rings.pop(name, None)
        with self._catalog_lock:
            self._catalog.pop(name, None)
        with self._hidden_lock:
            self._hidden.pop(name, None)
        self._safe(self.on_catalog_changed, name)
        self._safe(self.on_peers_changed, name)

    def _wire_channel(self, channel: Channel) -> None:
        self._ciphers.add_channel(channel.name, channel.secret)
        with self._rings_lock:
            if channel.name not in self._rings:
                self._rings[channel.name] = _PublishRing(self._settings.ring_size)
        self._transport.add_channel(channel)

    # -- publish / unpublish -----------------------------------------------

    def publish_current(self, channel_name: str) -> Optional[ItemMeta]:
        """Read the OS clipboard, push it onto the channel's ring, notify peers.

        Returns the new :class:`ItemMeta` or ``None`` if the clipboard was
        empty / unsupported / sync is paused.
        """
        if not self.sync_enabled():
            return None
        if channel_name not in self._channels:
            raise ChannelError(f"not joined to channel '{channel_name}'")

        try:
            read = self._clipboard.read()
        except ClipboardError as exc:
            log.warning("clipboard read failed: %s", exc)
            return None
        if read is None:
            return None
        content_type, data = read

        if len(data) > self._settings.max_payload:
            log.warning(
                "clipboard payload too large (%d bytes > max %d)",
                len(data), self._settings.max_payload,
            )
            return None

        ring = self._get_ring(channel_name)
        seq = ring.allocate_seq()
        meta = ItemMeta(
            seq=seq,
            timestamp=time.time(),
            origin=self._settings.origin,
            origin_name=self._settings.origin_name,
            content_type=content_type,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            preview=_make_preview(content_type, data),
        )
        ring.push(meta, data)
        self._transport.set_latest_seq(channel_name, meta.seq)
        self._transport.publish_notify(channel_name, meta)
        return meta

    def unpublish_last(self, channel_name: str) -> bool:
        """Drop the newest item from this channel's outgoing ring."""
        ring = self._get_ring(channel_name)
        popped = ring.pop_latest()
        if popped is None:
            return False
        self._transport.set_latest_seq(channel_name, ring.latest_seq())
        return True

    def unpublish(self, channel_name: str, seq: int) -> bool:
        """Drop a specific item from this channel's outgoing ring.

        Receivers see the removal the next time their poll-result merges
        with our ring (within ``poll_interval`` seconds in the worst case;
        usually sooner because our next ANNOUNCE carries a changed
        ``latest_seq`` and triggers an immediate catch-up poll if the
        removed item was the top of the ring).
        """
        ring = self._get_ring(channel_name)
        removed = ring.remove(seq)
        if removed is None:
            return False
        # Tell the transport the new top-of-ring so the next ANNOUNCE
        # reflects reality. If the ring is empty we advertise -1.
        self._transport.set_latest_seq(channel_name, ring.latest_seq())
        return True

    def my_published(self, channel_name: str) -> list[ItemMeta]:
        """Items this machine is currently publishing on ``channel_name``."""
        ring = self._get_ring(channel_name)
        items = ring.items()
        items.sort(key=lambda it: it.timestamp, reverse=True)
        return items

    # -- hide (local-only suppression of peer items) ----------------------

    def hide(self, channel_name: str, origin: str, seq: int) -> bool:
        """Hide a peer's item from this machine's 'Available' view.

        Local-only: the peer continues to publish it; other receivers still
        see it. Hiding our *own* item is rejected -- use ``unpublish`` for
        that, since hiding it locally while still broadcasting would be
        confusing.
        """
        if origin == self._settings.origin:
            return False
        with self._hidden_lock:
            self._hidden.setdefault(channel_name, set()).add((origin, seq))
        self._safe(self.on_catalog_changed, channel_name)
        return True

    def unhide(self, channel_name: str, origin: str, seq: int) -> bool:
        """Reverse :meth:`hide` for a specific item."""
        with self._hidden_lock:
            entries = self._hidden.get(channel_name)
            if not entries or (origin, seq) not in entries:
                return False
            entries.discard((origin, seq))
            if not entries:
                self._hidden.pop(channel_name, None)
        self._safe(self.on_catalog_changed, channel_name)
        return True

    def clear_hidden(self, channel_name: str) -> int:
        """Unhide every item on ``channel_name``; return the count cleared."""
        with self._hidden_lock:
            entries = self._hidden.pop(channel_name, None)
        count = len(entries) if entries else 0
        if count:
            self._safe(self.on_catalog_changed, channel_name)
        return count

    def hidden_items(self, channel_name: str) -> list[CatalogEntry]:
        """Catalog entries currently hidden on ``channel_name``.

        Returned so the UI can offer "Show hidden" / per-item unhide. Only
        entries we still have in the catalog are surfaced -- a stale hide
        whose underlying item is gone is silently ignored.
        """
        with self._hidden_lock:
            hidden = set(self._hidden.get(channel_name, ()))
        if not hidden:
            return []
        with self._catalog_lock:
            per_channel = self._catalog.get(channel_name, {})
            entries = [per_channel[key] for key in hidden if key in per_channel]
        entries.sort(key=lambda e: e.item.timestamp, reverse=True)
        return entries

    # -- pull ---------------------------------------------------------------

    def pull(self, channel_name: str, origin: str, seq: int) -> Optional[ItemMeta]:
        """Fetch an item from its publishing peer and copy onto the OS clipboard.

        Returns the :class:`ItemMeta` actually copied or ``None`` if the item
        could not be retrieved (peer gone, payload mismatched its hash, ...).
        """
        if not self.sync_enabled():
            return None
        with self._catalog_lock:
            entry = self._catalog.get(channel_name, {}).get((origin, seq))
        if entry is None:
            return None

        result = self._transport.fetch(entry.peer, seq)
        if result is None:
            return None
        meta, body = result

        # Integrity check: AEAD already verified the wire bytes, but the
        # claimed-by-the-publisher sha256 lets us cross-check that the menu
        # entry we showed and the bytes we are about to paste match.
        if hashlib.sha256(body).hexdigest() != meta.sha256:
            log.warning("sha256 mismatch on pulled item, dropping")
            return None

        try:
            self._clipboard.write(meta.content_type, body)
        except ClipboardError as exc:
            log.warning("clipboard write failed: %s", exc)
            return None

        # Per design decision #4: pulled items stay published. We do not
        # remove the catalog entry.
        return meta

    # -- queries the UI calls ----------------------------------------------

    def available_items(self, channel_name: str) -> list[CatalogEntry]:
        """Items on ``channel_name`` that this machine has not hidden."""
        with self._hidden_lock:
            hidden = set(self._hidden.get(channel_name, ()))
        with self._catalog_lock:
            per_channel = self._catalog.get(channel_name, {})
            if hidden:
                entries = [e for key, e in per_channel.items() if key not in hidden]
            else:
                entries = list(per_channel.values())
        # Newest first -- matches expected menu order.
        entries.sort(key=lambda e: e.item.timestamp, reverse=True)
        return entries

    def peers(self, channel_name: str) -> list[Peer]:
        return self._transport.peers(channel_name)

    # -- transport callbacks -----------------------------------------------

    def _on_announce(self, peer: Peer) -> None:
        # If this announce shows the peer's view of the world differs from
        # ours -- they have newer items (we need to catch up) OR they have a
        # lower latest_seq than ours (they unpublished; we need to drop the
        # stale entries) -- request a POLL via the worker thread.
        with self._catalog_lock:
            per_channel = self._catalog.get(peer.channel, {})
            known = max(
                (seq for (origin, seq) in per_channel if origin == peer.origin),
                default=-1,
            )
        if peer.latest_seq != known:
            self._enqueue_poll(peer)
        self._safe(self.on_peers_changed, peer.channel)

    def _on_peer_lost(self, peer: Peer) -> None:
        with self._catalog_lock:
            per_channel = self._catalog.get(peer.channel)
            if per_channel:
                for key in [k for k in per_channel if k[0] == peer.origin]:
                    per_channel.pop(key, None)
        self._safe(self.on_catalog_changed, peer.channel)
        self._safe(self.on_peers_changed, peer.channel)

    def _on_publish_notify(self, channel: str, item: ItemMeta, peer: Peer) -> None:
        # We may have an ANNOUNCE-derived peer with no TCP port yet; the
        # poll for catch-up will resolve that on the next ANNOUNCE.
        with self._catalog_lock:
            self._catalog.setdefault(channel, {})[(item.origin, item.seq)] = (
                CatalogEntry(channel=channel, item=item, peer=peer)
            )
        self._safe(self.on_catalog_changed, channel)

    def _on_poll(self, channel: str) -> list[ItemMeta]:
        """Peer asked what we are publishing on this channel."""
        ring = self._get_ring(channel) if channel in self._channels else None
        return ring.items() if ring else []

    def _on_poll_result(self, channel: str, items: list[ItemMeta], peer: Peer) -> None:
        """Peer told us their full ring buffer -- merge into the catalog."""
        kept = {it.seq for it in items}
        with self._catalog_lock:
            per_channel = self._catalog.setdefault(channel, {})
            # Drop stale entries from this origin that fell out of the peer's
            # ring (so unpublishes propagate naturally).
            for key in [k for k in per_channel
                        if k[0] == peer.origin and k[1] not in kept]:
                per_channel.pop(key, None)
            for it in items:
                per_channel[(it.origin, it.seq)] = CatalogEntry(
                    channel=channel, item=it, peer=peer,
                )
        self._safe(self.on_catalog_changed, channel)

    def _on_fetch(self, channel: str, seq: int):
        ring = self._get_ring(channel) if channel in self._channels else None
        if ring is None:
            return None
        entry = ring.get(seq)
        if entry is None:
            return None
        return entry.meta, entry.body

    def _on_fetch_result(self, channel, item, body, peer) -> None:
        # The pull() method handles the result inline; the standalone
        # callback path is only used if some future feature triggers a
        # fetch outside pull(). Left as a no-op deliberately.
        pass

    # -- poll worker + slow-poll safety net --------------------------------

    def _enqueue_poll(self, peer: Peer) -> None:
        """Queue a POLL request, deduping if one is already in flight.

        Multiple announces from the same peer arriving in quick succession
        (or an announce coincident with a slow-poll tick) would otherwise
        schedule the same TCP round-trip several times. The dedupe key is
        ``(channel, origin)`` -- the live :class:`Peer` is resolved by the
        worker at execution time, so it always uses the freshest endpoint.
        """
        key = (peer.channel, peer.origin)
        with self._poll_inflight_lock:
            if key in self._poll_inflight:
                return
            self._poll_inflight.add(key)
        self._poll_queue.put_nowait(key)

    def _poll_worker_loop(self) -> None:
        """Single thread that drains the poll queue.

        One persistent worker avoids the OS thread-creation churn of the
        previous "spawn a thread per poll" approach. POLLs are inherently
        serializable here: latency on a LAN is small, and the slow-poll
        cadence is on the order of seconds, so a single worker is plenty.
        """
        while not self._poll_stop.is_set():
            try:
                item = self._poll_queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if item is None:           # shutdown sentinel
                return
            channel_name, origin = item
            try:
                peer = self._find_peer(channel_name, origin)
                if peer is not None:
                    # Result merges into the catalog via on_poll_result.
                    self._transport.poll(peer)
            except Exception:
                log.exception("poll worker raised")
            finally:
                with self._poll_inflight_lock:
                    self._poll_inflight.discard(item)

    def _find_peer(self, channel_name: str, origin: str) -> Optional[Peer]:
        for peer in self._transport.peers(channel_name):
            if peer.origin == origin:
                return peer
        return None

    def _slow_poll_loop(self) -> None:
        """Periodic safety-net poll for every known peer.

        We deliberately do NOT skip based on ``latest_seq == known``: removing
        an item from the middle of the ring (a selective unpublish) leaves
        ``latest_seq`` unchanged, so the ANNOUNCE-driven catch-up cannot
        detect it. The slow poll is the convergence guarantee for that case.

        The cost is small -- on an idle network this is one short TCP
        round-trip per peer every ``poll_interval`` (default 10s), routed
        through the single poll-worker thread (no thread spawning).
        """
        interval = max(2.0, self._settings.poll_interval)
        while not self._poll_stop.wait(interval):
            for channel in self._channels.list_channels():
                for peer in self._transport.peers(channel.name):
                    self._enqueue_poll(peer)

    # -- helpers ------------------------------------------------------------

    def _get_ring(self, channel_name: str) -> _PublishRing:
        with self._rings_lock:
            ring = self._rings.get(channel_name)
            if ring is None:
                ring = _PublishRing(self._settings.ring_size)
                self._rings[channel_name] = ring
            return ring

    def _safe(self, fn, *args) -> None:
        try:
            fn(*args)
        except Exception:
            log.exception("daemon UI callback raised")


# ---------------------------------------------------------------------------
# CLI entry point. Useful for headless testing and as a sanity-check tool.
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the daemon headless: announce + serve, no UI."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    daemon = Daemon()
    daemon.start()
    log.info("clipsync daemon up: origin=%s channels=%s tcp_port=%d",
             daemon.origin_name, [c.name for c in daemon.list_channels()],
             daemon._transport.tcp_port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        daemon.stop()


if __name__ == "__main__":
    main()
