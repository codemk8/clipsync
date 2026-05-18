"""
clipsync.ui.menu_darwin
=======================

macOS menu bar app using ``rumps``.

Menu structure:

    ClipSync - #work
        Publish current clipboard
        Unpublish >
        --
        Available on #work >
        Hide peer item >
        --
        Channels >
            #work  (active) >
                Set as active
                View join string...
                Share via pairing...
                Leave channel
            #screenshots >
                ...
            --
            Create channel...
            Join from clipboard
            Receive via pairing...
        Sync: On
        Quit

rumps drives the AppKit event loop on the main thread. The daemon's callbacks
fire from network threads; we set a "dirty" flag from them and rebuild the
menu on a 2-second timer running on the main thread. That avoids any
cross-thread AppKit mutation.
"""

from __future__ import annotations

import logging
import time

import rumps
from rumps.rumps import SeparatorMenuItem  # not re-exported by rumps/__init__

from ..daemon import Daemon
from ..core.channels import ChannelError


log = logging.getLogger(__name__)


def _clear_submenu(item: rumps.MenuItem) -> None:
    """`rumps.MenuItem.clear()` calls `self._menu.removeAllItems()`, but
    `_menu` (the underlying NSMenu) is lazily created on first `add()` —
    so `.clear()` on a never-populated submenu raises AttributeError."""
    if getattr(item, "_menu", None) is not None:
        item.clear()


def _age(timestamp: float) -> str:
    """Compact 'how long ago' label for the menu."""
    delta = max(0, int(time.time() - timestamp))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


class ClipSyncApp(rumps.App):
    """The menu bar application."""

    def __init__(self, daemon: Daemon):
        super().__init__("ClipSync", title="📋", quit_button=None)
        self._daemon = daemon
        self._daemon.on_catalog_changed = self._mark_dirty
        self._daemon.on_peers_changed = self._mark_dirty

        # Active SEND channel (decision #8: single-select for send).
        chans = self._daemon.list_channels()
        self._active_channel: str | None = chans[0].name if chans else None

        # Stable references to the menu items we mutate. Dict-by-title
        # lookup is fragile once titles change at runtime.
        self._mi_publish = rumps.MenuItem("Publish current clipboard",
                                          callback=self._publish)
        # Submenu of my own published items -- click one to unpublish it.
        # Replaces the old single-click "Unpublish last" so the user can
        # remove arbitrary items, not just the newest.
        self._mi_unpublish = rumps.MenuItem("Unpublish")
        self._mi_available = rumps.MenuItem("Available on (no channel)")
        # Parallel submenu of peer items the user wants suppressed from the
        # local "Available" view. Local-only -- does not affect peers.
        self._mi_hide = rumps.MenuItem("Hide peer item")
        # Single "Channels" submenu: each channel becomes its own sub-submenu
        # with Set-as-active / View join string / Leave. Replaces the old
        # text-command "Manage channels..." window.
        self._mi_channels = rumps.MenuItem("Channels")
        self._mi_sync = rumps.MenuItem("Sync: On", callback=self._toggle_sync)
        self._mi_quit = rumps.MenuItem("Quit", callback=self._quit)

        # Hold references to the separators so we can hide them along with
        # their adjacent channel-dependent items when no channel is joined.
        # Without that, leaving the last channel leaves two empty separators
        # bracketing a row of greyed-out submenus, which reads as broken.
        self._sep_after_unpublish = SeparatorMenuItem()
        self._sep_after_hide = SeparatorMenuItem()
        self._sep_before_quit = SeparatorMenuItem()

        self.menu = [
            self._mi_publish,
            self._mi_unpublish,
            self._sep_after_unpublish,
            self._mi_available,
            self._mi_hide,
            self._sep_after_hide,
            self._mi_channels,
            self._mi_sync,
            self._sep_before_quit,
            self._mi_quit,
        ]

        self._dirty = True
        # Track the youngest item timestamp on screen so we only rebuild for
        # age changes when there is actually a young item whose label would
        # shift ("12s ago" -> "13s ago"). Old items ("3m ago") roll over much
        # less often and do not justify per-tick rebuilds.
        self._youngest_shown: float = 0.0

        # Pairing state. Set by daemon callbacks on background threads,
        # consumed by the tick handler on the AppKit main thread (rumps
        # modals are all main-thread-only).
        self._pairing_active: str | None = None   # "share" | "receive" | None
        self._pairing_label: str = ""              # e.g. "#work" for share
        self._pairing_peers_ready: bool = False
        self._pairing_peer_picked: bool = False
        self._pairing_pick_min_at: float = 0.0     # earliest time to pop picker
        self._pairing_pick_max_at: float = 0.0     # latest -- pop even if empty
        self._pending_sas: tuple[str, str] | None = None
        self._pending_result: tuple[str, str] | None = None
        self._daemon.on_pairing_peers_changed = self._on_pairing_peers
        self._daemon.on_pairing_sas_ready = self._on_pairing_sas_ready
        self._daemon.on_pairing_paired = self._on_pairing_paired
        self._daemon.on_pairing_failed = self._on_pairing_failed

        self._refresh()
        # 2s tick. The handler is cheap when nothing has changed -- it just
        # checks two flags and returns -- so this is fine to leave running.
        rumps.Timer(self._tick, 2.0).start()

    # -- dirty flag from daemon callbacks ----------------------------------

    def _mark_dirty(self, _channel: str) -> None:
        self._dirty = True

    def _tick(self, _timer) -> None:
        # Drain pairing-UI events first. Each rumps.alert / rumps.Window is
        # modal and consumes a tick; we get the next one back on the next
        # 2s firing. Order matters: surface the final result, then the SAS
        # prompt, then the peer picker. Background-thread callbacks never
        # touch rumps directly -- they only set the flags this loop reads.
        if self._pending_result is not None:
            title, body = self._pending_result
            self._pending_result = None
            rumps.notification("ClipSync", title, body)
            self._dirty = True
        if self._pending_sas is not None:
            sas, who = self._pending_sas
            self._pending_sas = None
            choice = rumps.alert(
                "Verify pairing code",
                f"Code: {sas}\n\nPeer: {who}\n\n"
                "Confirm only if BOTH screens show this exact code.",
                ok="Confirm",
                cancel="Reject",
            )
            if choice == 1:
                self._daemon.confirm_pairing()
            else:
                self._daemon.reject_pairing()
            self._dirty = True
        if (self._pairing_active == "receive"
                and not self._pairing_peer_picked):
            now = time.monotonic()
            if now >= self._pairing_pick_max_at or (
                now >= self._pairing_pick_min_at and self._pairing_peers_ready
            ):
                self._show_peer_picker()

        # Refresh only when the data changed or an item's age label would
        # actually move. Items older than ~60s only roll over once per minute,
        # so on an idle daemon this collapses to a no-op.
        if self._dirty or self._needs_age_refresh():
            self._refresh()

    def _needs_age_refresh(self) -> bool:
        if self._youngest_shown == 0.0:
            return False
        return (time.time() - self._youngest_shown) < 60.0

    # -- redraw -------------------------------------------------------------

    def _refresh(self) -> None:
        active = self._active_channel
        self.title = f"📋 #{active}" if active else "📋"

        # When no channel is joined, the channel-dependent surfaces (Publish,
        # Unpublish, Available, Hide) have nothing to act on. NSMenu would
        # auto-grey their submenu containers because their only children are
        # disabled placeholders -- so the menu reads as "everything broken".
        # Hide the whole top section instead; the user is left with the path
        # forward (Channels >) and the system controls (Sync, Quit).
        has_channel = active is not None
        for item in (self._mi_publish, self._mi_unpublish,
                     self._sep_after_unpublish,
                     self._mi_available, self._mi_hide,
                     self._sep_after_hide):
            self._set_hidden(item, not has_channel)

        if has_channel:
            youngest_avail = self._rebuild_available(active)
            youngest_mine = self._rebuild_unpublish(active)
            self._rebuild_hide(active)
        else:
            youngest_avail = 0.0
            youngest_mine = 0.0
        self._rebuild_channels(active)
        self._mi_sync.title = "Sync: On" if self._daemon.sync_enabled() else "Sync: Off"
        # We only need the youngest across both visible lists, since both
        # surfaces show "Ns ago" labels that need to tick along.
        self._youngest_shown = max(youngest_avail, youngest_mine)
        self._dirty = False

    @staticmethod
    def _set_hidden(item, value: bool) -> None:
        """Toggle hidden state on a MenuItem or SeparatorMenuItem. Separators
        don't expose ``.hidden`` in rumps, so we reach for the underlying
        NSMenuItem in that case."""
        if hasattr(item, "hidden"):
            item.hidden = value
        else:
            item._menuitem.setHidden_(value)

    def _rebuild_available(self, active: str | None) -> float:
        """Rebuild the Available submenu; return the youngest timestamp shown."""
        _clear_submenu(self._mi_available)
        if active is None:
            self._mi_available.title = "Available on (no channel)"
            placeholder = rumps.MenuItem("(no channel joined)")
            placeholder.set_callback(None)
            self._mi_available.add(placeholder)
            return 0.0

        self._mi_available.title = f"Available on #{active}"
        entries = self._daemon.available_items(active)
        if not entries:
            placeholder = rumps.MenuItem("(no items)")
            placeholder.set_callback(None)
            self._mi_available.add(placeholder)
            return 0.0

        youngest = 0.0
        for entry in entries:
            meta = entry.item
            label = f"{meta.preview} - {entry.peer.origin_name} - {_age(meta.timestamp)}"
            item = rumps.MenuItem(label)
            item.set_callback(
                lambda _it, ch=active, org=meta.origin, sq=meta.seq:
                self._pull(ch, org, sq)
            )
            self._mi_available.add(item)
            if meta.timestamp > youngest:
                youngest = meta.timestamp
        return youngest

    def _rebuild_unpublish(self, active: str | None) -> float:
        """Rebuild the 'Unpublish' submenu listing my own published items."""
        _clear_submenu(self._mi_unpublish)
        if active is None:
            self._mi_unpublish.title = "Unpublish"
            placeholder = rumps.MenuItem("(no channel joined)")
            placeholder.set_callback(None)
            self._mi_unpublish.add(placeholder)
            return 0.0

        mine = self._daemon.my_published(active)
        if not mine:
            self._mi_unpublish.title = "Unpublish"
            placeholder = rumps.MenuItem("(nothing published)")
            placeholder.set_callback(None)
            self._mi_unpublish.add(placeholder)
            return 0.0

        self._mi_unpublish.title = f"Unpublish from #{active}"
        youngest = 0.0
        for meta in mine:
            label = f"{meta.preview} - {_age(meta.timestamp)}"
            item = rumps.MenuItem(label)
            item.set_callback(
                lambda _it, ch=active, sq=meta.seq: self._unpublish_one(ch, sq)
            )
            self._mi_unpublish.add(item)
            if meta.timestamp > youngest:
                youngest = meta.timestamp
        return youngest

    def _rebuild_hide(self, active: str | None) -> None:
        """Rebuild the 'Hide peer item' submenu (local-only suppression)."""
        _clear_submenu(self._mi_hide)
        if active is None:
            self._mi_hide.title = "Hide peer item"
            placeholder = rumps.MenuItem("(no channel joined)")
            placeholder.set_callback(None)
            self._mi_hide.add(placeholder)
            return

        # Show only peer items (filter out mine; you unpublish your own).
        my_origin = self._daemon.origin
        peer_entries = [e for e in self._daemon.available_items(active)
                        if e.item.origin != my_origin]
        hidden = self._daemon.hidden_items(active)

        if not peer_entries and not hidden:
            self._mi_hide.title = "Hide peer item"
            placeholder = rumps.MenuItem("(no peer items)")
            placeholder.set_callback(None)
            self._mi_hide.add(placeholder)
            return

        self._mi_hide.title = f"Hide / Unhide on #{active}"
        for entry in peer_entries:
            meta = entry.item
            label = (f"Hide: {meta.preview} - {entry.peer.origin_name} - "
                     f"{_age(meta.timestamp)}")
            item = rumps.MenuItem(label)
            item.set_callback(
                lambda _it, ch=active, org=meta.origin, sq=meta.seq:
                self._hide_one(ch, org, sq)
            )
            self._mi_hide.add(item)
        # Currently-hidden items get an unhide action below the live ones.
        if hidden:
            sep = rumps.MenuItem("--- hidden ---")
            sep.set_callback(None)
            self._mi_hide.add(sep)
            for entry in hidden:
                meta = entry.item
                label = f"Unhide: {meta.preview} - {entry.peer.origin_name}"
                item = rumps.MenuItem(label)
                item.set_callback(
                    lambda _it, ch=active, org=meta.origin, sq=meta.seq:
                    self._unhide_one(ch, org, sq)
                )
                self._mi_hide.add(item)

    def _rebuild_channels(self, active: str | None) -> None:
        """Rebuild the Channels submenu.

        Structure:
            Channels
                #work  (active)
                    Set as active
                    View join string...
                    Leave channel
                #screenshots
                    ...
                ---
                Create channel...
                Join from clipboard
        """
        _clear_submenu(self._mi_channels)
        channels = self._daemon.list_channels()
        self._mi_channels.title = "Channels"

        for ch in channels:
            label = f"#{ch.name}" + ("  (active)" if ch.name == active else "")
            ch_submenu = rumps.MenuItem(label)

            set_active = rumps.MenuItem("Set as active")
            # Already-active is a no-op; greying out keeps the menu honest.
            if ch.name == active:
                set_active.set_callback(None)
            else:
                set_active.set_callback(
                    lambda _it, name=ch.name: self._switch_channel(name)
                )
            ch_submenu.add(set_active)

            view = rumps.MenuItem("View join string…")
            view.set_callback(
                lambda _it, name=ch.name: self._view_join_string(name)
            )
            ch_submenu.add(view)

            share = rumps.MenuItem("Share via pairing…")
            share.set_callback(
                lambda _it, name=ch.name: self._share_via_pairing(name)
            )
            ch_submenu.add(share)

            leave = rumps.MenuItem("Leave channel")
            leave.set_callback(
                lambda _it, name=ch.name: self._leave_channel_confirm(name)
            )
            ch_submenu.add(leave)

            self._mi_channels.add(ch_submenu)

        # Separator only meaningful when there are channels above the bottom
        # actions; otherwise it floats at the top of an empty menu.
        if channels:
            self._mi_channels.add(rumps.separator)

        create = rumps.MenuItem("Create channel…",
                                callback=self._create_channel_prompt)
        self._mi_channels.add(create)

        join = rumps.MenuItem("Join from clipboard",
                              callback=self._join_from_clipboard)
        self._mi_channels.add(join)

        receive = rumps.MenuItem("Receive via pairing…",
                                 callback=self._receive_via_pairing)
        self._mi_channels.add(receive)

    # -- actions ------------------------------------------------------------

    def _publish(self, _item) -> None:
        if self._active_channel is None:
            rumps.alert("No channel", "Create or join a channel first.")
            return
        meta = self._daemon.publish_current(self._active_channel)
        if meta is None:
            rumps.notification(
                "ClipSync", "Publish failed",
                "Clipboard empty, too large, or sync is paused.",
            )
        self._refresh()

    def _unpublish_one(self, channel: str, seq: int) -> None:
        self._daemon.unpublish(channel, seq)
        self._refresh()

    def _hide_one(self, channel: str, origin: str, seq: int) -> None:
        self._daemon.hide(channel, origin, seq)
        self._refresh()

    def _unhide_one(self, channel: str, origin: str, seq: int) -> None:
        self._daemon.unhide(channel, origin, seq)
        self._refresh()

    def _pull(self, channel: str, origin: str, seq: int) -> None:
        meta = self._daemon.pull(channel, origin, seq)
        if meta is None:
            rumps.notification("ClipSync", "Pull failed",
                               "Peer unreachable or item gone.")
        else:
            rumps.notification("ClipSync", f"Pulled from #{channel}", meta.preview)
        self._refresh()

    def _switch_channel(self, name: str) -> None:
        self._active_channel = name
        self._refresh()

    def _toggle_sync(self, _item) -> None:
        self._daemon.set_sync_enabled(not self._daemon.sync_enabled())
        self._refresh()

    def _create_channel_prompt(self, _item) -> None:
        """Single-field prompt for a channel name. On OK: create + show + copy
        the join string. Auto-copying means the user can paste it into chat
        with no extra step."""
        window = rumps.Window(
            title="Create channel",
            message="Channel name (e.g. 'work', 'screenshots'):",
            default_text="",
            ok="Create",
            cancel="Cancel",
            dimensions=(320, 22),
        )
        response = window.run()
        if not response.clicked:
            return
        name = response.text.strip()
        if not name:
            return
        try:
            channel = self._daemon.create_channel(name)
        except ChannelError as exc:
            rumps.alert("Could not create channel", str(exc))
            return
        if self._active_channel is None:
            self._active_channel = channel.name
        self._show_and_copy_join_string(channel)
        self._refresh()

    def _view_join_string(self, channel_name: str) -> None:
        ch = next(
            (c for c in self._daemon.list_channels() if c.name == channel_name),
            None,
        )
        if ch is None:
            rumps.alert("Channel not found", channel_name)
            return
        self._show_and_copy_join_string(ch)

    def _show_and_copy_join_string(self, channel) -> None:
        join_string = channel.to_join_string()
        try:
            self._daemon.copy_text_to_clipboard(join_string)
            copied = True
        except Exception:
            copied = False
        footer = "\n\n(Copied to clipboard.)" if copied else ""
        rumps.alert(
            f"Join string for #{channel.name}",
            f"{join_string}{footer}",
        )

    def _join_from_clipboard(self, _item) -> None:
        text = self._daemon.read_clipboard_text()
        if not text or "clipsync://" not in text:
            rumps.notification(
                "ClipSync", "Nothing to join",
                "Copy a clipsync:// join string first, then try again.",
            )
            return
        # Trim surrounding whitespace, in case the user copied a line with
        # leading/trailing spaces or a trailing newline.
        try:
            channel = self._daemon.join_channel(text.strip())
        except ChannelError as exc:
            rumps.alert("Could not join channel", str(exc))
            return
        if self._active_channel is None:
            self._active_channel = channel.name
        rumps.notification("ClipSync", f"Joined #{channel.name}", "")
        self._refresh()

    def _leave_channel_confirm(self, channel_name: str) -> None:
        # rumps.alert returns 1 for OK, 0 for cancel.
        choice = rumps.alert(
            f"Leave #{channel_name}?",
            "This removes the channel and its secret from this machine. "
            "Other members are unaffected; you can rejoin later with the "
            "channel's join string.",
            ok="Leave",
            cancel="Cancel",
        )
        if choice != 1:
            return
        try:
            self._daemon.leave_channel(channel_name)
        except ChannelError as exc:
            rumps.alert("Could not leave channel", str(exc))
            return
        if self._active_channel == channel_name:
            chans = self._daemon.list_channels()
            self._active_channel = chans[0].name if chans else None
        self._refresh()

    # -- pairing flow -------------------------------------------------------

    def _share_via_pairing(self, channel_name: str) -> None:
        try:
            self._daemon.start_pairing_share(channel_name)
        except (ChannelError, RuntimeError) as exc:
            rumps.alert("Could not start pairing", str(exc))
            return
        self._pairing_active = "share"
        self._pairing_label = f"#{channel_name}"
        self._pairing_peer_picked = False
        self._pairing_peers_ready = False
        rumps.notification(
            "ClipSync", f"Sharing {self._pairing_label} via pairing",
            "Waiting for a nearby device to connect…",
        )

    def _receive_via_pairing(self, _item) -> None:
        try:
            self._daemon.start_pairing_receive()
        except RuntimeError as exc:
            rumps.alert("Could not start pairing", str(exc))
            return
        self._pairing_active = "receive"
        self._pairing_label = ""
        self._pairing_peers_ready = False
        self._pairing_peer_picked = False
        now = time.monotonic()
        # Give discovery a short grace period so a slow second peer still
        # has a chance to appear before the user is prompted. Force-pop the
        # picker after the upper bound regardless, so a no-peers situation
        # surfaces clearly instead of hanging silently.
        self._pairing_pick_min_at = now + 3.0
        self._pairing_pick_max_at = now + 8.0
        rumps.notification(
            "ClipSync", "Receive via pairing",
            "Looking for nearby ClipSync devices…",
        )

    def _show_peer_picker(self) -> None:
        peers = self._daemon.pairing_peers()
        self._pairing_peer_picked = True   # block re-popping during the modal
        if not peers:
            rumps.alert(
                "No devices found",
                "No nearby ClipSync devices were advertising a pairing "
                "session. Start 'Share via pairing…' on the other machine "
                "and try again.",
            )
            self._daemon.cancel_pairing()
            self._pairing_active = None
            return
        lines = "\n".join(
            f"  {i + 1}. {p.display} — {p.label}"
            for i, p in enumerate(peers)
        )
        window = rumps.Window(
            title="Pair with nearby device",
            message=(
                f"Available devices:\n{lines}\n\n"
                "Enter the number to pair with:"
            ),
            default_text="1",
            ok="Pair",
            cancel="Cancel",
            dimensions=(60, 22),
        )
        response = window.run()
        if not response.clicked:
            self._daemon.cancel_pairing()
            self._pairing_active = None
            return
        try:
            idx = int(response.text.strip()) - 1
            if idx < 0 or idx >= len(peers):
                raise ValueError
        except ValueError:
            rumps.alert("Invalid choice", "Pairing cancelled.")
            self._daemon.cancel_pairing()
            self._pairing_active = None
            return
        self._daemon.pick_pairing_peer(peers[idx].peer_id)

    # Background-thread callbacks: set flags only. Tick consumes them.

    def _on_pairing_peers(self, peers) -> None:
        if peers:
            self._pairing_peers_ready = True

    def _on_pairing_sas_ready(self, sas: str, peer_display: str) -> None:
        self._pending_sas = (sas, peer_display)

    def _on_pairing_paired(self, channel) -> None:
        if self._pairing_active == "share":
            self._pending_result = (
                "Pairing complete",
                f"{self._pairing_label} shared via pairing.",
            )
        else:
            name = channel.name if channel is not None else "?"
            self._pending_result = (
                "Pairing complete",
                f"Joined #{name} via pairing.",
            )
        self._pairing_active = None
        self._pairing_label = ""

    def _on_pairing_failed(self, reason: str) -> None:
        self._pending_result = ("Pairing failed", reason)
        self._pairing_active = None
        self._pairing_label = ""

    def _quit(self, _item) -> None:
        self._daemon.stop()
        rumps.quit_application()


def run() -> None:
    """Entry point for the macOS app."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    daemon = Daemon()
    daemon.start()
    try:
        ClipSyncApp(daemon).run()
    finally:
        daemon.stop()


if __name__ == "__main__":
    run()
