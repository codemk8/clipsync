"""
clipsync.ui.menu_darwin
=======================

macOS menu bar app using ``rumps``.

Menu structure (per PROJECT_STATUS.md item 6):

    ClipSync - #work
        Publish current clipboard
        Unpublish last
        --
        Available on #work
            image - 248 KB - mac-studio - 12s ago     [click = pull]
            text - "Q3 roadmap dr..." - thinkpad - 3m ago
        --
        Channel
            #work  (active)
            #screenshots
        Sync: On
        Manage channels...
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

from ..daemon import Daemon
from ..core.channels import ChannelError


log = logging.getLogger(__name__)


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
        self._mi_channel = rumps.MenuItem("Channel")
        self._mi_sync = rumps.MenuItem("Sync: On", callback=self._toggle_sync)
        self._mi_manage = rumps.MenuItem("Manage channels...",
                                         callback=self._manage_channels)
        self._mi_quit = rumps.MenuItem("Quit", callback=self._quit)

        self.menu = [
            self._mi_publish,
            self._mi_unpublish,
            None,
            self._mi_available,
            self._mi_hide,
            None,
            self._mi_channel,
            self._mi_sync,
            self._mi_manage,
            None,
            self._mi_quit,
        ]

        self._dirty = True
        # Track the youngest item timestamp on screen so we only rebuild for
        # age changes when there is actually a young item whose label would
        # shift ("12s ago" -> "13s ago"). Old items ("3m ago") roll over much
        # less often and do not justify per-tick rebuilds.
        self._youngest_shown: float = 0.0
        self._refresh()
        # 2s tick. The handler is cheap when nothing has changed -- it just
        # checks two flags and returns -- so this is fine to leave running.
        rumps.Timer(self._tick, 2.0).start()

    # -- dirty flag from daemon callbacks ----------------------------------

    def _mark_dirty(self, _channel: str) -> None:
        self._dirty = True

    def _tick(self, _timer) -> None:
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

        youngest_avail = self._rebuild_available(active)
        youngest_mine = self._rebuild_unpublish(active)
        self._rebuild_hide(active)
        self._rebuild_channels(active)
        self._mi_sync.title = "Sync: On" if self._daemon.sync_enabled() else "Sync: Off"
        # We only need the youngest across both visible lists, since both
        # surfaces show "Ns ago" labels that need to tick along.
        self._youngest_shown = max(youngest_avail, youngest_mine)
        self._dirty = False

    def _rebuild_available(self, active: str | None) -> float:
        """Rebuild the Available submenu; return the youngest timestamp shown."""
        self._mi_available.clear()
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
        self._mi_unpublish.clear()
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
        self._mi_hide.clear()
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
        self._mi_channel.clear()
        channels = self._daemon.list_channels()
        if not channels:
            self._mi_channel.title = "Channel: (none joined)"
            placeholder = rumps.MenuItem("Join one via 'Manage channels...'")
            placeholder.set_callback(None)
            self._mi_channel.add(placeholder)
            return

        self._mi_channel.title = f"Channel: #{active}" if active else "Channel"
        for ch in channels:
            label = f"#{ch.name}" + ("  (active)" if ch.name == active else "")
            item = rumps.MenuItem(label)
            item.set_callback(
                lambda _it, name=ch.name: self._switch_channel(name)
            )
            self._mi_channel.add(item)

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

    def _manage_channels(self, _item) -> None:
        """Minimal modal for create / join / show / leave.

        rumps does not offer a rich dialog; this is a single text-line
        command surface ("c <name>", "j <join-string>", "s <name>", "l <name>").
        Enough to drive the daemon end-to-end on macOS.
        """
        window = rumps.Window(
            title="Manage channels",
            message=(
                "  c <name>          - create a channel\n"
                "  j <join-string>   - join via clipsync:// string\n"
                "  s <name>          - show the join string\n"
                "  l <name>          - leave a channel"
            ),
            default_text="",
            ok="Run",
            cancel="Done",
            dimensions=(420, 120),
        )
        while True:
            response = window.run()
            if not response.clicked:
                break
            self._handle_manage(response.text.strip())
            self._refresh()

    def _handle_manage(self, line: str) -> None:
        if not line:
            return
        op, _, rest = line.partition(" ")
        op = op.lower()
        rest = rest.strip()
        try:
            if op == "c":
                ch = self._daemon.create_channel(rest)
                if self._active_channel is None:
                    self._active_channel = ch.name
                rumps.alert("Channel created",
                            f"#{ch.name}\n\nJoin string:\n{ch.to_join_string()}")
            elif op == "j":
                ch = self._daemon.join_channel(rest)
                if self._active_channel is None:
                    self._active_channel = ch.name
                rumps.alert("Joined", f"#{ch.name}")
            elif op == "s":
                ch = next(
                    (c for c in self._daemon.list_channels() if c.name == rest),
                    None,
                )
                if ch is None:
                    rumps.alert("Unknown channel", rest)
                else:
                    rumps.alert(f"Join string for #{ch.name}", ch.to_join_string())
            elif op == "l":
                self._daemon.leave_channel(rest)
                if self._active_channel == rest:
                    chans = self._daemon.list_channels()
                    self._active_channel = chans[0].name if chans else None
            else:
                rumps.alert("Unknown command",
                            "Use c / j / s / l followed by a name or join string.")
        except ChannelError as exc:
            rumps.alert("ClipSync error", str(exc))

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
