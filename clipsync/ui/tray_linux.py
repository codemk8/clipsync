"""
clipsync.ui.tray_linux
======================

Linux system tray app using PySide6.

Menu structure mirrors the macOS app -- see PROJECT_STATUS.md item 6 for the
agreed layout. Qt handles nested submenus and dynamic rebuilding well; we
rebuild on a 2-second QTimer so "12s ago" labels stay current and any change
flagged by daemon callbacks is picked up shortly after.

Threading: daemon callbacks fire from network threads. Qt requires UI
mutations on the main (GUI) thread, so we marshal them in via a
``QTimer.singleShot`` queued to the main event loop.
"""

from __future__ import annotations

import logging
import sys
import time

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QAction, QIcon, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QInputDialog,
    QMenu,
    QMessageBox,
    QSystemTrayIcon,
)

from ..daemon import Daemon
from ..core.channels import ChannelError


log = logging.getLogger(__name__)


def _age(timestamp: float) -> str:
    delta = max(0, int(time.time() - timestamp))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def _placeholder_icon() -> QIcon:
    """Solid-color square icon. The real app would ship a proper asset."""
    pix = QPixmap(22, 22)
    pix.fill(Qt.GlobalColor.darkCyan)
    return QIcon(pix)


class ClipSyncTray(QSystemTrayIcon):
    """The system tray application."""

    def __init__(self, daemon: Daemon, app: QApplication):
        super().__init__(_placeholder_icon(), parent=app)
        self._daemon = daemon
        self._app = app
        chans = self._daemon.list_channels()
        self._active_channel: str | None = chans[0].name if chans else None

        self._menu = QMenu()
        self.setContextMenu(self._menu)
        self.setToolTip("ClipSync")
        self.setVisible(True)

        # Dirty flag set by daemon callbacks (from network threads). The tick
        # consults it on the Qt main thread so we never mutate Qt widgets
        # off-thread, and we avoid rebuilding the menu on every tick.
        self._dirty = True
        self._youngest_shown: float = 0.0
        self._daemon.on_catalog_changed = self._mark_dirty
        self._daemon.on_peers_changed = self._mark_dirty

        self._tick_timer = QTimer(self)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start(2000)

        self._refresh()

    def _mark_dirty(self, _channel: str) -> None:
        self._dirty = True

    def _tick(self) -> None:
        # Rebuild only when data changed or a young item's "12s ago" label
        # would actually move. On an idle daemon this becomes a no-op.
        if self._dirty or (
            self._youngest_shown != 0.0
            and (time.time() - self._youngest_shown) < 60.0
        ):
            self._refresh()

    # -- redraw -------------------------------------------------------------

    def _refresh(self) -> None:
        active = self._active_channel
        self.setToolTip(f"ClipSync #{active}" if active else "ClipSync")
        youngest = 0.0

        self._menu.clear()

        publish = QAction("Publish current clipboard", self._menu)
        publish.triggered.connect(self._publish)
        publish.setEnabled(active is not None and self._daemon.sync_enabled())
        self._menu.addAction(publish)

        # Unpublish submenu: my own items, click removes from the ring.
        if active is None:
            unpub_menu = self._menu.addMenu("Unpublish")
            placeholder = unpub_menu.addAction("(no channel joined)")
            placeholder.setEnabled(False)
        else:
            mine = self._daemon.my_published(active)
            if not mine:
                unpub_menu = self._menu.addMenu("Unpublish")
                placeholder = unpub_menu.addAction("(nothing published)")
                placeholder.setEnabled(False)
            else:
                unpub_menu = self._menu.addMenu(f"Unpublish from #{active}")
                for meta in mine:
                    label = f"{meta.preview} - {_age(meta.timestamp)}"
                    act = unpub_menu.addAction(label)
                    act.triggered.connect(
                        lambda _checked=False, ch=active, sq=meta.seq:
                        self._unpublish_one(ch, sq)
                    )
                    if meta.timestamp > youngest:
                        youngest = meta.timestamp

        self._menu.addSeparator()

        # Available items submenu.
        if active is None:
            avail = self._menu.addMenu("Available on (no channel)")
            placeholder = avail.addAction("(no channel joined)")
            placeholder.setEnabled(False)
        else:
            avail = self._menu.addMenu(f"Available on #{active}")
            entries = self._daemon.available_items(active)
            if not entries:
                placeholder = avail.addAction("(no items)")
                placeholder.setEnabled(False)
            for entry in entries:
                meta = entry.item
                label = (f"{meta.preview} - {entry.peer.origin_name} - "
                         f"{_age(meta.timestamp)}")
                action = avail.addAction(label)
                action.triggered.connect(
                    lambda _checked=False, ch=active, org=meta.origin, sq=meta.seq:
                    self._pull(ch, org, sq)
                )
                if meta.timestamp > youngest:
                    youngest = meta.timestamp

        # Hide submenu: peer items the user wants suppressed locally.
        if active is not None:
            my_origin = self._daemon.origin
            peer_entries = [e for e in self._daemon.available_items(active)
                            if e.item.origin != my_origin]
            hidden = self._daemon.hidden_items(active)
            if peer_entries or hidden:
                hide_menu = self._menu.addMenu(f"Hide / Unhide on #{active}")
                for entry in peer_entries:
                    meta = entry.item
                    label = (f"Hide: {meta.preview} - {entry.peer.origin_name} "
                             f"- {_age(meta.timestamp)}")
                    act = hide_menu.addAction(label)
                    act.triggered.connect(
                        lambda _checked=False, ch=active, org=meta.origin, sq=meta.seq:
                        self._hide_one(ch, org, sq)
                    )
                if hidden:
                    hide_menu.addSeparator()
                    for entry in hidden:
                        meta = entry.item
                        label = f"Unhide: {meta.preview} - {entry.peer.origin_name}"
                        act = hide_menu.addAction(label)
                        act.triggered.connect(
                            lambda _checked=False, ch=active, org=meta.origin, sq=meta.seq:
                            self._unhide_one(ch, org, sq)
                        )

        self._menu.addSeparator()

        # Active-channel submenu.
        channels = self._daemon.list_channels()
        if not channels:
            chan_menu = self._menu.addMenu("Channel: (none joined)")
            placeholder = chan_menu.addAction("Join via 'Manage channels...'")
            placeholder.setEnabled(False)
        else:
            chan_menu = self._menu.addMenu(
                f"Channel: #{active}" if active else "Channel"
            )
            for ch in channels:
                label = f"#{ch.name}" + ("  (active)" if ch.name == active else "")
                action = chan_menu.addAction(label)
                action.triggered.connect(
                    lambda _checked=False, name=ch.name: self._switch_channel(name)
                )

        sync_label = "Sync: On" if self._daemon.sync_enabled() else "Sync: Off"
        sync_action = QAction(sync_label, self._menu)
        sync_action.triggered.connect(self._toggle_sync)
        self._menu.addAction(sync_action)

        manage = QAction("Manage channels...", self._menu)
        manage.triggered.connect(self._manage_channels)
        self._menu.addAction(manage)

        self._menu.addSeparator()
        quit_action = QAction("Quit", self._menu)
        quit_action.triggered.connect(self._quit)
        self._menu.addAction(quit_action)

        self._youngest_shown = youngest
        self._dirty = False

    # -- actions ------------------------------------------------------------

    def _publish(self) -> None:
        if self._active_channel is None:
            return
        meta = self._daemon.publish_current(self._active_channel)
        if meta is None:
            self.showMessage(
                "ClipSync", "Publish failed: clipboard empty, too large, or sync paused.",
                QSystemTrayIcon.MessageIcon.Warning, 3000,
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
            self.showMessage(
                "ClipSync", "Pull failed: peer unreachable or item gone.",
                QSystemTrayIcon.MessageIcon.Warning, 3000,
            )
        else:
            self.showMessage(
                "ClipSync", f"Pulled from #{channel}: {meta.preview}",
                QSystemTrayIcon.MessageIcon.Information, 2500,
            )
        self._refresh()

    def _switch_channel(self, name: str) -> None:
        self._active_channel = name
        self._refresh()

    def _toggle_sync(self) -> None:
        self._daemon.set_sync_enabled(not self._daemon.sync_enabled())
        self._refresh()

    # -- channel management -------------------------------------------------

    def _manage_channels(self) -> None:
        options = ["Create channel", "Join via clipsync:// string",
                   "Show join string", "Leave channel", "Cancel"]
        choice, ok = QInputDialog.getItem(
            None, "ClipSync - Manage channels", "Action:",
            options, 0, False,
        )
        if not ok or choice == "Cancel":
            return

        try:
            if choice == "Create channel":
                name, ok = QInputDialog.getText(None, "Create channel", "Name:")
                if ok and name.strip():
                    ch = self._daemon.create_channel(name.strip())
                    if self._active_channel is None:
                        self._active_channel = ch.name
                    self._show_join_string(ch)
            elif choice == "Join via clipsync:// string":
                text, ok = QInputDialog.getText(
                    None, "Join channel", "Paste clipsync:// join string:",
                )
                if ok and text.strip():
                    ch = self._daemon.join_channel(text.strip())
                    if self._active_channel is None:
                        self._active_channel = ch.name
                    QMessageBox.information(None, "Joined", f"#{ch.name}")
            elif choice == "Show join string":
                channels = self._daemon.list_channels()
                if not channels:
                    QMessageBox.warning(None, "No channels", "No channels joined.")
                else:
                    names = [c.name for c in channels]
                    name, ok = QInputDialog.getItem(
                        None, "Show join string", "Channel:", names, 0, False,
                    )
                    if ok:
                        ch = next(c for c in channels if c.name == name)
                        self._show_join_string(ch)
            elif choice == "Leave channel":
                channels = self._daemon.list_channels()
                if not channels:
                    return
                names = [c.name for c in channels]
                name, ok = QInputDialog.getItem(
                    None, "Leave channel", "Channel:", names, 0, False,
                )
                if ok:
                    self._daemon.leave_channel(name)
                    if self._active_channel == name:
                        chans = self._daemon.list_channels()
                        self._active_channel = chans[0].name if chans else None
        except ChannelError as exc:
            QMessageBox.critical(None, "ClipSync error", str(exc))

        self._refresh()

    def _show_join_string(self, ch) -> None:
        QMessageBox.information(
            None,
            f"Join string for #{ch.name}",
            f"Share this with the other machine (out-of-band):\n\n{ch.to_join_string()}",
        )

    # -- shutdown -----------------------------------------------------------

    def _quit(self) -> None:
        self._daemon.stop()
        self._app.quit()


def run() -> None:
    """Entry point for the Linux app."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app = QApplication(sys.argv)
    # Tray-only app: do not exit when the (non-existent) last window closes.
    app.setQuitOnLastWindowClosed(False)
    daemon = Daemon()
    daemon.start()
    try:
        tray = ClipSyncTray(daemon, app)  # noqa: F841 -- holds the tray icon
        sys.exit(app.exec())
    finally:
        daemon.stop()


if __name__ == "__main__":
    run()
