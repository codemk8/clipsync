"""
clipsync.ui.tray_linux
======================

Linux system tray app using PySide6.

Menu structure mirrors the macOS app: a single ``Channels`` submenu with one
sub-submenu per channel (Set as active / View join string / Share via
pairing / Leave channel) and Create / Join from clipboard / Receive via
pairing at the bottom. Qt handles nested submenus and dynamic rebuilding
well; we rebuild on a 2-second QTimer so "12s ago" labels stay current and
any change flagged by daemon callbacks is picked up shortly after.

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

        # Pairing state: same pattern as macOS -- daemon callbacks set flags
        # on background threads, the QTimer-driven tick on the GUI thread
        # is the only place we open Qt modals.
        self._pairing_active: str | None = None
        self._pairing_label: str = ""
        self._pairing_peers_ready: bool = False
        self._pairing_peer_picked: bool = False
        self._pairing_pick_min_at: float = 0.0
        self._pairing_pick_max_at: float = 0.0
        self._pending_sas: tuple[str, str] | None = None
        self._pending_result: tuple[str, str] | None = None
        self._handling_modal = False
        self._daemon.on_pairing_peers_changed = self._on_pairing_peers
        self._daemon.on_pairing_sas_ready = self._on_pairing_sas_ready
        self._daemon.on_pairing_paired = self._on_pairing_paired
        self._daemon.on_pairing_failed = self._on_pairing_failed

        self._tick_timer = QTimer(self)
        self._tick_timer.timeout.connect(self._tick)
        self._tick_timer.start(2000)

        self._refresh()

    def _mark_dirty(self, _channel: str) -> None:
        self._dirty = True

    def _tick(self) -> None:
        # Drain pairing-UI events; Qt modals would re-enter if a second
        # tick fires while one is up, so we gate with _handling_modal and
        # surface one event per tick.
        if not self._handling_modal:
            if self._pending_result is not None:
                title, body = self._pending_result
                self._pending_result = None
                self.showMessage(
                    title, body,
                    QSystemTrayIcon.MessageIcon.Information, 3000,
                )
                self._dirty = True
            elif self._pending_sas is not None:
                sas, who = self._pending_sas
                self._pending_sas = None
                self._handling_modal = True
                try:
                    self._prompt_sas(sas, who)
                finally:
                    self._handling_modal = False
                self._dirty = True
            elif (self._pairing_active == "receive"
                  and not self._pairing_peer_picked):
                now = time.monotonic()
                if now >= self._pairing_pick_max_at or (
                    now >= self._pairing_pick_min_at and self._pairing_peers_ready
                ):
                    self._handling_modal = True
                    try:
                        self._show_peer_picker()
                    finally:
                        self._handling_modal = False

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

        # When no channel is joined, the channel-dependent surfaces would
        # all show "(no channel joined)" placeholders. That reads as broken;
        # collapse them entirely and let the Channels submenu carry the
        # path forward.
        if active is not None:
            publish = QAction("Publish current clipboard", self._menu)
            publish.triggered.connect(self._publish)
            publish.setEnabled(self._daemon.sync_enabled())
            self._menu.addAction(publish)

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

        # Channels submenu: each channel is its own sub-submenu with
        # Set-as-active / View join string / Leave actions; create + join
        # actions sit at the bottom. Replaces the older multi-step
        # 'Manage channels...' QInputDialog flow.
        chan_menu = self._menu.addMenu("Channels")
        channels = self._daemon.list_channels()
        for ch in channels:
            label = f"#{ch.name}" + ("  (active)" if ch.name == active else "")
            ch_submenu = chan_menu.addMenu(label)

            set_active = ch_submenu.addAction("Set as active")
            if ch.name == active:
                set_active.setEnabled(False)
            else:
                set_active.triggered.connect(
                    lambda _checked=False, name=ch.name: self._switch_channel(name)
                )

            view = ch_submenu.addAction("View join string…")
            view.triggered.connect(
                lambda _checked=False, name=ch.name: self._view_join_string(name)
            )

            share = ch_submenu.addAction("Share via pairing…")
            share.triggered.connect(
                lambda _checked=False, name=ch.name: self._share_via_pairing(name)
            )

            leave = ch_submenu.addAction("Leave channel")
            leave.triggered.connect(
                lambda _checked=False, name=ch.name: self._leave_channel_confirm(name)
            )

        if channels:
            chan_menu.addSeparator()
        create = chan_menu.addAction("Create channel…")
        create.triggered.connect(self._create_channel_prompt)
        join = chan_menu.addAction("Join from clipboard")
        join.triggered.connect(self._join_from_clipboard)
        receive = chan_menu.addAction("Receive via pairing…")
        receive.triggered.connect(self._receive_via_pairing)

        sync_label = "Sync: On" if self._daemon.sync_enabled() else "Sync: Off"
        sync_action = QAction(sync_label, self._menu)
        sync_action.triggered.connect(self._toggle_sync)
        self._menu.addAction(sync_action)

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

    def _create_channel_prompt(self) -> None:
        name, ok = QInputDialog.getText(None, "Create channel", "Channel name:")
        if not ok:
            return
        name = name.strip()
        if not name:
            return
        try:
            channel = self._daemon.create_channel(name)
        except ChannelError as exc:
            QMessageBox.critical(None, "Could not create channel", str(exc))
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
            QMessageBox.warning(None, "Channel not found", channel_name)
            return
        self._show_and_copy_join_string(ch)

    def _show_and_copy_join_string(self, channel) -> None:
        join_string = channel.to_join_string()
        copied = True
        try:
            self._daemon.copy_text_to_clipboard(join_string)
        except Exception:
            copied = False
        footer = "\n\n(Copied to clipboard.)" if copied else ""
        QMessageBox.information(
            None,
            f"Join string for #{channel.name}",
            f"Share this with the other machine (out-of-band):\n\n"
            f"{join_string}{footer}",
        )

    def _join_from_clipboard(self) -> None:
        text = self._daemon.read_clipboard_text()
        if not text or "clipsync://" not in text:
            self.showMessage(
                "ClipSync", "Copy a clipsync:// join string first, then try again.",
                QSystemTrayIcon.MessageIcon.Warning, 3000,
            )
            return
        try:
            channel = self._daemon.join_channel(text.strip())
        except ChannelError as exc:
            QMessageBox.critical(None, "Could not join channel", str(exc))
            return
        if self._active_channel is None:
            self._active_channel = channel.name
        self.showMessage(
            "ClipSync", f"Joined #{channel.name}",
            QSystemTrayIcon.MessageIcon.Information, 2500,
        )
        self._refresh()

    def _leave_channel_confirm(self, channel_name: str) -> None:
        choice = QMessageBox.question(
            None,
            f"Leave #{channel_name}?",
            "This removes the channel and its secret from this machine. "
            "Other members are unaffected; you can rejoin later with the "
            "channel's join string.",
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if choice != QMessageBox.StandardButton.Yes:
            return
        try:
            self._daemon.leave_channel(channel_name)
        except ChannelError as exc:
            QMessageBox.critical(None, "Could not leave channel", str(exc))
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
            QMessageBox.critical(None, "Could not start pairing", str(exc))
            return
        self._pairing_active = "share"
        self._pairing_label = f"#{channel_name}"
        self._pairing_peers_ready = False
        self._pairing_peer_picked = False
        self.showMessage(
            "ClipSync",
            f"Sharing {self._pairing_label} — waiting for a nearby device…",
            QSystemTrayIcon.MessageIcon.Information, 3000,
        )

    def _receive_via_pairing(self) -> None:
        try:
            self._daemon.start_pairing_receive()
        except RuntimeError as exc:
            QMessageBox.critical(None, "Could not start pairing", str(exc))
            return
        self._pairing_active = "receive"
        self._pairing_label = ""
        self._pairing_peers_ready = False
        self._pairing_peer_picked = False
        now = time.monotonic()
        self._pairing_pick_min_at = now + 3.0
        self._pairing_pick_max_at = now + 8.0
        self.showMessage(
            "ClipSync", "Looking for nearby ClipSync devices…",
            QSystemTrayIcon.MessageIcon.Information, 3000,
        )

    def _show_peer_picker(self) -> None:
        peers = self._daemon.pairing_peers()
        self._pairing_peer_picked = True
        if not peers:
            QMessageBox.information(
                None, "No devices found",
                "No nearby ClipSync devices were advertising a pairing "
                "session. Start 'Share via pairing…' on the other machine "
                "and try again.",
            )
            self._daemon.cancel_pairing()
            self._pairing_active = None
            return
        labels = [f"{p.display} — {p.label}" for p in peers]
        choice, ok = QInputDialog.getItem(
            None, "Pair with nearby device", "Device:",
            labels, 0, False,
        )
        if not ok:
            self._daemon.cancel_pairing()
            self._pairing_active = None
            return
        idx = labels.index(choice)
        self._daemon.pick_pairing_peer(peers[idx].peer_id)

    def _prompt_sas(self, sas: str, peer_display: str) -> None:
        choice = QMessageBox.question(
            None,
            "Verify pairing code",
            f"Code: {sas}\n\nPeer: {peer_display}\n\n"
            "Confirm only if BOTH screens show this exact code.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if choice == QMessageBox.StandardButton.Yes:
            self._daemon.confirm_pairing()
        else:
            self._daemon.reject_pairing()

    # Background-thread callbacks: set flags only.

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
