"""
clipsync.platform.linux
=======================

Linux clipboard via ``wl-clipboard`` (Wayland) or ``xclip`` (X11).

We shell out rather than pulling in heavy Qt/X11 bindings; the system tray
already needs PySide6 so we could lean on ``QClipboard`` there, but the
daemon must be able to read/write the clipboard *without* the GUI loop
running (and Wayland's clipboard semantics make Qt's clipboard fragile
under those conditions). The CLI tools are well-behaved subprocess sinks.

Detection: prefer ``wl-copy``/``wl-paste`` if ``$WAYLAND_DISPLAY`` is set,
else ``xclip`` if ``$DISPLAY`` is set. Tool absence raises ClipboardError
at first use so the user gets an actionable error rather than a silent
no-op.

Normalization: text on the wire is UTF-8; images on the wire are PNG.
``wl-paste`` and ``xclip`` can both report MIME types and stream raw bytes
of any reported type, which is exactly what we need.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional

from ..core.clipboard import Clipboard, ClipboardError, validate_content_type
from ..core.protocol import CONTENT_IMAGE, CONTENT_TEXT


def _which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def _is_wayland() -> bool:
    return bool(os.environ.get("WAYLAND_DISPLAY"))


def _is_x11() -> bool:
    return bool(os.environ.get("DISPLAY"))


class LinuxClipboard(Clipboard):
    """``wl-clipboard`` / ``xclip`` backed :class:`Clipboard`."""

    def __init__(self):
        if _is_wayland() and _which("wl-paste") and _which("wl-copy"):
            self._backend = "wayland"
        elif _is_x11() and _which("xclip"):
            self._backend = "x11"
        elif _which("wl-paste") and _which("wl-copy"):
            # No display env, but tools present -- probably a headless test.
            # Use Wayland tools; they will fail loudly if there is no socket.
            self._backend = "wayland"
        elif _which("xclip"):
            self._backend = "x11"
        else:
            raise ClipboardError(
                "no clipboard backend found: install 'wl-clipboard' (Wayland) "
                "or 'xclip' (X11)"
            )

    # -- read ---------------------------------------------------------------

    def read(self):
        if self._backend == "wayland":
            return self._read_wayland()
        return self._read_x11()

    def _read_wayland(self):
        types = self._run(["wl-paste", "--list-types"], check=False)
        if types is None:
            return None
        mime_types = [line.strip() for line in types.splitlines() if line.strip()]
        # Image first -- match the macOS preference order.
        if "image/png" in mime_types:
            data = self._run_raw(["wl-paste", "--type", "image/png", "--no-newline"])
            if data:
                return CONTENT_IMAGE, data
        for t in mime_types:
            if t.startswith("text/"):
                data = self._run_raw(["wl-paste", "--type", t, "--no-newline"])
                if data is not None:
                    try:
                        return CONTENT_TEXT, data.decode("utf-8").encode("utf-8")
                    except UnicodeDecodeError:
                        # Some apps advertise text/* but offer a non-UTF-8
                        # encoding; skip and try the next type.
                        continue
        return None

    def _read_x11(self):
        targets = self._run(["xclip", "-selection", "clipboard", "-o", "-t", "TARGETS"],
                            check=False)
        if targets is None:
            return None
        offered = {line.strip() for line in targets.splitlines() if line.strip()}
        if "image/png" in offered:
            data = self._run_raw(["xclip", "-selection", "clipboard", "-o",
                                  "-t", "image/png"])
            if data:
                return CONTENT_IMAGE, data
        for t in ("UTF8_STRING", "text/plain;charset=utf-8", "text/plain", "STRING"):
            if t in offered:
                data = self._run_raw(["xclip", "-selection", "clipboard", "-o",
                                      "-t", t])
                if data is not None:
                    try:
                        return CONTENT_TEXT, data.decode("utf-8").encode("utf-8")
                    except UnicodeDecodeError:
                        continue
        return None

    # -- write --------------------------------------------------------------

    def write(self, content_type: str, data: bytes) -> None:
        validate_content_type(content_type)
        if content_type == CONTENT_TEXT:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ClipboardError(f"text payload is not valid UTF-8: {exc}") from exc

        if self._backend == "wayland":
            mime = "image/png" if content_type == CONTENT_IMAGE else "text/plain;charset=utf-8"
            self._pipe_in(["wl-copy", "--type", mime], data)
        else:
            mime = "image/png" if content_type == CONTENT_IMAGE else "UTF8_STRING"
            self._pipe_in(["xclip", "-selection", "clipboard", "-t", mime, "-i"], data)

    # -- subprocess helpers -------------------------------------------------

    def _run(self, argv: list[str], check: bool = True) -> Optional[str]:
        try:
            out = subprocess.run(argv, capture_output=True, check=check, timeout=5.0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except subprocess.CalledProcessError:
            return None
        try:
            return out.stdout.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _run_raw(self, argv: list[str]) -> Optional[bytes]:
        try:
            out = subprocess.run(argv, capture_output=True, check=False, timeout=5.0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        if out.returncode != 0:
            return None
        return out.stdout

    def _pipe_in(self, argv: list[str], data: bytes) -> None:
        try:
            proc = subprocess.run(argv, input=data, capture_output=True, timeout=5.0)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise ClipboardError(f"{argv[0]} failed: {exc}") from exc
        if proc.returncode != 0:
            raise ClipboardError(
                f"{argv[0]} exited {proc.returncode}: "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
