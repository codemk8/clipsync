"""
clipsync.core.clipboard
=======================

Abstract clipboard interface. Platform implementations live in platform/.

The wire format normalizes everything to two content types (see protocol.py):
UTF-8 text and PNG bytes. Implementations of :class:`Clipboard` are responsible
for converting from / to the OS-native representations -- e.g. macOS may hold
TIFF in the pasteboard image slot, X11 may hand back string objects -- so that
the rest of the codebase never has to guess.

No change-watcher: sharing is opt-in (decision #1 in PROJECT_STATUS.md). The
sender publishes explicitly, so we never need to poll the OS clipboard for
changes.
"""

from __future__ import annotations

import abc
from typing import Optional

from .protocol import CONTENT_TEXT, CONTENT_IMAGE


class ClipboardError(Exception):
    """Raised when reading or writing the OS clipboard fails."""


class Clipboard(abc.ABC):
    """Platform-agnostic clipboard handle.

    Implementations: :mod:`clipsync.platform.darwin`, :mod:`clipsync.platform.linux`.
    """

    @abc.abstractmethod
    def read(self) -> Optional[tuple[str, bytes]]:
        """Return ``(content_type, data)`` or ``None`` if the clipboard is empty.

        ``content_type`` is one of :data:`CONTENT_TEXT` / :data:`CONTENT_IMAGE`.
        Text is always UTF-8 bytes; images are always PNG bytes. The clipboard
        layer hides every other native format from callers.
        """

    @abc.abstractmethod
    def write(self, content_type: str, data: bytes) -> None:
        """Place ``data`` on the OS clipboard under ``content_type``.

        Implementations may raise :class:`ClipboardError` on platform failure.
        ``content_type`` must be one of the two supported types; anything else
        is rejected here rather than at the platform layer.
        """


def validate_content_type(content_type: str) -> str:
    """Return ``content_type`` if supported, else raise ClipboardError."""
    if content_type not in (CONTENT_TEXT, CONTENT_IMAGE):
        raise ClipboardError(
            f"unsupported content type {content_type!r}; "
            f"expected {CONTENT_TEXT!r} or {CONTENT_IMAGE!r}"
        )
    return content_type


def get_clipboard() -> Clipboard:
    """Return the right :class:`Clipboard` impl for the current OS.

    Imports the platform module lazily so that a Linux-only host never tries
    to import PyObjC and vice versa.
    """
    import sys
    if sys.platform == "darwin":
        from ..platform.darwin import DarwinClipboard
        return DarwinClipboard()
    if sys.platform.startswith("linux"):
        from ..platform.linux import LinuxClipboard
        return LinuxClipboard()
    raise ClipboardError(f"clipsync has no clipboard backend for {sys.platform!r}")
