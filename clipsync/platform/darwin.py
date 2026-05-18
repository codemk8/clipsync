"""
clipsync.platform.darwin
========================

macOS clipboard via NSPasteboard (PyObjC).

NSPasteboard speaks UTIs (`public.utf8-plain-text`, `public.png`,
`public.tiff`, ...). We read whatever is offered and normalize to the two
content types ClipSync puts on the wire: UTF-8 text and PNG.

Most pasteboard images on macOS arrive as TIFF -- screenshots and copies from
many apps store TIFF representations rather than PNG. We convert via
``NSBitmapImageRep`` so the receiver always sees PNG.

PyObjC is imported lazily inside the methods so that simply importing this
file on a non-Mac (e.g. in CI) does not explode -- the constructor is the
hard failure point.
"""

from __future__ import annotations

from ..core.clipboard import Clipboard, ClipboardError, validate_content_type
from ..core.protocol import CONTENT_IMAGE, CONTENT_TEXT


class DarwinClipboard(Clipboard):
    """NSPasteboard-backed :class:`Clipboard`."""

    def __init__(self):
        try:
            from AppKit import NSPasteboard  # noqa: F401  -- import check
        except ImportError as exc:
            raise ClipboardError(
                "macOS clipboard backend requires pyobjc-framework-Cocoa "
                "(install with: pip install pyobjc-framework-Cocoa)"
            ) from exc
        # We do not stash NSPasteboard.generalPasteboard() because the
        # pasteboard's change-count drives the singleton; we re-resolve it
        # on each call to be safe.

    # -- read ---------------------------------------------------------------

    def read(self):
        from AppKit import NSPasteboard, NSImage, NSBitmapImageRep, NSPasteboardTypePNG
        pb = NSPasteboard.generalPasteboard()
        # Image first -- if the user copied an image we want to send the
        # image, not its filename. Try PNG, then fall back to TIFF -> PNG.
        png_data = pb.dataForType_(NSPasteboardTypePNG)
        if png_data is not None and png_data.length() > 0:
            return CONTENT_IMAGE, bytes(png_data)

        # NSImage can ingest any supported representation, but it carries
        # no original bytes. We go through the raw TIFF path so the
        # conversion is explicit and lossless.
        from AppKit import NSPasteboardTypeTIFF
        tiff = pb.dataForType_(NSPasteboardTypeTIFF)
        if tiff is not None and tiff.length() > 0:
            rep = NSBitmapImageRep.imageRepWithData_(tiff)
            if rep is not None:
                from AppKit import NSBitmapImageFileTypePNG
                png = rep.representationUsingType_properties_(
                    NSBitmapImageFileTypePNG, {}
                )
                if png is not None:
                    return CONTENT_IMAGE, bytes(png)

        # Text fallback.
        from AppKit import NSPasteboardTypeString
        text = pb.stringForType_(NSPasteboardTypeString)
        if text is not None:
            return CONTENT_TEXT, text.encode("utf-8")

        return None

    # -- write --------------------------------------------------------------

    def write(self, content_type: str, data: bytes) -> None:
        validate_content_type(content_type)
        from AppKit import (
            NSPasteboard, NSData,
            NSPasteboardTypeString, NSPasteboardTypePNG,
        )
        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()

        if content_type == CONTENT_TEXT:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ClipboardError(f"text payload is not valid UTF-8: {exc}") from exc
            ok = pb.setString_forType_(text, NSPasteboardTypeString)
        else:  # CONTENT_IMAGE
            ns_data = NSData.dataWithBytes_length_(data, len(data))
            ok = pb.setData_forType_(ns_data, NSPasteboardTypePNG)

        if not ok:
            raise ClipboardError("NSPasteboard rejected the write")
