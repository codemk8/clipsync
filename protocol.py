"""
clipsync.core.protocol
======================

The wire contract for ClipSync. This module is intentionally free of any
networking or cryptography -- it only defines *what* the daemons say to each
other and how those statements are turned into bytes and back.

Layering
--------
A message on the wire has two parts::

    +-------------------+----------------------------+
    |  JSON header      |  optional raw binary body  |
    |  (UTF-8, framed)  |  (clipboard payload bytes) |
    +-------------------+----------------------------+

The header is a JSON object; the body is the actual clipboard content
(UTF-8 text or PNG bytes). Most messages have no body at all -- only a
FETCH_RESULT carries one. Keeping the body *out* of the JSON means we never
have to base64-encode large images (which would inflate them ~33%).

The crypto layer (crypto.py) encrypts the header+body blob as a unit; the
transport layer (transport.py) is responsible for framing. This module just
provides the structured form and the (de)serialization helpers.

Message types
-------------
ANNOUNCE        multicast, periodic. "I am here, on this channel, and the
                newest item I have published is seq N." Doubles as peer
                discovery and as the new-item signal for receivers.
PUBLISH_NOTIFY  multicast, one-shot. Sent the instant a user publishes, so
                peers update their menu without waiting for the next poll.
POLL            unicast TCP. "What is the newest seq you have published?"
                The slow safety-net fallback if a NOTIFY was dropped.
POLL_RESULT     unicast TCP. Reply to POLL: current ring buffer summary.
FETCH           unicast TCP. "Send me the payload for seq N."
FETCH_RESULT    unicast TCP. Reply to FETCH: header + binary body.
ERROR           unicast TCP. Something went wrong with the prior request.
"""

from __future__ import annotations

import enum
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


# Bump this if the wire format ever changes incompatibly. Daemons refuse
# messages whose major version differs from their own.
PROTOCOL_VERSION = 1

# Content types we put on the wire. We normalize *everything* to one of
# these two on the sending side so receivers never have to guess.
CONTENT_TEXT = "text/plain; charset=utf-8"
CONTENT_IMAGE = "image/png"


class MessageType(str, enum.Enum):
    """Every kind of message that can travel on the wire."""

    ANNOUNCE = "announce"
    PUBLISH_NOTIFY = "publish_notify"
    POLL = "poll"
    POLL_RESULT = "poll_result"
    FETCH = "fetch"
    FETCH_RESULT = "fetch_result"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Item metadata -- the description of one published clipboard entry.
# This is what populates the "Available on #channel" menu list. It never
# contains the payload itself; the payload is fetched on demand.
# ---------------------------------------------------------------------------


@dataclass
class ItemMeta:
    """Metadata describing a single published clipboard item.

    seq          monotonically increasing per-origin sequence number
    timestamp    unix time the item was published
    origin       UUID of the daemon that published it
    origin_name  human-readable host label, for the menu ("mac-studio")
    content_type one of CONTENT_TEXT / CONTENT_IMAGE
    size         payload size in bytes
    sha256       hex digest of the payload, for integrity + dedupe
    preview      short human preview: snippet for text, "image 248 KB" for
                 images. Lets the menu show something useful before fetch.
    """

    seq: int
    timestamp: float
    origin: str
    origin_name: str
    content_type: str
    size: int
    sha256: str
    preview: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ItemMeta":
        return cls(
            seq=int(d["seq"]),
            timestamp=float(d["timestamp"]),
            origin=str(d["origin"]),
            origin_name=str(d["origin_name"]),
            content_type=str(d["content_type"]),
            size=int(d["size"]),
            sha256=str(d["sha256"]),
            preview=str(d["preview"]),
        )


# ---------------------------------------------------------------------------
# The message envelope.
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Raised when bytes on the wire cannot be understood as a valid message."""


@dataclass
class Message:
    """A single ClipSync protocol message (header + optional body).

    The header fields below are common to all message types. Type-specific
    data lives in ``payload`` (a plain dict, shape depends on ``type``).
    The binary ``body`` is only populated for FETCH_RESULT.
    """

    type: MessageType
    channel: str                       # channel name this message belongs to
    sender: str                        # origin UUID of the sending daemon
    sender_name: str = ""              # human-readable host label
    version: int = PROTOCOL_VERSION
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = field(default_factory=time.time)
    payload: dict = field(default_factory=dict)
    body: bytes = b""                  # raw clipboard bytes; FETCH_RESULT only

    # -- serialization ------------------------------------------------------

    def encode(self) -> bytes:
        """Serialize to a length-framed ``header || body`` byte blob.

        Layout::

            [4 bytes big-endian header length][header JSON][body bytes]

        The crypto layer encrypts this whole blob; the transport layer reads
        the 4-byte prefix to know how much header to parse, and infers the
        body length from the surrounding frame.
        """
        header = {
            "v": self.version,
            "type": self.type.value,
            "channel": self.channel,
            "sender": self.sender,
            "sender_name": self.sender_name,
            "msg_id": self.msg_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "body_len": len(self.body),
        }
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        if len(header_bytes) > 0xFFFFFFFF:
            raise ProtocolError("header too large to frame")
        prefix = len(header_bytes).to_bytes(4, "big")
        return prefix + header_bytes + self.body

    @classmethod
    def decode(cls, blob: bytes) -> "Message":
        """Inverse of :meth:`encode`. Raises ProtocolError on malformed input."""
        if len(blob) < 4:
            raise ProtocolError("blob shorter than 4-byte length prefix")
        header_len = int.from_bytes(blob[:4], "big")
        if len(blob) < 4 + header_len:
            raise ProtocolError("blob shorter than declared header length")

        try:
            header = json.loads(blob[4:4 + header_len].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"header is not valid JSON: {exc}") from exc

        version = int(header.get("v", 0))
        if version != PROTOCOL_VERSION:
            # A different *major* version means we cannot safely interpret
            # the rest. Reject loudly rather than guessing.
            raise ProtocolError(
                f"unsupported protocol version {version} "
                f"(this daemon speaks {PROTOCOL_VERSION})"
            )

        try:
            msg_type = MessageType(header["type"])
        except (KeyError, ValueError) as exc:
            raise ProtocolError(f"unknown message type: {exc}") from exc

        body_len = int(header.get("body_len", 0))
        body = blob[4 + header_len:]
        if len(body) != body_len:
            raise ProtocolError(
                f"body length mismatch: header says {body_len}, "
                f"got {len(body)} bytes"
            )

        for required in ("channel", "sender"):
            if required not in header:
                raise ProtocolError(f"header missing required field '{required}'")

        return cls(
            type=msg_type,
            channel=str(header["channel"]),
            sender=str(header["sender"]),
            sender_name=str(header.get("sender_name", "")),
            version=version,
            msg_id=str(header.get("msg_id", uuid.uuid4().hex)),
            timestamp=float(header.get("timestamp", 0.0)),
            payload=dict(header.get("payload", {})),
            body=body,
        )


# ---------------------------------------------------------------------------
# Constructor helpers.
#
# These are the *only* way the rest of the codebase should build messages --
# they keep the per-type payload shapes in one place, so a typo in a payload
# key is caught here rather than three modules away.
# ---------------------------------------------------------------------------


def make_announce(
    channel: str,
    sender: str,
    sender_name: str,
    tcp_port: int,
    latest_seq: int,
) -> Message:
    """Periodic 'I am here' multicast.

    ``tcp_port`` tells peers where to send POLL/FETCH for this daemon.
    ``latest_seq`` is the newest published seq -- a receiver compares it
    against what it has shown and knows instantly if it missed something.
    """
    return Message(
        type=MessageType.ANNOUNCE,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"tcp_port": int(tcp_port), "latest_seq": int(latest_seq)},
    )


def make_publish_notify(channel: str, sender: str, sender_name: str,
                        item: ItemMeta) -> Message:
    """One-shot 'I just published something' multicast.

    Carries the full ItemMeta so receivers can populate their menu line
    immediately, without a follow-up POLL.
    """
    return Message(
        type=MessageType.PUBLISH_NOTIFY,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"item": item.to_dict()},
    )


def make_poll(channel: str, sender: str, sender_name: str) -> Message:
    """Unicast 'what is the newest seq you have?' -- the slow safety net."""
    return Message(
        type=MessageType.POLL,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
    )


def make_poll_result(channel: str, sender: str, sender_name: str,
                     items: list[ItemMeta]) -> Message:
    """Reply to POLL: a summary of every item currently in the ring buffer."""
    return Message(
        type=MessageType.POLL_RESULT,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"items": [it.to_dict() for it in items]},
    )


def make_fetch(channel: str, sender: str, sender_name: str, seq: int) -> Message:
    """Unicast 'send me the payload for this seq'."""
    return Message(
        type=MessageType.FETCH,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"seq": int(seq)},
    )


def make_fetch_result(channel: str, sender: str, sender_name: str,
                      item: ItemMeta, body: bytes) -> Message:
    """Reply to FETCH: the item metadata plus the actual payload bytes.

    This is the only message type that carries a binary ``body``.
    """
    return Message(
        type=MessageType.FETCH_RESULT,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"item": item.to_dict()},
        body=body,
    )


def make_error(channel: str, sender: str, sender_name: str,
              reason: str, ref_msg_id: str = "") -> Message:
    """Unicast error reply. ``ref_msg_id`` points back at the failed request."""
    return Message(
        type=MessageType.ERROR,
        channel=channel,
        sender=sender,
        sender_name=sender_name,
        payload={"reason": reason, "ref_msg_id": ref_msg_id},
    )


# ---------------------------------------------------------------------------
# Payload accessors.
#
# Reading payload dicts by hand everywhere invites typo bugs and gives no
# validation. These helpers are the typed read-side counterpart to the
# make_* constructors -- use them instead of touching msg.payload directly.
# ---------------------------------------------------------------------------


def announce_fields(msg: Message) -> tuple[int, int]:
    """Return ``(tcp_port, latest_seq)`` from an ANNOUNCE message."""
    if msg.type is not MessageType.ANNOUNCE:
        raise ProtocolError(f"expected ANNOUNCE, got {msg.type.value}")
    try:
        return int(msg.payload["tcp_port"]), int(msg.payload["latest_seq"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ProtocolError(f"malformed ANNOUNCE payload: {exc}") from exc


def notify_item(msg: Message) -> ItemMeta:
    """Return the ItemMeta carried by a PUBLISH_NOTIFY message."""
    if msg.type is not MessageType.PUBLISH_NOTIFY:
        raise ProtocolError(f"expected PUBLISH_NOTIFY, got {msg.type.value}")
    try:
        return ItemMeta.from_dict(msg.payload["item"])
    except (KeyError, TypeError) as exc:
        raise ProtocolError(f"malformed PUBLISH_NOTIFY payload: {exc}") from exc


def poll_result_items(msg: Message) -> list[ItemMeta]:
    """Return the list of ItemMeta from a POLL_RESULT message."""
    if msg.type is not MessageType.POLL_RESULT:
        raise ProtocolError(f"expected POLL_RESULT, got {msg.type.value}")
    try:
        return [ItemMeta.from_dict(d) for d in msg.payload["items"]]
    except (KeyError, TypeError) as exc:
        raise ProtocolError(f"malformed POLL_RESULT payload: {exc}") from exc


def fetch_seq(msg: Message) -> int:
    """Return the requested seq from a FETCH message."""
    if msg.type is not MessageType.FETCH:
        raise ProtocolError(f"expected FETCH, got {msg.type.value}")
    try:
        return int(msg.payload["seq"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ProtocolError(f"malformed FETCH payload: {exc}") from exc


def fetch_result_item(msg: Message) -> ItemMeta:
    """Return the ItemMeta from a FETCH_RESULT message (body holds payload)."""
    if msg.type is not MessageType.FETCH_RESULT:
        raise ProtocolError(f"expected FETCH_RESULT, got {msg.type.value}")
    try:
        return ItemMeta.from_dict(msg.payload["item"])
    except (KeyError, TypeError) as exc:
        raise ProtocolError(f"malformed FETCH_RESULT payload: {exc}") from exc


def error_reason(msg: Message) -> str:
    """Return the human-readable reason string from an ERROR message."""
    if msg.type is not MessageType.ERROR:
        raise ProtocolError(f"expected ERROR, got {msg.type.value}")
    return str(msg.payload.get("reason", "unspecified error"))
