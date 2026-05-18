# ClipSync — Project Status

Cross-OS clipboard sharing (text + images) over a local Ethernet/LAN.
macOS menu bar app + Linux system tray app, sharing one Python core.

This document is the handoff context. It records **what is built**, **what is
left**, and **every design decision** so work can continue without re-deriving
the rationale.

---

## The product in one paragraph

A small daemon runs on each machine with a menu bar icon (macOS) or system
tray icon (Linux). Users organize sharing into **channels** — named, encrypted
groups like `#work` or `#screenshots`. Sharing is **opt-in push, manual pull**:
nothing leaves your machine until you click "Publish current clipboard"; nothing
enters your clipboard until you click an item in the "Available on #channel"
list. There is no server — channels are pure shared secrets exchanged
out-of-band via a `clipsync://` join string.

---

## Locked design decisions

These were settled with the user. Do not revisit without asking.

1. **Sharing model = opt-in push + manual pull.** The clipboard is NOT watched
   for auto-broadcast. The sender explicitly publishes; receivers explicitly
   pull. Both ends stay in control. (This is "mode 4" from the design chat.)

2. **Receivers poll, but polling only refreshes the menu list.** Polling never
   writes the system clipboard. The final pull into the clipboard is always a
   deliberate click.

3. **New-item delivery = hybrid notify + poll.** On publish, the sender sends
   one `PUBLISH_NOTIFY` multicast so peers' menus update instantly. A slow
   background `POLL` (~10s) is the safety net for dropped notifications.
   `ANNOUNCE` packets also carry `latest_seq`, so a missed notify is caught at
   the next announce.

4. **Pulled items stay published** (semantics "(i)"). When a receiver pulls an
   item, it copies locally and the item REMAINS available to everyone else on
   the channel until it ages out of the ring buffer or the sender unpublishes.
   No "consumed"/queue semantics — this is a shared pasteboard, not a handoff.

5. **Sender holds a small ring buffer per channel** (default last 5 items), not
   just one. Lets a briefly-offline receiver still grab recent items and lets
   the user publish a few things back-to-back.

6. **Channels are found out-of-band, never auto-discovered.** A channel is a
   name + secret. The secret travels only in a `clipsync://` join string that a
   human deliberately carries between machines. Auto-discovery would make "on
   the LAN" equal "can join", defeating per-channel encryption.

7. **Per-channel encryption with no server.** Holding a channel's key is the
   sole definition of membership. The key does triple duty: confidentiality,
   message authentication, and access control (you can't even see a channel's
   peers without its key).

8. **Send channel is single-select; receive channels are multi-select.** You
   publish to one active channel at a time, but receive from all joined
   channels at once.

9. **Normalize formats on the wire:** UTF-8 for text, PNG for images. Every OS
   converts to/from these so receivers never guess formats.

10. **Language:** Python core shared by both OSes. macOS UI via `rumps`; Linux
    UI via Qt (`PySide6`). (User leaned toward Python-everywhere for code reuse;
    confirm `rumps` vs native Swift if revisited.)

---

## Architecture

```
clipsync/
├── core/                  # platform-agnostic, shared by both OSes
│   ├── protocol.py        # [DONE] wire message types + serialization
│   ├── crypto.py          # [DONE] per-channel AES-256-GCM + replay defense
│   ├── channels.py        # [DONE] channel registry, join strings, persistence
│   ├── transport.py       # [DONE] UDP multicast + TCP networking
│   ├── clipboard.py       # [DONE] abstract read/write/normalize interface
│   └── pairing.py         # [DONE] mDNS + X25519 + SAS pairing for join-string handoff
├── platform/
│   ├── darwin.py          # [DONE] NSPasteboard clipboard impl (PyObjC)
│   └── linux.py           # [DONE] wl-clipboard / xclip clipboard impl
├── ui/
│   ├── menu_darwin.py     # [DONE] rumps menu bar app
│   └── tray_linux.py      # [DONE] PySide6 system tray app
├── daemon.py              # [DONE] wires core+platform+ui together; entry point
├── config.py              # [DONE] non-channel settings (ring size, intervals)
├── pyproject.toml         # [DONE]
├── requirements.txt       # [DONE]
└── PROJECT_STATUS.md      # this file
```

Wire layering (bottom to top):
```
  transport.py   — frames packets, owns sockets
  crypto.py      — seals/opens each packet (AES-GCM per channel)
  protocol.py    — structures the plaintext (header JSON + binary body)
```

---

## Module status

### core/protocol.py — DONE, tested

The wire contract. No networking, no crypto — just message structure.

- Packet plaintext = `[4-byte big-endian header length][JSON header][binary body]`.
  Body is OUTSIDE the JSON so images aren't base64-inflated ~33%.
- 7 message types: `ANNOUNCE`, `PUBLISH_NOTIFY`, `POLL`, `POLL_RESULT`,
  `FETCH`, `FETCH_RESULT`, `ERROR`.
- `Message` dataclass with `.encode()` / `.decode()`.
- `ItemMeta` dataclass = metadata for one published clipboard item; this is the
  menu's data model. Carries `sha256` (integrity + dedupe), `preview` (menu
  label text), never the payload itself.
- `make_*()` constructors and `*_fields()` accessors are the ONLY sanctioned
  way to build/read messages — keeps payload shapes in one place.
- `PROTOCOL_VERSION = 1`; version mismatch is a hard reject in `decode()`.

### core/crypto.py — DONE, tested

Per-channel authenticated encryption.

- `derive_channel_key()` — HKDF-SHA256, channel name as `info` for domain
  separation (same secret + different channel name = unrelated keys).
- `ChannelCipher` — one per channel. `.seal(Message) -> bytes` and
  `.open(bytes) -> Message`. Packet = `[12-byte nonce][AES-256-GCM ct+tag]`.
  Channel name bound into GCM AAD.
- `CipherRegistry` — holds all joined channels' ciphers. Inbound packets have
  NO cleartext channel label — registry tries every cipher's `.open()` until
  one's AEAD tag verifies. A packet no cipher opens = a channel you haven't
  joined = silently dropped. **This is how access control falls out of crypto.**
- Replay defense: rejects messages older than `REPLAY_WINDOW` (30s) and
  remembers recent `msg_id`s to reject duplicates. Seen-cache is time-bounded.
- `CryptoError` is deliberately coarse — callers treat any failure as "drop
  packet silently", never branch on reason (no info leak to a prober).
- Known limitation: protects against LAN outsiders, NOT against a malicious
  channel member. Inherent to keyed-channel-no-server. Matches the stated
  "trusted Ethernet" threat model.

### core/channels.py — DONE, tested

Channel lifecycle + join strings + persistence.

- `Channel` dataclass: `name`, `secret` (32 random bytes), `group`, `port`.
- `Channel.create()` — new channel, fresh random secret.
- Join string: `clipsync://join?n=<name>&k=<secret-b64url>&g=<group>&p=<port>`.
  `to_join_string()` / `from_join_string()`. URL form survives pasting into
  chat apps; encodes cleanly to a QR code.
- Multicast group derived deterministically from the secret (SHA-256 →
  239.192.0.0/14). Both machines compute the same group with nothing extra to
  exchange. Parser recomputes + cross-checks `g=` → mangled paste fails loudly.
- `ChannelRegistry` — thread-safe, persisted to `~/.config/clipsync/channels.json`.
  File is **0600**, written **atomically** (temp file + rename), temp created
  0600 from the start so the secret is never briefly world-readable.
- Joining a name-clash with a *different* secret is REFUSED (would silently
  disconnect you from your real channel). Re-joining the identical channel is
  idempotent.
- A corrupt config raises rather than silently starting empty (so a user never
  silently loses all channels). Judgment call — flagged for possible revisit.

---

## Implementation notes (modules now built)

### core/transport.py — DONE

UDP multicast + TCP networking, wired through `CipherRegistry`.

- One `SOCK_DGRAM` socket per channel, bound to the channel's port, joined
  to the channel's group. `SO_REUSEADDR` (+ `SO_REUSEPORT` where available)
  so two daemons on one host (handy for tests) can both bind.
- `IP_MULTICAST_TTL = 1` keeps traffic on the local segment. `IP_MULTICAST_LOOP`
  is on so a single host can talk to itself for smoke tests — the crypto
  layer's `msg_id` dedupe rejects the looped copy from the sender's POV, and
  the daemon's `if msg.sender == self._origin` guard short-circuits in
  `_handle_udp_packet` before any work.
- One shared TCP listener; each accept hands off to a per-request worker
  thread that does one read, one dispatch, one write, and closes.
- Per-channel peer roster keyed by `(channel, origin)`; `_peer_gc_loop`
  evicts after `peer_timeout` and fires `on_peer_lost`. The roster surfaces
  to the daemon, which then drops that origin's catalog entries.
- All outbound messages go through `CipherRegistry.seal()`; all inbound
  through `CipherRegistry.open()`. Unopenable packets (other channels, noise,
  replays) are silently dropped.

### core/clipboard.py — DONE

ABC with `read() -> (content_type, data) | None` and `write(content_type, data)`.
Helper `validate_content_type()` rejects anything but UTF-8 text and PNG.
`get_clipboard()` lazily imports the right backend so a non-Mac host never
tries to import PyObjC.

### platform/darwin.py — DONE

NSPasteboard via PyObjC. Read order: PNG → TIFF (converted to PNG via
`NSBitmapImageRep`) → UTF-8 string. Write: clears the pasteboard then sets
the single corresponding type. PyObjC is imported lazily so module import
alone does not require it.

### platform/linux.py — DONE

Shells out to `wl-paste`/`wl-copy` (Wayland) or `xclip` (X11). Detection:
prefer Wayland when `$WAYLAND_DISPLAY` is set and the tool exists, else X11
when `$DISPLAY` and `xclip` exist. Read order: image/png first, then any
`text/*` type that decodes as UTF-8. Tool absence raises `ClipboardError`
at construction time so the daemon fails loudly rather than silently.

### config.py — DONE

`Settings` dataclass + `SettingsStore` persisted to `~/.config/clipsync/settings.json`
(0600, atomic write). Carries ring size, intervals, peer timeout, max payload,
and the stable per-machine `origin` UUID + `origin_name`. First run materializes
defaults so identity survives restarts.

### daemon.py — DONE

Owns:
- a `CipherRegistry` populated from joined channels,
- a per-channel `_PublishRing` (default last 5 items),
- an inbound `_catalog` keyed by `(channel, origin, seq)` (so two daemons
  sharing a seq number never collide),
- a `Transport` wired with the seven callbacks (announce / peer-lost /
  publish-notify / poll / poll-result / fetch / fetch-result),
- a slow-poll loop that fires `transport.poll()` on every known peer every
  `poll_interval` to catch any dropped `PUBLISH_NOTIFY`.

Public API: `publish_current`, `unpublish_last`, `pull`, `available_items`,
`peers`, `create_channel`, `join_channel`, `leave_channel`, `set_sync_enabled`.
UI hooks: `on_catalog_changed`, `on_peers_changed`.

The integrity step in `pull()` re-hashes the fetched body and compares to
`ItemMeta.sha256` before writing the OS clipboard. AEAD already authenticated
the bytes on the wire; this catches any mismatch between the metadata we
showed in the menu and the body that arrived.

### core/pairing.py — DONE

Short-lived pairing protocol that hands a channel's join string from one
machine ("giver") to another ("taker") without requiring the user to copy
or type the `clipsync://` URL.

- **Discovery:** mDNS advertise + browse for `_clipsync-pair._tcp` with
  TXT records `role`, `display`, `label`. Two backends behind a small ABC
  in `core/_mdns.py`:
  - **macOS**: shells out to `/usr/bin/dns-sd` (so we coexist with the
    system `mDNSResponder` that holds UDP/5353 without `SO_REUSEPORT`).
  - **Linux / fallback**: pure-Python `zeroconf` (works alongside avahi,
    which does set `SO_REUSEPORT`, or stands alone).
- **Key agreement:** ephemeral X25519 over a fresh TCP socket. Both sides
  exchange HELLO with their public keys and 8-byte nonces.
- **SAS:** `HKDF-SHA256(shared, info=b"clipsync-pair-sas|" + transcript)`
  truncated to 4 decimal digits. Transcript pins (initiator_pub,
  responder_pub, initiator_nonce, responder_nonce) — taker is initiator,
  giver is responder. Both screens display the SAS; the user verifies a
  match before clicking Confirm.
- **Confirm round:** each side sends an AES-GCM-sealed CONFIRM frame
  (AAD=`b"confirm"`). A LAN MITM would compute different `session_key`s
  per leg, so its forwarded CONFIRM fails AEAD on the other side.
- **Transfer:** giver sends a GIFT frame (AAD=`b"gift"`) carrying the
  channel's `clipsync://` join string sealed under `session_key`. Taker
  decrypts, installs via `ChannelRegistry.join()`, sends OK (AAD=`b"ok"`),
  both close.
- **Defense in depth:** SAS verification is the load-bearing check; AAD
  prevents replay across message types; ephemeral keys + nonces make each
  session unique; 2-minute hard session timeout.
- **Threat model:** same as the rest of the system — LAN outsider in scope,
  malicious channel member out (inherent to no-server keyed channels).

The module exposes `PairingService` with `start_share(payload, label)` /
`start_receive()` / `pick_peer(peer_id)` / `confirm()` / `reject()` /
`cancel()` and four callbacks (`on_peers_changed`, `on_sas_ready`,
`on_paired`, `on_failed`). The daemon owns one instance and forwards the
callbacks as `on_pairing_*` hooks the UI installs. The `clipsync://` join
string remains as the power-user / scripted fallback.

A two-terminal CLI harness lives at `python -m clipsync.core.pairing
{share,receive}` for protocol smoke testing without UI.

### ui/menu_darwin.py + ui/tray_linux.py — DONE

Menu structure:
```
📋 ClipSync — #work
├── Publish current clipboard
├── Unpublish ▸
├── ──────────────
├── Available on #work ▸           (this list kept fresh by polling)
│   ├── image · 248 KB · mac-studio · 12s ago     → click = pull
│   └── text · "Q3 roadmap dr…" · thinkpad · 3m ago
├── Hide peer item ▸
├── ──────────────
├── Channels ▸
│   ├── #work  (active) ▸
│   │   ├── Set as active
│   │   ├── View join string…
│   │   ├── Share via pairing…
│   │   └── Leave channel
│   ├── #screenshots ▸
│   │   └── …
│   ├── ──────────────
│   ├── Create channel…
│   ├── Join from clipboard
│   └── Receive via pairing…
├── Sync: On                       (global pause toggle)
└── Quit
```
- macOS: `rumps`. Menu rebuilt on a 2s `rumps.Timer` and on daemon callbacks
  (callbacks just flip a dirty flag; the next tick redraws on the main
  thread). Channel management is in-menu — `Create channel…` is a
  single-field prompt; `Join from clipboard` reads the OS clipboard and
  parses it. `View join string…` auto-copies the URL.
- Linux: `PySide6` system tray. Daemon callbacks marshal to the Qt main
  loop via the same dirty-flag pattern. `QInputDialog.getItem` powers the
  peer picker; `QMessageBox.question` is the SAS confirmation. Placeholder
  solid icon; replace with a real asset before shipping.
- Pairing modals (peer pick, SAS confirm, completion notification) are all
  popped from the tick handler so background daemon threads never touch
  AppKit / Qt directly.

---

## How to verify what's built

Imports + the loopback smoke test:

```bash
cd ..   # so that `clipsync` is importable as a package
python3 -c "from clipsync.core import protocol, crypto, channels, transport, clipboard; print('core OK')"
```

End-to-end on a single host (two daemons with separate config dirs, talking
over multicast loopback) was validated in the smoke test that ships in the
build session. Re-run by spinning up two `Daemon` instances with different
`XDG_CONFIG_HOME` directories, joining the same channel, and confirming
that `publish_current` on one is visible via `available_items` and pullable
via `pull` on the other.

---

## Threat model (explicit)

- **In scope:** outsiders on the same LAN — they cannot read, forge, replay, or
  even enumerate channel peers without the channel key.
- **Out of scope:** a malicious *member* of a channel (anyone with the key can
  publish and read — inherent to a no-server keyed-channel design); a
  compromised host; physical access to `channels.json`.
- **User-facing safety:** opt-in push means secrets (passwords, 2FA codes)
  never leave a machine unless the user explicitly publishes them.
