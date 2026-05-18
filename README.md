# ClipSync

Cross-OS clipboard sharing — text and images — over a local Ethernet/LAN.
A menu bar app on macOS and a system tray app on Linux, sharing one Python core.

No server, no cloud. Sharing is organized into encrypted **channels**, and is
deliberate in both directions: you explicitly publish, receivers explicitly pull.

## Status

Early development. The shared core is partially built:

| Module | Status |
|---|---|
| `core/protocol.py` — wire format | ✅ done, tested |
| `core/crypto.py` — per-channel encryption | ✅ done, tested |
| `core/channels.py` — channels + join strings | ✅ done, tested |
| `core/transport.py` — networking | ⬜ next |
| `core/clipboard.py` — clipboard interface | ⬜ todo |
| `platform/`, `ui/`, `daemon.py` | ⬜ todo |

See **`PROJECT_STATUS.md`** for the full design rationale, locked decisions,
and the remaining build plan.

## How it works

- **Channels** — named encrypted groups (`#work`, `#screenshots`). A channel is
  just a shared secret; two machines are on the same channel when they hold the
  same key. You join a channel by pasting a `clipsync://` join string that an
  existing member shares with you out-of-band.
- **Opt-in push** — nothing leaves your machine until you click *Publish current
  clipboard*. Passwords and one-time codes never sync by accident.
- **Manual pull** — receivers see what's available on a channel and click to
  pull an item into their own clipboard.
- **Encrypted** — every packet is sealed with the channel's key (AES-256-GCM).
  A machine on the LAN without the key can't read, forge, or even see a
  channel's traffic.

## Install (development)

```bash
pip install -r requirements.txt          # core dependency: cryptography
# macOS UI:   pip install rumps pyobjc-framework-Cocoa
# Linux UI:   pip install PySide6
```

## Quick check

```bash
python3 -c "from clipsync.core import protocol, crypto, channels; print('core imports OK')"
```

## Layout

```
clipsync/
├── core/        platform-agnostic: protocol, crypto, channels, transport, clipboard
├── platform/    per-OS clipboard access (darwin / linux)
├── ui/          per-OS menu bar / system tray apps
└── daemon.py    entry point — wires it all together
```
