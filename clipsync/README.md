# ClipSync

Cross-OS clipboard sharing — text and images — over a local Ethernet/LAN.
A menu bar app on macOS and a system tray app on Linux, sharing one Python core.

No server, no cloud. Sharing is organized into encrypted **channels**, and is
deliberate in both directions: you explicitly publish, receivers explicitly pull.

## Status

End-to-end working. Two daemons on the same LAN find each other on a shared
channel, publish flows over UDP multicast + TCP, and pull copies the item
onto the local clipboard:

| Module | Status |
|---|---|
| `core/protocol.py` — wire format | ✅ done, tested |
| `core/crypto.py` — per-channel encryption | ✅ done, tested |
| `core/channels.py` — channels + join strings | ✅ done, tested |
| `core/transport.py` — UDP multicast + TCP | ✅ done |
| `core/clipboard.py` — clipboard ABC | ✅ done |
| `platform/darwin.py` — NSPasteboard | ✅ done |
| `platform/linux.py` — wl-clipboard / xclip | ✅ done |
| `config.py` — runtime settings | ✅ done |
| `daemon.py` — entry point | ✅ done |
| `ui/menu_darwin.py` — rumps menu bar | ✅ done |
| `ui/tray_linux.py` — PySide6 system tray | ✅ done |

See **`PROJECT_STATUS.md`** for the full design rationale and locked decisions.

## How it works

- **Channels** — named encrypted groups (`#work`, `#screenshots`). A channel is
  just a shared secret; two machines are on the same channel when they hold the
  same key. You join a channel by pasting a `clipsync://` join string that an
  existing member shares with you out-of-band.
- **Opt-in push** — nothing leaves your machine until you click *Publish current
  clipboard*. Passwords and one-time codes never sync by accident.
- **Manual pull** — receivers see what's available on a channel and click to
  pull an item into their own clipboard.
- **Selective removal** — *Unpublish ▸* lists every item this machine is
  publishing; click one to drop it for everyone. *Hide ▸* lists peer items;
  click one to suppress it only from this machine's view (peers still see it).
- **Encrypted** — every packet is sealed with the channel's key (AES-256-GCM).
  A machine on the LAN without the key can't read, forge, or even see a
  channel's traffic.

## Install (development)

Requires Python 3.10+. On a system with PEP 668 (recent macOS, Debian/Ubuntu),
`pip install` directly into the system Python is blocked, so use a venv:

```bash
# from the repo root (the directory that *contains* the clipsync package)
python3 -m venv .venv
source .venv/bin/activate                  # bash/zsh; on fish: source .venv/bin/activate.fish

# core (both OSes):
pip install -r clipsync/requirements.txt   # cryptography>=42

# macOS UI:
pip install rumps pyobjc-framework-Cocoa

# Linux UI:
pip install PySide6
# Plus install one of the clipboard CLIs via your package manager:
#   Wayland:  sudo apt install wl-clipboard       (or pacman -S wl-clipboard, ...)
#   X11:      sudo apt install xclip
```

Alternatively, with `pyproject.toml`:

```bash
pip install -e clipsync                    # core only
pip install -e 'clipsync[macos]'           # core + macOS UI
pip install -e 'clipsync[linux]'           # core + Linux UI
```

## Quick check

Run from the repo root (the directory containing the `clipsync/` package
folder), so the package import resolves:

```bash
python3 -c "from clipsync.core import protocol, crypto, channels, transport, clipboard; print('core OK')"
```

If you get `ModuleNotFoundError: No module named 'cryptography'`, the venv is
not active or `pip install` was skipped above.

## Run

```bash
# macOS (menu bar):
python3 -m clipsync.ui.menu_darwin

# Linux (system tray):
python3 -m clipsync.ui.tray_linux

# Headless daemon (announces + serves but no UI):
python3 -m clipsync.daemon
```

First-run flow:
1. On machine A: *Manage channels...* → `c work` to create a channel.
   The dialog prints the `clipsync://join?...` string.
2. On machine B: *Manage channels...* → `j <paste that string>` to join.
3. On either side: *Publish current clipboard* publishes the OS clipboard.
4. On the other: open *Available on #work* and click the item to pull it.

## Layout

```
clipsync/
├── core/        platform-agnostic: protocol, crypto, channels, transport, clipboard
├── platform/    per-OS clipboard access (darwin / linux)
├── ui/          per-OS menu bar / system tray apps
└── daemon.py    entry point — wires it all together
```
