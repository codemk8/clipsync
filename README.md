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

## Installation

### Prerequisites

- **Python 3.10 or newer** (`python3 --version` to check).
- **macOS:** any reasonably recent version.
- **Linux:** a Wayland or X11 session, plus a clipboard CLI:
  - Wayland — `wl-clipboard` (`sudo apt install wl-clipboard`, `sudo pacman -S wl-clipboard`, etc.)
  - X11 — `xclip` (`sudo apt install xclip`, `sudo dnf install xclip`, etc.)
- **Network:** both machines on the same LAN, with UDP multicast allowed.
  Many corporate / guest Wi-Fi networks block multicast and peer-to-peer
  traffic — a home or office Ethernet/Wi-Fi works.

### 1. Clone the repo

```bash
git clone https://github.com/<you>/clipsync.git
cd clipsync
```

### 2. Create a virtual environment

Recent macOS, Debian, and Ubuntu enforce PEP 668, which blocks `pip install`
into the system Python. A venv is the supported path:

```bash
python3 -m venv .venv
source .venv/bin/activate            # bash/zsh
# fish:  source .venv/bin/activate.fish
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
```

Re-activate the venv whenever you open a new terminal before running ClipSync.

### 3. Install ClipSync

Pick the install command for your OS. Either the editable `pyproject.toml`
install or the explicit `requirements.txt` form works — they install the same
packages.

**macOS (menu bar app):**

```bash
pip install -e 'clipsync[macos]'
# equivalent to:
# pip install -r clipsync/requirements.txt
# pip install rumps pyobjc-framework-Cocoa
```

**Linux (system tray app):**

```bash
pip install -e 'clipsync[linux]'
# equivalent to:
# pip install -r clipsync/requirements.txt
# pip install PySide6
```

**Headless / core only (no UI):**

```bash
pip install -e clipsync
```

### 4. Verify the install

From the repo root (the directory containing the `clipsync/` package folder):

```bash
python3 -c "from clipsync.core import protocol, crypto, channels, transport, clipboard; print('core OK')"
```

You should see `core OK`. Common failures:

- `ModuleNotFoundError: No module named 'cryptography'` — the venv isn't
  active, or the `pip install` step was skipped. Re-run `source .venv/bin/activate`
  and the install command above.
- `ModuleNotFoundError: No module named 'clipsync'` — you're not in the repo
  root. `cd` to the directory that contains the `clipsync/` package folder.

### 5. (Optional) firewall

ClipSync uses UDP multicast for discovery (`ANNOUNCE`, `PUBLISH_NOTIFY`) and
TCP for transfers (`POLL`, `FETCH`). The UDP port is the one carried in the
`clipsync://` join string — `47100` by default. TCP listens on an ephemeral
port that's advertised in `ANNOUNCE`. If your host firewall is strict, allow
inbound UDP on the channel's port and inbound TCP from the LAN.

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
├── config.py    non-channel settings (intervals, ring size, payload cap)
└── daemon.py    entry point — wires it all together
```
