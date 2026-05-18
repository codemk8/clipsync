"""
clipsync.core._mdns
===================

Thin abstraction over two different mDNS implementations:

* **macOS** ships its own ``mDNSResponder`` daemon and holds UDP/5353 without
  ``SO_REUSEPORT``, so ``python-zeroconf`` cannot bind alongside it. We
  shell out to ``/usr/bin/dns-sd`` instead, which talks to
  ``mDNSResponder`` over its private Unix-domain socket and coexists by
  design.
* **Linux** has no built-in mDNS responder (or it's avahi, which does set
  ``SO_REUSEPORT``), so the pure-Python ``zeroconf`` library works fine.

Both backends present the same surface to ``pairing.py``: ``register`` to
advertise a service and ``browse`` to discover peers. Handles returned by
``register`` / ``browse`` are stopped via their ``stop()`` method.

This module is internal -- consumers should depend on the
``MdnsBackend``/``DiscoveredPeer`` types and the ``get_backend()`` factory.
"""

from __future__ import annotations

import abc
import logging
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DiscoveredPeer:
    """A nearby service instance the backend has resolved."""
    name: str                # zeroconf instance name (unique on the network)
    host: str                # host name (e.g. "alice.local.")
    address: str             # resolved IPv4 dotted-quad
    port: int
    txt: dict[str, str] = field(default_factory=dict)


class _Handle(abc.ABC):
    """Common base for the two handle types -- registration and browse."""

    @abc.abstractmethod
    def stop(self) -> None: ...


class RegisterHandle(_Handle):
    pass


class BrowseHandle(_Handle):
    pass


class MdnsBackend(abc.ABC):
    """Service type is fixed at construction (the protocol owns it)."""

    def __init__(self, service_type: str):
        self.service_type = service_type

    @abc.abstractmethod
    def register(self, instance: str, port: int,
                 txt: dict[str, str]) -> RegisterHandle:
        """Advertise a service. ``instance`` is the unique name within the
        service type; the backend formats the FQDN. Returns a handle whose
        ``stop()`` unregisters."""

    @abc.abstractmethod
    def browse(self,
               on_added: Callable[[DiscoveredPeer], None],
               on_removed: Callable[[str], None]) -> BrowseHandle:
        """Start browsing. ``on_added`` fires with each newly-resolved peer
        (already includes TXT records and address). ``on_removed`` fires
        with the instance name when the peer is withdrawn. Returns a handle
        whose ``stop()`` cancels the browse."""


def get_backend(service_type: str) -> MdnsBackend:
    """Pick the right backend for the current OS.

    macOS goes through dns-sd; everything else falls back to python-zeroconf.
    If dns-sd isn't on PATH for some reason on a Mac, the zeroconf backend
    is tried as a last resort (it will likely raise on bind, but at least
    the failure is loud rather than mysterious)."""
    if sys.platform == "darwin" and shutil.which("dns-sd"):
        return _DarwinBackend(service_type)
    return _ZeroconfBackend(service_type)


# ---------------------------------------------------------------------------
# Helpers shared by both backends
# ---------------------------------------------------------------------------

def _primary_ipv4() -> str:
    """Best-effort local IPv4 used as the advertised address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# ---------------------------------------------------------------------------
# zeroconf backend (Linux / non-Mac fallback)
# ---------------------------------------------------------------------------

class _ZeroconfBackend(MdnsBackend):

    def register(self, instance, port, txt):
        # Imported lazily so a host that only ever runs the dns-sd backend
        # does not need the zeroconf wheel installed.
        from zeroconf import IPVersion, ServiceInfo, Zeroconf
        full_type = self.service_type if self.service_type.endswith(".") \
            else self.service_type + ".local."
        zc = Zeroconf(ip_version=IPVersion.V4Only)
        info = ServiceInfo(
            type_=full_type,
            name=f"{instance}.{full_type}",
            addresses=[socket.inet_aton(_primary_ipv4())],
            port=port,
            properties={k.encode("utf-8"): v.encode("utf-8")
                        for k, v in txt.items()},
            server=f"{socket.gethostname()}.local.",
        )
        zc.register_service(info)
        return _ZeroconfRegisterHandle(zc, info)

    def browse(self, on_added, on_removed):
        from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf
        full_type = self.service_type if self.service_type.endswith(".") \
            else self.service_type + ".local."
        zc = Zeroconf(ip_version=IPVersion.V4Only)

        class _L(ServiceListener):
            def add_service(self_inner, zc_, type_, name):
                info = zc_.get_service_info(type_, name, timeout=3000)
                if info is None:
                    return
                addresses = info.parsed_addresses(IPVersion.V4Only) \
                    if info.addresses else []
                if not addresses:
                    return
                txt_out = {
                    (k.decode("utf-8", "replace") if isinstance(k, bytes) else k):
                    (v.decode("utf-8", "replace") if isinstance(v, bytes) else (v or ""))
                    for k, v in (info.properties or {}).items() if k
                }
                on_added(DiscoveredPeer(
                    name=name, host=info.server or "",
                    address=addresses[0], port=info.port or 0,
                    txt=txt_out,
                ))

            def remove_service(self_inner, zc_, type_, name):
                on_removed(name)

            def update_service(self_inner, zc_, type_, name):
                self_inner.add_service(zc_, type_, name)

        browser = ServiceBrowser(zc, full_type, _L())
        return _ZeroconfBrowseHandle(zc, browser)


class _ZeroconfRegisterHandle(RegisterHandle):
    def __init__(self, zc, info):
        self._zc = zc
        self._info = info

    def stop(self):
        try:
            self._zc.unregister_service(self._info)
        except Exception:
            log.exception("zeroconf unregister failed")
        try:
            self._zc.close()
        except Exception:
            log.exception("zeroconf close failed")


class _ZeroconfBrowseHandle(BrowseHandle):
    def __init__(self, zc, browser):
        self._zc = zc
        self._browser = browser

    def stop(self):
        try:
            self._browser.cancel()
        except Exception:
            log.exception("zeroconf browser cancel failed")
        try:
            self._zc.close()
        except Exception:
            log.exception("zeroconf close failed")


# ---------------------------------------------------------------------------
# dns-sd backend (macOS)
# ---------------------------------------------------------------------------

# The output of `dns-sd -B` is a stream of column-aligned lines whose second
# whitespace token is "Add" or "Rmv" and whose last token is the instance
# name; we ignore everything else (header line, "STARTING..." marker, etc.).
_BROWSE_DATA_RE = re.compile(r"\b(Add|Rmv)\b.*\s+(\S+)\s*$")

# Reach-line from `dns-sd -L`:
#   ".... can be reached at hub.local.:12345 (interface 1) Flags: 1"
_REACH_RE = re.compile(r"can be reached at (\S+?):(\d+)")


class _DarwinBackend(MdnsBackend):

    def register(self, instance, port, txt):
        args = ["dns-sd", "-R", instance, self.service_type, ".", str(port)]
        for k, v in txt.items():
            args.append(f"{k}={v}")
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        return _DnsSdRegisterHandle(proc)

    def browse(self, on_added, on_removed):
        proc = subprocess.Popen(
            ["dns-sd", "-B", self.service_type, "."],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, text=True, bufsize=1,
        )
        stop_event = threading.Event()
        seen: set[str] = set()
        seen_lock = threading.Lock()
        thread = threading.Thread(
            target=_darwin_browse_loop,
            args=(proc, self.service_type, on_added, on_removed,
                  stop_event, seen, seen_lock),
            daemon=True, name="dns-sd-browse",
        )
        thread.start()
        return _DnsSdBrowseHandle(proc, thread, stop_event)


class _DnsSdRegisterHandle(RegisterHandle):
    def __init__(self, proc: subprocess.Popen):
        self._proc = proc

    def stop(self):
        _terminate(self._proc)


class _DnsSdBrowseHandle(BrowseHandle):
    def __init__(self, proc, thread, stop_event):
        self._proc = proc
        self._thread = thread
        self._stop = stop_event

    def stop(self):
        self._stop.set()
        _terminate(self._proc)
        self._thread.join(timeout=2.0)


def _terminate(proc: subprocess.Popen) -> None:
    """SIGTERM, fall back to SIGKILL after a short wait. dns-sd unregisters
    cleanly on SIGTERM via mDNSResponder's goodbye-packet logic."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass


def _darwin_browse_loop(proc, service_type, on_added, on_removed,
                        stop_event, seen, seen_lock):
    """Read `dns-sd -B` stdout line by line. For each Add line, resolve the
    instance (host + port + TXT) by spawning a short `dns-sd -L`, then fire
    on_added. For each Rmv line, fire on_removed.

    dns-sd reports one Add line per interface, so we dedupe by instance name
    using ``seen``."""
    assert proc.stdout is not None
    while not stop_event.is_set():
        line = proc.stdout.readline()
        if not line:
            break
        m = _BROWSE_DATA_RE.search(line.rstrip("\n"))
        if m is None:
            continue
        action, instance = m.group(1), m.group(2)
        if action == "Add":
            with seen_lock:
                if instance in seen:
                    continue
                seen.add(instance)
            try:
                resolved = _darwin_resolve(instance, service_type)
            except Exception:
                log.exception("dns-sd resolve failed for %s", instance)
                with seen_lock:
                    seen.discard(instance)
                continue
            if resolved is None:
                with seen_lock:
                    seen.discard(instance)
                continue
            host, port, txt = resolved
            try:
                address = socket.gethostbyname(host.rstrip("."))
            except OSError:
                log.debug("could not resolve %s to IPv4; dropping peer", host)
                with seen_lock:
                    seen.discard(instance)
                continue
            on_added(DiscoveredPeer(
                name=instance, host=host, address=address, port=port, txt=txt,
            ))
        else:  # Rmv
            with seen_lock:
                if instance in seen:
                    seen.discard(instance)
                else:
                    continue
            on_removed(instance)


def _darwin_resolve(instance: str, service_type: str,
                    timeout_s: float = 4.0) -> Optional[tuple[str, int, dict[str, str]]]:
    """Run a short `dns-sd -L` to get the host:port + TXT for ``instance``.

    dns-sd -L is a streaming subscription -- we read until we have the first
    full resolution (reach line + immediately-following TXT line) or the
    timeout elapses, then terminate it."""
    proc = subprocess.Popen(
        ["dns-sd", "-L", instance, service_type, "."],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL, text=True, bufsize=1,
    )
    q: queue.Queue[Optional[str]] = queue.Queue()

    def reader():
        try:
            assert proc.stdout is not None
            for line in iter(proc.stdout.readline, ""):
                q.put(line)
        finally:
            q.put(None)

    threading.Thread(target=reader, daemon=True, name="dns-sd-L").start()

    deadline = time.monotonic() + timeout_s
    host: Optional[str] = None
    port: Optional[int] = None
    try:
        while time.monotonic() < deadline:
            remaining = max(0.05, deadline - time.monotonic())
            try:
                line = q.get(timeout=remaining)
            except queue.Empty:
                break
            if line is None:
                break
            m = _REACH_RE.search(line)
            if m is not None:
                host = m.group(1)
                port = int(m.group(2))
                # The TXT line follows immediately; skip blank lines if any.
                while time.monotonic() < deadline:
                    try:
                        txt_line = q.get(
                            timeout=max(0.05, deadline - time.monotonic())
                        )
                    except queue.Empty:
                        return None
                    if txt_line is None:
                        return None
                    if not txt_line.strip():
                        continue
                    txt: dict[str, str] = {}
                    for tok in txt_line.strip().split():
                        if "=" in tok:
                            k, v = tok.split("=", 1)
                            txt[k] = v
                    return host, port, txt
        return None
    finally:
        _terminate(proc)
