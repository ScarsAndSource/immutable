#!/usr/bin/env python3
"""tools/web_console.py: launch the Immutable web console.

  python tools/web_console.py [--mode demo|exam] [--port 8000] [--dir DIR] [--open]

demo  one process playing every role (student, witness, assessor, tamper lab)
exam  student pages only; assessor, witness and tamper-lab endpoints refuse

The console is for loopback only. --allow-remote exists for a locked-down rehearsal
network and is not recommended: the console runs student code.
"""
import argparse
import ipaddress
import os
import sys
import webbrowser
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from immutable.server import ImmutableWebServer  # noqa: E402


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Immutable web console")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--dir", default=None, help="working directory for evidence and session data")
    ap.add_argument("--mode", choices=("demo", "exam"), default="demo")
    ap.add_argument("--open", action="store_true", help="open the browser")
    ap.add_argument("--allow-remote", action="store_true", help="permit a non-loopback --host")
    a = ap.parse_args()

    if not _loopback(a.host) and not (a.allow_remote or os.environ.get("IMMUTABLE_PUBLIC_HOST")):
        print(f"refusing to bind {a.host}: the console runs student code. "
              "Use 127.0.0.1, or pass --allow-remote if you really mean it.", file=sys.stderr)
        return 2

    server = ImmutableWebServer(host=a.host, port=a.port,
                                root_dir=Path(a.dir) if a.dir else None, mode=a.mode)
    url = f"http://{a.host}:{server.port}"
    print(f"Immutable console ({a.mode} mode): {url}")
    print("Open that exact address. Other hosts and other sites are refused. Ctrl+C to stop.")
    if a.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
