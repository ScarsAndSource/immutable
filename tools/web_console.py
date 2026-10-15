#!/usr/bin/env python3
"""tools/web_console.py: Launch the Immutable Web Console and API service.

Usage:
  python tools/web_console.py [--host 127.0.0.1] [--port 8000] [--open]
"""
import argparse
import sys
import webbrowser
from pathlib import Path

# Add src/ and repo root
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

from immutable.server import ImmutableWebServer


def main() -> int:
    parser = argparse.ArgumentParser(description="Immutable Web Console & API Service")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--dir", default=None, help="Working directory for evidence and session data")
    parser.add_argument("--open", action="store_true", help="Automatically open browser")
    args = parser.parse_args()

    root_dir = Path(args.dir) if args.dir else None
    server = ImmutableWebServer(host=args.host, port=args.port, root_dir=root_dir)
    url = f"http://{args.host}:{server.port}"

    print(f"=== Immutable Web Console ===")
    print(f"Listening on: {url}")
    print(f"Candidate Workspace, Live Ledger, Assessor Audit, and Tamper Lab active.")
    print("Press Ctrl+C to terminate.")

    if args.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Immutable Web Console...")
    finally:
        server.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
