#!/usr/bin/env bash
# prepare  (connected machine): wheels + vendored web assets
# install  (offline machine):   venv from the wheelhouse, then preflight
# Build the wheels on the same OS, CPU and Python version as the lab machines.
set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
  prepare)
    python3 -m pip download -d vendor/wheels cryptography segno setuptools wheel
    python3 scripts/vendor_web.py
    echo "Copy the whole repository, including vendor/ and web/vendor/, to each lab machine."
    ;;
  install)
    python3 -m venv .venv
    # shellcheck disable=SC1091
    . .venv/bin/activate
    pip install --no-index --find-links vendor/wheels setuptools wheel
    pip install --no-index --find-links vendor/wheels --no-build-isolation -e ".[qr]"
    python scripts/preflight.py
    ;;
  *)
    echo "usage: $0 prepare|install" >&2
    exit 2
    ;;
esac
