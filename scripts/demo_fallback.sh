#!/usr/bin/env bash
# Captures real tool output into demo/fallback/ for when the live demo cannot run.
# Run from anywhere; takes a minute or two. Commit the folder and keep a copy on a USB stick.
set -uo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
OUT=demo/fallback
mkdir -p "$OUT"
SEED="${SEED:-1}"

run() {                      # run NAME COMMAND...   (non-zero exit is recorded, not fatal)
  local name="$1"; shift
  if "$@" > "$OUT/$name" 2>&1; then echo "ok        $name"; else echo "exit $?    $name"; fi
}

run 01-scenarios.txt            "$PY" tools/tamper_lab.py list
run 02-control-and-deletion.txt "$PY" tools/tamper_lab.py run C0 D1 --n 5 --seed "$SEED"
run 03-full-matrix.txt          "$PY" tools/tamper_lab.py run --n 20 --seed "$SEED"
run 04-power-sweep.json         "$PY" tools/tamper_lab.py sweep --seed "$SEED" --ops 10
run 05-crash-fuzz-honest.txt    "$PY" tools/crash_fuzz.py 200
run 06-crash-fuzz-lying.txt     "$PY" tools/crash_fuzz.py 200 --lie
run 07-case-note-seed17.txt     "$PY" tools/evaluate.py replay --seed 17 --seats 6 --profile typical

( cd "$OUT" && sha256sum ./* > SHA256SUMS 2>/dev/null || shasum -a 256 ./* > SHA256SUMS )
{ date -u +"captured %Y-%m-%d %H:%M:%S UTC"; echo "seed $SEED"; "$PY" --version; git rev-parse --short HEAD 2>/dev/null; } > "$OUT/CAPTURE.txt"
echo "wrote $OUT (a line starting 'exit' above means that tool reported failures: read that file)"
