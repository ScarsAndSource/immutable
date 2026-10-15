# Rehearsal

Three people. **Driver** (hands on keyboard), **Narrator** (talks to the judges),
**Safety** (watches the clock, the fallback and the terminal). Swap roles in every run.

## Schedule

| When | What | Done when |
|---|---|---|
| T-7 days | `scripts/offline_install.sh prepare`, then `install` on the demo machine with Wi-Fi off | `scripts/preflight.py --smoke` prints READY |
| T-5 | Migrate `innerHTML` sites to `html`; delete fake fallback data in `app.js` | preflight shows no innerHTML warning |
| T-4 | Real VM power-off run, `tools/powercut.py`; record the result | `docs/EVALUATION.md` real row filled |
| T-3 | Run every command in `docs/EVALUATION.md`; fill the results table | each number has a seed, date and file |
| T-2 | `scripts/demo_fallback.sh`; record a screen video of the full run | `demo/fallback/` and the video are on a USB stick |
| T-1 | Full timed rehearsal on the demo machine, offline, projector resolution | under 3 minutes, no improvisation |
| T-2 hours | Fresh checkout, `preflight.py --strict --smoke`, new `--dir`, browser at 125 percent zoom | READY |
| T-15 min | Start the console, open the page, press nothing else | page loads styled with Wi-Fi off |

## Drills (do each once, on purpose)

| Failure | Recovery |
|---|---|
| Backend dies mid-demo | Banner shows; restart `web_console.py` with a fresh `--dir`; or go to `demo/fallback/` |
| Page loads without styling | Vendored assets missing: `preflight.py`; fall back to the video |
| Port busy | `--port 8010` and open that address; other addresses are refused by design |
| 401 or 421 in the browser console | You opened a different host name; use exactly the printed URL |
| QR does not scan | Read the `IMR1.` text, or run `validate_receipt.py` on the saved slip |
| Witness not delivering | Show it as unanchored tail; that is the honest case, not a crash |
| Clock wrong | `preflight.py` warns; say so; verdicts do not depend on absolute time |
| Judge asks for a number | Read it from `docs/EVALUATION.md`, with its seed and "simulated" |

## Built or designed: say it exactly

| Item | Say |
|---|---|
| Signed chained events, WAL recovery, batches, roster, verifier, witness, receipt and validator, tamper lab | "Built" |
| False-alarm and crash numbers | "Measured on simulated sessions" |
| Real power-off | "Measured once in a VM" (only after T-4 is done) |
| Browser receipt validator, Pi witness, chained ingest log | "Designed, not built" |
| Real institute pilot, legal review | "Not done" |

## Kill criteria carried over

- Cross-machine round trip not working by 25 percent of build time: stop adding features.
- False alarms above about 1 percent without gutting detection: report time as uncertain instead.
- Witness not working by 60 percent: demote to server checkpoints plus receipts and label the
  witness "designed, not built".

## Final checklist

- [ ] Wi-Fi off, page loads styled
- [ ] `preflight.py --strict --smoke` says READY
- [ ] `docs/POLICY.md` matches the code (preflight checks it)
- [ ] Every number on a slide traces to a file in `demo/fallback/` or `docs/EVALUATION.md`
- [ ] Fallback folder and video on a USB stick and on a second laptop
- [ ] Terminal font large; notifications off; one browser window only
- [ ] The words "tamper-proof", "cheating", "blockchain", "AI" are not on any slide
- [ ] Everyone knows the first sentence of the pitch and the honest answer to question 1
