# Evaluation

Numbers in this project come from these commands, and from nowhere else. Every table is
labelled **simulated** unless it came from `evaluate.py real`.

## What to run

| Question | Command |
|---|---|
| Do the attacks get caught? | `python tools/tamper_lab.py run --n 200 --seed 1` |
| Do honest faults raise false alarms? | `python tools/evaluate.py false-alarms --labs 84 --seats 6 --seed 1 --out eval/` |
| Does the clock policy fit the drift data? | `python tools/evaluate.py calibrate --per-cell 60 --out eval/` |
| Does a lying disk show up as loss, never silence? | `python tools/crash_fuzz.py 500 --lie` |
| Does recovery keep every acknowledged event? | `python tools/crash_fuzz.py 500` and `python tools/tamper_lab.py sweep --ops 10` |
| Is the merge order-independent? | `python tools/shuffle_check.py --roster R --assessor-pub P --runs 200 DIRS...` |
| Does a real power-off lose acked events? | `tools/powercut.py` (VM, see its docstring) |
| What does one flagged seed look like? | `python tools/evaluate.py replay --seed N --seats 6` |

84 labs times 6 seats is 504 simulated clean sessions. With zero TAMPER_SUSPECTED, the
rule-of-three upper bound on the false-alarm rate is about 0.6 percent (3 divided by 504).
Report that bound, not "zero".

## How to read the tamper matrix

Each trial ends in one of: detected, undetectable by design (with the reason, for example
key theft with no outside anchor), missed, or false alarm. A "detected" claim that is really
a miss is the failure that matters most. `MISSED` and `FALSE_ALARM` make the command exit 1.

## Results

Run `scripts/demo_fallback.sh` to capture raw outputs into `demo/fallback/`, then copy the
figures you quote into this table with the seed and date.

| Measure | Value | Seed | Date | Source file | Simulated? |
|---|---|---|---|---|---|
| Scenarios run, trials each | | | | | yes |
| Missed, false alarm | | | | | yes |
| Clean sessions, TAMPER_SUSPECTED | | | | | yes |
| Note rate on clean sessions | | | | | yes |
| Crash fuzz, acked events lost (honest disk) | | | | | yes |
| Crash fuzz, losses visible (lying disk) | | | | | yes |
| Shuffle runs, distinct case hashes | | | | | yes |
| Real VM power-off, acked events lost | | | | | no |

Performance figures (append latency, verify time for a 3,000-event log) were targets, not
measurements. Measure on the demo machine before quoting any.
