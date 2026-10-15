# V2 decisions

Status: ASSUMED means chosen by me to proceed; override any of them before V2-1.

| # | Decision | Why | Cost | Status |
|---|---|---|---|---|
| D1 | Server is a roster "server" holder; its Ed25519 key lives in an Edge Function secret | reuses witness and anchor machinery | trust the Supabase project owner for the key; compromise forges receipts | ASSUMED |
| D2 | FINAL receipt is server-signed; the workstation `IMR1.` receipt is kept for offline fallback only | a root student cannot forge a server signature | one more format | ASSUMED |
| D3 | Keep `canon.py`; add the ASCII-key rule for server docs | JCS-identical bytes without touching v1 vectors | a decoder must enforce the rule | ASSUMED |
| D4 | Event `v` = 2, prefix `immutable/v1/` kept | old vectors and domains keep working | name is slightly misleading | ASSUMED |
| D5 | Time authority is server `now()`; client clock is informative | defeats clock edits | server dark time needs the tick rule | ASSUMED |
| D6 | Lock after one failed save plus one failed immediate retry | no false lock on one dropped packet; no typing in an outage | up to about 7 s of buffered typing at risk if the app crashes | ASSUMED |
| D7 | Grace: threshold 15 s, per-outage 120 s, total 300 s, examiner-configurable | bounds outage-farming | numbers are guesses; tune on measured lab drops | ASSUMED |
| D8 | Lab-wide faults are handled by assessor-signed incident documents, plus automatic server-dark subtraction | fair to students | needs the examiner to act during the exam | ASSUMED |
| D9 | Authorization is seat-key possession plus invigilator seat assignment; no student passwords | fits the roster model | not suited to BYO devices | ASSUMED |
| D10 | Conduct flags never move the verdict | focus loss has benign causes | a judge may ask why violations are only flagged | ASSUMED |
| D11 | Receipt reasons: submitted, window_end, grace_expired only (no examiner force-close) | smaller surface | emergencies need a new signed config | ASSUMED |
| D12 | Blob retention: keep latest per path at each checkpoint, plus every RUN_START and SUBMIT blob; prune the rest after finalization (hashes stay in the chain) | storage arithmetic: 20 KB file saved every 2 s for 3 h is about 108 MB per student | intermediate versions not recoverable | ASSUMED |
| D13 | Languages first: Python and C; java, cpp, js are in the enum but built later | scope | adapters for others later | ASSUMED |
| D14 | Examiner signs config and incidents with a CLI tool (assessor key offline); a dashboard only submits signed files | keeps the key off the web | less convenient | ASSUMED |
| D15 | Shell: Electron; Python core as PyInstaller sidecar on 127.0.0.1 with a bearer token | reuse the existing core | AV false positives are possible; test on a clean machine | ASSUMED |

## V2-1 spikes (each must pass or the plan changes)
1. An Edge Function verifies an Ed25519 signature and signs an ack within the latency target (p95 under 300 ms is my guess).
2. `pgcrypto` digest in the trigger reproduces `hashing.hx("event", body)` byte for byte.
3. A scheduler tick at 15 s granularity is available on your Supabase plan.
4. Supabase free-tier request and storage limits hold for 5 stations at 1 batch per 2 s.
5. A packaged Electron plus sidecar runs without admin on a clean Windows machine.
