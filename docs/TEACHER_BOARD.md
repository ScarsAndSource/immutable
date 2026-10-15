# Teacher Board

Real-time, read-only awareness of exam room health, designed for a proctor or invigilator.

## Philosophy: Protected, Not Watched

The Teacher Board is deliberately minimal:
- **No keystroke stream or cursor tracking**: Students think and draft in private.
- **No screenshots or camera feeds**: Hardware drivers are unmonitored.
- **No "idle student" alerts**: A student thinking quietly for 20 minutes is not an anomaly.
- **What it does show**: Machine liveness, system reboots (boot count), unsent queue depth (events committed locally but not yet co-signed), and the last coarse action (`SAVE solution.py`, `RUN`, `CHECKPOINT`).

## States

| State | Definition | Visual Indicator |
|---|---|---|
| `active` | Contact received within `quiet_after_s` (default: 20s) | Green pill |
| `quiet` | Contact between 20s and `offline_after_s` (default: 60s) | Amber pill |
| `offline` | No contact for > 60s | Red pill |
| `not_started`| Listed in roster but seat has never contacted witness | Grey pill |

## Incidents

- **Restart / Reboot**: Detected when a seat reports a new `boot_id` or `boot_count > 1`.
- **Unsent Queue**: Difference between local agent seq and witness held seq (`last_seq - held_upto`). Indicates data at risk if power drops immediately.
- **Lab-Wide Incident**: Triggered when at least 3 seats and at least 40% of the room go offline simultaneously (e.g. switch outage, lab power failure).

## Access

- Console demo: Available under the **Teacher** tab in demo mode (omitted in exam mode).
- Real-lab witness: Token-gated via `--teacher-token-file` on `witness_node.py`.
- Supabase Edge Functions: Served by `supabase/functions/board` requiring `Authorization: Bearer <TEACHER_TOKEN>`.
