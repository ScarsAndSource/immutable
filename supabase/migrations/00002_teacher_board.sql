-- Teacher board extensions: denormalized last-known activity per seat, and boot tracking.
-- Safe to apply multiple times.

alter table sessions
  add column if not exists last_boot_id text,
  add column if not exists last_typ text,
  add column if not exists last_file text,
  add column if not exists last_event_id text,
  add column if not exists last_seq integer,
  add column if not exists last_admit_ms bigint;

create table if not exists seat_boots (
  seat_id       text not null,
  boot_id       text not null,
  first_seen_ms bigint not null,
  primary key (seat_id, boot_id)
);

create index if not exists idx_seat_boots_seat on seat_boots(seat_id);

alter table seat_boots enable row level security;
-- Service role has full access; anonymous has none.
