/* teacher.js: the lab board. Server text reaches the DOM only through html`` (safe.js).
 *
 *   TeacherBoard.mount(root, opts) -> { start(), stop(), refresh() }
 *     opts.board / opts.seat   URLs of the two read-only endpoints
 *     opts.headers()           extra request headers (the bearer token on the witness page)
 *     opts.onUnauthorized()    called on a 401
 *     opts.simToggle           show the "Simulated class" switch (console demo only)
 *
 * Shows liveness, the type and time of the last action, and restarts. Never file names,
 * contents or code: the server does not send them, and this page has nowhere to put them.
 */
(function () {
  "use strict";

  const POLL_MS = 5000;     // 30 seats: a plain poll is plenty, Realtime is not worth it
  const FETCH_MS = 4000;
  const LOST_AFTER = 2;     // failed polls in a row before "lost contact" shows

  const STATUS = {
    offline:     { label: "Offline",            mark: "▲" },
    unsubmitted: { label: "Not submitted",      mark: "▲" },
    ended:       { label: "Ended",              mark: "■" },
    quiet:       { label: "Quiet",              mark: "◐" },
    restarted:   { label: "Back after restart", mark: "↻" },
    active:      { label: "Active",             mark: "●" },
    not_started: { label: "Not started",        mark: "○" },
    submitted:   { label: "Submitted",          mark: "✓" },
    transferred: { label: "Moved seat",         mark: "→" },
  };
  const ORDER = Object.keys(STATUS);
  const WHY = {
    offline: "No contact for longer than the offline limit. This is where a power cut, a dead switch port or a frozen machine shows up. If contact returns on the same boot, it was the network or the agent. A new boot means the machine restarted.",
    unsubmitted: "The exam window has closed and this seat has not submitted.",
    ended: "The session ended without a submission (timeout or abort).",
    quiet: "A few heartbeats missed. Often a network blip: watch it for a minute before acting.",
    restarted: "Contact came back on a new boot id, so the machine or its agent restarted. Its log records the recovery.",
    active: "In regular contact with the witness.",
    not_started: "No contact from this seat yet.",
    submitted: "Submitted and sealed.",
    transferred: "This seat was replaced by another machine. Later events arrive under the new seat.",
  };
  const EVENT = {
    FILE_SAVE: "Saved a file", RUN_START: "Started a run", RUN_END: "Run finished",
    SUBMIT: "Submitted", SESSION_END: "Session ended", SESSION_START: "Session started",
    CHECKPOINT: "Checkpoint", HEARTBEAT: "Heartbeat", BOOT: "Machine started",
    RECOVERY: "Recovered after a cut", SYNC_STATE: "Sync state changed",
    TRANSFER: "Moved to a new seat",
  };

  function dur(ms) {
    if (ms == null) return "—";
    const s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return s + " s";
    const m = Math.floor(s / 60);
    if (m < 10) return m + " m " + String(s % 60).padStart(2, "0") + " s";
    if (m < 60) return m + " m";
    return Math.floor(m / 60) + " h " + String(m % 60).padStart(2, "0") + " m";
  }
  const clock = (ms) => (ms == null ? "—" : new Date(ms).toLocaleTimeString());
  const evName = (t) => EVENT[t] || t;

  async function getJson(url, opts) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_MS);
    try {
      const res = await fetch(url, {
        headers: opts.headers ? opts.headers() : {}, signal: ctl.signal, cache: "no-store",
      });
      if (res.status === 401 && opts.onUnauthorized) opts.onUnauthorized();
      if (!res.ok) throw new Error("HTTP " + res.status);
      return await res.json();
    } finally {
      clearTimeout(timer);
    }
  }

  function mount(root, opts) {
    const st = {
      data: null, got: 0, fails: 0, timer: 0, tick: 0, running: false, inflight: false,
      filter: new Set(), sel: null, detail: null, sim: true, sound: false,
      prev: new Map(), seenLab: new Set(), primed: false, ctx: null, title0: "",
    };

    root.innerHTML = html`
      <div class="tb">
        <div class="between">
          <div>
            <div class="eyebrow">Teacher</div>
            <h1 class="tb-h">Lab board</h1>
            <p class="mute small tb-sub"></p>
          </div>
          <div class="gap tb-ctl">
            <span class="tb-fresh mono small mute"></span>
            ${opts.simToggle ? html`<label class="tb-chk"><input type="checkbox" data-act="sim" checked/> Simulated class</label>` : ""}
            <label class="tb-chk"><input type="checkbox" data-act="sound"/> Sound alert</label>
            <button type="button" class="btn" data-act="refresh">Refresh</button>
          </div>
        </div>
        <div class="tb-banners" role="status"></div>
        <div class="tb-chips" role="group" aria-label="Filter by status"></div>
        <div class="tb-grid"></div>
        <div class="tb-detail"></div>
        <p class="mute small tb-note">Protected, not watched. This board shows whether each machine is in contact, and the type and time of its last action. It never shows file names, contents or code. Times are the witness's clock: when it learned of the event.</p>
        <div class="tb-sr" aria-live="polite"></div>
      </div>`;

    const q = (s) => root.querySelector(s);
    const el = { sub: q(".tb-sub"), fresh: q(".tb-fresh"), banners: q(".tb-banners"),
                 chips: q(".tb-chips"), grid: q(".tb-grid"), detail: q(".tb-detail"), sr: q(".tb-sr") };
    const since = () => (st.got ? performance.now() - st.got : 0);
    const ageSpan = (ms) => html`<span class="tb-age mono" data-age="${ms}">${dur(ms)}</span>`;

    // ------------------------------------------------------------------ render
    function heard(s) {
      if (s.status === "not_started") return "No contact yet";
      if (s.status === "submitted") return html`Submitted ${s.last_contact_ms ? "· " + clock(s.last_contact_ms) : ""}`;
      if (s.status === "transferred") return "Seat replaced by another machine";
      if (s.age_ms == null) return "—";
      return s.status === "offline"
        ? html`<b>No contact for ${ageSpan(s.age_ms)}</b>`
        : html`Heard ${ageSpan(s.age_ms)} ago`;
    }

    function card(s, now) {
      const m = STATUS[s.status] || { label: s.status, mark: "?" };
      const act = s.last_action;
      const on = st.sel && st.sel.key === s.key;
      return html`<button type="button" class="tb-card tb-s-${s.status}${s.simulated ? " tb-sim" : ""}${on ? " on" : ""}" data-key="${s.key}" data-session="${s.session || ""}" data-ws="${s.ws}">
        <span class="tb-top"><b class="mono">${s.ws}</b><span class="tb-pill"><span aria-hidden="true">${m.mark}</span> ${m.label}</span></span>
        <span class="tb-cand">${s.candidate || "spare seat"}${s.simulated ? " · simulated" : ""}</span>
        <span class="tb-line">${heard(s)}</span>
        <span class="tb-line">${act ? html`${evName(act.type)}${act.seen_ms != null ? html` · ${ageSpan(Math.max(0, now - act.seen_ms))} ago` : ""}` : "No action reported yet"}</span>
        ${s.restarts ? html`<span class="tb-line tb-sm">Restarted ×${s.restarts}${s.last_restart && s.last_restart.gap_before_ms != null ? " · back after " + dur(s.last_restart.gap_before_ms) : ""}</span>` : ""}
        ${s.waiting ? html`<span class="tb-line tb-sm">${s.waiting} event${s.waiting === 1 ? "" : "s"} not yet at the witness</span>` : ""}
        ${s.budget ? html`<span class="tb-line tb-sm">Grace left ${dur(s.budget.remaining_ms)}</span>` : ""}
      </button>`;
    }

    function banners(d) {
      const out = [];
      if (st.fails >= LOST_AFTER) {
        out.push(html`<div class="tb-banner bad"><b>Lost contact with the witness.</b> This picture is <span class="tb-lost mono">${dur(since())}</span> old. Treat every card as stale until this clears.</div>`);
      }
      if (d) {
        for (const l of d.lab || []) {
          if (l.kind === "dropout") {
            out.push(html`<div class="tb-banner warn"><b>${l.count} of ${l.of} seats</b> stopped reporting within ${dur(d.policy.lab_window_ms)} of each other, from ${clock(l.since_ms)}. That points at the room (switch, router, power, or this witness), not at ${l.count} separate machines. Per-seat alerts are held back.</div>`);
          } else {
            out.push(html`<div class="tb-banner info"><b>${l.count} of ${l.of} seats</b> restarted within ${dur(d.policy.lab_recovery_window_ms)} of each other, from ${clock(l.since_ms)}. Consistent with a lab-wide power cut. Each seat's log records a recovery: check the audit view afterwards.</div>`);
          }
        }
        if (d.has_simulated) {
          out.push(html`<div class="tb-banner sim">Seats marked <b>simulated</b> are generated for the demo and are not evidence. Only the other seats are real.</div>`);
        }
      }
      return out;
    }

    function chips(d) {
      const c = d.counts;
      const one = (k) => html`<button type="button" class="tb-chip tb-s-${k}" data-filter="${k}" aria-pressed="${st.filter.has(k) ? "true" : "false"}">${c[k]} ${STATUS[k].label.toLowerCase()}</button>`;
      return html`<span class="tb-total">${c.total} seats</span>${ORDER.filter((k) => c[k]).map(one)}${st.filter.size ? html`<button type="button" class="tb-chip" data-filter="">Show all</button>` : ""}`;
    }

    function trailView(d) {
      if (!d) return html`<p class="mute small">No contact history yet.</p>`;
      const gaps = d.gaps || [];
      const boots = d.boots || [];
      const limit = st.data ? dur(st.data.policy.active_ms) : "";
      return html`
        <h3 class="tb-h3">Silences longer than ${limit}</h3>
        ${gaps.length ? html`<div class="tb-table"><table><thead><tr><th>From</th><th>To</th><th>Silent for</th><th>What happened</th></tr></thead><tbody>${gaps.slice().reverse().map((g) => html`<tr><td class="mono">${clock(g.from_ms)}</td><td class="mono">${clock(g.to_ms)}</td><td>${dur(g.gap_ms)}</td><td>${g.cause === "restart" ? "Machine restarted" : "Same boot: network or agent"}</td></tr>`)}</tbody></table></div>` : html`<p class="mute small">None. Contact has been steady.</p>`}
        <h3 class="tb-h3">Boots</h3>
        <ul class="plain">${boots.map((b, i) => html`<li><b class="mono">${i + 1}</b><span>First seen ${clock(b.seen_ms)}${i > 0 && b.gap_before_ms != null ? " · back after " + dur(b.gap_before_ms) : ""}</span></li>`)}</ul>`;
    }

    function detail(d) {
      if (!st.sel) return "";
      const s = d.seats.find((x) => x.key === st.sel.key);
      if (!s) return "";
      const m = STATUS[s.status] || { label: s.status, mark: "?" };
      const a = s.last_action, e = s.last_event;
      return html`<div class="card tb-dcard">
        <div class="between">
          <div><div class="eyebrow">Seat</div><h2 class="mono">${s.ws}</h2>
            <div class="mute small">${s.candidate || "spare seat"} · session ${s.session || "none yet"}</div></div>
          <div class="gap"><span class="tb-pill tb-s-${s.status}"><span aria-hidden="true">${m.mark}</span> ${m.label}</span>
            <button type="button" class="btn" data-act="close">Close</button></div>
        </div>
        <p class="tb-why">${WHY[s.status] || ""}</p>
        <div class="tb-facts">
          <div><span>Last contact</span><b>${s.last_contact_ms ? clock(s.last_contact_ms) + (s.last_contact_kind ? " · " + s.last_contact_kind : "") : "—"}</b></div>
          <div><span>Last action</span><b>${a ? evName(a.type) + " · " + clock(a.seen_ms) : "—"}</b></div>
          <div><span>Last event</span><b>${e ? evName(e.type) + " · " + clock(e.seen_ms) : "—"}</b></div>
          <div><span>Held by witness</span><b>${s.held_upto != null && s.held_upto >= 0 ? "to event " + s.held_upto : "nothing yet"}</b></div>
          <div><span>Not yet at witness</span><b>${s.waiting != null ? s.waiting + " events" : "—"}</b></div>
          <div><span>Restarts</span><b>${s.restarts}</b></div>
          ${s.budget ? html`<div><span>Grace left</span><b>${dur(s.budget.remaining_ms)} of ${dur(s.budget.total_ms)}</b></div>` : ""}
        </div>
        ${s.session ? trailView(st.detail) : html`<p class="mute small">No contact yet, so there is no history.</p>`}
      </div>`;
    }

    function fresh() {
      el.fresh.textContent = !st.data
        ? (st.fails ? "No answer yet" : "Connecting…")
        : st.fails ? `Update failed ${st.fails}×, data is ${dur(since())} old`
        : `Updated ${dur(since())} ago`;
    }

    function paint() {
      const d = st.data;
      const f = document.activeElement;
      let keep = null;                                 // keep keyboard focus across re-renders
      if (f && root.contains(f) && f.dataset) {
        if (f.dataset.key) keep = '[data-key="' + CSS.escape(f.dataset.key) + '"]';
        else if (f.dataset.filter !== undefined) keep = '[data-filter="' + CSS.escape(f.dataset.filter) + '"]';
      }
      el.banners.innerHTML = html`${banners(d)}`;
      if (!d) {
        el.chips.innerHTML = "";
        el.grid.innerHTML = html`<p class="mute">Waiting for the first update…</p>`;
        el.detail.innerHTML = "";
        el.sub.textContent = "";
        fresh();
        return;
      }
      el.sub.textContent = [d.exam_id, d.witness ? "witness " + d.witness : "", d.source].filter(Boolean).join(" · ");
      el.chips.innerHTML = html`${chips(d)}`;
      const rows = d.seats.filter((s) => !st.filter.size || st.filter.has(s.status));
      el.grid.innerHTML = html`${rows.length ? rows.map((s) => card(s, d.now_ms)) : html`<p class="mute">No seats match this filter.</p>`}`;
      el.detail.innerHTML = html`${detail(d)}`;
      if (keep) {
        const n = root.querySelector(keep);
        if (n) n.focus({ preventScroll: true });
      }
      fresh();
    }

    // ------------------------------------------------------------------ alerts
    function beep() {
      try {
        const C = window.AudioContext || window.webkitAudioContext;
        if (!C) return;
        if (!st.ctx) st.ctx = new C();
        if (st.ctx.state === "suspended") st.ctx.resume();
        const o = st.ctx.createOscillator(), g = st.ctx.createGain();
        o.frequency.value = 660; g.gain.value = 0.05;
        o.connect(g); g.connect(st.ctx.destination);
        o.start(); o.stop(st.ctx.currentTime + 0.25);
      } catch (_) { /* sound is a convenience, never an error */ }
    }

    function alerts(d) {
      const drop = (d.lab || []).find((l) => l.kind === "dropout");
      const grouped = new Set(drop ? drop.ws : []);    // one incident, not one alert per seat
      const msgs = [];
      for (const l of d.lab || []) {
        const k = l.kind + ":" + l.since_ms;
        if (!st.seenLab.has(k)) {
          st.seenLab.add(k);
          if (st.primed) msgs.push(l.kind === "dropout"
            ? `${l.count} of ${l.of} seats went quiet together`
            : `${l.count} of ${l.of} seats restarted together`);
        }
      }
      for (const s of d.seats) {
        if (st.primed && s.status === "offline" && st.prev.has(s.key)
            && st.prev.get(s.key) !== "offline" && !grouped.has(s.ws)) msgs.push(`Seat ${s.ws} is offline`);
      }
      st.prev = new Map(d.seats.map((s) => [s.key, s.status]));
      st.primed = true;
      const urgent = (d.counts.offline || 0) + (d.counts.unsubmitted || 0);
      document.title = (urgent ? "(" + urgent + ") " : "") + "Lab board";
      if (msgs.length) {
        el.sr.textContent = msgs.join(". ");
        if (st.sound) beep();
      }
    }

    // ------------------------------------------------------------------ data
    async function loadDetail() {
      if (!st.sel || !st.sel.session) { st.detail = null; return; }
      try {
        st.detail = await getJson(opts.seat + "?session=" + encodeURIComponent(st.sel.session)
                                  + "&ws=" + encodeURIComponent(st.sel.ws), opts);
      } catch (_) { st.detail = null; }
    }

    async function poll() {
      if (!st.running || st.inflight) return;
      st.inflight = true;
      try {
        const d = await getJson(opts.board + (opts.simToggle && !st.sim ? "?sim=0" : ""), opts);
        st.data = d; st.got = performance.now(); st.fails = 0;
        alerts(d);
        if (st.sel) await loadDetail();
      } catch (_) {
        st.fails += 1;
      } finally {
        st.inflight = false;
      }
      paint();
      if (st.running) st.timer = setTimeout(poll, POLL_MS);
    }

    function live() {                                  // once a second: tick ages, no network
      const add = since();
      root.querySelectorAll(".tb-age").forEach((n) => {
        const b = Number(n.dataset.age);
        if (Number.isFinite(b)) n.textContent = dur(b + add);
      });
      const lost = q(".tb-lost");
      if (lost) lost.textContent = dur(add);
      fresh();
    }

    async function select(key, session, ws) {
      if (st.sel && st.sel.key === key) { st.sel = null; st.detail = null; paint(); return; }
      st.sel = { key, session, ws };
      st.detail = null;
      paint();
      await loadDetail();
      paint();
      el.detail.scrollIntoView({ block: "nearest" });
    }

    function refresh() {
      clearTimeout(st.timer);
      st.inflight = false;
      poll();
    }

    // ------------------------------------------------------------------ events
    root.addEventListener("click", (e) => {
      const t = e.target;
      if (!t.closest) return;
      const f = t.closest("[data-filter]");
      if (f) {
        const k = f.dataset.filter;
        if (!k) st.filter.clear(); else if (st.filter.has(k)) st.filter.delete(k); else st.filter.add(k);
        paint();
        return;
      }
      const c = t.closest("[data-key]");
      if (c) { select(c.dataset.key, c.dataset.session, c.dataset.ws); return; }
      const a = t.closest("[data-act]");
      if (!a) return;
      if (a.dataset.act === "close") { st.sel = null; st.detail = null; paint(); }
      else if (a.dataset.act === "refresh") refresh();
    });
    root.addEventListener("change", (e) => {
      const act = e.target.dataset ? e.target.dataset.act : "";
      if (act === "sim") { st.sim = e.target.checked; st.prev = new Map(); st.primed = false; refresh(); }
      if (act === "sound") { st.sound = e.target.checked; if (st.sound) beep(); }
    });

    paint();
    return {
      start() {
        if (st.running) return;
        st.running = true;
        st.title0 = document.title;
        poll();
        st.tick = setInterval(live, 1000);
      },
      stop() {
        st.running = false;
        clearTimeout(st.timer);
        clearInterval(st.tick);
        if (st.title0) document.title = st.title0;
      },
      refresh,
    };
  }

  window.TeacherBoard = { mount };
})();
