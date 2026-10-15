/* Immutable web console client.
 * Server text reaches the DOM only through html`` (safe.js) or textContent. */

const I18N = {
  en: {
    briefing_title: "Before you begin",
    briefing_sub: "An immutable ship’s logbook of your practical exam. Protected, not watched.",
    record_title: "What we record",
    record_1_title: "File state fingerprints",
    record_1_desc: "Cryptographic SHA-256 digests committed only when you explicitly save, execute, or submit code.",
    record_2_title: "System restart & sync intervals",
    record_2_desc: "Timestamps of terminal power events, kernel boots, and local network packet deliveries.",
    record_3_title: "Local hardware checksum integrity",
    record_3_desc: "Periodic peripheral seal verifications to ensure the workstation partition remains unaltered.",
    never_title: "What we never record",
    never_1_title: "Keystrokes, timing cadence, or cursor paths",
    never_1_desc: "No keyloggers or behavior profiling. You think and draft in total privacy.",
    never_2_title: "Screen captures, desktop stream, or frame buffers",
    never_2_desc: "Zero visual recording of your work process or scratch notes.",
    never_3_title: "Camera, microphone, acoustic, or biometric scans",
    never_3_desc: "All audiovisual capture drivers are electrically disconnected on this node.",
    never_4_title: "Network traffic outside the isolated exam bundle",
    never_4_desc: "The local switch strictly permits only offline manual mirror references.",
    guarantee_text: "“Protected, not watched. This cryptographic record protects your submission if hardware power drops or an evaluation is formally contested.”",
    affirm_label: "I acknowledge the immutable audit log policy for Seat 19",
    start_btn: "I understand, start my exam",
    receipt_header: "Submitted",
    receipt_footnote: "Keep this receipt. If your result is ever questioned, the assessor can check it against the lab's records.",
    copy_slip: "Copy",
    copied: "Copied",
  },
  hi: {
    briefing_title: "शुरू करने से पहले",
    briefing_sub: "आपकी प्रायोगिक परीक्षा का अपरिवर्तनीय लॉगबुक। सुरक्षित, निगरानी मुक्त।",
    record_title: "हम क्या दर्ज करते हैं",
    record_1_title: "फ़ाइल स्थिति फ़िंगरप्रिंट्स",
    record_1_desc: "क्रिप्टोग्राफ़िक SHA-256 डाइजेस्ट केवल तब दर्ज होते हैं जब आप कोड सहेजते, चलाते या जमा करते हैं।",
    record_2_title: "सिस्टम पुनः आरंभ और सिंक अंतराल",
    record_2_desc: "टर्मिनल पावर घटनाओं, कर्नेल बूट्स और स्थानीय नेटवर्क पैकेट वितरण के समय टिकट।",
    record_3_title: "स्थानीय हार्डवेयर चेकसम सत्यनिष्ठा",
    record_3_desc: "कार्यस्थान विभाजन को अपरिवर्तित रखने के लिए आवधिक सुरक्षा सील सत्यापन।",
    never_title: "हम कभी क्या दर्ज नहीं करते",
    never_1_title: "कीस्ट्रोक्स, टाइपिंग गति या कर्सर पथ",
    never_1_desc: "कोई कीलॉगर या व्यवहार प्रोफ़ाइलिंग नहीं। आप पूर्ण गोपनीयता में सोचते और लिखते हैं।",
    never_2_title: "स्क्रीन कैप्चर, डेस्कटॉप स्ट्रीम या फ़्रेम बफ़र्स",
    never_2_desc: "आपकी कार्य प्रक्रिया या रफ़ नोट्स की कोई दृश्य रिकॉर्डिंग नहीं होती।",
    never_3_title: "कैमरा, माइक्रोफ़ोन या बायोमेट्रिक स्कैन",
    never_3_desc: "इस नोड पर सभी ऑडियोविज़ुअल कैप्चर ड्राइवर हार्डवेयर स्तर पर डिस्कनेक्ट हैं।",
    never_4_title: "परीक्षा बंडल के बाहर नेटवर्क ट्रैफ़िक",
    never_4_desc: "स्थानीय स्विच केवल ऑफ़लाइन मैन्युअल संदर्भों की अनुमति देता है।",
    guarantee_text: "“सुरक्षित, निगरानी मुक्त। यह क्रिप्टोग्राफ़िक रिकॉर्ड बिजली गुल होने या अंक विवाद की स्थिति में आपकी रक्षा करता है।”",
    affirm_label: "मैं सीट 19 के लिए अपरिवर्तनीय ऑडिट लॉग नीति को स्वीकार करता हूँ",
    start_btn: "मैं समझ गया, परीक्षा शुरू करें",
    receipt_header: "जमा किया गया",
    receipt_footnote: "इस रसीद को सुरक्षित रखें। परिणाम पर कभी सवाल उठे तो परीक्षक इसे प्रयोगशाला के रिकॉर्ड से मिलाकर जाँच सकता है।",
    copy_slip: "कॉपी करें",
    copied: "कॉपी हो गया",
  },
};

const VIEWS = ["briefing", "workstation", "receipt", "assessor", "tamperlab", "witness"];
const FILES = {
  "solution.py":
    '"""Practical Exam: Task 1 - Consistent Digest Matrix"""\n\n' +
    "def solve(n: int) -> int:\n" +
    "    total = sum(i * i for i in range(n))\n" +
    '    print(f"Computed sum of squares for {n}: {total}")\n' +
    "    return total\n\n" +
    'if __name__ == "__main__":\n' +
    "    solve(10)\n",
  "test_cases.py":
    "import unittest\nfrom solution import solve\n\n" +
    "class SolutionTests(unittest.TestCase):\n" +
    "    def test_small(self):\n" +
    "        self.assertEqual(solve(3), 0 + 1 + 4)\n\n" +
    'if __name__ == "__main__":\n' +
    "    unittest.main()\n",
};

let currentLang = "en";
let sessionData = null;
let activeFile = "solution.py";
let allScenarios = [];
let currentReceipt = null;
let toastTimer = null;

const $ = (id) => document.getElementById(id);
const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };
const badge = (text, kind = "") => html`<span class="badge ${kind}">${text}</span>`;
const offline = (title) => html`<div class="card"><h2 class="serif">${title}</h2><p class="mute">Cannot reach the evidence server. Make sure web_console.py is running.</p></div>`;

// --- API ---
async function api(path, options = {}) {
  try {
    const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`);
    document.body.dataset.backend = "up";
    return await res.json();
  } catch (err) {
    document.body.dataset.backend = "down";
    console.warn("Backend unavailable:", err.message);
    return null;
  }
}

// --- Router ---
function navigateTo(viewId) {
  VIEWS.forEach((id) => { const el = $(`view-${id}`); if (el) el.classList.toggle("hidden", id !== viewId); });
  document.querySelectorAll("[data-nav-view]").forEach((b) => {
    const on = b.dataset.navView === viewId;
    b.classList.toggle("on", on);
    if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  window.scrollTo({ top: 0, behavior: "smooth" });
  const load = { workstation: refreshSession, receipt: loadReceipt, assessor: loadAssessorCase, tamperlab: loadTamperLab, witness: loadWitnessReport }[viewId];
  if (load) load();
}

// --- Language ---
function setLanguage(lang) {
  currentLang = lang;
  const t = I18N[lang] || I18N.en;
  document.documentElement.lang = lang;
  $("lang-en").classList.toggle("on", lang === "en");
  $("lang-hi").classList.toggle("on", lang === "hi");
  const map = {
    "main-heading": t.briefing_title, "sub-heading": t.briefing_sub,
    "txt-record-title": t.record_title, "txt-never-title": t.never_title,
    "marginal-text": t.guarantee_text, "txt-affirm-label": t.affirm_label,
    "btn-text": t.start_btn, "txt-receipt-header": t.receipt_header,
    "txt-receipt-footnote": t.receipt_footnote, "copy-text": t.copy_slip,
  };
  for (let i = 1; i <= 3; i++) { map[`txt-record-${i}-t`] = t[`record_${i}_title`]; map[`txt-record-${i}-d`] = t[`record_${i}_desc`]; }
  for (let i = 1; i <= 4; i++) { map[`txt-never-${i}-t`] = t[`never_${i}_title`]; map[`txt-never-${i}-d`] = t[`never_${i}_desc`]; }
  for (const [id, text] of Object.entries(map)) setText(id, text);
}

// --- Workstation ---
async function refreshSession() {
  const data = await api("/api/student/session");
  if (data) { sessionData = data; renderWorkstation(data); }
  else { renderFilesList([]); renderEventsLedger([]); }
}

function renderWorkstation(data) {
  setText("ws-terminal-id", `Lab 04 · ${data.ws_id}`);
  setText("ws-head-hash", data.head ? data.head.slice(0, 16) + "…" : "—");
  setText("ws-seq-counter", `Seq ${data.last_seq}`);
  setText("ws-witness-tag", `Witness · ${data.witness?.anchors_count || 0} co-signatures`);
  renderSyncState(data.sync || {});
  renderFilesList(data.files || []);
  renderEventsLedger(data.events || []);

  const btn = $("btn-submit-exam");
  btn.disabled = false;
  if (data.ended) { btn.textContent = "View receipt"; btn.onclick = () => navigateTo("receipt"); }
  else { btn.textContent = "Final submit & seal"; btn.onclick = handleFinalSubmit; }
}

function renderSyncState(sync) {
  const state = sync.state || "connecting";
  const messages = {
    synced: `Saved and confirmed through event #${sync.last_confirmed_seq}.`,
    probing: "Saving is being retried. You can keep typing for a moment.",
    locked: "Sync stopped. Editing is paused until the saved work is confirmed. Your local draft is safe.",
    resync: "Reconnecting and confirming the saved evidence. Editing remains paused.",
    connecting: "Connecting evidence sync. Editing will open after the first confirmation.",
    finalized: "This session is finalized. Your receipt is available.",
  };
  const banner = $("sync-status-banner");
  banner.textContent = messages[state] || "Checking evidence sync…";
  banner.classList.toggle("bad", state === "locked");
  $("code-editor-textarea").readOnly = sync.editable !== true;
  $("btn-save-file").disabled = sync.editable !== true;
}

function renderFilesList(files) {
  const c = $("ws-files-list");
  c.innerHTML = "";
  files.forEach((f) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tab" + (f.path === activeFile ? " on" : "");
    b.textContent = f.path;
    b.title = f.sha256 ? `${f.size} B · ${f.sha256.slice(0, 16)}…` : `${f.size} B`;
    b.addEventListener("click", () => selectFile(f.path));
    c.appendChild(b);
  });
}

function renderEventsLedger(events) {
  setText("ws-events-total-count", `${events.length} events`);
  const c = $("ws-events-stream");
  c.innerHTML = "";
  [...events].reverse().forEach((ev, i) => {
    const d = ev.data || {};
    const detail = d.path ? `${d.path} (${d.size || 0} B)`
      : d.reason ? `reason: ${d.reason}`
      : d.manifest_sha256 ? `manifest: ${d.manifest_sha256.slice(0, 8)}…`
      : d.merkle_root ? `root: ${d.merkle_root.slice(0, 8)}…` : "";
    const time = ev.wall_ms ? new Date(ev.wall_ms).toLocaleTimeString() : "";
    const li = document.createElement("li");
    li.className = "ev" + (i === 0 ? " new" : "");
    li.innerHTML = html`<div><span><b class="mono">#${String(ev.seq).padStart(4, "0")}</b> <span class="tag">${ev.type}</span></span><span class="mono mute">${time}</span></div><div><span class="detail mute">${detail}</span><span class="mono mute">${ev.hash ? ev.hash.slice(0, 8) : ""}</span></div>`;
    c.appendChild(li);
  });
}

function selectFile(path) {
  activeFile = path;
  setText("editor-filename", path);
  if (FILES[path] !== undefined) $("code-editor-textarea").value = FILES[path];
  refreshSession();
}

async function withLabel(id, busy, idle, fn) {
  const btn = $(id);
  btn.textContent = busy; btn.disabled = true;
  try { return await fn(); }
  finally { btn.textContent = idle; btn.disabled = false; }
}

async function handleSaveFile() {
  const content = $("code-editor-textarea").value;
  const res = await withLabel("btn-save-file", "Saving…", "Save", () =>
    api("/api/student/file", { method: "POST", body: JSON.stringify({ path: activeFile, content }) }));
  showToast(res?.confirmed ? "Saved and confirmed" : "Saved locally. Confirmation is retrying");
  refreshSession();
}

async function handleRunCode() {
  const res = await withLabel("btn-run-code", "Running…", "Run", () =>
    api("/api/student/run", { method: "POST", body: JSON.stringify({ path: activeFile }) }));
  const term = $("execution-terminal-output");
  if (res) {
    const err = res.stderr ? `\n[stderr]\n${res.stderr}` : "";
    term.textContent = `[exit ${res.exit_code} · ${res.duration_ms} ms]\n${res.stdout || ""}${err}`;
    showToast("Run recorded");
  } else {
    term.textContent = "Run failed. The server is unreachable or running code is disabled.";
  }
  refreshSession();
}

async function handleCheckpoint() {
  await withLabel("btn-checkpoint", "Working…", "Checkpoint", () => api("/api/student/checkpoint", { method: "POST" }));
  showToast("Checkpoint committed");
  refreshSession();
}

async function handleFlush() {
  await withLabel("btn-flush", "Syncing…", "Sync", () => api("/api/student/flush", { method: "POST" }));
  showToast("Delivered to the witness");
  refreshSession();
}

async function handleFinalSubmit() {
  if (!window.confirm("Final submit? This freezes your files, seals the session and issues your receipt. It cannot be undone.")) return;
  const btn = $("btn-submit-exam");
  btn.textContent = "Submitting…"; btn.disabled = true;
  const res = await api("/api/student/submit", { method: "POST" });
  if (!res) {
    btn.textContent = "Final submit & seal"; btn.disabled = false;
    showToast("Submit failed. Check the connection and try again");
    return;
  }
  sessionData = { ...(sessionData || {}), receipt: res };
  navigateTo("receipt");
}

// --- Receipt ---
function slipText(r) {
  return [
    "IMMUTABLE RECEIPT",
    `Exam ${r.exam_id}   Seat ${r.ws_id}   Candidate ${r.candidate}`,
    `Events recorded: ${r.events}`,
    `Final event: ${r.head_groups}`,
    `Signed by this computer at ${r.signed_at} (its own clock)`,
    `Receipt ID: ${r.receipt_id}`,
    "",
    r.token, // keep last: the validator reads from IMR1. to the end
  ].join("\n");
}

async function loadReceipt() {
  let r = sessionData?.receipt;
  if (!r || !r.token) r = await api("/api/student/receipt");
  if (!r || !r.token) {
    currentReceipt = null;
    setText("receipt-no", "");
    setText("receipt-submitted-date", "Not submitted yet");
    setText("receipt-standing", "Nothing to show until you submit.");
    $("receipt-qr").innerHTML = "";
    return;
  }
  currentReceipt = r;
  setText("receipt-no", "№ " + r.receipt_id);
  setText("receipt-id", r.receipt_id);
  setText("receipt-submitted-date", r.signed_at);
  setText("receipt-seat-val", r.ws_id);
  setText("receipt-events", String(r.events));
  setText("receipt-head", r.head_groups);
  setText("receipt-standing", r.standing.text);
  setText("receipt-seal", r.standing.code === "HELD_BY_WITNESS" ? "Held by witness" : "Signed by this computer");
  $("digest-raw").value = r.token;
  const qr = $("receipt-qr");
  if (r.qr_svg) qr.innerHTML = html`${raw(r.qr_svg)}`; else qr.innerHTML = "";
  $("receipt-qr-missing").classList.toggle("hidden", !!r.qr_svg);
}

async function checkReceipt() {
  const out = $("receipt-check-out");
  out.replaceChildren();
  const res = await api("/api/receipt/check", { method: "POST", body: JSON.stringify({ token: $("receipt-check-input").value }) });
  if (!res) return;
  const add = (text, cls) => {
    const li = document.createElement("li");
    li.textContent = text; // textContent, never innerHTML
    if (cls) li.className = cls;
    out.appendChild(li);
  };
  for (const c of res.checks) add(`${c.ok ? "Pass" : c.required ? "Fail" : "Note"} · ${c.text}`, c.ok ? "ok" : c.required ? "bad" : "mute");
  add(res.valid ? "Receipt valid" : "Receipt not valid", "verdict " + (res.valid ? "ok" : "bad"));
  add(res.limits, "mute small");
}

// --- Assessor audit ---
async function loadAssessorCase() {
  const box = $("assessor-content-area");
  box.innerHTML = html`<p class="mute">Verifying signatures…</p>`;
  const data = await api("/api/assessor/case");
  if (!data || !data.body) { box.innerHTML = html`${offline("Assessor store offline")}`; return; }

  const b = data.body, s = b.summary || {}, ses = b.sessions?.[0] || {};
  const suspect = ses.verdict === "TAMPER_SUSPECTED";
  const stat = (label, v, cls = "") => html`<div class="stat"><span class="mute">${label}</span><b class="serif ${cls}">${v}</b></div>`;
  const list = (items, mark, cls) => items.length
    ? items.map((t) => html`<li class="${cls}"><b>${mark}</b><span>${t}</span></li>`)
    : html`<li class="mute"><span>None.</span></li>`;

  const proven = (ses.chains?.[0]?.proven || []).map((p) => p.text);
  const unprovable = (ses.chains?.[0]?.unprovable || []).map((u) => u.text);
  const flagged = (ses.findings || []).filter((f) => f.severity === "suspect").map((f) => `[${f.code}] event ${f.seq}: ${f.detail}`);

  box.innerHTML = html`
    <div class="card">
      <div class="between">
        <div><div class="eyebrow">Case</div><h2>${b.exam_id}</h2></div>
        <span class="mono small mute">spec ${b.spec} · verifier ${b.verifier} · ${data.hash ? data.hash.slice(0, 12) : ""}…</span>
      </div>
      <div class="stats">
        ${stat("Sessions", s.sessions ?? 0)}
        ${stat("Anchored", s.anchored ?? 0, "ok")}
        ${stat("Self-consistent only", s.self_consistent_only ?? 0)}
        ${stat("Tamper suspected", s.tamper_suspected ?? 0, s.tamper_suspected ? "bad" : "")}
      </div>
    </div>
    <div class="card">
      <div class="between">
        <h2>Session ${ses.session_id ?? "—"}</h2>
        <div class="gap">${badge("Assurance " + (ses.assurance ?? "—"))}${badge(ses.verdict ?? "—", suspect ? "bad" : "ok")}</div>
      </div>
      <div class="cols3" style="margin-top:20px">
        <div><h3>Proven</h3><ul class="plain">${list(proven, "+", "ok")}</ul></div>
        <div><h3>Suspicious</h3><ul class="plain">${list(flagged, "!", "bad")}</ul></div>
        <div><h3>Cannot be proven</h3><ul class="plain">${list(unprovable, "?", "mute")}</ul></div>
      </div>
      <details><summary>Case note</summary><pre class="note">${data.rendered_text ?? ""}</pre></details>
    </div>`;
}

// --- Tamper lab ---
async function loadTamperLab() {
  const list = $("tamperlab-scenarios-list");
  if (!allScenarios.length) {
    const sc = await api("/api/tamperlab/scenarios");
    if (sc && sc.length) allScenarios = sc;
  }
  if (!allScenarios.length) { list.innerHTML = html`<p class="mute">Cannot reach the evidence server.</p>`; return; }
  list.innerHTML = html`${allScenarios.map((sc) => html`
    <div class="scn">
      <span class="id">${sc.id}</span>
      <span class="badge">${sc.group}</span>
      <span class="t">${sc.title}</span>
      <span class="mono small mute">expect ${sc.expected}</span>
      <button type="button" class="btn" data-id="${sc.id}">Run</button>
    </div>`)}`;
}

async function runScenarioTrial(id) {
  const card = $("tamperlab-live-result");
  card.classList.remove("hidden");
  card.innerHTML = html`<div class="card mute">Running ${id}…</div>`;
  const t = await api("/api/tamperlab/run", { method: "POST", body: JSON.stringify({ scenario_id: id, seed: 0 }) });
  if (!t) { card.innerHTML = html`${offline("Trial failed")}`; return; }
  const match = t.outcome === t.expected;
  const codes = t.suspect && t.suspect.length ? t.suspect.join(", ") : "none";
  card.innerHTML = html`
    <div class="card">
      <div class="between">
        <h2>${t.scenario_id}${t.title ? ": " + t.title : ""}</h2>
        <div class="gap">${badge("Expected " + t.expected)}${badge("Outcome " + t.outcome, match ? "ok" : "bad")}</div>
      </div>
      <p class="mono small" style="margin-top:12px"><span class="mute">Verdict</span> ${t.verdict ?? "n/a"} &nbsp; <span class="mute">Suspect codes</span> ${codes}</p>
    </div>`;
}

// --- Witness ---
async function loadWitnessReport() {
  const box = $("witness-content-area");
  box.innerHTML = html`<p class="mute">Polling witness…</p>`;
  const r = await api("/api/witness/report");
  if (!r) { box.innerHTML = html`${offline("Witness unreachable")}`; return; }
  const seats = r.seats || [];
  const refused = r.refusals?.length || 0;
  box.innerHTML = html`
    <div class="card">
      <div class="between"><div><div class="eyebrow">Witness node</div><h2>${r.witness}</h2></div>${badge("Equivocation proof active", "ok")}</div>
      <div class="stats" style="grid-template-columns:repeat(3,1fr)">
        <div class="stat"><span class="mute">Exam</span><b class="mono" style="font-size:15px">${r.exam_id}</b></div>
        <div class="stat"><span class="mute">Seats held</span><b class="serif">${seats.length}</b></div>
        <div class="stat"><span class="mute">Refused batches</span><b class="serif ${refused ? "bad" : "ok"}">${refused}</b></div>
      </div>
    </div>
    <div class="card" style="padding:8px 8px 0;overflow-x:auto">
      <table>
        <thead><tr><th>Session</th><th>Seat</th><th>Held to</th><th>Events</th><th>Contacts</th><th>Max silence</th></tr></thead>
        <tbody>${seats.map((s) => html`<tr><td class="mono">${s.session}</td><td class="mono">${s.ws}</td><td class="mono">seq ${s.held_upto}</td><td>${s.events_held}</td><td>${s.contacts}</td><td class="mute">${Math.round((s.longest_contact_gap_ms || 0) / 1000)} s</td></tr>`)}</tbody>
      </table>
    </div>`;
}

// --- Toast ---
function showToast(msg) {
  setText("toast-message", msg);
  const t = $("toast-banner");
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add("hidden"), 3000);
}

// --- Receipt actions ---
function setupReceiptActions() {
  $("copy-btn").addEventListener("click", () => {
    if (!currentReceipt) return;
    navigator.clipboard.writeText(slipText(currentReceipt)).then(() => {
      setText("copy-text", I18N[currentLang].copied);
      showToast("Receipt copied");
      setTimeout(() => setText("copy-text", I18N[currentLang].copy_slip), 2000);
    }).catch(() => { const d = $("digest-raw"); d.classList.remove("hidden"); d.focus(); d.select(); });
  });
  $("print-btn").addEventListener("click", () => window.print());
  $("save-btn").addEventListener("click", () => {
    if (!currentReceipt) return;
    const url = URL.createObjectURL(new Blob([slipText(currentReceipt) + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url; a.download = `receipt-${currentReceipt.receipt_id}.txt`;
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  });
}

// --- Init ---
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-nav-view]").forEach((b) => b.addEventListener("click", () => navigateTo(b.dataset.navView)));
  $("lang-en").addEventListener("click", () => setLanguage("en"));
  $("lang-hi").addEventListener("click", () => setLanguage("hi"));

  $("start-btn").addEventListener("click", () => {
    const chk = $("affirmation-check");
    if (!chk.checked) {
      const row = chk.closest(".affirm");
      chk.focus(); row.classList.add("flash");
      setTimeout(() => row.classList.remove("flash"), 1200);
      return;
    }
    const btn = $("start-btn");
    btn.disabled = true;
    setText("btn-text", "Verifying station…");
    setTimeout(() => { btn.disabled = false; setLanguage(currentLang); navigateTo("workstation"); }, 500);
  });

  $("btn-save-file").addEventListener("click", handleSaveFile);
  $("btn-run-code").addEventListener("click", handleRunCode);
  $("btn-checkpoint").addEventListener("click", handleCheckpoint);
  $("btn-flush").addEventListener("click", handleFlush);
  $("btn-reverify").addEventListener("click", loadAssessorCase);
  $("btn-check-receipt").addEventListener("click", checkReceipt);
  $("btn-poll-witness").addEventListener("click", loadWitnessReport);
  $("tamperlab-scenarios-list").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-id]");
    if (b) runScenarioTrial(b.dataset.id);
  });
  setupReceiptActions();

  $("code-editor-textarea").value = FILES[activeFile];
  setLanguage("en");
  navigateTo("briefing");
});
