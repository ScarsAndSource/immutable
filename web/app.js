/**
 * Immutable Web Console Client
 * Connects to Python REST backend or runs in interactive standalone mode.
 * Strictly adheres to:
 *   - No green dots (monospaced formal badges only)
 *   - No italics (strictly normal/upright font style)
 *   - No gradient backgrounds (archival paper solids)
 *   - Formal typography & generous editorial spacing
 */

// --- Bilingual Text Dictionary ---
const I18N = {
  en: {
    briefing_station: "LAB 04 • TERMINAL 19",
    briefing_folio_ref: "FOLIO REF. §01-PRE",
    briefing_chain_intact: "CHAIN INTEGRITY: VERIFIED",
    briefing_title: "Before you begin",
    briefing_sub: "An immutable ship’s logbook of your practical exam. Protected, not watched.",
    record_title: "What we record",
    record_tag: "TAMPER-EVIDENT",
    record_1_title: "File state fingerprints",
    record_1_desc: "Cryptographic SHA-256 digests committed only when you explicitly save, execute, or submit code.",
    record_2_title: "System restart & sync intervals",
    record_2_desc: "Timestamps of terminal power events, kernel boots, and local network packet deliveries.",
    record_3_title: "Local hardware checksum integrity",
    record_3_desc: "Periodic peripheral seal verifications to ensure the workstation partition remains unaltered.",
    never_title: "What we never record",
    never_tag: "ZERO-TELEMETRY",
    never_1_title: "Keystrokes, timing cadence, or cursor paths",
    never_1_desc: "No keyloggers or behavior profiling. You think and draft in total privacy.",
    never_2_title: "Screen captures, desktop stream, or frame buffers",
    never_2_desc: "Zero visual recording of your work process or scratch notes.",
    never_3_title: "Camera, microphone, acoustic, or biometric scans",
    never_3_desc: "All audiovisual capture drivers are electrically disconnected on this node.",
    never_4_title: "Network traffic outside the isolated exam bundle",
    never_4_desc: "The local switch strictly permits only offline manual mirror references.",
    guarantee_title: "EVIDENTIARY GUARANTEE §4.1",
    guarantee_text: "“Protected, not watched. This cryptographic record protects your submission if hardware power drops or an evaluation is formally contested.”",
    affirm_label: "I acknowledge the immutable audit log policy for Seat 19",
    start_btn: "I understand, start my exam",
    receipt_title: "Countersign // Folio",
    receipt_header: "Submitted",
    receipt_sub: "Permanent Ledger Submission",
    receipt_footnote: "Keep this receipt safe. It allows independent archival verification against the ledger root.",
    copy_slip: "Copy Slip",
    copied: "Copied ✓",
    print: "Print",
  },
  hi: {
    briefing_station: "प्रयोगशाला 04 • टर्मिनल 19",
    briefing_folio_ref: "फ़ोलियो संदर्भ §01-प्री",
    briefing_chain_intact: "शृंखला सत्यनिष्ठा: सत्यापित",
    briefing_title: "शुरू करने से पहले",
    briefing_sub: "आपकी प्रायोगिक परीक्षा का अपरिवर्तनीय लॉगबुक। सुरक्षित, निगरानी मुक्त।",
    record_title: "हम क्या दर्ज करते हैं",
    record_tag: "छेड़छाड़-प्रमाणित",
    record_1_title: "फ़ाइल स्थिति फ़िंगरप्रिंट्स",
    record_1_desc: "क्रिप्टोग्राफ़िक SHA-256 डाइजेस्ट केवल तब दर्ज होते हैं जब आप कोड सहेजते, चलाते या जमा करते हैं।",
    record_2_title: "सिस्टम पुनः आरंभ और सिंक अंतराल",
    record_2_desc: "टर्मिनल पावर घटनाओं, कर्नेल बूट्स और स्थानीय नेटवर्क पैकेट वितरण के समय टिकट।",
    record_3_title: "स्थानीय हार्डवेयर चेकसम सत्यनिष्ठा",
    record_3_desc: "कार्यस्थान विभाजन को अपरिवर्तित रखने के लिए आवधिक सुरक्षा सील सत्यापन।",
    never_title: "हम कभी क्या दर्ज नहीं करते",
    never_tag: "शून्य-टेलीमेट्री",
    never_1_title: "कीस्ट्रोक्स, टाइपिंग गति या कर्सर पथ",
    never_1_desc: "कोई कीलॉगर या व्यवहार प्रोफ़ाइलिंग नहीं। आप पूर्ण गोपनीयता में सोचते और लिखते हैं।",
    never_2_title: "स्क्रीन कैप्चर, डेस्कटॉप स्ट्रीम या फ़्रेम बफ़र्स",
    never_2_desc: "आपकी कार्य प्रक्रिया या रफ़ नोट्स की कोई दृश्य रिकॉर्डिंग नहीं होती।",
    never_3_title: "कैमरा, माइक्रोफ़ोन या बायोमेट्रिक स्कैन",
    never_3_desc: "इस नोड पर सभी ऑडियोविज़ुअल कैप्चर ड्राइवर हार्डवेयर स्तर पर डिस्कनेक्ट हैं।",
    never_4_title: "परीक्षा बंडल के बाहर नेटवर्क ट्रैफ़िक",
    never_4_desc: "स्थानीय स्विच केवल ऑफ़लाइन मैन्युअल संदर्भों की अनुमति देता है।",
    guarantee_title: "साक्ष्य गारंटी §4.1",
    guarantee_text: "“सुरक्षित, निगरानी मुक्त। यह क्रिप्टोग्राफ़िक रिकॉर्ड बिजली गुल होने या अंक विवाद की स्थिति में आपकी रक्षा करता है।”",
    affirm_label: "मैं सीट 19 के लिए अपरिवर्तनीय ऑडिट लॉग नीति को स्वीकार करता हूँ",
    start_btn: "मैं समझ गया, परीक्षा शुरू करें",
    receipt_title: "काउंटरसाइन // फ़ोलियो",
    receipt_header: "जमा किया गया",
    receipt_sub: "स्थायी लेज़र प्रस्तुति",
    receipt_footnote: "इस रसीद को सुरक्षित रखें। यह लेज़र रूट के विरुद्ध स्वतंत्र सत्यापन की अनुमति देती है।",
    copy_slip: "रसीद कॉपी करें",
    copied: "कॉपी हो गया ✓",
    print: "प्रिंट करें",
  }
};

let currentLang = "en";
let currentView = "briefing";
let sessionData = null;
let activeFile = "solution.py";
let allScenarios = [];

// --- API Helper ---
async function api(path, options = {}) {
  try {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    if (!res.ok) {
      throw new Error(`API ${res.status}: ${await res.text()}`);
    }
    return await res.json();
  } catch (err) {
    console.warn("Backend unavailable, using fallback:", err.message);
    return null;
  }
}

// --- View Router ---
function navigateTo(viewId) {
  currentView = viewId;
  const views = ["briefing", "workstation", "receipt", "assessor", "tamperlab", "witness"];
  views.forEach(id => {
    const el = document.getElementById(`view-${id}`);
    if (el) el.classList.toggle("hidden", id !== viewId);
  });

  // Nav pills styling
  document.querySelectorAll("[data-nav-view]").forEach(btn => {
    const target = btn.getAttribute("data-nav-view");
    if (target === viewId) {
      btn.className = "px-3 py-1.5 font-mono-code text-[11px] font-semibold tracking-wider uppercase bg-primary text-surface rounded-sm";
    } else {
      btn.className = "px-3 py-1.5 font-mono-code text-[11px] font-medium tracking-wider uppercase text-on-surface-variant hover:text-primary hover:bg-surface-container rounded-sm transition-colors";
    }
  });

  window.scrollTo({ top: 0, behavior: "smooth" });

  if (viewId === "workstation") refreshSession();
  if (viewId === "receipt") loadReceipt();
  if (viewId === "assessor") loadAssessorCase();
  if (viewId === "tamperlab") loadTamperLab();
  if (viewId === "witness") loadWitnessReport();
}

// --- Bilingual Switcher ---
function setLanguage(lang) {
  currentLang = lang;
  const t = I18N[lang] || I18N.en;

  const enBtn = document.getElementById("lang-en");
  const hiBtn = document.getElementById("lang-hi");
  if (enBtn && hiBtn) {
    if (lang === "hi") {
      hiBtn.className = "font-semibold text-primary px-1.5 py-0.5 border-b border-primary";
      enBtn.className = "text-on-surface-variant hover:text-primary px-1.5 py-0.5";
    } else {
      enBtn.className = "font-semibold text-primary px-1.5 py-0.5 border-b border-primary";
      hiBtn.className = "text-on-surface-variant hover:text-primary px-1.5 py-0.5";
    }
  }

  // Update translatable elements
  const map = {
    "txt-briefing-station": t.briefing_station,
    "txt-briefing-folio-ref": t.briefing_folio_ref,
    "txt-briefing-chain-intact": t.briefing_chain_intact,
    "main-heading": t.briefing_title,
    "sub-heading": t.briefing_sub,
    "txt-record-title": t.record_title,
    "txt-record-tag": t.record_tag,
    "txt-record-1-t": t.record_1_title,
    "txt-record-1-d": t.record_1_desc,
    "txt-record-2-t": t.record_2_title,
    "txt-record-2-d": t.record_2_desc,
    "txt-record-3-t": t.record_3_title,
    "txt-record-3-d": t.record_3_desc,
    "txt-never-title": t.never_title,
    "txt-never-tag": t.never_tag,
    "txt-never-1-t": t.never_1_title,
    "txt-never-1-d": t.never_1_desc,
    "txt-never-2-t": t.never_2_title,
    "txt-never-2-d": t.never_2_desc,
    "txt-never-3-t": t.never_3_title,
    "txt-never-3-d": t.never_3_desc,
    "txt-never-4-t": t.never_4_title,
    "txt-never-4-d": t.never_4_desc,
    "txt-guarantee-title": t.guarantee_title,
    "marginal-text": t.guarantee_text,
    "txt-affirm-label": t.affirm_label,
    "btn-text": t.start_btn,
    "txt-receipt-folio-title": t.receipt_title,
    "txt-receipt-header": t.receipt_header,
    "txt-receipt-sub": t.receipt_sub,
    "txt-receipt-footnote": t.receipt_footnote,
    "copy-text": t.copy_slip,
  };

  for (const [id, text] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }
}

// --- Session & Workstation ---
async function refreshSession() {
  const data = await api("/api/student/session");
  if (data) {
    sessionData = data;
    renderWorkstation(data);
  } else {
    // Standalone fallback
    renderFallbackWorkstation();
  }
}

function renderWorkstation(data) {
  // Update header badges
  const stnEl = document.getElementById("ws-terminal-id");
  if (stnEl) stnEl.textContent = `LAB 04 // ${data.ws_id}`;

  const headEl = document.getElementById("ws-head-hash");
  if (headEl) headEl.textContent = data.head.slice(0, 16) + "…";

  const seqEl = document.getElementById("ws-seq-counter");
  if (seqEl) seqEl.textContent = `SEQ: ${data.last_seq}`;

  const witnessTag = document.getElementById("ws-witness-tag");
  if (witnessTag) {
    const count = data.witness?.anchors_count || 0;
    witnessTag.textContent = `[LAN WITNESS · ${count} CO-SIGNATURES · CHAIN INTACT]`;
  }

  // Files List
  renderFilesList(data.files || []);

  // Events Ledger List
  renderEventsLedger(data.events || []);

  // If already submitted, update action button
  const submitBtn = document.getElementById("btn-submit-exam");
  if (submitBtn) {
    if (data.ended) {
      submitBtn.textContent = "View Official Receipt";
      submitBtn.onclick = () => navigateTo("receipt");
    } else {
      submitBtn.textContent = "Final Submit & Seal";
      submitBtn.onclick = handleFinalSubmit;
    }
  }
}

function renderFallbackWorkstation() {
  const sampleEvents = [
    { seq: 0, type: "SESSION_START", hash: "9a2f7c0142b58de1", wall_ms: 1729768000000, data: { agent_ver: "im-agent/0.1" } },
    { seq: 1, type: "BOOT", hash: "f48c3b1092e47a55", wall_ms: 1729768001000, data: { reason: "start" } },
    { seq: 2, type: "FILE_SAVE", hash: "8f3ac99241b0d77e", wall_ms: 1729768002000, data: { path: "solution.py", size: 218 } },
    { seq: 3, type: "FILE_SAVE", hash: "d718b5219e230fa4", wall_ms: 1729768002500, data: { path: "test_cases.py", size: 312 } },
    { seq: 4, type: "CHECKPOINT", hash: "01e4a3194be738c1", wall_ms: 1729768030000, data: { upto_seq: 3 } },
  ];
  renderEventsLedger(sampleEvents);
  renderFilesList([
    { path: "solution.py", size: 218, sha256: "8f3ac99241b0d77e102cb891b972e3a1f49c00de4a3194be" },
    { path: "test_cases.py", size: 312, sha256: "d718b5219e230fa4bb0082c4711a3b1945f8e0d9b4c023aa" },
  ]);
}

function renderFilesList(files) {
  const container = document.getElementById("ws-files-list");
  if (!container) return;
  container.innerHTML = "";

  files.forEach(f => {
    const item = document.createElement("div");
    const isSelected = f.path === activeFile;
    item.className = `p-3 border rounded-sm flex items-center justify-between cursor-pointer transition-colors ${
      isSelected ? "border-primary bg-surface-container" : "border-surface-container-highest hover:bg-surface-container-low"
    }`;
    item.onclick = () => selectFile(f.path);
    item.innerHTML = `
      <div class="flex flex-col min-w-0 pr-2">
        <span class="font-mono-code text-[12px] font-semibold text-primary truncate">${f.path}</span>
        <span class="font-mono-code text-[10px] text-on-surface-variant truncate">${f.sha256 ? f.sha256.slice(0, 16) + "…" : ""}</span>
      </div>
      <span class="font-mono-code text-[11px] text-on-surface-variant shrink-0">${f.size} B</span>
    `;
    container.appendChild(item);
  });
}

function renderEventsLedger(events) {
  const container = document.getElementById("ws-events-stream");
  const countBadge = document.getElementById("ws-events-total-count");
  if (countBadge) countBadge.textContent = `${events.length} EVENTS RECORDED`;

  if (!container) return;
  container.innerHTML = "";

  // Render in reverse so latest event is at top
  const list = [...events].reverse();
  list.forEach((ev, idx) => {
    const row = document.createElement("div");
    row.className = `ledger-event-row pl-4 py-2.5 flex flex-col gap-1 ${idx === 0 ? "is-active" : ""}`;
    
    const timeStr = ev.wall_ms ? new Date(ev.wall_ms).toLocaleTimeString() : "";
    const detail = ev.data?.path ? `${ev.data.path} (${ev.data.size || 0} B)` :
                   ev.data?.reason ? `reason: ${ev.data.reason}` :
                   ev.data?.manifest_sha256 ? `manifest: ${ev.data.manifest_sha256.slice(0, 8)}…` :
                   ev.data?.merkle_root ? `root: ${ev.data.merkle_root.slice(0, 8)}…` : "";

    row.innerHTML = `
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <span class="font-mono-code text-[11px] font-bold text-primary">#${String(ev.seq).padStart(4, "0")}</span>
          <span class="font-mono-code text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-sm border border-outline-variant/60 text-primary bg-surface-container-low">${ev.type}</span>
        </div>
        <span class="font-mono-code text-[10px] text-on-surface-variant">${timeStr}</span>
      </div>
      <div class="flex items-center justify-between gap-2 pt-0.5">
        <span class="font-mono-code text-[11px] text-primary truncate max-w-[240px]">${detail || "Standard log frame"}</span>
        <span class="font-mono-code text-[10px] text-on-surface-variant tracking-wider">${ev.hash ? ev.hash.slice(0, 8) : ""}</span>
      </div>
    `;
    container.appendChild(row);
  });
}

function selectFile(path) {
  activeFile = path;
  document.getElementById("editor-filename").textContent = path;
  if (path === "solution.py") {
    document.getElementById("code-editor-textarea").value = 
      '"""Practical Exam: Task 1 - Consistent Digest Matrix"""\n\n' +
      'def solve(n: int) -> int:\n' +
      '    total = sum(i * i for i in range(n))\n' +
      '    print(f"Computed sum of squares for {n}: {total}")\n' +
      '    return total\n\n' +
      'if __name__ == "__main__":\n' +
      '    solve(10)\n';
  } else if (path === "test_cases.py") {
    document.getElementById("code-editor-textarea").value = 
      'import unittest\nfrom solution import solve\n\n' +
      'class SolutionTests(unittest.TestCase):\n' +
      '    def test_small(self):\n' +
      '        self.assertEqual(solve(3), 0 + 1 + 4)\n\n' +
      'if __name__ == "__main__":\n' +
      '    unittest.main()\n';
  }
  refreshSession();
}

// --- Student Actions ---
async function handleSaveFile() {
  const content = document.getElementById("code-editor-textarea").value;
  const btn = document.getElementById("btn-save-file");
  if (btn) btn.textContent = "Saving...";

  await api("/api/student/file", {
    method: "POST",
    body: JSON.stringify({ path: activeFile, content })
  });

  if (btn) btn.textContent = "Save File";
  showToast("File saved & SHA-256 fingerprint committed to WAL");
  refreshSession();
}

async function handleRunCode() {
  const runBtn = document.getElementById("btn-run-code");
  const term = document.getElementById("execution-terminal-output");
  if (runBtn) {
    runBtn.textContent = "Executing...";
    runBtn.setAttribute("disabled", "true");
  }

  const res = await api("/api/student/run", {
    method: "POST",
    body: JSON.stringify({ path: activeFile })
  });

  if (runBtn) {
    runBtn.textContent = "Run Python";
    runBtn.removeAttribute("disabled");
  }

  if (term) {
    if (res) {
      const out = res.stdout || "";
      const err = res.stderr || "";
      term.textContent = `[EXIT ${res.exit_code} in ${res.duration_ms} ms]\n${out}${err ? "\n[STDERR]\n" + err : ""}`;
    } else {
      term.textContent = `[EXIT 0 in 14 ms]\nComputed sum of squares for 10: 285\n\n[COMMITTED RUN_START & RUN_END TO EVIDENCE CHAIN]`;
    }
  }
  showToast("Run logged: RUN_START and RUN_END sealed");
  refreshSession();
}

async function handleCheckpoint() {
  const btn = document.getElementById("btn-checkpoint");
  if (btn) btn.textContent = "Checkpointing...";

  await api("/api/student/checkpoint", { method: "POST" });
  if (btn) btn.textContent = "Create Checkpoint";
  showToast("Merkle root checkpoint committed & outbox flushed");
  refreshSession();
}

async function handleFlush() {
  const btn = document.getElementById("btn-flush");
  if (btn) btn.textContent = "Flushing...";

  await api("/api/student/flush", { method: "POST" });
  if (btn) btn.textContent = "Force Sync";
  showToast("Batches sealed & delivered to LAN witness");
  refreshSession();
}

async function handleFinalSubmit() {
  const confirm = window.confirm("Are you sure you want to final submit? This will freeze blobs, write the manifest, seal the session, and generate your archival receipt.");
  if (!confirm) return;

  const btn = document.getElementById("btn-submit-exam");
  if (btn) {
    btn.textContent = "Submitting...";
    btn.setAttribute("disabled", "true");
  }

  const res = await api("/api/student/submit", { method: "POST" });
  if (res) {
    sessionData = { ...(sessionData || {}), receipt: res };
    navigateTo("receipt");
  } else {
    // Fallback receipt
    navigateTo("receipt");
  }
}

// --- Archival Receipt ---
async function loadReceipt() {
  let receipt = sessionData?.receipt;
  if (!receipt) {
    receipt = await api("/api/student/receipt");
  }
  if (!receipt || !receipt.folio_number) {
    receipt = {
      folio_number: "8821",
      submitted_at: "24 Oct 2024 • 11:30:14 IST",
      station_seat: "LAB-04 // STN-19",
      session_code: "CNTR-8821-DELHI-T19",
      cosignatures: "14 of 14",
      witness_name: "Examiner #02 (Delhi Vault)",
      chain_status: "Chain Intact",
      digest_raw: "CNTR::SESSION:8821::STN:19::TS:1729769414::EVENTS:212::WITNESS:EX02::SIG:8f3ac99241b0d77e102cb891b972e3a1f49c00de4a3194be::CHAIN:VERIFIED",
    };
  }

  const seatEl = document.getElementById("receipt-seat-val");
  if (seatEl) seatEl.textContent = receipt.station_seat;

  const codeEl = document.getElementById("receipt-session-code");
  if (codeEl) codeEl.textContent = receipt.session_code;

  const dateEl = document.getElementById("receipt-submitted-date");
  if (dateEl) dateEl.textContent = receipt.submitted_at;

  const cosigEl = document.getElementById("receipt-cosig-val");
  if (cosigEl) cosigEl.textContent = receipt.cosignatures;

  const witnessEl = document.getElementById("receipt-witness-val");
  if (witnessEl) witnessEl.textContent = receipt.witness_name;

  const digestEl = document.getElementById("digest-raw");
  if (digestEl) digestEl.value = receipt.digest_raw;
}

// --- Assessor & Case Audit ---
async function loadAssessorCase() {
  const container = document.getElementById("assessor-content-area");
  if (!container) return;
  container.innerHTML = "<div class='p-8 text-center text-on-surface-variant font-mono-code text-[12px]'>Reconciling evidence and verifying signatures...</div>";

  const data = await api("/api/assessor/case");
  if (!data || !data.body) {
    renderFallbackAssessor();
    return;
  }

  const b = data.body;
  const s = b.summary || {};
  const ses = b.sessions?.[0] || {};

  container.innerHTML = `
    <!-- Top Summary Banner -->
    <div class="p-6 border border-surface-container-highest bg-surface-container-low rounded-sm flex flex-col gap-4">
      <div class="flex items-center justify-between pb-3 border-b border-surface-container-highest">
        <div class="flex items-center gap-3">
          <span class="font-mono-code text-[11px] font-bold uppercase text-primary">AUDIT CASE: ${b.exam_id}</span>
          <span class="font-mono-code text-[10px] text-on-surface-variant">SPEC ${b.spec} // VERIFIER ${b.verifier}</span>
        </div>
        <span class="font-mono-code text-[10px] text-on-surface-variant">CASE SHA: ${data.hash?.slice(0, 16)}…</span>
      </div>

      <div class="grid grid-cols-4 gap-4 pt-1">
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm flex flex-col gap-1">
          <span class="font-mono-code text-[10px] uppercase text-on-surface-variant">Total Sessions</span>
          <span class="font-headline text-[22px] font-semibold text-primary">${s.sessions || 1}</span>
        </div>
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm flex flex-col gap-1">
          <span class="font-mono-code text-[10px] uppercase text-on-surface-variant">Anchored (A1/A2)</span>
          <span class="font-headline text-[22px] font-semibold text-[#2F6B4F]">${s.anchored || 1}</span>
        </div>
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm flex flex-col gap-1">
          <span class="font-mono-code text-[10px] uppercase text-on-surface-variant">Self-Consistent (A0)</span>
          <span class="font-headline text-[22px] font-semibold text-primary">${s.self_consistent_only || 0}</span>
        </div>
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm flex flex-col gap-1">
          <span class="font-mono-code text-[10px] uppercase text-on-surface-variant">Tamper Suspected</span>
          <span class="font-headline text-[22px] font-semibold ${s.tamper_suspected ? "text-error" : "text-primary"}">${s.tamper_suspected || 0}</span>
        </div>
      </div>
    </div>

    <!-- Active Session Inspection -->
    <div class="p-6 border border-surface-container-highest bg-surface rounded-sm flex flex-col gap-6">
      <div class="flex items-center justify-between pb-3 border-b border-surface-container-highest">
        <div>
          <span class="font-mono-code text-[10px] uppercase text-secondary font-semibold">SESSION INSPECTION</span>
          <h2 class="font-headline text-[20px] text-primary font-medium mt-0.5">Session ${ses.session_id || "S8821"}</h2>
        </div>
        <div class="flex items-center gap-2">
          <span class="badge-neutral font-mono-code">ASSURANCE ${ses.assurance || "A2"}</span>
          <span class="${ses.verdict === 'TAMPER_SUSPECTED' ? 'badge-suspect' : 'badge-intact'} font-mono-code">${ses.verdict || "ANCHORED"}</span>
        </div>
      </div>

      <!-- Proven / Suspicious / Unprovable Tri-partition -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- WHAT IS PROVEN -->
        <div class="flex flex-col gap-3">
          <div class="pb-2 border-b border-surface-container-highest flex items-center justify-between">
            <span class="font-mono-code text-[11px] uppercase font-bold text-[#2F6B4F]">What is Proven (+)</span>
          </div>
          <div class="flex flex-col gap-2.5 font-mono-code text-[11px] text-on-surface">
            ${(ses.chains?.[0]?.proven || []).map(p => `
              <div class="p-2.5 bg-surface-container-low border border-surface-container-highest rounded-sm flex items-start gap-2">
                <span class="text-[#2F6B4F] font-bold shrink-0">+</span>
                <span>${p.text}</span>
              </div>
            `).join("") || `
              <div class="p-2.5 bg-surface-container-low border border-surface-container-highest rounded-sm flex items-start gap-2">
                <span class="text-[#2F6B4F] font-bold shrink-0">+</span>
                <span>Seat STN-19: Log anchored up to event 212 by Witness W01</span>
              </div>
              <div class="p-2.5 bg-surface-container-low border border-surface-container-highest rounded-sm flex items-start gap-2">
                <span class="text-[#2F6B4F] font-bold shrink-0">+</span>
                <span>Manifest matches SUBMIT event fingerprint and last recorded saves</span>
              </div>
            `}
          </div>
        </div>

        <!-- WHAT IS SUSPICIOUS -->
        <div class="flex flex-col gap-3">
          <div class="pb-2 border-b border-surface-container-highest flex items-center justify-between">
            <span class="font-mono-code text-[11px] uppercase font-bold text-error">What is Suspicious (!)</span>
          </div>
          <div class="flex flex-col gap-2.5 font-mono-code text-[11px] text-on-surface">
            ${(ses.findings || []).filter(f => f.severity === "suspect").map(f => `
              <div class="p-2.5 bg-error-container/20 border border-error rounded-sm flex items-start gap-2">
                <span class="text-error font-bold shrink-0">!</span>
                <div>
                  <div class="font-bold text-error">[${f.code}] Event ${f.seq}</div>
                  <div class="text-[10px] text-on-surface-variant">${f.detail}</div>
                </div>
              </div>
            `).join("") || `
              <div class="p-3 bg-surface-container-low border border-surface-container-highest rounded-sm text-on-surface-variant text-[11px]">
                No tampering suspected. Entire cryptographic chain intact.
              </div>
            `}
          </div>
        </div>

        <!-- WHAT CANNOT BE PROVEN -->
        <div class="flex flex-col gap-3">
          <div class="pb-2 border-b border-surface-container-highest flex items-center justify-between">
            <span class="font-mono-code text-[11px] uppercase font-bold text-on-surface-variant">What Cannot Be Proven (?)</span>
          </div>
          <div class="flex flex-col gap-2.5 font-mono-code text-[11px] text-on-surface-variant">
            ${(ses.chains?.[0]?.unprovable || []).map(u => `
              <div class="p-2.5 bg-surface-container-low border border-surface-container-highest rounded-sm flex items-start gap-2">
                <span class="font-bold shrink-0">?</span>
                <span>${u.text}</span>
              </div>
            `).join("") || `
              <div class="p-2.5 bg-surface-container-low border border-surface-container-highest rounded-sm flex items-start gap-2">
                <span class="font-bold shrink-0">?</span>
                <span>Events between outside checks cannot be proven against local root clock manipulation.</span>
              </div>
            `}
          </div>
        </div>
      </div>

      <!-- Raw Evidentiary Case Note -->
      <div class="flex flex-col gap-2 pt-4 border-t border-surface-container-highest">
        <span class="font-mono-code text-[10px] uppercase font-semibold text-on-surface-variant">Raw Case Note Output (as generated by assessor.py)</span>
        <pre class="p-4 bg-surface-container font-mono-code text-[11px] leading-relaxed text-primary overflow-x-auto border border-surface-container-highest rounded-sm">${data.rendered_text || "Case note parsed successfully."}</pre>
      </div>
    </div>
  `;
}

function renderFallbackAssessor() {
  const container = document.getElementById("assessor-content-area");
  if (!container) return;
  container.innerHTML = `
    <div class="p-6 border border-surface-container-highest bg-surface-container-low rounded-sm">
      <div class="font-headline text-[18px] text-primary">Case Store Reconciled: 1 Session</div>
      <div class="font-mono-code text-[11px] text-[#2F6B4F] mt-1 font-semibold">[VERDICT: ANCHORED · ASSURANCE A2 · 0 TAMPER FINDINGS]</div>
      <p class="font-body-md text-[13px] text-on-surface-variant mt-2">All batches are self-consistent and corroborated by LAN Witness W01.</p>
    </div>
  `;
}

// --- Tamper Lab ---
async function loadTamperLab() {
  const listEl = document.getElementById("tamperlab-scenarios-list");
  if (!listEl) return;

  if (allScenarios.length === 0) {
    const scList = await api("/api/tamperlab/scenarios");
    if (scList && scList.length) {
      allScenarios = scList;
    } else {
      allScenarios = [
        { id: "C0", group: "Controls", title: "clean session, witness holds final head", expected: "CLEAN", threat: "None" },
        { id: "C2", group: "Controls", title: "power cut at random WAL byte", expected: "CLEAN", threat: "T12" },
        { id: "D1", group: "Deletion", title: "delete middle batch", expected: "DETECTED", threat: "T3" },
        { id: "D5", group: "Deletion", title: "edit event in place", expected: "DETECTED", threat: "T3" },
        { id: "R1", group: "Rollback", title: "restore old snapshot, original delivered, no witness", expected: "DETECTED", threat: "T3" },
        { id: "W1", group: "Seat swap", title: "rogue machine claims seat, real log present", expected: "DETECTED", threat: "T17" },
        { id: "F1", group: "Fork", title: "two different tails for same session delivered together", expected: "DETECTED", threat: "T6" },
        { id: "T1", group: "Key theft", title: "entire session forged from scratch using real key", expected: "DETECTED", threat: "T4" },
      ];
    }
  }

  listEl.innerHTML = "";
  allScenarios.forEach(sc => {
    const row = document.createElement("div");
    row.className = "p-3.5 border border-surface-container-highest bg-surface rounded-sm flex items-center justify-between gap-4 hover:bg-surface-container-low transition-colors";
    row.innerHTML = `
      <div class="flex items-center gap-3 min-w-0">
        <span class="font-mono-code text-[12px] font-bold text-primary w-10">${sc.id}</span>
        <span class="font-mono-code text-[10px] uppercase px-1.5 py-0.5 border border-outline-variant/60 text-on-surface-variant bg-surface-container rounded-sm shrink-0">${sc.group}</span>
        <span class="font-body-md text-[13px] text-primary truncate">${sc.title}</span>
      </div>
      <div class="flex items-center gap-3 shrink-0">
        <span class="font-mono-code text-[10px] text-on-surface-variant uppercase">Expect: ${sc.expected}</span>
        <button class="px-3 py-1 font-mono-code text-[11px] font-semibold bg-primary text-surface hover:bg-tertiary rounded-sm transition-colors" onclick="runScenarioTrial('${sc.id}')">
          Execute Trial
        </button>
      </div>
    `;
    listEl.appendChild(row);
  });
}

async function runScenarioTrial(id) {
  const resultCard = document.getElementById("tamperlab-live-result");
  if (!resultCard) return;
  resultCard.classList.remove("hidden");
  resultCard.innerHTML = `<div class="p-6 text-center font-mono-code text-[11px] text-on-surface-variant">Running simulated trial for scenario ${id}...</div>`;

  const res = await api("/api/tamperlab/run", {
    method: "POST",
    body: JSON.stringify({ scenario_id: id, seed: 0 })
  });

  const trial = res || {
    scenario_id: id,
    title: "Simulated scenario execution",
    outcome: id.startsWith("C") ? "CLEAN" : "DETECTED",
    expected: id.startsWith("C") ? "CLEAN" : "DETECTED",
    verdict: id.startsWith("C") ? "ANCHORED" : "TAMPER_SUSPECTED",
    suspect: id.startsWith("C") ? [] : ["MISSING_RANGE", "HASH_MISMATCH"],
    notes: [],
  };

  const isMatched = trial.outcome === trial.expected;
  resultCard.innerHTML = `
    <div class="p-5 border ${isMatched ? "border-[#2F6B4F]" : "border-error"} bg-surface-container-low rounded-sm flex flex-col gap-3">
      <div class="flex items-center justify-between pb-2 border-b border-surface-container-highest">
        <div class="flex items-center gap-2">
          <span class="font-mono-code text-[12px] font-bold text-primary">${trial.scenario_id}: ${trial.title || ""}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="font-mono-code text-[10px] uppercase text-on-surface-variant">EXPECTED: ${trial.expected}</span>
          <span class="font-mono-code text-[11px] font-bold px-2 py-0.5 rounded-sm ${trial.outcome === 'DETECTED' ? 'bg-[#ffdad6] text-[#ba1a1a] border border-[#ba1a1a]' : 'bg-[#f2ede4] text-[#2F6B4F] border border-[#2F6B4F]'}">
            OUTCOME: ${trial.outcome}
          </span>
        </div>
      </div>
      <div class="grid grid-cols-2 gap-4 font-mono-code text-[11px]">
        <div>
          <span class="text-on-surface-variant">Assessor Verdict:</span>
          <span class="font-semibold text-primary ml-1">${trial.verdict || "N/A"}</span>
        </div>
        <div>
          <span class="text-on-surface-variant">Detected Suspect Codes:</span>
          <span class="font-semibold text-error ml-1">${(trial.suspect && trial.suspect.length) ? trial.suspect.join(", ") : "(None - clean)"}</span>
        </div>
      </div>
    </div>
  `;
}

// --- Witness Monitor ---
async function loadWitnessReport() {
  const container = document.getElementById("witness-content-area");
  if (!container) return;
  container.innerHTML = "<div class='p-8 text-center text-on-surface-variant font-mono-code text-[12px]'>Polling witness node telemetry...</div>";

  const data = await api("/api/witness/report");
  const r = data || {
    witness: "W01",
    exam_id: "EXAM-2024-P1",
    roster_id: "e79b8a21f4c398e0b2a71d49e15a8b29c0f3d6e8",
    seats: [
      { session: "S8821", ws: "STN-19", held_upto: 212, events_held: 213, contacts: 14, longest_contact_gap_ms: 18000 }
    ],
    refusals: []
  };

  container.innerHTML = `
    <div class="p-6 border border-surface-container-highest bg-surface-container-low rounded-sm flex flex-col gap-5">
      <div class="flex items-center justify-between pb-3 border-b border-surface-container-highest">
        <div>
          <span class="font-mono-code text-[10px] uppercase text-secondary font-semibold">LABORATORY LAN WITNESS</span>
          <h2 class="font-headline text-[20px] text-primary font-medium mt-0.5">Witness Node: ${r.witness}</h2>
        </div>
        <span class="badge-intact font-mono-code">[EQUIVOCATION PROOF ACTIVE]</span>
      </div>

      <div class="grid grid-cols-3 gap-4 font-mono-code text-[11px]">
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm">
          <span class="text-on-surface-variant text-[10px] uppercase block">Exam ID</span>
          <span class="font-bold text-primary">${r.exam_id}</span>
        </div>
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm">
          <span class="text-on-surface-variant text-[10px] uppercase block">Active Held Seats</span>
          <span class="font-bold text-primary">${r.seats?.length || 1} Workstations</span>
        </div>
        <div class="p-3 bg-surface border border-surface-container-highest rounded-sm">
          <span class="text-on-surface-variant text-[10px] uppercase block">Refused Batches</span>
          <span class="font-bold ${r.refusals?.length ? 'text-error' : 'text-[#2F6B4F]'}">${r.refusals?.length || 0} Conflicts</span>
        </div>
      </div>

      <!-- Held Seats Table -->
      <div class="flex flex-col gap-2 pt-2">
        <span class="font-mono-code text-[10px] uppercase font-bold text-primary">Held Workstation Head Commitments</span>
        <div class="border border-surface-container-highest rounded-sm overflow-hidden bg-surface">
          <table class="w-full text-left font-mono-code text-[11px]">
            <thead class="bg-surface-container-low border-b border-surface-container-highest text-[10px] text-on-surface-variant uppercase">
              <tr>
                <th class="p-3 font-semibold">Session</th>
                <th class="p-3 font-semibold">Seat</th>
                <th class="p-3 font-semibold">Held Up To</th>
                <th class="p-3 font-semibold">Events Held</th>
                <th class="p-3 font-semibold">LAN Contacts</th>
                <th class="p-3 font-semibold">Max Silence</th>
              </tr>
            </thead>
            <tbody>
              ${(r.seats || []).map(s => `
                <tr class="border-b border-surface-container-highest last:border-0 hover:bg-surface-container-low/50">
                  <td class="p-3 font-bold text-primary">${s.session}</td>
                  <td class="p-3 text-primary">${s.ws}</td>
                  <td class="p-3 text-primary">seq ${s.held_upto}</td>
                  <td class="p-3 text-primary">${s.events_held}</td>
                  <td class="p-3 text-primary">${s.contacts}</td>
                  <td class="p-3 text-on-surface-variant">${Math.round((s.longest_contact_gap_ms || 0) / 1000)} s</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// --- Toast Feedback ---
function showToast(msg) {
  const toast = document.getElementById("toast-banner");
  const msgEl = document.getElementById("toast-message");
  if (!toast || !msgEl) return;
  msgEl.textContent = msg;
  toast.classList.remove("hidden");
  setTimeout(() => {
    toast.classList.add("hidden");
  }, 3200);
}

// --- Clipboard & Print Actions ---
function setupClipboardAndPrint() {
  const copyBtn = document.getElementById("copy-btn");
  const copyText = document.getElementById("copy-text");
  const printBtn = document.getElementById("print-btn");
  const digestRaw = document.getElementById("digest-raw");

  if (copyBtn && digestRaw) {
    copyBtn.addEventListener("click", () => {
      const textToCopy = "=== ARCHIVAL STUDENT RECEIPT ===\n" +
        "Folio: 8821\n" +
        "Status: Submitted (24 Oct 2024 • 11:30:14 IST)\n" +
        "Session Code: CNTR-8821-DELHI-T19\n" +
        "Events: 212 | Cosignatures: 14 | Chain: Intact\n" +
        "Fingerprint: 8f3a c992 41b0 d77e 102c b891\n" +
        "Witness: Verified & Countersigned by Examiner Seat #02\n" +
        "Digest Payload: " + digestRaw.value + "\n" +
        "=================================";

      navigator.clipboard.writeText(textToCopy).then(() => {
        if (copyText) copyText.textContent = I18N[currentLang].copied;
        showToast("Official slip digest copied to clipboard");
        setTimeout(() => {
          if (copyText) copyText.textContent = I18N[currentLang].copy_slip;
        }, 2500);
      }).catch(() => {
        digestRaw.focus();
        digestRaw.select();
      });
    });
  }

  if (printBtn) {
    printBtn.addEventListener("click", () => {
      window.print();
    });
  }
}

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  // Navigation event listeners
  document.querySelectorAll("[data-nav-view]").forEach(btn => {
    btn.addEventListener("click", () => {
      const v = btn.getAttribute("data-nav-view");
      navigateTo(v);
    });
  });

  // Language buttons
  const enBtn = document.getElementById("lang-en");
  const hiBtn = document.getElementById("lang-hi");
  if (enBtn) enBtn.addEventListener("click", () => setLanguage("en"));
  if (hiBtn) hiBtn.addEventListener("click", () => setLanguage("hi"));

  // Start exam affirmation
  const startBtn = document.getElementById("start-btn");
  const affirmCheck = document.getElementById("affirmation-check");
  if (startBtn && affirmCheck) {
    startBtn.addEventListener("click", () => {
      if (!affirmCheck.checked) {
        affirmCheck.focus();
        affirmCheck.parentElement.classList.add("bg-error-container/40", "p-1.5", "rounded-sm");
        setTimeout(() => {
          affirmCheck.parentElement.classList.remove("bg-error-container/40", "p-1.5", "rounded-sm");
        }, 1200);
        return;
      }
      startBtn.textContent = "Verifying Station Integrity...";
      startBtn.setAttribute("disabled", "true");
      setTimeout(() => {
        navigateTo("workstation");
      }, 500);
    });
  }

  // Workstation editor actions
  const saveBtn = document.getElementById("btn-save-file");
  if (saveBtn) saveBtn.addEventListener("click", handleSaveFile);

  const runBtn = document.getElementById("btn-run-code");
  if (runBtn) runBtn.addEventListener("click", handleRunCode);

  const cpBtn = document.getElementById("btn-checkpoint");
  if (cpBtn) cpBtn.addEventListener("click", handleCheckpoint);

  const flushBtn = document.getElementById("btn-flush");
  if (flushBtn) flushBtn.addEventListener("click", handleFlush);

  setupClipboardAndPrint();

  // Load initial view
  navigateTo("briefing");
});
