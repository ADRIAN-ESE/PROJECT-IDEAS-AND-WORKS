/* ==========================================================================
   PhishGuard — frontend controller (v2)
   ========================================================================== */

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const RING_CIRCUMFERENCE = 2 * Math.PI * 52; // r = 52

const VERDICTS = {
  clean:        { label: "Clean",        tone: "ok"   },
  low:          { label: "Low risk",     tone: "low"  },
  suspicious:   { label: "Suspicious",   tone: "warn" },
  phishing:     { label: "Phishing",     tone: "crit" },
  normal:       { label: "Normal",       tone: "ok"   },
  moderate:     { label: "Moderate",     tone: "warn" },
  high:         { label: "High",         tone: "crit" },
  critical:     { label: "Critical",     tone: "crit" },
  "at-risk":    { label: "At risk",      tone: "warn" },
  "likely-takeover": { label: "Likely takeover", tone: "crit" },
  compromised:  { label: "Compromised",  tone: "crit" },
  "no-signals": { label: "No signals",   tone: "ok"   },
};

const TONE_COLOR = { ok: "var(--ok)", low: "var(--low)", warn: "var(--warn)", crit: "var(--crit)" };

const VERDICT_NOTE = {
  clean: "No significant phishing signals were detected. Stay alert — scanners can miss novel lures.",
  low: "A few weak signals are present. Verify the sender and hover over links before clicking.",
  suspicious: "Multiple phishing techniques are present. Do not click links or open attachments; confirm with the sender through another channel.",
  phishing: "This message matches known phishing patterns. Do not reply, click or open anything — report and delete it.",
};

const ADVICE = {
  clean: [
    "Hover over links before clicking — a clean score is never a guarantee.",
    "Keep your email client, browser and OS up to date.",
  ],
  low: [
    "Verify the sender using a contact you already trust, not details in this message.",
    "Do not download attachments you were not expecting.",
  ],
  suspicious: [
    "Do not click links — type the service address into your browser yourself.",
    "Report the message as phishing in your mail client.",
    "If you already clicked, change the password from a different device and enable MFA.",
  ],
  phishing: [
    "Delete the message now — do not reply, click or open attachments.",
    "If you entered credentials, change that password immediately and anywhere you reused it.",
    "Enable multi-factor authentication on the targeted account.",
    "Run a full security scan if an attachment was opened.",
    "Report it to your security team or reportphishing@apwg.org.",
    "Check the address on the Exposure tab.",
    "Review the indicator list below on the Dashboard → Threat intel workbench.",
  ],
  normal:    ["Continue normal monitoring — no anomaly thresholds were crossed."],
  moderate:  ["Review the flagged events with the account owner.", "Tighten alert thresholds for this user or mailbox."],
  high:      ["Investigate the flagged logins immediately.", "Force a password reset and revoke active sessions.", "Check inbox rules for tampering."],
  critical:  ["Treat the account as compromised: rotate credentials and sign out every session.", "Review sent mail and forwarding rules.", "Open an incident and notify the user's manager."],
  "at-risk": ["Review the indicators with the account owner.", "Enable MFA and confirm recovery options are correct."],
  "likely-takeover": ["Assume the mailbox is compromised and rotate credentials now.", "Audit forwarding rules, delegates and recovery methods.", "Warn counterparties whose replies may be intercepted."],
  compromised: ["Immediate response: rotate the password from a trusted device and sign out all sessions.", "Remove attacker rules/delegates and re-enable MFA.", "Preserve evidence (export messages) before cleanup.", "Check the address on the Exposure tab for breaches."],
  "no-signals": ["No takeover indicators were provided — re-run with the observed signals for a real assessment."],
};

const CATEGORIES = {
  sender:        { label: "Sender & domain",    icon: '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>' },
  urls:          { label: "Links & URLs",       icon: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>' },
  content:       { label: "Content analysis",   icon: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M16 13H8M16 17H8M10 9H8"/>' },
  attachments:   { label: "Attachments",        icon: '<path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/>' },
  headers:       { label: "Header forensics",   icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' },
  threatintel:   { label: "Threat intelligence", icon: '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>' },
  activity:      { label: "Activity anomalies", icon: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>' },
  takeover:      { label: "Takeover signals",   icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>' },
};

const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };
const GROUP_ORDER = ["sender", "urls", "content", "attachments", "headers", "threatintel", "activity", "takeover"];

const SAMPLE_PHISHING = {
  sender: "PayPal Security <alerts@paypa1-account-verify.xyz>",
  subject: "URGENT: Your PayPal account will be suspended in 24 hours",
  body:
`Dear Customer,

We detected unusual activity on your account. Your account will be
suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account:
http://192.168.10.44/paypal-secure/login.php?ref=aG9zdD1waGFscGUubmV0JnVzZXI9MzQyMQ==

Failure to respond will result in permanent restriction. Please confirm
your password and provide your credit card number to restore access.

Thank you,
PayPal Customer Care`,
  headers:
`Authentication-Results: mx.example.com; spf=fail dkim=fail dmarc=fail
Received: from unknown (192.168.10.44)
Reply-To: helpdesk@attacker-mail.ru`,
  attachments: "invoice_2026.zip, update.exe",
};

const SAMPLE_LEGIT = {
  sender: "Jane Doe <jane.doe@northwind-co.com>",
  subject: "Notes from today's design review",
  body:
`Hi Sam,

Thanks for the thoughtful review this afternoon. I've attached the updated
mockups — the dashboard spacing change looked good to everyone.

Could you take a look before Thursday? Ping me on Teams if anything is
unclear.

Best,
Jane`,
  headers: "Authentication-Results: mx.northwind-co.com; spf=pass dkim=pass dmarc=pass",
  attachments: "mockups_v3.pdf",
};

const SAMPLE_ACTIVITY = {
  logins: JSON.stringify([
    { ts: "2026-10-07T09:12:00", user: "j.doe@northwind-co.com", ip: "198.51.100.20", geo: "DE", device: "Corp-Laptop-14", success: true },
    { ts: "2026-10-07T13:45:00", user: "j.doe@northwind-co.com", ip: "198.51.100.20", geo: "DE", device: "Corp-Laptop-14", success: true },
    { ts: "2026-10-07T23:48:00", user: "j.doe@northwind-co.com", ip: "203.0.113.77", geo: "NG", device: "UnknownBrowser", success: false },
    { ts: "2026-10-07T23:51:00", user: "j.doe@northwind-co.com", ip: "203.0.113.77", geo: "NG", device: "UnknownBrowser", success: false },
    { ts: "2026-10-07T23:53:00", user: "j.doe@northwind-co.com", ip: "203.0.113.77", geo: "NG", device: "UnknownBrowser", success: false },
    { ts: "2026-10-07T23:55:00", user: "j.doe@northwind-co.com", ip: "203.0.113.77", geo: "NG", device: "UnknownBrowser", success: false },
    { ts: "2026-10-07T23:58:00", user: "j.doe@northwind-co.com", ip: "203.0.113.77", geo: "NG", device: "UnknownBrowser", success: true },
    { ts: "2026-10-08T00:30:00", user: "j.doe@northwind-co.com", ip: "192.0.2.140", geo: "US", device: "Chrome/Unknown", success: true }
  ], null, 1),
  emails: JSON.stringify([
    { ts: "2026-10-08T00:45:00", from: "j.doe@northwind-co.com",
      recipients: Array.from({ length: 35 }, (_, i) => `client${i}@external.example`), subject: "Updated invoice" }
  ], null, 1),
};

/* ------------------------------- helpers -------------------------------- */

function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(message, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = message;
  $("#toast-stack").appendChild(el);
  setTimeout(() => el.classList.add("out"), 2600);
  setTimeout(() => el.remove(), 3000);
}

function setLoading(btn, loading, text) {
  btn.classList.toggle("loading", loading);
  btn.disabled = loading;
  if (text) btn.querySelector(".btn-label").textContent = text;
}

function countUp(el, target, duration = 850) {
  const start = Number(el.textContent) || 0;
  const t0 = performance.now();
  const step = (now) => {
    const p = Math.min(1, (now - t0) / duration);
    el.textContent = Math.round(start + (target - start) * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
  setTimeout(() => { el.textContent = target; }, duration + 120);
}

function scoreTone(score) {
  if (score >= 75) return "crit";
  if (score >= 50) return "warn";
  return "ok";
}

function nowLabel(ts) {
  const d = new Date(ts);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function api(path, options = {}) {
  const resp = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  let data = null;
  try { data = await resp.json(); } catch { /* empty body */ }
  if (!resp.ok) throw new Error((data && data.error) || `Request failed (${resp.status})`);
  return data;
}

/* ------------------------------ theme ----------------------------------- */

const savedTheme = localStorage.getItem("pg-theme");
if (savedTheme) document.documentElement.dataset.theme = savedTheme;

$("#theme-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next;
  localStorage.setItem("pg-theme", next);
});

/* ------------------------------- tabs ----------------------------------- */

$$(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".nav-btn").forEach((b) => {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-selected", b === btn ? "true" : "false");
    });
    $$(".view").forEach((v) => v.classList.toggle("active", v.id === btn.dataset.tab));
    if (btn.dataset.tab === "dashboard") loadDashboard();
    if (btn.dataset.tab === "exposure") loadIndicators();
  });
});

function gotoTab(id) {
  const btn = document.querySelector(`.nav-btn[data-tab="${id}"]`);
  if (btn) btn.click();
}

/* ------------------------- analyzer: input ------------------------------- */

let pendingAttachmentHashes = [];

const bodyEl = $("#body");
bodyEl.addEventListener("input", () => { $("#char-count").textContent = bodyEl.value.length; });

function fillForm(data) {
  $("#sender").value = data.sender || "";
  $("#subject").value = data.subject || "";
  $("#body").value = data.body || "";
  $("#headers").value = data.headers || "";
  $("#attachments").value = typeof data.attachments === "string"
    ? data.attachments
    : (data.attachments || []).join(", ");
  $("#char-count").textContent = ($("#body").value || "").length;
}

$("#sample-btn").addEventListener("click", () => {
  pendingAttachmentHashes = [];
  fillForm(SAMPLE_PHISHING);
  toast("Sample phishing email loaded", "info");
});

$("#sample-legit-btn").addEventListener("click", () => {
  pendingAttachmentHashes = [];
  fillForm(SAMPLE_LEGIT);
  toast("Legitimate email loaded", "info");
});

$("#clear-btn").addEventListener("click", () => {
  pendingAttachmentHashes = [];
  fillForm({});
  $("#report").hidden = true;
  $("#empty-state").hidden = false;
  $("#analyze-error").hidden = true;
  $("#upload-status").hidden = true;
});

/* --------------------------- .eml upload --------------------------------- */

const dropzone = $("#dropzone");
const fileInput = $("#file-input");

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); }
});
["dragover", "dragenter"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add("drag"); }));
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); }));
dropzone.addEventListener("drop", (e) => {
  const file = e.dataTransfer.files && e.dataTransfer.files[0];
  if (file) uploadEml(file);
});
fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) uploadEml(fileInput.files[0]);
  fileInput.value = "";
});

async function uploadEml(file) {
  const status = $("#upload-status");
  status.hidden = false;
  status.classList.remove("err");
  status.textContent = `Parsing ${file.name}…`;

  try {
    const form = new FormData();
    form.append("file", file);
    const resp = await fetch("/api/parse-eml", { method: "POST", body: form });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Upload failed.");

    pendingAttachmentHashes = data.attachment_hashes || [];
    fillForm(data);
    status.textContent = `✓ Parsed ${file.name} — ${data.meta.attachment_count} attachment(s), `
      + `${data.headers ? data.headers.split("\n").length : 0} header lines. Ready to analyze.`;
    toast("Message file parsed", "ok");
  } catch (err) {
    status.classList.add("err");
    status.textContent = `✕ ${err.message}`;
  }
}

/* --------------------------- analyzer: run -------------------------------- */

$("#analyze-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#analyze-btn");
  const errBox = $("#analyze-error");
  errBox.hidden = true;
  setLoading(btn, true, "Analyzing…");

  try {
    const data = await api("/api/analyze", {
      method: "POST",
      body: JSON.stringify({
        sender: $("#sender").value,
        subject: $("#subject").value,
        body: $("#body").value,
        headers: $("#headers").value,
        attachments: $("#attachments").value,
        attachment_hashes: pendingAttachmentHashes,
      }),
    });
    renderReport(data);
    toast(`Analysis complete — score ${data.score}/100`, data.score >= 50 ? "err" : "ok");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    setLoading(btn, false, "Run analysis");
  }
});

/* ---------------------------- email report -------------------------------- */

let currentReport = null;

function renderReport(data) {
  currentReport = data;

  $("#empty-state").hidden = true;
  $("#report").hidden = false;

  const meta = VERDICTS[data.verdict] || { label: data.verdict, tone: scoreTone(data.score) };
  const note = VERDICT_NOTE[data.verdict] ||
    "Automated assessment complete — review the findings below.";

  const ring = $("#ring");
  ring.style.stroke = TONE_COLOR[meta.tone];
  ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - data.score / 100));
  countUp($("#gauge-value"), data.score);

  const badge = $("#verdict");
  badge.textContent = meta.label;
  badge.className = `verdict-badge ${toneClass(meta.tone)}`;
  $("#verdict-note").textContent = note;
  $("#scan-id").textContent = `Scan ${data.scan_id || "LOCAL"}`;
  $("#scan-time").textContent = data.analyzed_at ? new Date(data.analyzed_at).toLocaleString()
                                                 : new Date().toLocaleString();

  renderCategories(data.categories || {});

  // links
  const urls = data.urls || [];
  $("#urls-section").hidden = !urls.length;
  $("#url-count").textContent = urls.length;
  $("#url-list").innerHTML = urls.map((u) => `<li>${escapeHtml(u)}</li>`).join("");

  renderIocs(data);
  renderThreatIntel(data);
  renderFindings(data.findings || []);

  $("#advice-list").innerHTML = (ADVICE[data.verdict] || ["Review the findings manually."])
    .map((a) => `<li>${escapeHtml(a)}</li>`).join("");

  updateFeedbackBar(data);
}

function toneClass(tone) {
  return { ok: "clean", low: "low", warn: "suspicious", crit: "phishing" }[tone] || "clean";
}

function renderCategories(categories) {
  const maxCat = Math.max(...Object.values(categories), 1);
  $("#cat-grid").innerHTML = Object.entries(categories).map(([key, pts]) => `
    <div class="cat-chip" title="${escapeHtml(CATEGORIES[key]?.label || key)}">
      <div class="top"><span>${escapeHtml(CATEGORIES[key]?.label || key)}</span><b>${pts}</b></div>
      <div class="mini-bar"><span data-w="${Math.round((pts / maxCat) * 100)}"></span></div>
    </div>`).join("");
  requestAnimationFrame(() => {
    $$("#cat-grid .mini-bar span").forEach((bar) => { bar.style.width = bar.dataset.w + "%"; });
  });
}

function renderFindings(findings) {
  $("#finding-count").textContent = findings.length;
  if (!findings.length) {
    $("#finding-groups").innerHTML =
      `<div class="no-findings">No suspicious signals detected across any analysis stage.</div>`;
    return;
  }
  const byCat = {};
  findings.forEach((f) => (byCat[f.category] = byCat[f.category] || []).push(f));

  $("#finding-groups").innerHTML = GROUP_ORDER
    .filter((cat) => byCat[cat])
    .map((cat) => {
      const meta = CATEGORIES[cat] || { label: cat, icon: "" };
      return `
        <div class="finding-group">
          <div class="group-head">
            <span class="g-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${meta.icon}</svg></span>
            ${escapeHtml(meta.label)}
            <span class="count-pill">${byCat[cat].length}</span>
          </div>
          ${byCat[cat].map((f) => `
            <div class="finding ${f.severity}">
              <span class="sev ${f.severity}">${SEVERITY_LABEL[f.severity] || f.severity}</span>
              <div class="finding-body">
                <div class="finding-title">
                  <span>${escapeHtml(f.title)}</span>
                  <span class="points">+${f.points}</span>
                </div>
                <p>${escapeHtml(f.detail)}</p>
              </div>
            </div>`).join("")}
        </div>`;
    }).join("");
}

function renderIocs(data) {
  const iocs = data.iocs;
  const section = $("#ioc-section");
  if (!iocs) { section.hidden = true; return; }

  const rows = [
    ...iocs.urls.map((v) => ["url", v]),
    ...iocs.domains.map((v) => ["domain", v]),
    ...iocs.ips.map((v) => ["ip", v]),
    ...iocs.emails.map((v) => ["email", v]),
    ...iocs.hashes.map((h) => [h.type, h.value]),
  ];
  section.hidden = rows.length === 0;
  $("#ioc-count").textContent = rows.length;

  const flagged = new Set(((data.threat_intel || {}).matches || []).map((m) => m.indicator));
  $("#ioc-grid").innerHTML = rows.map(([type, value]) => {
    const isFlagged = flagged.has(value);
    return `
      <div class="ioc-row">
        <span class="ioc-type">${escapeHtml(type)}</span>
        <span class="ioc-value">${escapeHtml(value)}</span>
        ${isFlagged ? '<span class="ioc-flag">TI hit</span>' : ""}
      </div>`;
  }).join("");
}

function renderThreatIntel(data) {
  const ti = data.threat_intel;
  const section = $("#ti-section");
  if (!ti) { section.hidden = true; return; }
  section.hidden = false;

  const matches = ti.matches || [];
  if (!matches.length) {
    $("#ti-summary").innerHTML = `
      <div class="ti-box ok">
        <strong>No matches in ${ti.feed_size} feed entries + ${ti.watchlist_size} watchlist indicator(s)</strong>
        None of the ${ti.checked} extracted indicator(s) matched bundled threat intelligence
        or the analyst watchlist. This does not guarantee the indicators are benign.
      </div>`;
    return;
  }
  $("#ti-summary").innerHTML = `
    <div class="ti-box bad">
      <strong>${matches.length} threat-intelligence match(es) out of ${ti.checked} indicators</strong>
      ${matches.map((m) => `
        <div class="ti-match">
          <span class="ti-cat ${m.confidence}">${escapeHtml(m.confidence)}</span>
          <code>${escapeHtml(m.indicator)}</code>
          <span>${escapeHtml(m.category)} · ${escapeHtml(m.source)}</span>
        </div>`).join("")}
    </div>`;
}

/* ---------------------------- report actions ----------------------------- */

function reportAsText() {
  if (!currentReport) return "";
  const meta = VERDICTS[currentReport.verdict] || { label: currentReport.verdict };
  const lines = [
    "PhishGuard — Email Threat Analysis Report",
    `Scan ID    : ${currentReport.scan_id || "n/a"}`,
    `Timestamp  : ${currentReport.analyzed_at || new Date().toISOString()}`,
    `Score      : ${currentReport.score}/100`,
    `Verdict    : ${meta.label}`,
    "",
    "Findings:",
    ...(currentReport.findings || []).map(
      (f) => `  [${String(f.severity).toUpperCase().padEnd(6)}] (${f.category}) ${f.title} +${f.points}\n           ${f.detail}`),
  ];
  const iocs = currentReport.iocs;
  if (iocs) {
    lines.push("", "Indicators:");
    ["urls", "domains", "ips", "emails"].forEach((g) =>
      (iocs[g] || []).forEach((v) => lines.push(`  ${g}: ${v}`)));
    (iocs.hashes || []).forEach((h) => lines.push(`  ${h.type}: ${h.value} (${h.source})`));
  }
  lines.push("", "Recommended actions:", ...(ADVICE[currentReport.verdict] || []).map((a) => `  - ${a}`));
  return lines.join("\n");
}

$("#copy-btn").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(reportAsText());
    toast("Report copied to clipboard", "ok");
  } catch { toast("Clipboard unavailable — use Download JSON", "err"); }
});

$("#copy-iocs-btn")?.addEventListener("click", async () => {
  const iocs = currentReport && currentReport.iocs;
  if (!iocs) return;
  const text = [
    ...iocs.urls, ...iocs.domains, ...iocs.ips, ...iocs.emails,
    ...iocs.hashes.map((h) => h.value),
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    toast("IOCs copied", "ok");
  } catch { toast("Clipboard unavailable", "err"); }
});

$("#download-btn").addEventListener("click", () => {
  if (!currentReport) return;
  const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `phishguard-${currentReport.scan_id || "report"}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast("JSON report downloaded", "ok");
});

$("#print-btn").addEventListener("click", () => window.print());

/* ------------------------------- feedback --------------------------------- */

function updateFeedbackBar(data) {
  const hasId = Boolean(data.scan_id);
  $("#fb-tp").disabled = !hasId;
  $("#fb-fp").disabled = !hasId;
  $("#fb-tp").classList.toggle("active-tp", data.feedback === "tp");
  $("#fb-fp").classList.toggle("active-fp", data.feedback === "fp");
  $("#fb-status").textContent = data.feedback === "tp" ? "Marked true positive"
    : data.feedback === "fp" ? "Marked false positive"
    : hasId ? "Was this detection correct?" : "";
}

async function sendFeedback(label) {
  if (!currentReport || !currentReport.scan_id) return;
  try {
    await api("/api/feedback", {
      method: "POST",
      body: JSON.stringify({ incident_id: currentReport.scan_id, label }),
    });
    currentReport.feedback = label;
    updateFeedbackBar(currentReport);
    toast(label === "tp" ? "Marked true positive" : "Marked false positive", "ok");
  } catch (err) { toast(err.message, "err"); }
}

$("#fb-tp").addEventListener("click", () => sendFeedback("tp"));
$("#fb-fp").addEventListener("click", () => sendFeedback("fp"));

/* --------------------------- exposure: password --------------------------- */

$("#password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#password-btn");
  const errBox = $("#password-error");
  const out = $("#password-result");
  errBox.hidden = true;
  out.hidden = true;
  setLoading(btn, true, "Checking…");

  try {
    const data = await api("/api/password-check", {
      method: "POST",
      body: JSON.stringify({ password: $("#password").value }),
    });
    $("#password").value = "";
    out.hidden = false;
    if (data.exposed) {
      out.className = "notice bad";
      out.innerHTML = `<strong>Exposed ${data.count.toLocaleString()} time${data.count === 1 ? "" : "s"}</strong>
        This password appears in known breach corpora. Stop using it everywhere
        immediately and replace it with a long, unique passphrase.
        <small>${escapeHtml(data.note || "")}</small>`;
    } else {
      out.className = "notice ok";
      out.innerHTML = `<strong>Not found in known breaches</strong>
        Not in the HIBP corpus — that alone does not make it strong: use a long,
        unique passphrase stored in a password manager.
        <small>${escapeHtml(data.note || "")}</small>`;
    }
    toast("Password check complete", "ok");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    setLoading(btn, false, "Check password");
  }
});

/* --------------------------- exposure: breaches --------------------------- */

$("#breach-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#breach-btn");
  const errBox = $("#breach-error");
  const out = $("#breach-result");
  errBox.hidden = true;
  out.hidden = true;
  setLoading(btn, true, "Checking…");

  try {
    const data = await api("/api/breach-check", {
      method: "POST",
      body: JSON.stringify({ email: $("#email").value, api_key: $("#api-key").value }),
    });
    out.hidden = false;
    if (!data.breaches || !data.breaches.length) {
      out.className = "notice ok";
      out.innerHTML = `<strong>No breaches found</strong>${escapeHtml(data.message || "")}`;
    } else {
      out.className = "notice bad";
      out.innerHTML = `<strong>${data.breaches.length} breach(es) found</strong>` +
        data.breaches.map((b) => `
          <div class="breach-item">
            <div><strong>${escapeHtml(b.title || b.name)}</strong></div>
            <div class="meta">${escapeHtml(b.breach_date || "")} · ${escapeHtml(b.domain || "n/a")}</div>
            <div class="tags">${(b.data_classes || []).slice(0, 8).map((c) => `<span class="tag">${escapeHtml(c)}</span>`).join("")}</div>
          </div>`).join("");
    }
    toast("Breach lookup complete", "ok");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    setLoading(btn, false, "Check breaches");
  }
});

/* ------------------------ exposure: takeover ------------------------------ */

let indicatorCatalogue = [];

async function loadIndicators() {
  if (indicatorCatalogue.length) return;
  try {
    indicatorCatalogue = await api("/api/indicators");
    $("#takeover-list").innerHTML = indicatorCatalogue.map((ind) => `
      <label class="check-item">
        <input type="checkbox" name="indicator" value="${escapeHtml(ind.key)}" />
        <span class="ci-body">
          <span class="ci-title">${escapeHtml(ind.title)}</span>
          <span class="ci-meta">${escapeHtml(ind.severity)} severity · <span class="ci-pts">+${ind.points} pts</span></span>
        </span>
      </label>`).join("");
  } catch (err) {
    $("#takeover-list").innerHTML = `<p class="help">${escapeHtml(err.message)}</p>`;
  }
}

$("#takeover-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#takeover-btn");
  const errBox = $("#takeover-error");
  errBox.hidden = true;
  const selected = $$('#takeover-list input[name="indicator"]:checked').map((i) => i.value);
  if (!selected.length) {
    errBox.textContent = "Select at least one observed indicator.";
    errBox.hidden = false;
    return;
  }
  setLoading(btn, true, "Assessing…");

  try {
    const data = await api("/api/takeover", {
      method: "POST",
      body: JSON.stringify({ indicators: selected }),
    });
    renderAssessment(data, $("#takeover-result"), "takeover");
    toast(`Takeover risk ${data.score}/100`, data.score >= 50 ? "err" : "ok");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    setLoading(btn, false, "Assess takeover risk");
  }
});

/* ----------------------------- activity ---------------------------------- */

$("#activity-sample").addEventListener("click", () => {
  $("#logins").value = SAMPLE_ACTIVITY.logins;
  $("#sendemails").value = SAMPLE_ACTIVITY.emails;
  toast("Sample events loaded", "info");
});

$("#activity-clear").addEventListener("click", () => {
  $("#logins").value = "";
  $("#sendemails").value = "";
  $("#activity-result").hidden = true;
  $("#activity-empty").hidden = false;
  $("#activity-error").hidden = true;
});

function parseJsonField(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) return [];
  const parsed = JSON.parse(trimmed);
  if (!Array.isArray(parsed)) throw new Error("Field must contain a JSON array.");
  return parsed;
}

$("#activity-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#activity-btn");
  const errBox = $("#activity-error");
  errBox.hidden = true;

  let logins, emails;
  try {
    logins = parseJsonField($("#logins").value);
    emails = parseJsonField($("#sendemails").value);
  } catch (err) {
    errBox.textContent = `Invalid JSON: ${err.message}`;
    errBox.hidden = false;
    return;
  }

  setLoading(btn, true, "Analysing…");
  try {
    const data = await api("/api/activity", {
      method: "POST",
      body: JSON.stringify({ logins, emails }),
    });
    $("#activity-empty").hidden = true;
    renderAssessment(data, $("#activity-result"), "activity");
    toast(`Activity score ${data.score}/100`, data.score >= 60 ? "err" : "ok");
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    setLoading(btn, false, "Analyse activity");
  }
});

/* generic assessment renderer (activity + takeover) */
function renderAssessment(data, container, kind) {
  const meta = VERDICTS[data.verdict] || { label: data.verdict, tone: scoreTone(data.score) };
  const advice = ADVICE[data.verdict] || [];

  container.innerHTML = `
    <div class="assess-head">
      <div class="assess-score ${meta.tone === "low" ? "warn" : meta.tone}">${data.score}</div>
      <div>
        <span class="assess-verdict" style="color:${TONE_COLOR[meta.tone]}">${escapeHtml(meta.label)}</span>
        <div class="assess-meta">${escapeHtml(data.scan_id || "")} · ${escapeHtml(nowLabel(data.analyzed_at || Date.now()))}</div>
        <p class="assess-note">${data.counts ? `${data.counts.findings} finding(s) across ${data.counts.logins ?? "-"} login and ${data.counts.emails ?? "-"} mail events.` : ""}</p>
      </div>
    </div>
    <div class="report-section">
      <div class="section-title"><h3>Findings</h3><span class="count-pill">${(data.findings || []).length}</span></div>
      ${renderFindingsPlain(data.findings || [])}
    </div>
    <div class="report-section">
      <div class="section-title"><h3>Recommended actions</h3></div>
      <ul class="advice-list">${advice.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>
    </div>
    <div class="report-actions">
      <button class="btn secondary small" data-act="copy">Copy</button>
      <button class="btn secondary small" data-act="json">Download JSON</button>
      <button class="btn secondary small" data-act="tp" ${data.scan_id ? "" : "disabled"}>✓ True positive</button>
      <button class="btn secondary small" data-act="fp" ${data.scan_id ? "" : "disabled"}>✕ False positive</button>
    </div>`;

  container.querySelector('[data-act="copy"]').addEventListener("click", async () => {
    const text = `${kind} assessment ${data.scan_id || ""} — ${data.score}/100 ${meta.label}\n` +
      (data.findings || []).map((f) => `  [${f.severity}] ${f.title} +${f.points}\n     ${f.detail}`).join("\n");
    try { await navigator.clipboard.writeText(text); toast("Copied", "ok"); }
    catch { toast("Clipboard unavailable", "err"); }
  });
  container.querySelector('[data-act="json"]').addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard-${kind}-${data.scan_id || "report"}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  });
  ["tp", "fp"].forEach((label) => {
    container.querySelector(`[data-act="${label}"]`).addEventListener("click", async () => {
      try {
        await api("/api/feedback", {
          method: "POST",
          body: JSON.stringify({ incident_id: data.scan_id, label }),
        });
        toast(label === "tp" ? "Marked true positive" : "Marked false positive", "ok");
      } catch (err) { toast(err.message, "err"); }
    });
  });
  container.hidden = false;
}

function renderFindingsPlain(findings) {
  if (!findings.length) return `<div class="no-findings">No anomalies detected — behaviour matches the expected baseline.</div>`;
  return findings.map((f) => `
    <div class="finding ${f.severity}">
      <span class="sev ${f.severity}">${SEVERITY_LABEL[f.severity] || f.severity}</span>
      <div class="finding-body">
        <div class="finding-title"><span>${escapeHtml(f.title)}</span><span class="points">+${f.points}</span></div>
        <p>${escapeHtml(f.detail)}</p>
      </div>
    </div>`).join("");
}

/* ----------------------------- dashboard ---------------------------------- */

$("#refresh-dash").addEventListener("click", () => { loadDashboard(); toast("Dashboard refreshed", "info"); });

async function loadDashboard() {
  try {
    const [stats, alerts, incidents, feed] = await Promise.all([
      api("/api/stats"), api("/api/alerts"), api("/api/incidents"), api("/api/ti/feed"),
    ]);

    $("#kpi-incidents").textContent = stats.total_incidents;
    $("#kpi-alerts").textContent = stats.open_alerts;
    $("#kpi-avg").textContent = stats.avg_score;
    $("#kpi-accuracy").textContent = stats.feedback.accuracy == null ? "—" : `${stats.feedback.accuracy}%`;
    $("#kpi-feed").textContent = feed.size;
    $("#footer-version").textContent = `PhishGuard v${stats.version || "2.0"} · ${stats.total_incidents} incidents recorded`;
    $("#feed-info").textContent = `${feed.size} entries · ${feed.categories.join(", ")}`;

    renderAlerts(alerts);
    renderVerdictChart(stats);
    renderFeedbackSummary(stats.feedback);
    renderIncidents(incidents);
    loadIocTable();
  } catch (err) {
    toast(`Dashboard: ${err.message}`, "err");
  }
}

function renderAlerts(alerts) {
  $("#alert-count").textContent = `${alerts.length} total`;
  const list = $("#alert-list");
  if (!alerts.length) {
    list.innerHTML = `<p class="help">No alerts generated yet. Alerts open automatically when an incident scores ≥ 50.</p>`;
    return;
  }
  list.innerHTML = alerts.map((a) => `
    <div class="alert-row ${a.severity} ${a.status === "resolved" ? "resolved" : ""}" data-alert="${a.id}">
      <div class="alert-main">
        <span class="alert-title">${escapeHtml(a.title)}</span>
        <span class="alert-meta">#${a.id} · ${escapeHtml(nowLabel(a.created_at))}</span>
      </div>
      <span class="status-pill ${a.status}">${a.status}</span>
      <span class="sev ${a.severity === "critical" ? "high" : a.severity === "high" ? "medium" : "low"}">${a.severity}</span>
      <div class="alert-actions">
        ${a.status === "new" ? '<button class="fb-btn" data-status="acknowledged">Ack</button>' : ""}
        ${a.status !== "resolved" ? '<button class="fb-btn" data-status="resolved">Resolve</button>' : ""}
      </div>
    </div>`).join("");

  list.querySelectorAll("button[data-status]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.closest("[data-alert]").dataset.alert;
      try {
        await api(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status: btn.dataset.status }) });
        loadDashboard();
      } catch (err) { toast(err.message, "err"); }
    });
  });
}

function renderVerdictChart(stats) {
  const order = ["phishing", "suspicious", "low", "clean"];
  const colors = { phishing: "var(--crit)", suspicious: "var(--warn)", low: "var(--low)", clean: "var(--ok)" };
  const counts = stats.by_verdict || {};
  const max = Math.max(...order.map((k) => counts[k] || 0), 1);
  $("#verdict-chart").innerHTML = order.map((key) => {
    const n = counts[key] || 0;
    return `
      <div class="vbar">
        <span class="label"><i class="dot ${key === "phishing" ? "crit" : key === "suspicious" ? "warn" : key === "low" ? "low" : "ok"}"></i>${key}</span>
        <div class="track"><span style="width:${Math.round((n / max) * 100)}%;background:${colors[key]}"></span></div>
        <b>${n}</b>
      </div>`;
  }).join("");
}

function renderFeedbackSummary(fb) {
  $("#feedback-summary").innerHTML = `
    <div class="big">${fb.accuracy == null ? "—" : fb.accuracy + "%"}</div>
    <div>${fb.true_positives} true positive · ${fb.false_positives} false positive
         (${fb.judged} judged)</div>
    <div class="help">Accuracy = true positives ÷ judged detections. Mark reports as TP/FP
         to calibrate the engine's thresholds.</div>`;
}

function renderIncidents(incidents) {
  $("#incident-count").textContent = `${incidents.length} shown`;
  const body = $("#incident-body");
  if (!incidents.length) {
    body.innerHTML = `<tr><td colspan="7" class="help">No incidents recorded yet.</td></tr>`;
    return;
  }
  body.innerHTML = incidents.map((i) => `
    <tr data-incident="${i.id}">
      <td class="subject">${escapeHtml(i.title)}</td>
      <td><span class="kind-chip ${i.kind}">${i.kind}</span></td>
      <td class="score-cell ${scoreTone(i.score)}">${i.score}</td>
      <td><span class="mini-verdict ${toneClass(scoreTone(i.score))}">${escapeHtml((VERDICTS[i.verdict] || {}).label || i.verdict)}</span></td>
      <td>${escapeHtml(nowLabel(i.created_at))}</td>
      <td>
        <div class="fb-btns">
          <button class="fb-btn ${i.feedback === "tp" ? "on-tp" : ""}" data-fb="tp" data-id="${i.id}">TP</button>
          <button class="fb-btn ${i.feedback === "fp" ? "on-fp" : ""}" data-fb="fp" data-id="${i.id}">FP</button>
        </div>
      </td>
      <td><button class="fb-btn" data-open="${i.id}">Open</button></td>
    </tr>`).join("");

  body.querySelectorAll("[data-fb]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      try {
        await api("/api/feedback", {
          method: "POST",
          body: JSON.stringify({ incident_id: btn.dataset.id, label: btn.dataset.fb }),
        });
        loadDashboard();
        toast("Feedback saved", "ok");
      } catch (err) { toast(err.message, "err"); }
    });
  });

  body.querySelectorAll("[data-open]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      openIncident(btn.dataset.open);
    });
  });

  body.querySelectorAll("tr[data-incident]").forEach((row) => {
    row.addEventListener("click", () => openIncident(row.dataset.incident));
  });
}

async function openIncident(id) {
  try {
    const detail = await api(`/api/incidents/${id}`);
    if (detail.kind === "email") {
      fillForm(detail.inputs || {});
      pendingAttachmentHashes = (detail.inputs || {}).attachment_hashes || [];
      renderReport({ ...detail.report, feedback: detail.feedback });
      gotoTab("analyzer");
      window.scrollTo({ top: 0, behavior: "smooth" });
    } else if (detail.kind === "activity") {
      $("#activity-empty").hidden = true;
      renderAssessment(detail.report, $("#activity-result"), "activity");
      gotoTab("activity");
    } else if (detail.kind === "takeover") {
      const inputs = (detail.inputs || {}).indicators || [];
      loadIndicators().then(() => {
        $$('#takeover-list input[name="indicator"]').forEach((cb) => { cb.checked = inputs.includes(cb.value); });
      });
      renderAssessment(detail.report, $("#takeover-result"), "takeover");
      gotoTab("exposure");
    }
  } catch (err) { toast(err.message, "err"); }
}

async function loadIocTable() {
  try {
    const data = await api("/api/iocs");
    $("#ioc-total").textContent = `${data.iocs.length} unique`;
    const body = $("#dash-ioc-body");
    if (!data.iocs.length) {
      body.innerHTML = `<tr><td colspan="4" class="help">No indicators extracted yet — run an email analysis first.</td></tr>`;
      return;
    }
    body.innerHTML = data.iocs.slice(0, 30).map((i) => `
      <tr>
        <td class="subject" style="font-family:var(--font-mono);font-size:.76rem">${escapeHtml(i.value)}</td>
        <td>${escapeHtml(i.type)}</td>
        <td>${i.count}</td>
        <td>${i.flagged ? `<span class="ioc-flag">${escapeHtml(i.category || "match")}</span>` : '<span class="help">clean</span>'}</td>
      </tr>`).join("");
  } catch (err) {
    $("#dash-ioc-body").innerHTML = `<tr><td colspan="4" class="help">${escapeHtml(err.message)}</td></tr>`;
  }
}

/* ------------------------- threat intel workbench -------------------------- */

$("#ti-check-btn").addEventListener("click", async () => {
  const out = $("#ti-result");
  const lines = $("#ti-input").value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!lines.length) { toast("Enter at least one indicator", "err"); return; }
  out.hidden = false;
  out.className = "notice info";
  out.textContent = "Checking…";
  try {
    const data = await api("/api/ti/check", { method: "POST", body: JSON.stringify({ indicators: lines }) });
    if (!data.matches.length) {
      out.className = "notice ok";
      out.innerHTML = `<strong>No matches</strong>${data.checked} indicator(s) checked against ${data.feed_size} feed entries and ${data.watchlist_size} watchlist entries.`;
    } else {
      out.className = "notice bad";
      out.innerHTML = `<strong>${data.matches.length} match(es)</strong>` + data.matches.map((m) => `
        <div class="ti-match">
          <span class="ti-cat ${m.confidence}">${escapeHtml(m.confidence)}</span>
          <code>${escapeHtml(m.indicator)}</code>
          <span>${escapeHtml(m.category)} · ${escapeHtml(m.source)}</span>
        </div>`).join("");
    }
  } catch (err) {
    out.className = "notice bad";
    out.innerHTML = `<strong>Error</strong>${escapeHtml(err.message)}`;
  }
});

$("#ti-add-btn").addEventListener("click", async () => {
  const value = $("#ti-input").value.split("\n").map((s) => s.trim()).filter(Boolean)[0];
  if (!value) { toast("Enter an indicator to add", "err"); return; }
  try {
    const data = await api("/api/ti/add", { method: "POST", body: JSON.stringify({ indicator: value }) });
    toast(`Added to watchlist (${data.watchlist_size} total)`, "ok");
  } catch (err) { toast(err.message, "err"); }
});

/* ------------------------------- init ------------------------------------- */

loadIndicators();
