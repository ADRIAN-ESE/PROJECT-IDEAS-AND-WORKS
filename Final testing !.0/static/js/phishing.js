/**
 * CyberAware — Phishing Simulator
 */

const Phishing = {
  examples: [],
  current: null,
  found: new Set(),

  async init() {
    try {
      const res = await fetch("/api/phishing-examples");
      if (res.status === 401) {
        this.examples = [];
        this.renderList("Sign in to unlock the phishing simulator.");
        return;
      }
      if (res.status === 403) {
        const data = await res.json();
        this.examples = [];
        this.renderList(data.error || "Your account needs approval to access training.");
        return;
      }
      if (!res.ok) throw new Error(`Phishing request failed: ${res.status}`);
      this.examples = await res.json();
    } catch (e) {
      console.error("Failed to load phishing examples", e);
      this.examples = [];
      this.renderList("The phishing examples could not be loaded. Please try again.");
      return;
    }
    this.renderList();
  },

  renderList(message = "") {
    const list = document.getElementById("phishingList");
    if (!list) return;

    if (!this.examples.length) {
      const signedIn = Boolean(Auth?.user);
      list.innerHTML = `<div class="module-gate"><span class="module-gate-icon">🎣</span><h3>Phishing practice is ready when you are</h3><p>${message}</p><button class="btn btn-primary" type="button">${signedIn ? "Go to dashboard" : "Sign in to continue"}</button></div>`;
      list.querySelector("button")?.addEventListener("click", () => {
        if (signedIn) App.navigate("dashboard");
        else Auth?.open("login", message);
      });
      return;
    }

    list.innerHTML = this.examples.map(ex => `
      <div class="phish-card" data-id="${ex.id}">
        <div class="diff">${ex.difficulty} ${ex.is_phishing ? "· Phishing" : "· Safe Example"}</div>
        <h3>${ex.title}</h3>
        <p>From: ${ex.from_name}</p>
      </div>
    `).join("");

    list.querySelectorAll(".phish-card").forEach(card => {
      card.addEventListener("click", () => this.open(card.dataset.id));
    });
  },

  open(id) {
    if (typeof Auth !== "undefined" && !Auth.canAccessTraining()) {
      return;
    }

    this.current = this.examples.find(e => e.id === id);
    if (!this.current) return;

    this.found = new Set();
    document.getElementById("phishingList").classList.add("hidden");
    document.getElementById("phishingSim").classList.remove("hidden");
    document.getElementById("phishExplanation").classList.add("hidden");
    document.getElementById("foundFlags").innerHTML = "";
    document.getElementById("flagCount").textContent = "0";
    document.getElementById("flagTotal").textContent = this.current.red_flags.length;

    this.renderEmail();

    // Buttons
    document.getElementById("revealFlagsBtn").onclick = () => this.revealAll();
    document.getElementById("nextPhishBtn").onclick = () => this.close();
    document.querySelector(".email-toolbar-btn").onclick = () => this.close();
  },

  renderEmail() {
    const ex = this.current;
    const meta = document.getElementById("emailMeta");
    const body = document.getElementById("emailBody");

    // Mark potential red-flag zones
    const fromClass = ex.red_flags.some(f => f.selector === "from_email") ? "clickable-flag" : "";
    const subjectClass = ex.red_flags.some(f => f.selector === "subject") ? "clickable-flag" : "";

    meta.innerHTML = `
      <div class="row"><span class="label">From</span>
        <span class="value ${fromClass}" data-flag="from_email">${ex.from_name} &lt;${ex.from_email}&gt;</span>
      </div>
      <div class="row"><span class="label">To</span><span class="value">${ex.to}</span></div>
      <div class="row"><span class="label">Subject</span>
        <span class="value ${subjectClass}" data-flag="subject">${ex.subject}</span>
      </div>
      <div class="row"><span class="label">Date</span><span class="value">${ex.date}</span></div>
    `;

    // Process body — wrap known flag selectors with clickable spans
    let html = ex.body_html;

    // Simple heuristic: make the main CTA link clickable if flagged
    if (ex.red_flags.some(f => f.selector === "body_link")) {
      html = html.replace(
        /<a\s+href="[^"]*"/gi,
        (match) => match + ' class="clickable-flag" data-flag="body_link"'
      );
    }

    // Greeting / urgency text approximations
    if (ex.red_flags.some(f => f.selector === "greeting")) {
      html = html.replace(
        /(Dear Valued Customer|Dear Employee|Hello,)/i,
        '<span class="clickable-flag" data-flag="greeting">$1</span>'
      );
    }
    if (ex.red_flags.some(f => f.selector === "urgency" || f.selector === "urgency_secrecy" || f.selector === "threat")) {
      const sel = ex.red_flags.find(f =>
        f.selector === "urgency" || f.selector === "urgency_secrecy" || f.selector === "threat"
      ).selector;
      html = html.replace(
        /(24 hours|48 hours|end of day|time-sensitive|permanently suspended|account lockout|do not discuss)/gi,
        `<span class="clickable-flag" data-flag="${sel}">$1</span>`
      );
    }
    if (ex.red_flags.some(f => f.selector === "wire_details")) {
      html = html.replace(
        /(Bank:|Account:|SWIFT:)/gi,
        '<span class="clickable-flag" data-flag="wire_details">$1</span>'
      );
    }
    if (ex.red_flags.some(f => f.selector === "unexpected_share")) {
      html = html.replace(
        /(shared a document with you)/i,
        '<span class="clickable-flag" data-flag="unexpected_share">$1</span>'
      );
    }

    body.innerHTML = html;

    // Click handlers for flags
    document.querySelectorAll(".clickable-flag").forEach(el => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const flagId = el.dataset.flag;
        this.markFound(flagId, el);
      });
    });
  },

  markFound(selector, el) {
    if (this.found.has(selector)) return;
    const flag = this.current.red_flags.find(f => f.selector === selector);
    if (!flag) return;

    this.found.add(selector);
    el.classList.add("found");

    const list = document.getElementById("foundFlags");
    const li = document.createElement("li");
    li.textContent = "🚩 " + flag.label;
    list.appendChild(li);

    document.getElementById("flagCount").textContent = this.found.size;

    // If all found
    if (this.found.size >= this.current.red_flags.length) {
      this.showExplanation();
    }
  },

  revealAll() {
    this.current.red_flags.forEach(flag => {
      if (!this.found.has(flag.selector)) {
        // Find matching elements
        document.querySelectorAll(`[data-flag="${flag.selector}"]`).forEach(el => {
          this.markFound(flag.selector, el);
        });
      }
    });
    this.showExplanation();
  },

  showExplanation() {
    const box = document.getElementById("phishExplanation");
    box.classList.remove("hidden");
    box.innerHTML = `<strong>${this.current.is_phishing ? "This is a phishing email." : "This is a legitimate example."}</strong><br>${this.current.explanation}`;

    // Record progress
    if (typeof Dashboard !== "undefined") {
      Dashboard.recordPhish({
        id: this.current.id,
        title: this.current.title,
        found: this.found.size,
        total: this.current.red_flags.length,
        date: new Date().toISOString()
      });
    }
  },

  close() {
    document.getElementById("phishingSim").classList.add("hidden");
    document.getElementById("phishingList").classList.remove("hidden");
    this.current = null;
  }
};
