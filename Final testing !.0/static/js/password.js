/**
 * CyberAware — Password Strength Checker
 */

const PasswordChecker = {
  debounceTimer: null,

  init() {
    const input = document.getElementById("passwordInput");
    const toggle = document.getElementById("togglePassword");

    if (!input) return;

    input.addEventListener("input", () => {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = setTimeout(() => this.analyze(input.value), 200);
    });

    toggle?.addEventListener("click", () => {
      const isPass = input.type === "password";
      input.type = isPass ? "text" : "password";
      toggle.textContent = isPass ? "🙈" : "👁️";
    });
  },

  async analyze(password) {
    const label = document.getElementById("strengthLabel");
    const bar = document.getElementById("strengthBar");
    const stats = document.getElementById("passwordStats");

    if (!password) {
      label.textContent = "Start typing…";
      bar.style.width = "0%";
      bar.className = "strength-bar";
      stats.innerHTML = "";
      return;
    }

    try {
      const res = await fetch("/api/check-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      if (!res.ok) {
        if (["approval_required", "two_factor_setup_required"].includes(data.code)) {
          Auth?.showToast(data.error, "warning");
          App.navigate("dashboard");
          return;
        }
        throw new Error(data.error || "Password analysis failed.");
      }
      this.render(data);
    } catch (e) {
      if (e instanceof Error && e.message !== "Failed to fetch") {
        Auth?.showToast(e.message, "error");
        return;
      }
      // Fallback client-side analysis if API unavailable
      this.render(this.localAnalyze(password));
    }
  },

  localAnalyze(password) {
    const length = password.length;
    const has_lower = /[a-z]/.test(password);
    const has_upper = /[A-Z]/.test(password);
    const has_digit = /\d/.test(password);
    const has_symbol = /[^a-zA-Z0-9]/.test(password);

    let charset = 0;
    if (has_lower) charset += 26;
    if (has_upper) charset += 26;
    if (has_digit) charset += 10;
    if (has_symbol) charset += 32;
    const entropy = charset > 0 ? length * Math.log2(charset) : 0;

    let score = 0;
    const feedback = [];
    if (length >= 12) score += 25;
    else if (length >= 8) score += 15;
    else feedback.push("Use at least 12 characters.");
    if (has_lower && has_upper) score += 20;
    else feedback.push("Mix upper and lower case.");
    if (has_digit) score += 15;
    else feedback.push("Add numbers.");
    if (has_symbol) score += 20;
    else feedback.push("Add symbols.");
    if (length >= 16) score += 10;
    score = Math.max(0, Math.min(100, score));

    let strength, strength_class;
    if (score >= 80) { strength = "Excellent"; strength_class = "excellent"; }
    else if (score >= 60) { strength = "Strong"; strength_class = "strong"; }
    else if (score >= 40) { strength = "Fair"; strength_class = "fair"; }
    else if (score >= 20) { strength = "Weak"; strength_class = "weak"; }
    else { strength = "Very Weak"; strength_class = "very-weak"; }

    return {
      score, strength, strength_class,
      entropy_bits: Math.round(entropy * 10) / 10,
      crack_time: entropy > 60 ? "years+" : entropy > 40 ? "days" : "minutes or less",
      length, has_lower, has_upper, has_digit, has_symbol,
      is_common: false, feedback
    };
  },

  render(data) {
    const label = document.getElementById("strengthLabel");
    const bar = document.getElementById("strengthBar");
    const stats = document.getElementById("passwordStats");

    label.textContent = `${data.strength} (${data.score}/100)`;
    bar.style.width = data.score + "%";
    bar.className = "strength-bar " + data.strength_class;

    const checks = [
      { ok: data.length >= 12, text: "12+ chars" },
      { ok: data.has_lower, text: "Lowercase" },
      { ok: data.has_upper, text: "Uppercase" },
      { ok: data.has_digit, text: "Number" },
      { ok: data.has_symbol, text: "Symbol" }
    ];

    stats.innerHTML = `
      <div class="stat-box">
        <div class="label">Entropy</div>
        <div class="value">${data.entropy_bits} bits</div>
      </div>
      <div class="stat-box">
        <div class="label">Est. Crack Time</div>
        <div class="value">${data.crack_time}</div>
      </div>
      <div class="checklist">
        ${checks.map(c => `
          <span class="check-item ${c.ok ? "pass" : "fail"}">
            ${c.ok ? "✓" : "○"} ${c.text}
          </span>
        `).join("")}
      </div>
      ${data.feedback && data.feedback.length ? `
        <ul class="feedback-list" style="grid-column:1/-1;list-style:none;padding:0">
          ${data.feedback.map(f => `<li>💡 ${f}</li>`).join("")}
        </ul>
      ` : ""}
    `;
  }
};
