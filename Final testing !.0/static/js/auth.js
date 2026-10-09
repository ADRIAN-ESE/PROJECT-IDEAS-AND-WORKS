/**
 * CyberAware — Account authentication, 2FA security, and session state
 */

const Auth = {
  user: null,
  pending2faSecret: null,

  async init() {
    document.getElementById("authOpenBtn")?.addEventListener("click", () => this.open("login"));
    document.getElementById("authCloseBtn")?.addEventListener("click", () => this.close());
    document.getElementById("showRegisterBtn")?.addEventListener("click", () => this.showForm("register"));
    document.getElementById("showLoginBtn")?.addEventListener("click", () => this.showForm("login"));
    document.getElementById("backToLoginBtn")?.addEventListener("click", () => this.showForm("login"));
    document.getElementById("logoutBtn")?.addEventListener("click", () => this.logout());

    document.getElementById("loginForm")?.addEventListener("submit", (event) => this.login(event));
    document.getElementById("login2faForm")?.addEventListener("submit", (event) => this.login2fa(event));
    document.getElementById("registerForm")?.addEventListener("submit", (event) => this.register(event));

    document.getElementById("showPwResetBtn")?.addEventListener("click", () => this.showForm("pwreset-request"));
    document.getElementById("pwResetBackLogin")?.addEventListener("click", () => this.showForm("login"));
    document.getElementById("pwResetBackRequest")?.addEventListener("click", () => this.showForm("pwreset-request"));
    document.getElementById("pwResetRequestBtn")?.addEventListener("click", () => this.requestPasswordReset());
    document.getElementById("pwResetConfirmBtn")?.addEventListener("click", () => this.confirmPasswordReset());

    document.getElementById("registerPassword")?.addEventListener("input", (e) => this.previewRegisterPassword(e.target.value));

    document.getElementById("accountAccessAction")?.addEventListener("click", async () => {
      if (this.user && !this.user.approved) {
        await this.refresh();
        if (this.user?.approved) {
          this.showToast("Your account has been approved.", "success");
          if (typeof Phishing !== "undefined") await Phishing.init();
        }
        else this.showToast("Your account is still waiting for administrator approval.", "info");
        return;
      }
      this.open2faModal();
    });

    document.getElementById("open2faBtn")?.addEventListener("click", () => this.open2faModal());
    document.getElementById("twoFactorCloseBtn")?.addEventListener("click", () => this.close2faModal());
    document.getElementById("start2faSetupBtn")?.addEventListener("click", () => this.start2faSetup());
    document.getElementById("twoFactorEnableForm")?.addEventListener("submit", (e) => this.enable2fa(e));
    document.getElementById("disable2faBtn")?.addEventListener("click", () => this.disable2fa());
    document.getElementById("copySecretBtn")?.addEventListener("click", () => this.copySecretKey());
    document.getElementById("copyBackupCodesBtn")?.addEventListener("click", () => this.copyBackupCodes());
    document.getElementById("finish2faSetupBtn")?.addEventListener("click", () => {
      this.close2faModal();
      this.showToast("2FA setup complete! Your account is now secured.", "success");
    });

    document.getElementById("openAccountSettingsBtn")?.addEventListener("click", () => this.openAccountModal());
    document.getElementById("accountCloseBtn")?.addEventListener("click", () => this.closeAccountModal());
    document.getElementById("submitChangePw")?.addEventListener("click", () => this.changePassword());
    document.getElementById("submitDeleteAccount")?.addEventListener("click", () => this.deleteAccount());

    document.getElementById("exportCsvBtn")?.addEventListener("click", () => this.exportProgressCsv());
    document.getElementById("adminExportCsvBtn")?.addEventListener("click", () => this.exportAdminCsv());

    document.getElementById("authModal")?.addEventListener("click", (event) => {
      if (event.target.id === "authModal") this.close();
    });
    document.getElementById("twoFactorModal")?.addEventListener("click", (event) => {
      if (event.target.id === "twoFactorModal") this.close2faModal();
    });
    document.getElementById("accountModal")?.addEventListener("click", (event) => {
      if (event.target.id === "accountModal") this.closeAccountModal();
    });

    await this.refresh();
  },

  async refresh() {
    try {
      const response = await fetch("/api/auth/me");
      if (response.ok) {
        const data = await response.json();
        this.user = data.user;
      } else {
        this.user = null;
      }
    } catch (error) {
      this.user = null;
    }
    this.renderState();
  },

  requireAccount(message = "Please sign in to unlock the training modules.") {
    if (this.user) return true;
    this.open("login", message);
    return false;
  },

  canAccessTraining() {
    if (!this.user) {
      this.open("login", "Sign in to access training.");
      return false;
    }
    if (this.user.role !== "admin" && !this.user.approved) {
      this.showToast("Your account is waiting for administrator approval.", "info");
      return false;
    }
    if (this.user.role !== "admin" && this.user.progressive_2fa_required
      && this.user.quizzes_completed >= 2 && !this.user.two_factor_enabled) {
      this.showToast("Set up two-factor authentication to continue training.", "warning");
      return false;
    }
    return true;
  },

  renderState() {
    const signedIn = Boolean(this.user);
    const greeting = document.getElementById("userGreeting");
    const signIn = document.getElementById("authOpenBtn");
    const logout = document.getElementById("logoutBtn");
    const adminItem = document.getElementById("adminNavItem");
    const banner = document.getElementById("accountAccessBanner");
    const accessTitle = document.getElementById("accountAccessTitle");
    const accessMessage = document.getElementById("accountAccessMessage");
    const accessAction = document.getElementById("accountAccessAction");
    const stat2FA = document.getElementById("stat2FA");

    if (greeting) {
      greeting.textContent = signedIn ? `Hi, ${this.user.username}` : "Guest mode";
      greeting.classList.toggle("hidden", !signedIn);
    }
    signIn?.classList.toggle("hidden", signedIn);
    logout?.classList.toggle("hidden", !signedIn);
    adminItem?.classList.toggle("hidden", this.user?.role !== "admin");

    if (stat2FA) {
      const is2fa = Boolean(this.user?.two_factor_enabled);
      stat2FA.textContent = is2fa ? "Protected (2FA)" : "Disabled";
      stat2FA.className = `status-pill ${is2fa ? "status-verified" : "status-disabled"}`;
    }

    const waitingForApproval = signedIn && this.user.role !== "admin" && !this.user.approved;
    const mustSetUp2fa = signedIn && this.user.role !== "admin"
      && this.user.approved && this.user.progressive_2fa_required
      && this.user.quizzes_completed >= 2 && !this.user.two_factor_enabled;
    banner?.classList.toggle("hidden", !waitingForApproval && !mustSetUp2fa);
    if (waitingForApproval) {
      if (accessTitle) accessTitle.textContent = "Waiting for administrator approval";
      if (accessMessage) accessMessage.textContent = "Training access will be available after an administrator approves your account.";
      if (accessAction) {
        accessAction.textContent = "Check approval status";
        accessAction.classList.remove("hidden");
      }
    } else if (mustSetUp2fa) {
      if (accessTitle) accessTitle.textContent = "Set up two-factor authentication";
      if (accessMessage) accessMessage.textContent = "You have completed two quizzes. Set up 2FA to continue with training and progress features.";
      if (accessAction) {
        accessAction.textContent = "Set Up 2FA";
        accessAction.classList.remove("hidden");
      }
    } else {
      accessAction?.classList.add("hidden");
    }

    if (signedIn && this.user.role !== "admin" && !this.user.approved
      && typeof App !== "undefined" && ["learn", "quiz", "phishing", "password"].includes(App.currentSection)) {
      App.showSection("dashboard");
    } else if (signedIn && this.user.role !== "admin" && this.user.approved
      && this.user.progressive_2fa_required && this.user.quizzes_completed >= 2
      && !this.user.two_factor_enabled
      && typeof App !== "undefined" && ["learn", "quiz", "phishing", "password"].includes(App.currentSection)) {
      App.showSection("dashboard");
    }

    const canLoadProgress = signedIn && (
      this.user.role === "admin"
      || (this.user.approved && (!this.user.progressive_2fa_required
        || this.user.quizzes_completed < 2 || this.user.two_factor_enabled))
    );
    if (canLoadProgress && typeof Dashboard !== "undefined") Dashboard.load();
  },

  open(mode = "login", customMessage = "") {
    document.getElementById("authModal")?.classList.remove("hidden");
    this.showForm(mode);
    const message = document.getElementById("authMessage");
    if (message) message.textContent = customMessage || "";
    document.querySelector(mode === "login" ? "#loginIdentifier" : (mode === "2fa" ? "#login2faCode" : "#registerUsername"))?.focus();
  },

  close() {
    document.getElementById("authModal")?.classList.add("hidden");
    const message = document.getElementById("authMessage");
    if (message) message.textContent = "";
  },

  showForm(mode) {
    const login = mode === "login";
    const is2fa = mode === "2fa";
    const register = mode === "register";
    const pwReq = mode === "pwreset-request";
    const pwConfirm = mode === "pwreset-confirm";

    document.getElementById("loginForm")?.classList.toggle("hidden", !login);
    document.getElementById("login2faForm")?.classList.toggle("hidden", !is2fa);
    document.getElementById("registerForm")?.classList.toggle("hidden", !register);
    document.getElementById("pwResetRequestForm")?.classList.toggle("hidden", !pwReq);
    document.getElementById("pwResetConfirmForm")?.classList.toggle("hidden", !pwConfirm);
    document.getElementById("loginForgotRow")?.classList.toggle("hidden", !login);

    const title = document.getElementById("authTitle");
    const subtitle = document.getElementById("authSubtitle");

    if (is2fa) {
      if (title) title.textContent = "Two-Factor Verification";
      if (subtitle) subtitle.textContent = "Security verification required for your CyberAware account.";
    } else if (login) {
      if (title) title.textContent = "Welcome back";
      if (subtitle) subtitle.textContent = "Sign in to save quizzes, streaks, and phishing practice to your account.";
    } else if (register) {
      if (title) title.textContent = "Create your account";
      if (subtitle) subtitle.textContent = "Create a secure account to keep your progress across devices.";
    } else if (pwReq) {
      if (title) title.textContent = "Reset your password";
      if (subtitle) subtitle.textContent = "We'll send a 6-digit reset code to the email on file.";
    } else if (pwConfirm) {
      if (title) title.textContent = "Choose a new password";
      if (subtitle) subtitle.textContent = "Enter the code we sent and create a strong new password.";
    }

    const message = document.getElementById("authMessage");
    if (message) message.textContent = "";
  },

  previewRegisterPassword(password) {
    const box = document.getElementById("registerPwFeedback");
    if (!box) return;
    if (!password) {
      box.classList.add("hidden");
      box.innerHTML = "";
      return;
    }
    const tips = [];
    if (password.length < 10) tips.push("10+ characters");
    if (!/[a-z]/.test(password)) tips.push("lowercase letter");
    if (!/[A-Z]/.test(password)) tips.push("uppercase letter");
    if (!/\d/.test(password)) tips.push("a number");
    if (!/[^a-zA-Z0-9]/.test(password)) tips.push("a symbol");
    if (tips.length === 0) {
      box.className = "pw-feedback ok";
      box.textContent = "Password looks strong.";
    } else {
      box.className = "pw-feedback warn";
      box.innerHTML = "Needs: " + tips.join(", ");
    }
    box.classList.remove("hidden");
  },

  async requestPasswordReset() {
    const email = document.getElementById("pwResetEmail")?.value?.trim().toLowerCase();
    const message = document.getElementById("authMessage");
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      if (message) message.textContent = "Enter a valid email address.";
      return;
    }
    const res = await fetch("/api/auth/password/reset-request", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email })
    });
    const data = await res.json();
    if (!res.ok) {
      if (message) message.textContent = data.error || "Could not send reset code.";
      return;
    }
    document.getElementById("pwResetConfirmEmail").value = email;
    this.showForm("pwreset-confirm");
    if (message) message.textContent = data.message || "If an account matches that email, a reset code has been sent.";
  },

  async confirmPasswordReset() {
    const email = document.getElementById("pwResetConfirmEmail")?.value?.trim().toLowerCase();
    const code = document.getElementById("pwResetConfirmCode")?.value?.trim();
    const new_password = document.getElementById("pwResetNewPassword")?.value;
    const message = document.getElementById("authMessage");

    if (!email || !code || !new_password) {
      if (message) message.textContent = "Email, reset code, and new password are required.";
      return;
    }
    const res = await fetch("/api/auth/password/reset-confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, code, new_password })
    });
    const data = await res.json();
    if (!res.ok) {
      const detail = data.details ? ` ${data.details.join(" ")}` : "";
      if (message) message.textContent = (data.error || "Password reset failed.") + detail;
      return;
    }
    this.showToast("Password reset successful! Sign in with your new password.", "success");
    this.showForm("login");
  },

  openAccountModal() {
    if (!this.requireAccount("Sign in to manage your account settings.")) return;
    document.getElementById("chgPwMessage").textContent = "";
    document.getElementById("deleteAccountMessage").textContent = "";
    document.getElementById("accountModal")?.classList.remove("hidden");
  },

  closeAccountModal() {
    document.getElementById("accountModal")?.classList.add("hidden");
  },

  async changePassword() {
    const msg = document.getElementById("chgPwMessage");
    const payload = {
      current_password: document.getElementById("chgPwCurrent")?.value,
      new_password: document.getElementById("chgPwNew")?.value,
      two_factor_code: document.getElementById("chgPw2fa")?.value?.trim() || undefined
    };
    const res = await fetch("/api/auth/password/change", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok) {
      const detail = data.details ? ` ${data.details.join(" ")}` : "";
      msg.textContent = (data.error || "Password change failed.") + detail;
      return;
    }
    document.getElementById("chgPwCurrent").value = "";
    document.getElementById("chgPwNew").value = "";
    document.getElementById("chgPw2fa").value = "";
    msg.textContent = "";
    this.showToast("Password updated successfully.", "success");
  },

  async deleteAccount() {
    const msg = document.getElementById("deleteAccountMessage");
    const password = document.getElementById("deleteAccountPassword")?.value;
    if (!password) {
      msg.textContent = "Enter your current password to confirm deletion.";
      return;
    }
    const confirmed = window.confirm("This permanently deletes your account and all progress. Are you absolutely sure?");
    if (!confirmed) return;
    const res = await fetch("/api/auth/account", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (!res.ok) {
      msg.textContent = data.error || "Could not delete account.";
      return;
    }
    document.getElementById("deleteAccountPassword").value = "";
    this.closeAccountModal();
    this.user = null;
    this.renderState();
    this.showToast("Your account has been permanently deleted.", "info");
    if (typeof App !== "undefined") App.navigate("home");
  },

  exportProgressCsv() {
    if (!this.requireAccount("Sign in to export your progress as CSV.")) return;
    window.location.href = "/api/export/progress.csv";
  },

  exportAdminCsv() {
    if (!this.user || this.user.role !== "admin") {
      this.showToast("Administrator access is required.", "error");
      return;
    }
    window.location.href = "/api/admin/export/users.csv";
  },

  async login(event) {
    event.preventDefault();
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        identifier: document.getElementById("loginIdentifier").value,
        password: document.getElementById("loginPassword").value
      })
    });

    const data = await response.json();
    const message = document.getElementById("authMessage");

    if (!response.ok) {
      if (message) message.textContent = data.error || "Authentication failed.";
      return;
    }

    if (data.two_factor_required) {
      this.showForm("2fa");
      document.getElementById("login2faCode")?.focus();
      this.showToast("Please enter your 2FA authenticator code.", "info");
      return;
    }

    this.user = data.user;
    this.renderState();
    this.close();
    this.showToast(`Welcome back, ${this.user.username}!`, "success");
    if (typeof Phishing !== "undefined") await Phishing.init();
    if (typeof Admin !== "undefined") Admin.render();
  },

  async login2fa(event) {
    event.preventDefault();
    const code = document.getElementById("login2faCode")?.value?.trim();
    if (!code) return;

    const response = await fetch("/api/auth/login/2fa", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });

    const data = await response.json();
    const message = document.getElementById("authMessage");

    if (!response.ok) {
      if (message) message.textContent = data.error || "Invalid 2FA code.";
      return;
    }

    this.user = data.user;
    this.renderState();
    this.close();
    this.showToast(`Authenticated successfully with 2FA!`, "success");
    if (typeof Phishing !== "undefined") await Phishing.init();
    if (typeof Admin !== "undefined") Admin.render();
  },

  async register(event) {
    event.preventDefault();
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("registerUsername").value,
        email: document.getElementById("registerEmail").value,
        password: document.getElementById("registerPassword").value
      })
    });
    await this.finishAuth(response);
  },

  async finishAuth(response) {
    const data = await response.json();
    const message = document.getElementById("authMessage");
    if (!response.ok) {
      if (message) message.textContent = data.error || "Authentication failed.";
      return;
    }
    this.user = data.user;
    this.renderState();
    this.close();
    this.showToast(data.message || "Account created successfully!", "success");
    if (!this.user.approved && typeof App !== "undefined") App.navigate("dashboard");
    if (this.user.approved && typeof Phishing !== "undefined") await Phishing.init();
    if (typeof Admin !== "undefined") Admin.render();
  },

  // ---------------------------------------------------------------------------
  // 2FA Management Modal Methods
  // ---------------------------------------------------------------------------

  open2faModal() {
    if (!this.user) {
      this.open("login", "Sign in to configure account security.");
      return;
    }

    const modal = document.getElementById("twoFactorModal");
    if (!modal) return;
    modal.classList.remove("hidden");

    const is2faActive = Boolean(this.user.two_factor_enabled);
    const activeSection = document.getElementById("twoFactorActiveSection");
    const setupSection = document.getElementById("twoFactorSetupSection");
    const backupSection = document.getElementById("twoFactorBackupCodesSection");
    const actionRow = document.getElementById("twoFactorActionRow");
    const statusPill = document.getElementById("twofaStatusPill");
    const statusText = document.getElementById("twofaStatusText");

    if (statusPill) {
      statusPill.textContent = is2faActive ? "2FA Enabled" : "2FA Disabled";
      statusPill.className = `status-pill ${is2faActive ? "status-verified" : "status-disabled"}`;
    }
    if (statusText) {
      statusText.textContent = is2faActive
        ? "Two-factor authentication is protecting your sign-ins with TOTP."
        : "Enabling 2FA adds an extra layer of defense against credential stuffing.";
    }

    activeSection?.classList.toggle("hidden", !is2faActive);
    setupSection?.classList.add("hidden");
    backupSection?.classList.add("hidden");
    actionRow?.classList.toggle("hidden", is2faActive);

    const msg = document.getElementById("twoFactorMessage");
    if (msg) msg.textContent = "";
  },

  close2faModal() {
    document.getElementById("twoFactorModal")?.classList.add("hidden");
  },

  async start2faSetup() {
    try {
      const res = await fetch("/api/auth/2fa/setup", { method: "POST" });
      if (!res.ok) throw new Error("Could not initialize 2FA setup");
      const data = await res.json();
      this.pending2faSecret = data.secret;

      document.getElementById("twoFactorSecretText").value = data.secret;
      document.getElementById("twoFactorSetupSection")?.classList.remove("hidden");
      document.getElementById("twoFactorActionRow")?.classList.add("hidden");
      document.getElementById("twoFactorActiveSection")?.classList.add("hidden");

      this.drawQrPattern(data.otpauth_url);
    } catch (e) {
      this.showToast("Could not start 2FA setup. Please try again.", "error");
    }
  },

  drawQrPattern(text) {
    const canvas = document.getElementById("twoFactorQrCanvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const size = canvas.width;
    ctx.clearRect(0, 0, size, size);

    ctx.fillStyle = "#101918";
    ctx.fillRect(0, 0, size, size);

    // Render pseudo-QR grid based on text hash
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = (hash << 5) - hash + text.charCodeAt(i);
      hash |= 0;
    }

    const cells = 21;
    const cellSize = size / cells;
    ctx.fillStyle = "#bef35f";

    // Standard position markers
    const drawFinder = (x, y) => {
      ctx.fillRect(x * cellSize, y * cellSize, 7 * cellSize, 7 * cellSize);
      ctx.fillStyle = "#101918";
      ctx.fillRect((x + 1) * cellSize, (y + 1) * cellSize, 5 * cellSize, 5 * cellSize);
      ctx.fillStyle = "#bef35f";
      ctx.fillRect((x + 2) * cellSize, (y + 2) * cellSize, 3 * cellSize, 3 * cellSize);
    };

    drawFinder(0, 0);
    drawFinder(14, 0);
    drawFinder(0, 14);

    // Data modules
    for (let r = 0; r < cells; r++) {
      for (let c = 0; c < cells; c++) {
        if ((r < 7 && c < 7) || (r < 7 && c >= 14) || (r >= 14 && c < 7)) continue;
        const val = Math.abs(Math.sin((r + 1) * (c + 1) * hash)) > 0.45;
        if (val) {
          ctx.fillRect(c * cellSize, r * cellSize, cellSize - 0.5, cellSize - 0.5);
        }
      }
    }
  },

  async enable2fa(event) {
    event.preventDefault();
    const code = document.getElementById("twoFactorVerifyCode")?.value?.trim();
    if (!code || !this.pending2faSecret) return;

    const res = await fetch("/api/auth/2fa/enable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: this.pending2faSecret, code })
    });

    const data = await res.json();
    const msg = document.getElementById("twoFactorMessage");

    if (!res.ok) {
      if (msg) msg.textContent = data.error || "Failed to verify 2FA code.";
      return;
    }

    this.user = data.user;
    this.renderState();
    if (typeof Dashboard !== "undefined") await Dashboard.load();

    // Show backup codes
    document.getElementById("twoFactorSetupSection")?.classList.add("hidden");
    const backupSection = document.getElementById("twoFactorBackupCodesSection");
    backupSection?.classList.remove("hidden");

    const list = document.getElementById("backupCodesList");
    if (list && data.backup_codes) {
      list.innerHTML = data.backup_codes.map(c => `<div class="backup-code-item">${c}</div>`).join("");
      this.savedBackupCodes = data.backup_codes.join("\n");
    }

    this.showToast("2FA successfully enabled! Save your backup codes.", "success");
  },

  async disable2fa() {
    const password = document.getElementById("disable2faPassword")?.value;
    if (!password) {
      this.showToast("Enter your account password to disable 2FA.", "warning");
      return;
    }

    const res = await fetch("/api/auth/2fa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password })
    });

    const data = await res.json();
    if (!res.ok) {
      this.showToast(data.error || "Could not disable 2FA.", "error");
      return;
    }

    this.user = data.user;
    this.renderState();
    this.open2faModal();
    this.showToast("Two-factor authentication disabled.", "info");
  },

  copySecretKey() {
    const secret = document.getElementById("twoFactorSecretText")?.value;
    if (secret) {
      navigator.clipboard.writeText(secret);
      this.showToast("Secret key copied to clipboard!", "success");
    }
  },

  copyBackupCodes() {
    if (this.savedBackupCodes) {
      navigator.clipboard.writeText(this.savedBackupCodes);
      this.showToast("Backup codes copied to clipboard!", "success");
    }
  },

  async logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    this.user = null;
    this.renderState();
    this.showToast("Signed out safely.", "info");
    if (typeof App !== "undefined") App.navigate("home");
  },

  showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast-message toast-${type}`;
    const icons = { success: "✅", error: "❌", warning: "⚠️", info: "🛡️" };
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || "🛡️"}</span>
      <span class="toast-text">${message}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.classList.add("show");
    }, 10);

    setTimeout(() => {
      toast.classList.remove("show");
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }
};
