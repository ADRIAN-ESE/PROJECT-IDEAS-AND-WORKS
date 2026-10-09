/**
 * CyberAware — Progress Dashboard, Topic Radar, Certificate & Compliance Exporter
 */

const Dashboard = {
  data: {
    quizzes: [],
    phishing: [],
    exams: [],
    streak: 0,
    lastActive: null,
    achievements: {},
    leaderboard: [],
    challenges: []
  },
  radarResizePending: false,

  topicsMeta: [
    { id: "phishing", name: "Phishing", label: "Phishing", icon: "🎣" },
    { id: "passwords", name: "Passwords", label: "Passwords", icon: "🔐" },
    { id: "social-engineering", name: "Social Eng.", label: "Soc. Eng.", icon: "🎭" },
    { id: "data-protection", name: "Data Protection", label: "Data Prot.", icon: "🛡️" },
    { id: "safe-browsing", name: "Safe Browsing", label: "Browsing", icon: "🌐" },
    { id: "wifi-security", name: "Wi-Fi Security", label: "Wi-Fi", icon: "📶" },
    { id: "device-security", name: "Device Security", label: "Devices", icon: "💻" },
    { id: "incident-response", name: "Incident Response", label: "Response", icon: "🚨" },
    { id: "cyber-law", name: "Cyber Law", label: "Cyber Law", icon: "⚖️" },
    { id: "governance", name: "Governance", label: "Governance", icon: "🏛️" },
    { id: "cyber-threat-management", name: "Cyber Threat Management", label: "Threat Mgmt.", icon: "🎯" }
  ],

  async init() {
    await this.load();

    const radarCanvas = document.getElementById("radarChart");
    radarCanvas?.addEventListener("pointermove", event => this.inspectRadarPointer(event));
    radarCanvas?.addEventListener("pointerleave", () => this.clearRadarInspection());
    window.addEventListener("resize", () => {
      if (this.radarResizePending) return;
      this.radarResizePending = true;
      window.requestAnimationFrame(() => {
        this.radarResizePending = false;
        this.drawRadar();
      });
    }, { passive: true });

    document.getElementById("resetProgressBtn")?.addEventListener("click", () => {
      const isAdmin = Auth?.user?.role === "admin";
      const message = isAdmin
        ? "Reset all of your quiz and phishing progress? This action cannot be undone."
        : "Send a request to an administrator to reset your quiz and phishing progress?";
      if (confirm(message)) this.reset();
    });

    // Certificate listeners
    document.getElementById("openCertBtn")?.addEventListener("click", () => this.openCertificate());
    document.getElementById("certCloseBtn")?.addEventListener("click", () => this.closeCertificate());
    document.getElementById("downloadCertBtn")?.addEventListener("click", () => this.downloadCertificate());
    document.getElementById("printCertBtn")?.addEventListener("click", () => window.print());
    document.getElementById("copyCertLinkBtn")?.addEventListener("click", () => this.copyCertId());

    // Report listeners
    document.getElementById("openReportBtn")?.addEventListener("click", () => this.openReport());
    document.getElementById("reportCloseBtn")?.addEventListener("click", () => this.closeReport());
    document.getElementById("downloadReportJsonBtn")?.addEventListener("click", () => this.downloadReportJson());
    document.getElementById("printReportBtn")?.addEventListener("click", () => window.print());
    document.getElementById("copyReportSummaryBtn")?.addEventListener("click", () => this.copyReportSummary());

    document.getElementById("certModal")?.addEventListener("click", (e) => {
      if (e.target.id === "certModal") this.closeCertificate();
    });
    document.getElementById("reportModal")?.addEventListener("click", (e) => {
      if (e.target.id === "reportModal") this.closeReport();
    });
  },

  async load() {
    if (typeof Auth === "undefined" || !Auth.user) {
      this.data = { quizzes: [], phishing: [], exams: [], streak: 0, lastActive: null, achievements: {}, leaderboard: [], challenges: [] };
      this.updateResetRequestStatus(null);
      this.render();
      return;
    }
    await this.loadResetRequestStatus();
    if (Auth.user.role !== "admin" && (
      !Auth.user.approved
      || (Auth.user.progressive_2fa_required
        && Auth.user.quizzes_completed >= 2 && !Auth.user.two_factor_enabled)
    )) {
      this.render();
      return;
    }
    try {
      const response = await fetch("/api/progress");
      if (!response.ok) throw new Error("Progress request failed");
      const payload = await response.json();
      this.data = { ...this.data, ...payload };
      await this.loadLeaderboard();
      await this.loadChallenges();
      this.checkAchievements();
      this.render();
    } catch (error) {
      console.warn("Could not load progress", error);
    }
  },

  async loadChallenges() {
    try {
      const response = await fetch("/api/challenges");
      if (!response.ok) throw new Error("Challenge request failed");
      const payload = await response.json();
      this.data.challenges = payload.challenges || [];
    } catch (error) {
      this.data.challenges = [];
    }
  },

  async loadLeaderboard() {
    try {
      const response = await fetch("/api/leaderboard");
      if (!response.ok) throw new Error("Leaderboard request failed");
      const payload = await response.json();
      this.data.leaderboard = payload.leaderboard || [];
    } catch (error) {
      this.data.leaderboard = [];
    }
  },

  async recordQuiz(entry) {
    if (typeof Auth === "undefined" || !Auth.user) {
      throw new Error("Sign in to submit quiz results.");
    }
    try {
      const res = await fetch("/api/progress/quiz", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry)
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.error || "Quiz submission failed.");
      }
      Auth.user.quizzes_completed = payload.quizzes_completed;
      Auth.renderState();
      if (typeof Auth.showToast === "function") {
        Auth.showToast(`Quiz result recorded: ${payload.percent}%!`, "success");
      }
      if (Auth.user.role === "admin" || !Auth.user.progressive_2fa_required
        || Auth.user.two_factor_enabled || Auth.user.quizzes_completed < 2) {
        await this.load();
      }
      return payload;
    } catch (error) {
      console.warn("Error recording quiz", error);
      throw error;
    }
  },

  async recordExam(entry) {
    if (typeof Auth === "undefined" || !Auth.user) {
      throw new Error("Sign in to submit the comprehensive exam.");
    }
    const response = await fetch("/api/exam/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(entry)
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "Exam submission failed.");

    if (typeof Auth.showToast === "function") {
      Auth.showToast(
        payload.passed
          ? `Comprehensive exam passed: ${payload.proficiency_level} proficiency.`
          : `Exam result recorded: ${payload.percent}%. Review and try again.`,
        payload.passed ? "success" : "info"
      );
    }
    await this.load();
    return payload;
  },

  async recordPhish(entry) {
    if (typeof Auth === "undefined" || !Auth.user) return;
    try {
      const res = await fetch("/api/progress/phishing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(entry)
      });
      if (res.ok && typeof Auth.showToast === "function") {
        Auth.showToast(`Phishing simulation completed (${entry.found}/${entry.total} flags)!`, "success");
      }
    } catch (e) {
      console.warn("Error recording phishing result", e);
    }
    await this.load();
  },

  async reset() {
    if (typeof Auth === "undefined" || !Auth.user) return;
    try {
      const response = await fetch("/api/progress", { method: "DELETE" });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not reset progress.");

      if (payload.requested) {
        this.updateResetRequestStatus({ status: payload.status, requested_at: new Date().toISOString() });
        Auth.showToast(payload.message || "Reset request sent for administrator approval.", "info");
        return;
      }

      Auth.showToast("Progress successfully reset.", "info");
      this.data = {
        ...this.data,
        quizzes: [],
        phishing: [],
        exams: [],
        streak: 0,
        lastActive: null,
        achievements: {}
      };
      this.render();
    } catch (error) {
      Auth.showToast(error.message || "Could not reset progress.", "error");
    }
  },

  async loadResetRequestStatus() {
    if (typeof Auth === "undefined" || !Auth.user || Auth.user.role === "admin") {
      this.updateResetRequestStatus(null);
      return;
    }
    try {
      const response = await fetch("/api/progress/reset-request");
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "Could not load reset request status.");
      this.updateResetRequestStatus(payload.request);
    } catch (error) {
      console.warn("Could not load progress reset request status", error);
    }
  },

  updateResetRequestStatus(request) {
    const button = document.getElementById("resetProgressBtn");
    const status = document.getElementById("resetProgressStatus");
    if (!button || !status) return;

    if (Auth?.user?.role === "admin") {
      button.disabled = false;
      button.querySelector("span").textContent = "Reset my progress";
      status.textContent = "Administrator resets take effect immediately.";
      return;
    }

    const requestStatus = request?.status;
    button.disabled = requestStatus === "pending";
    const buttonLabel = requestStatus === "pending"
      ? "Reset Request Pending"
      : "Request a reset";
    button.querySelector("span").textContent = buttonLabel;
    status.textContent = requestStatus === "pending"
      ? "Your reset request is waiting for administrator approval."
      : requestStatus === "rejected"
        ? "Your last reset request was declined. You may submit another request."
        : requestStatus === "approved"
          ? "Your reset request was approved and your progress was cleared."
          : "Progress reset requests must be approved by an administrator.";
  },

  checkAchievements() {
    const a = this.data.achievements;
    if (this.data.quizzes.length >= 1) a.first_quiz = true;
    if (this.data.quizzes.length >= 5) a.quiz_5 = true;
    if (this.data.quizzes.length >= 10) a.quiz_10 = true;
    if (this.data.quizzes.some(q => q.percent === 100)) a.perfect = true;
    if (this.data.phishing.length >= 1) a.first_phish = true;
    if (this.data.phishing.length >= 3) a.phish_3 = true;
    if (this.data.phishing.length >= 10) a.phish_10 = true;
    if (this.data.streak >= 3) a.streak_3 = true;
    if (this.data.streak >= 7) a.streak_7 = true;
    if (this.data.streak >= 30) a.streak_30 = true;
    if (this.data.exams.length >= 1) a.exam_complete = true;
    if (this.data.exams.some(exam => exam.passed)) a.exam_pass = true;
    if (this.data.exams.some(exam => exam.percent === 100)) a.exam_perfect = true;

    // Topic coverage
    const topics = new Set(this.data.quizzes.map(q => q.topic));
    if (topics.size >= 3) a.topics_3 = true;
    if (topics.size >= 8) a.all_topics = true;
    if (topics.size >= this.topicsMeta.length) a.full_spectrum = true;
  },

  getTopicScores() {
    const scores = {};
    this.topicsMeta.forEach(t => {
      const attempts = this.data.quizzes.filter(q => q.topic === t.id);
      if (attempts.length === 0) {
        scores[t.id] = { score: 0, count: 0, latest: null };
      } else {
        const recent = attempts.slice(0, 3);
        const avg = Math.round(recent.reduce((s, q) => s + q.percent, 0) / recent.length);
        scores[t.id] = { score: avg, count: attempts.length, latest: attempts[0].percent };
      }
    });
    return scores;
  },

  getOverallScore() {
    const topicScores = this.getTopicScores();
    const attempted = Object.values(topicScores).filter(v => v.count > 0);
    if (attempted.length === 0) return 0;

    const quizAvg = attempted.reduce((total, topic) => total + topic.score, 0) / attempted.length;

    let phishScore = 0;
    if (this.data.phishing.length > 0) {
      const recent = this.data.phishing.slice(0, 5);
      phishScore = recent.reduce((s, p) => s + (p.total ? (p.found / p.total) * 100 : 0), 0) / recent.length;
    }

    const overall = this.data.phishing.length > 0
      ? Math.round(quizAvg * 0.6 + phishScore * 0.4)
      : Math.round(quizAvg);

    return Math.min(100, overall);
  },

  getLevel(score) {
    if (score >= 90) return "Master Cyber Guardian";
    if (score >= 75) return "Advanced Defender";
    if (score >= 50) return "Awareness Specialist";
    if (score >= 25) return "Security Apprentice";
    return "Awareness Novice";
  },

  render() {
    const score = this.getOverallScore();
    const level = this.getLevel(score);

    const badge = document.getElementById("awarenessBadge");
    const scoreEl = document.getElementById("awarenessScore");
    const bar = document.getElementById("awarenessBar");
    const tip = document.getElementById("awarenessTip");

    if (badge) badge.textContent = level;
    if (scoreEl) scoreEl.textContent = score + "%";
    if (bar) bar.style.width = score + "%";
    if (tip) {
      if (score >= 85) {
        tip.textContent = "Outstanding training score. Pass the all-topics exam with at least 70% to earn your verified certificate.";
      } else if (score >= 50) {
        tip.textContent = "Solid progress. Complete more high-difficulty quizzes to achieve Defender status.";
      } else {
        tip.textContent = "Start with Phishing & Password modules to build your foundational security score.";
      }
    }

    document.getElementById("statQuizzes").textContent = this.data.quizzes.length;
    const avg = this.data.quizzes.length
      ? Math.round(this.data.quizzes.reduce((s, q) => s + q.percent, 0) / this.data.quizzes.length)
      : null;
    document.getElementById("statAvgScore").textContent = avg !== null ? avg + "%" : "—";
    document.getElementById("statPhishDone").textContent = this.data.phishing.length;
    document.getElementById("statStreak").textContent = (this.data.streak || 0) + " days";

    // Topic Mastery List
    this.renderTopicMastery();

    // History
    const history = document.getElementById("quizHistory");
    if (history) {
      const historyItems = [
        ...this.data.quizzes.map(quiz => ({
          ...quiz,
          historyName: quiz.topicName || quiz.topic
        })),
        ...(this.data.exams || []).map(exam => ({
          ...exam,
          historyName: "All-Topics Comprehensive Exam"
        }))
      ].sort((left, right) => new Date(right.date) - new Date(left.date));
      if (!historyItems.length) {
        history.innerHTML = `<p class="empty-state">No quizzes completed yet. Choose a topic to begin!</p>`;
      } else {
        history.innerHTML = historyItems.slice(0, 8).map(q => {
          const d = new Date(q.date);
          const scoreClass = q.percent >= 80 ? "score-high" : (q.percent >= 60 ? "score-med" : "score-low");
          return `
            <div class="history-item">
              <div class="history-item-left">
                <span class="topic">${q.historyName}</span>
                <span class="date">${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
              <span class="score ${scoreClass}">${q.percent}% (${q.score}/${q.total})</span>
            </div>
          `;
        }).join("");
      }
    }

    // Achievements
    const defs = [
      { id: "first_quiz", icon: "🎯", name: "First Quiz", desc: "Completed first assessment" },
      { id: "quiz_5", icon: "🔥", name: "5 Quizzes", desc: "Completed 5 assessments" },
      { id: "quiz_10", icon: "🧭", name: "Quiz Regular", desc: "Completed 10 topic quizzes" },
      { id: "perfect", icon: "💯", name: "Perfect Score", desc: "Scored 100% on a quiz" },
      { id: "first_phish", icon: "🎣", name: "First Phish Hunt", desc: "Spotted email red flags" },
      { id: "phish_3", icon: "👁️", name: "Eagle Eye", desc: "Completed 3 phishing simulations" },
      { id: "phish_10", icon: "🕵️", name: "Phishing Tracker", desc: "Completed 10 phishing simulations" },
      { id: "streak_3", icon: "📅", name: "3-Day Streak", desc: "Trained 3 days consecutively" },
      { id: "streak_7", icon: "🏆", name: "Week Warrior", desc: "7-day continuous security streak" },
      { id: "streak_30", icon: "🌟", name: "Monthly Defender", desc: "Trained 30 days consecutively" },
      { id: "topics_3", icon: "📚", name: "Explorer", desc: "Mastered 3 diverse topics" },
      { id: "all_topics", icon: "🛡️", name: "Cyber Guardian", desc: "Tested across 8+ domains" },
      { id: "full_spectrum", icon: "🌐", name: "Full Spectrum", desc: "Completed quizzes in all 11 topics" },
      { id: "exam_complete", icon: "📝", name: "Exam Candidate", desc: "Completed the all-topics comprehensive exam" },
      { id: "exam_pass", icon: "🎓", name: "Certified Defender", desc: "Passed the all-topics comprehensive exam" },
      { id: "exam_perfect", icon: "💎", name: "Flawless Defense", desc: "Scored 100% on the comprehensive exam" }
    ];

    const achEl = document.getElementById("achievements");
    if (achEl) {
      const earnedCount = defs.filter(d => this.data.achievements[d.id]).length;
      const countEl = document.getElementById("achieveCount");
      if (countEl) countEl.textContent = `${earnedCount} / ${defs.length}`;

      achEl.innerHTML = defs.map(d => {
        const earned = Boolean(this.data.achievements[d.id]);
        return `
          <div class="achievement ${earned ? "earned" : ""}" title="${d.desc}">
            <span class="icon">${d.icon}</span>
            <span class="name">${d.name}</span>
            <span class="badge-status">${earned ? "Unlocked" : "Locked"}</span>
          </div>
        `;
      }).join("");
    }

    // Leaderboard
    const leaderboardList = document.getElementById("leaderboardList");
    if (leaderboardList) {
      if (!this.data.leaderboard.length) {
        leaderboardList.innerHTML = '<p class="empty-state">No leaderboard activity yet.</p>';
      } else {
        leaderboardList.innerHTML = this.data.leaderboard.map((entry) => {
          const isCurrentUser = Auth.user && Auth.user.username.toLowerCase() === entry.username.toLowerCase();
          const medal = entry.rank === 1 ? "🥇" : (entry.rank === 2 ? "🥈" : (entry.rank === 3 ? "🥉" : `#${entry.rank}`));
          return `
            <div class="leaderboard-row ${isCurrentUser ? "current-user" : ""}">
              <span class="rank">${medal}</span>
              <span class="user">${entry.username} ${isCurrentUser ? '<span class="you-tag">YOU</span>' : ''}</span>
              <span class="stats-mini">${entry.quizzes_taken} quizzes · ${entry.avg_score}% avg</span>
              <span class="score">${entry.points} pts</span>
            </div>
          `;
        }).join("");
      }
    }

    // Challenges
    const challengeList = document.getElementById("challengeList");
    if (challengeList) {
      if (!this.data.challenges.length) {
        challengeList.innerHTML = '<p class="empty-state">No challenges available right now.</p>';
      } else {
        challengeList.innerHTML = this.data.challenges.map((challenge) => `
          <div class="challenge-item ${challenge.completed ? 'done' : ''}">
            <div class="challenge-info">
              <strong>${challenge.title}</strong>
              <small>${challenge.description}</small>
            </div>
            <div class="challenge-reward-wrap">
              <span class="challenge-meta">+${challenge.reward} XP</span>
              <span class="challenge-check">${challenge.completed ? "✓ Claimed" : "In Progress"}</span>
            </div>
          </div>
        `).join("");
      }
    }

    this.drawRadar();
  },

  renderTopicMastery() {
    const list = document.getElementById("topicMasteryList");
    if (!list) return;

    const scores = this.getTopicScores();
    const assessed = this.topicsMeta.filter(topic => scores[topic.id]?.count > 0);
    const coverage = document.getElementById("masteryCoverage");
    if (coverage) coverage.textContent = `${assessed.length} of ${this.topicsMeta.length} assessed`;

    list.innerHTML = this.topicsMeta.map(t => {
      const data = scores[t.id] || { score: 0, count: 0 };
      const score = data.score;
      const tier = score >= 85 ? "Expert" : (score >= 65 ? "Proficient" : (score >= 40 ? "Competent" : (data.count > 0 ? "Developing" : "Unattempted")));
      const tierClass = score >= 85 ? "tier-expert"
        : score >= 65 ? "tier-proficient"
          : score >= 40 ? "tier-competent"
            : data.count > 0 ? "tier-developing" : "tier-unattempted";

      return `
        <div class="topic-mastery-card">
          <div class="tm-header">
            <span class="tm-icon">${t.icon}</span>
            <div class="tm-title-block">
              <strong>${t.name}</strong>
              <small>${data.count ? `${data.count} completed attempt${data.count === 1 ? "" : "s"}` : "No assessments yet"}</small>
            </div>
            <span class="tm-tier ${tierClass}">${tier}</span>
          </div>
          <div class="tm-score-row">
            <strong>${data.count ? `${score}%` : "—"}</strong>
            <span>${data.count ? `Latest ${data.latest}%` : "Start with a quiz"}</span>
          </div>
          <div class="tm-bar-wrap" role="progressbar" aria-label="${t.name} mastery"
               aria-valuemin="0" aria-valuemax="100" aria-valuenow="${data.count ? score : 0}">
            <div class="tm-bar-fill" style="width: ${score}%;"></div>
          </div>
          <div class="tm-footer">
            <span>Recent average</span>
            <a href="#quiz" onclick="App.navigate('quiz')" class="tm-quiz-link">Practice topic <span aria-hidden="true">→</span></a>
          </div>
        </div>
      `;
    }).join("");
  },

  drawRadar() {
    const canvas = document.getElementById("radarChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const scores = this.getTopicScores();
    const rect = canvas.getBoundingClientRect();
    const w = Math.max(240, Math.min(rect.width || 640, 680));
    const h = Math.max(320, w * 0.69);
    const pixelRatio = window.devicePixelRatio || 1;
    canvas.width = Math.round(w * pixelRatio);
    canvas.height = Math.round(h * pixelRatio);
    canvas.style.height = `${h}px`;
    canvas.setAttribute(
      "aria-label",
      `Defense radar. ${this.topicsMeta.map(topic => {
        const data = scores[topic.id];
        return `${topic.name}: ${data?.count ? `${data.score}%` : "not assessed"}`;
      }).join("; ")}.`
    );
    ctx.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);

    const values = this.topicsMeta.map(topic =>
      scores[topic.id]?.count ? scores[topic.id].score / 100 : null
    );
    const cx = w / 2;
    const cy = h / 2;
    const radius = Math.min(w * 0.31, h * 0.34);
    const n = this.topicsMeta.length;
    const assessedTopics = this.topicsMeta.filter(topic => scores[topic.id]?.count > 0);
    const attemptedCount = assessedTopics.length;
    const averageScore = attemptedCount
      ? Math.round(assessedTopics.reduce((total, topic) => total + scores[topic.id].score, 0) / attemptedCount)
      : null;
    this.radarGeometry = { w, h, cx, cy, radius, count: n, assessedCount: attemptedCount, scores };

    ctx.clearRect(0, 0, w, h);

    for (let level = 1; level <= 5; level++) {
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const r = (radius * level) / 5;
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = level === 5 ? "rgba(0, 230, 180, 0.3)" : "rgba(230, 240, 235, 0.1)";
      ctx.lineWidth = level === 5 ? 1.4 : 1;
      ctx.stroke();
    }

    for (let i = 0; i < n; i++) {
      const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + radius * Math.cos(angle), cy + radius * Math.sin(angle));
      ctx.strokeStyle = "rgba(230, 240, 235, 0.12)";
      ctx.stroke();

      const labelRadius = radius + 14;
      const labelX = cx + labelRadius * Math.cos(angle);
      const labelY = cy + labelRadius * Math.sin(angle);
      ctx.fillStyle = "rgba(0, 230, 180, 0.88)";
      ctx.font = `700 ${w < 360 ? 9 : 10}px Inter, sans-serif`;
      ctx.textAlign = Math.cos(angle) > 0.25 ? "left" : Math.cos(angle) < -0.25 ? "right" : "center";
      ctx.textBaseline = Math.sin(angle) > 0.35 ? "top" : Math.sin(angle) < -0.35 ? "bottom" : "middle";
      ctx.fillText(String(i + 1).padStart(2, "0"), labelX, labelY);
    }

    ctx.fillStyle = "rgba(230, 240, 235, 0.55)";
    ctx.font = `500 ${w < 360 ? 8 : 9}px Inter, sans-serif`;
    ctx.textAlign = "left";
    ctx.textBaseline = "middle";
    for (let level = 1; level <= 5; level++) {
      const y = cy - radius * level / 5;
      ctx.fillText(`${level * 20}%`, cx + 5, y - 7);
    }

    if (attemptedCount === n) {
      ctx.beginPath();
      for (let i = 0; i <= n; i++) {
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const r = radius * values[i % n];
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      const areaFill = ctx.createLinearGradient(cx - radius, cy + radius, cx + radius, cy - radius);
      areaFill.addColorStop(0, "rgba(0, 230, 180, 0.08)");
      areaFill.addColorStop(1, "rgba(0, 230, 180, 0.27)");
      ctx.fillStyle = areaFill;
      ctx.fill();
      ctx.strokeStyle = "#00e6b4";
      ctx.lineWidth = 2.8;
      ctx.stroke();
    } else if (attemptedCount > 1) {
      for (let i = 0; i < n; i++) {
        const next = (i + 1) % n;
        if (values[i] === null || values[next] === null) continue;
        const startAngle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const endAngle = (Math.PI * 2 * next) / n - Math.PI / 2;
        ctx.beginPath();
        ctx.moveTo(
          cx + radius * values[i] * Math.cos(startAngle),
          cy + radius * values[i] * Math.sin(startAngle)
        );
        ctx.lineTo(
          cx + radius * values[next] * Math.cos(endAngle),
          cy + radius * values[next] * Math.sin(endAngle)
        );
        ctx.strokeStyle = "#00e6b4";
        ctx.lineWidth = 2.5;
        ctx.stroke();
      }
    }

    if (attemptedCount) {
      for (let i = 0; i < n; i++) {
        if (values[i] === null) continue;
        const angle = (Math.PI * 2 * i) / n - Math.PI / 2;
        const r = radius * values[i];
        const x = cx + r * Math.cos(angle);
        const y = cy + r * Math.sin(angle);
        ctx.beginPath();
        ctx.arc(x, y, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = "#00e6b4";
        ctx.fill();
        ctx.strokeStyle = "#101918";
        ctx.lineWidth = 2;
        ctx.stroke();
      }
    }

    ctx.beginPath();
    ctx.arc(cx, cy, Math.max(29, Math.min(38, radius * 0.24)), 0, Math.PI * 2);
    ctx.fillStyle = "#101918";
    ctx.fill();
    ctx.strokeStyle = "rgba(0, 230, 180, 0.45)";
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = "#f1f7f3";
    ctx.font = `700 ${w < 360 ? 17 : 20}px Inter, sans-serif`;
    ctx.fillText(averageScore === null ? "—" : `${averageScore}%`, cx, cy - 5);
    ctx.fillStyle = "rgba(230, 240, 235, 0.65)";
    ctx.font = `600 ${w < 360 ? 7 : 8}px Inter, sans-serif`;
    ctx.fillText(averageScore === null ? "NO DATA" : "DOMAIN AVG", cx, cy + 13);

    const summary = document.getElementById("radarSummary");
    if (summary) summary.textContent = attemptedCount
      ? `${attemptedCount} of ${n} assessed · ${averageScore}% average`
      : "No domains assessed";

    const legend = document.getElementById("radarLegend");
    if (legend) {
      legend.innerHTML = this.topicsMeta.map((topic, index) => {
        const data = scores[topic.id];
        return `
          <div class="radar-legend-item">
            <span class="radar-legend-index">${String(index + 1).padStart(2, "0")}</span>
            <span class="radar-legend-name">${topic.name}</span>
            <strong>${data?.count ? `${data.score}%` : "—"}</strong>
          </div>
        `;
      }).join("");
    }
    this.clearRadarInspection();
  },

  inspectRadarPointer(event) {
    const canvas = event.currentTarget;
    const geometry = this.radarGeometry;
    const tooltip = document.getElementById("radarTooltip");
    if (!geometry || !tooltip) return;

    const bounds = canvas.getBoundingClientRect();
    const x = (event.clientX - bounds.left) * geometry.w / bounds.width - geometry.cx;
    const y = (event.clientY - bounds.top) * geometry.h / bounds.height - geometry.cy;
    const distance = Math.hypot(x, y);
    if (distance < geometry.radius * 0.22 || distance > geometry.radius + 20) {
      this.clearRadarInspection();
      return;
    }

    const angle = (Math.atan2(y, x) + Math.PI / 2 + Math.PI * 2) % (Math.PI * 2);
    const index = Math.round(angle / (Math.PI * 2 / geometry.count)) % geometry.count;
    const topic = this.topicsMeta[index];
    const data = geometry.scores[topic.id];
    tooltip.textContent = data.count
      ? `${String(index + 1).padStart(2, "0")} · ${topic.name}: ${data.score}% recent average from ${data.count} attempt${data.count === 1 ? "" : "s"}`
      : `${String(index + 1).padStart(2, "0")} · ${topic.name}: not assessed yet`;
    canvas.style.cursor = "crosshair";
  },

  clearRadarInspection() {
    const tooltip = document.getElementById("radarTooltip");
    if (tooltip) {
      tooltip.textContent = this.radarGeometry?.assessedCount
        ? "Hover over a spoke to inspect its score."
        : "Complete a quiz to see your domain scores.";
    }
    const canvas = document.getElementById("radarChart");
    if (canvas) canvas.style.cursor = "default";
  },

  // ---------------------------------------------------------------------------
  // Certificate Generation & Export
  // ---------------------------------------------------------------------------

  async openCertificate() {
    if (!Auth.user) {
      Auth.open("login", "Sign in to view your verified training certificate.");
      return;
    }

    try {
      const res = await fetch("/api/certificate");
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.error || "Could not fetch certificate.");
      }
      const cert = payload;
      this.currentCert = cert;

      document.getElementById("certRecipientName").textContent = cert.username;
      document.getElementById("certScoreVal").textContent = cert.avg_score + "%";
      document.getElementById("certLevelVal").textContent = cert.badge_title;
      document.getElementById("certDateVal").textContent = cert.issue_date;
      document.getElementById("certIdVal").textContent = cert.cert_id;

      document.getElementById("certModal")?.classList.remove("hidden");
    } catch (e) {
      if (typeof Auth.showToast === "function") {
        Auth.showToast(e.message || "Pass the comprehensive exam to earn your certificate.", "warning");
      }
    }
  },

  closeCertificate() {
    document.getElementById("certModal")?.classList.add("hidden");
  },

  copyCertId() {
    if (this.currentCert && this.currentCert.cert_id) {
      navigator.clipboard.writeText(this.currentCert.cert_id);
      if (typeof Auth.showToast === "function") {
        Auth.showToast("Certificate verification ID copied!", "success");
      }
    }
  },

  downloadCertificate() {
    if (!this.currentCert) return;

    // Render Certificate to high-resolution Canvas (1200x800)
    const canvas = document.createElement("canvas");
    canvas.width = 1200;
    canvas.height = 800;
    const ctx = canvas.getContext("2d");

    // Background
    ctx.fillStyle = "#0b1110";
    ctx.fillRect(0, 0, 1200, 800);

    // Decorative gradient glow
    const grad = ctx.createRadialGradient(600, 400, 50, 600, 400, 600);
    grad.addColorStop(0, "rgba(190, 243, 95, 0.1)");
    grad.addColorStop(1, "rgba(11, 17, 16, 0.95)");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, 1200, 800);

    // Outer double border
    ctx.strokeStyle = "#bef35f";
    ctx.lineWidth = 4;
    ctx.strokeRect(30, 30, 1140, 740);

    ctx.strokeStyle = "rgba(255, 255, 255, 0.15)";
    ctx.lineWidth = 1;
    ctx.strokeRect(45, 45, 1110, 710);

    // Header Emblem
    ctx.fillStyle = "#bef35f";
    ctx.font = "bold 32px Outfit, sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("🛡️ CYBERAWARE SECURITY ACADEMY", 600, 120);

    ctx.fillStyle = "rgba(255, 255, 255, 0.6)";
    ctx.font = "16px Inter, sans-serif";
    ctx.fillText("OFFICIAL TRAINING & COMPETENCY VERIFICATION", 600, 155);

    // Line separator
    ctx.strokeStyle = "rgba(190, 243, 95, 0.4)";
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(350, 185);
    ctx.lineTo(850, 185);
    ctx.stroke();

    // Preamble
    ctx.fillStyle = "#aab8ae";
    ctx.font = "italic 20px Inter, sans-serif";
    ctx.fillText("This is to certify that", 600, 240);

    // Recipient Name
    ctx.fillStyle = "#ffffff";
    ctx.font = "bold 44px Outfit, sans-serif";
    ctx.fillText(this.currentCert.username.toUpperCase(), 600, 310);

    // Statement
    ctx.fillStyle = "#aab8ae";
    ctx.font = "18px Inter, sans-serif";
    ctx.fillText("has passed the all-topics cybersecurity exam and demonstrated", 600, 370);
    ctx.fillText("verified proficiency across all 11 cybersecurity learning domains.", 600, 400);

    // Metric Badges Box
    ctx.fillStyle = "rgba(23, 34, 32, 0.85)";
    ctx.strokeStyle = "rgba(190, 243, 95, 0.3)";
    ctx.lineWidth = 1.5;
    ctx.fillRect(150, 450, 900, 120);
    ctx.strokeRect(150, 450, 900, 120);

    const cols = [
      { label: "EXAM SCORE", val: `${this.currentCert.exam_score}%` },
      { label: "PROFICIENCY LEVEL", val: this.currentCert.proficiency_level },
      { label: "ISSUE DATE", val: this.currentCert.issue_date },
      { label: "CREDENTIAL ID", val: this.currentCert.cert_id }
    ];

    cols.forEach((col, idx) => {
      const cx = 260 + idx * 220;
      ctx.fillStyle = "#718078";
      ctx.font = "bold 12px Inter, sans-serif";
      ctx.fillText(col.label, cx, 490);

      ctx.fillStyle = "#bef35f";
      ctx.font = "bold 20px Outfit, sans-serif";
      ctx.fillText(col.val, cx, 530);
    });

    // Signature line & Seal
    ctx.fillStyle = "#aab8ae";
    ctx.font = "15px Inter, sans-serif";
    ctx.fillText("CyberAware Automated Verification Authority", 400, 680);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
    ctx.beginPath();
    ctx.moveTo(250, 655);
    ctx.lineTo(550, 655);
    ctx.stroke();

    ctx.fillStyle = "#bef35f";
    ctx.font = "bold 16px Outfit, sans-serif";
    ctx.fillText("VERIFIED DEFENDER SEAL 🛡️", 800, 675);

    // Trigger download
    const link = document.createElement("a");
    link.download = `CyberAware-Certificate-${this.currentCert.username}.png`;
    link.href = canvas.toDataURL("image/png");
    link.click();

    if (typeof Auth.showToast === "function") {
      Auth.showToast("Certificate PNG generated and downloaded!", "success");
    }
  },

  // ---------------------------------------------------------------------------
  // Training & Compliance Report
  // ---------------------------------------------------------------------------

  async openReport() {
    if (!Auth.user) {
      Auth.open("login", "Sign in to generate your compliance report.");
      return;
    }

    try {
      const res = await fetch("/api/progress/report");
      if (!res.ok) throw new Error("Could not fetch training report");
      const report = await res.json();
      this.currentReport = report;

      const area = document.getElementById("reportContentArea");
      if (!area) return;

      const metrics = report.metrics;
      const topics = report.topics;

      area.innerHTML = `
        <div class="report-meta-box">
          <div class="report-meta-row">
            <span><strong>User:</strong> ${report.user.username} (${report.user.email})</span>
            <span><strong>Generated:</strong> ${new Date(report.generated_at).toLocaleString()}</span>
          </div>
          <div class="report-meta-row" style="margin-top:0.4rem;">
            <span><strong>Average Assessment Score:</strong> ${metrics.average_score}%</span>
            <span><strong>Active Streak:</strong> ${metrics.current_streak} days</span>
            <span><strong>Status:</strong> ${report.user.two_factor_enabled ? "🛡️ 2FA Protected" : "Standard Account"}</span>
          </div>
        </div>

        <h4 style="margin: 1.25rem 0 0.5rem; color: var(--cyber-teal);">Domain Discipline Assessment Breakdown</h4>
        <table class="report-table">
          <thead>
            <tr>
              <th>Topic Domain</th>
              <th>Attempts</th>
              <th>Average Score</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${topics.length ? topics.map(t => `
              <tr>
                <td><strong>${t.name}</strong></td>
                <td>${t.attempts}</td>
                <td>${t.avg_score}%</td>
                <td><span class="status-pill ${t.status === 'Proficient' ? 'status-verified' : 'status-disabled'}">${t.status}</span></td>
              </tr>
            `).join('') : '<tr><td colspan="4" class="empty-state">No assessments completed yet.</td></tr>'}
          </tbody>
        </table>

        <h4 style="margin: 1.25rem 0 0.5rem; color: var(--cyber-teal);">Recent Assessment Records</h4>
        <div class="report-quiz-log">
          ${report.recent_quizzes.map(q => `
            <div class="report-log-entry">
              <span>${q.topic_name || q.topic}</span>
              <span>${q.score}/${q.total} (${q.percent}%)</span>
              <small>${new Date(q.date).toLocaleDateString()}</small>
            </div>
          `).join('') || '<p class="empty-state">No recent records.</p>'}
        </div>
      `;

      document.getElementById("reportModal")?.classList.remove("hidden");
    } catch (e) {
      if (typeof Auth.showToast === "function") {
        Auth.showToast("Could not load training report.", "error");
      }
    }
  },

  closeReport() {
    document.getElementById("reportModal")?.classList.add("hidden");
  },

  downloadReportJson() {
    if (!this.currentReport) return;
    const blob = new Blob([JSON.stringify(this.currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `CyberAware-Report-${Auth.user.username}.json`;
    a.click();
    URL.revokeObjectURL(url);
    if (typeof Auth.showToast === "function") {
      Auth.showToast("Compliance report JSON exported!", "success");
    }
  },

  copyReportSummary() {
    if (!this.currentReport) return;
    const m = this.currentReport.metrics;
    const summary = `CyberAware Training Summary for ${this.currentReport.user.username}\nOverall Score: ${m.average_score}%\nQuizzes Completed: ${m.total_quizzes}\nPhishing Sims: ${m.phishing_completed}\nCurrent Streak: ${m.current_streak} days\nGenerated: ${new Date().toISOString()}`;
    navigator.clipboard.writeText(summary);
    if (typeof Auth.showToast === "function") {
      Auth.showToast("Report summary copied to clipboard!", "success");
    }
  }
};
