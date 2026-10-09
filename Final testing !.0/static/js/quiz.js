/**
 * CyberAware — Quiz Engine
 */

const Quiz = {
  questions: [],
  currentIndex: 0,
  score: 0,
  answers: [],
  attemptId: null,
  selectedTopic: null,
  isComprehensiveExam: false,
  timerInterval: null,
  deadlineAt: null,
  timeLeft: 0,

  init() {
    this.renderTopicCards();
    document.getElementById("quizBackBtn")?.addEventListener("click", () => this.previous());
    document.getElementById("quizNextBtn")?.addEventListener("click", () => this.next());
    document.getElementById("quizQuitBtn")?.addEventListener("click", () => this.quit());
    document.getElementById("comprehensiveExamBtn")?.addEventListener("click", () => this.startComprehensiveExam());
    document.getElementById("quizDifficulty")?.addEventListener("change", () => this.updateTimeLimitHint());
    this.updateTimeLimitHint();
  },

  updateTimeLimitHint() {
    const hint = document.getElementById("quizTimeLimitHint");
    const difficulty = document.getElementById("quizDifficulty")?.value || "";
    if (!hint) return;
    const limits = { beginner: 10, intermediate: 15, advanced: 20 };
    hint.textContent = difficulty
      ? `${difficulty[0].toUpperCase()}${difficulty.slice(1)} quizzes have a ${limits[difficulty]}-minute limit.`
      : "Time limits: Beginner 10 min · Intermediate 15 min · Advanced 20 min. All Levels uses a weighted limit.";
  },

  renderTopicCards() {
    const container = document.getElementById("quizTopics");
    if (!container || !App.topics) return;

    container.innerHTML = App.topics.map(t => `
      <button type="button" class="quiz-topic-card" data-topic="${t.id}" aria-pressed="false">
        <span class="icon">${t.icon}</span>
        <strong>${t.name}</strong>
        <span class="topic-select-hint">Start topic</span>
      </button>
    `).join("");

    container.querySelectorAll(".quiz-topic-card").forEach(card => {
      card.addEventListener("click", () => {
        container.querySelectorAll(".quiz-topic-card").forEach(c => {
          c.classList.remove("selected");
          c.setAttribute("aria-pressed", "false");
        });
        card.classList.add("selected");
        card.setAttribute("aria-pressed", "true");
        this.selectedTopic = card.dataset.topic;
        this.start();
      });
    });
  },

  async start() {
    if (!this.selectedTopic) return;
    this.isComprehensiveExam = false;
    if (typeof Auth !== "undefined" && !Auth.canAccessTraining()) {
      return;
    }

    const difficulty = document.getElementById("quizDifficulty")?.value || "";
    clearInterval(this.timerInterval);
    this.deadlineAt = null;

    let url = `/api/quiz/${this.selectedTopic}`;
    const params = new URLSearchParams();
    if (difficulty) params.set("difficulty", difficulty);
    if (params.toString()) url += "?" + params.toString();

    try {
      const res = await fetch(url);
      const data = await res.json();
      if (!res.ok) {
        Auth?.showToast(data.error || "Could not load this quiz.", "error");
        if (["approval_required", "two_factor_setup_required"].includes(data.code)) {
          App.navigate("dashboard");
        }
        return;
      }
      this.questions = data.questions || [];
      this.attemptId = data.attempt_id;
      if (!this.attemptId || !Number.isInteger(data.time_limit_seconds) || data.time_limit_seconds < 1) {
        throw new Error("The quiz timer could not be started. Please try again.");
      }
      const deadlineAt = Date.parse(data.expires_at);
      if (!Number.isFinite(deadlineAt)) {
        throw new Error("The quiz deadline could not be verified. Please try again.");
      }
      this.deadlineAt = deadlineAt;
    } catch (e) {
      console.error("Failed to load quiz", e);
      Auth?.showToast(e.message || "Could not load this quiz.", "error");
      return;
    }

    if (this.questions.length === 0) {
      alert("No questions available for this selection.");
      return;
    }

    // Shuffle
    this.questions = this.prepareQuestions(this.questions);
    this.currentIndex = 0;
    this.score = 0;
    this.answers = [];

    document.getElementById("quizSetup").classList.add("hidden");
    document.getElementById("quizResults").classList.add("hidden");
    document.getElementById("quizPlay").classList.remove("hidden");
    document.getElementById("quizFeedback").classList.add("hidden");

    this.startTimer();
    this.showQuestion();
  },

  async startComprehensiveExam() {
    if (typeof Auth !== "undefined" && !Auth.canAccessTraining()) return;
    clearInterval(this.timerInterval);
    this.deadlineAt = null;

    try {
      const response = await fetch("/api/exam");
      const data = await response.json();
      if (!response.ok) {
        const missingTopics = Array.isArray(data.missing_topics) && data.missing_topics.length
          ? ` Topics remaining: ${data.missing_topics.join(", ")}.`
          : "";
        throw new Error(`${data.error || "Could not start the comprehensive exam."}${missingTopics}`);
      }
      if (!data.attempt_id || !Number.isInteger(data.time_limit_seconds)
        || data.time_limit_seconds !== 60 * 60) {
        throw new Error("The comprehensive exam timer could not be verified.");
      }
      const deadlineAt = Date.parse(data.expires_at);
      if (!Number.isFinite(deadlineAt)) {
        throw new Error("The comprehensive exam deadline could not be verified.");
      }
      if (!Array.isArray(data.questions) || data.questions.length !== 55) {
        throw new Error("The comprehensive exam could not be loaded completely.");
      }

      this.questions = this.prepareQuestions(data.questions);
      this.attemptId = data.attempt_id;
      this.deadlineAt = deadlineAt;
      this.isComprehensiveExam = true;
      this.selectedTopic = null;
      this.currentIndex = 0;
      this.score = 0;
      this.answers = [];

      document.getElementById("quizSetup").classList.add("hidden");
      document.getElementById("quizResults").classList.add("hidden");
      document.getElementById("quizPlay").classList.remove("hidden");
      document.getElementById("quizFeedback").classList.add("hidden");
      this.startTimer();
      this.showQuestion();
    } catch (error) {
      console.error("Failed to start comprehensive exam", error);
      Auth?.showToast(error.message || "Could not start the comprehensive exam.", "error");
    }
  },

  startTimer() {
    const timerEl = document.getElementById("quizTimer");
    timerEl.classList.remove("hidden", "is-warning", "is-critical");
    clearInterval(this.timerInterval);

    const update = () => {
      this.timeLeft = Math.max(0, Math.ceil((this.deadlineAt - Date.now()) / 1000));
      const minutes = Math.floor(this.timeLeft / 60);
      const seconds = this.timeLeft % 60;
      timerEl.textContent = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
      timerEl.setAttribute("aria-label", `${minutes} minutes ${seconds} seconds remaining`);
      timerEl.classList.toggle("is-warning", this.timeLeft <= 5 * 60 && this.timeLeft > 60);
      timerEl.classList.toggle("is-critical", this.timeLeft <= 60);

      if (this.timeLeft <= 0) this.expireQuiz();
    };

    update();
    this.timerInterval = setInterval(update, 1000);
  },

  expireQuiz() {
    clearInterval(this.timerInterval);
    this.timerInterval = null;
    this.answers = this.questions.map((question, index) =>
      this.answers[index] || { question_id: question.id, selected: -1 }
    );
    this.showResults(true);
  },

  shuffle(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
  },

  prepareQuestions(questions) {
    return this.shuffle(questions).map(question => {
      const optionOrder = this.shuffle(question.options.map((_, index) => index));
      return {
        ...question,
        options: optionOrder.map(index => question.options[index]),
        optionOrder,
      };
    });
  },

  showQuestion() {
    const q = this.questions[this.currentIndex];
    const card = document.getElementById("quizQuestionCard");
    const letters = ["A", "B", "C", "D", "E"];

    // Progress
    const pct = ((this.currentIndex) / this.questions.length) * 100;
    document.getElementById("quizProgressFill").style.width = pct + "%";
    document.getElementById("quizProgressText").textContent =
      `${this.currentIndex + 1} / ${this.questions.length}`;
    const savedAnswer = this.answers[this.currentIndex];
    const savedDisplayIndex = savedAnswer
      ? q.optionOrder.indexOf(savedAnswer.selected)
      : -1;
    const backButton = document.getElementById("quizBackBtn");
    backButton.disabled = this.currentIndex === 0;

    card.innerHTML = `
      ${q.topic_name ? `<span class="exam-topic-label">${q.topic_name}</span>` : ""}
      <span class="difficulty ${q.difficulty}">${q.difficulty}</span>
      <h3>${q.question}</h3>
      <div class="options-list">
        ${q.options.map((opt, i) => `
          <button class="option-btn${savedDisplayIndex === i ? " selected" : ""}" data-index="${i}" aria-pressed="${savedDisplayIndex === i}">
            <span class="option-letter">${letters[i]}</span>
            <span>${opt}</span>
          </button>
        `).join("")}
      </div>
    `;

    card.querySelectorAll(".option-btn").forEach(btn => {
      btn.addEventListener("click", () => this.selectAnswer(parseInt(btn.dataset.index, 10)));
    });

    const nextButton = document.getElementById("quizNextBtn");
    nextButton.disabled = !savedAnswer;
    nextButton.textContent = this.currentIndex === this.questions.length - 1
      ? "Review & submit"
      : "Next question";
    const feedback = document.getElementById("quizFeedback");
    if (savedAnswer) {
      feedback.classList.remove("hidden", "correct", "incorrect");
      feedback.textContent = "Your answer is saved. You can change it or move between questions before submitting.";
    } else {
      feedback.classList.add("hidden");
    }

  },

  selectAnswer(index) {
    const q = this.questions[this.currentIndex];
    this.answers[this.currentIndex] = {
      question_id: q.id,
      selected: q.optionOrder[index],
    };

    document.querySelectorAll(".option-btn").forEach(btn => {
      const selected = Number(btn.dataset.index) === index;
      btn.classList.toggle("selected", selected);
      btn.setAttribute("aria-pressed", String(selected));
    });

    const feedback = document.getElementById("quizFeedback");
    feedback.classList.remove("hidden", "correct", "incorrect");
    feedback.textContent = "Answer saved. You can change it or use Back to review earlier questions.";

    const nextButton = document.getElementById("quizNextBtn");
    nextButton.disabled = false;
    nextButton.textContent = this.currentIndex >= this.questions.length - 1
      ? "Review & submit"
      : "Next question";
  },

  previous() {
    if (this.currentIndex <= 0) return;
    this.currentIndex--;
    this.showQuestion();
  },

  next() {
    if (!this.answers[this.currentIndex]) return;
    if (this.currentIndex >= this.questions.length - 1) {
      this.showReview();
      return;
    }
    this.currentIndex++;
    this.showQuestion();
  },

  showReview() {
    const results = document.getElementById("quizResults");
    results.classList.remove("hidden");
    document.getElementById("quizPlay").classList.add("hidden");
    results.innerHTML = `
      <div class="quiz-review-header">
        <span class="eyebrow">Final review</span>
        <h3>Check your answers before submitting</h3>
        <p>Choose any question to revisit it. Your score is calculated after submission.</p>
      </div>
      <div class="quiz-review-list">
        ${this.questions.map((question, index) => {
          const answer = this.answers[index];
          const selectedOption = answer && answer.selected >= 0
            ? `Selected: ${question.options[question.optionOrder.indexOf(answer.selected)]}`
            : "Not answered";
          return `
            <button class="quiz-review-item" type="button" data-review-index="${index}">
              <span class="quiz-review-number">${String(index + 1).padStart(2, "0")}</span>
              <span class="quiz-review-copy">
                <strong>${question.question}</strong>
                <small>${question.topic_name ? `${question.topic_name} · ` : ""}${selectedOption}</small>
              </span>
              <span class="quiz-review-edit">Review</span>
            </button>
          `;
        }).join("")}
      </div>
      <div class="quiz-review-actions">
        <button class="btn btn-secondary" type="button" data-review-back>Back to quiz</button>
        <button class="btn btn-primary" type="button" data-review-submit>Submit quiz</button>
      </div>
    `;
    results.querySelectorAll("[data-review-index]").forEach(button => {
      button.addEventListener("click", () => {
        this.currentIndex = Number(button.dataset.reviewIndex);
        results.classList.add("hidden");
        document.getElementById("quizPlay").classList.remove("hidden");
        this.startTimer();
        this.showQuestion();
      });
    });
    results.querySelector("[data-review-back]")?.addEventListener("click", () => {
      this.currentIndex = this.questions.length - 1;
      results.classList.add("hidden");
      document.getElementById("quizPlay").classList.remove("hidden");
      this.startTimer();
      this.showQuestion();
    });
    results.querySelector("[data-review-submit]")?.addEventListener("click", () => this.showResults());
  },

  async showResults(timedOut = false) {
    clearInterval(this.timerInterval);
    this.timerInterval = null;
    this.answers = this.questions.map((question, index) =>
      this.answers[index] || { question_id: question.id, selected: -1 }
    );
    document.getElementById("quizPlay").classList.add("hidden");
    const results = document.getElementById("quizResults");
    results.classList.remove("hidden");
    results.innerHTML = "<p role=\"status\">Checking your answers…</p>";

    const topic = App.topics.find(t => t.id === this.selectedTopic);

    try {
      const submission = this.isComprehensiveExam
        ? await Dashboard.recordExam({ attempt_id: this.attemptId, answers: this.answers })
        : await Dashboard.recordQuiz({ attempt_id: this.attemptId, answers: this.answers });
      this.score = submission.score;
      const pct = submission.percent;
      const answerResults = new Map(submission.results.map(answer => [answer.question_id, answer]));
      const examStatus = this.isComprehensiveExam
        ? `<p class="comprehensive-exam-outcome ${submission.passed ? "is-passed" : "is-not-passed"}" role="status">
            ${submission.passed ? "PASS" : "NOT PASSED"} · ${submission.proficiency_level} proficiency · ${submission.pass_percent}% required
          </p>`
        : "";

      results.innerHTML = `
      <div class="score-circle">
        <span class="pct">${pct}%</span>
        <span class="label">${this.score} / ${this.questions.length}</span>
      </div>
      <h3>${this.isComprehensiveExam ? "All-Topics Exam Complete" : `${topic ? topic.name : "Quiz"} Complete`}</h3>
      ${timedOut ? '<p class="quiz-timeout-notice" role="status">Time is up. Unanswered questions were marked incorrect.</p>' : ""}
      ${examStatus}
      <p style="margin:0.5rem 0 1.5rem;color:var(--text-secondary)">
        ${this.isComprehensiveExam
          ? (submission.passed ? "Your verified exam result is recorded. Your certificate now displays this proficiency level." : "Review the answer explanations and try the all-topics exam again.")
          : (pct >= 80 ? "Excellent work! 🎉" : pct >= 60 ? "Good job — keep practicing!" : "Review the explanations and try again.")}
      </p>
      <div class="results-details">
        ${this.questions.map((question, i) => {
          const answer = answerResults.get(question.id);
          const selectedDisplayIndex = question.optionOrder.indexOf(answer.selected);
          const correctDisplayIndex = question.optionOrder.indexOf(answer.correct);
          return `
          <div class="result-item">
            <span class="q-status ${answer.is_correct ? "ok" : "bad"}">${answer.is_correct ? "✓" : "✗"}</span>
            ${question.topic_name ? `<span class="exam-result-topic">${question.topic_name} · </span>` : ""}
            <strong>Q${i + 1}:</strong> ${question.question}
            <div class="quiz-answer-review">
              <strong>Your answer:</strong> ${answer.selected >= 0 ? question.options[selectedDisplayIndex] : "Not answered"}
              <br><strong>Correct answer:</strong> ${question.options[correctDisplayIndex]}
              <br><strong>Why:</strong> ${answer.explanation}
            </div>
            ${answer.source ? `<a class="quiz-source-link" href="${answer.source}" target="_blank" rel="noopener noreferrer">${answer.source_is_related ? "Related reading" : "Source"}: ${answer.source_label || "Reference"}</a>` : ""}
          </div>
        `}).join("")}
      </div>
      <div style="display:flex;gap:0.75rem;justify-content:center;margin-top:1.5rem;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="Quiz.retry()">Retry</button>
        <button class="btn btn-secondary" onclick="Quiz.backToSetup()">Choose Another Topic</button>
        <button class="btn btn-ghost" onclick="navigate('dashboard')">View Dashboard</button>
      </div>
    `;
    } catch (error) {
      console.error("Failed to submit quiz", error);
      results.innerHTML = `
        <p role="alert">Could not submit this quiz: ${error.message}</p>
        <button class="btn btn-primary" onclick="Quiz.showResults()">Try submitting again</button>
      `;
    }
  },

  retry() {
    if (this.isComprehensiveExam) {
      this.startComprehensiveExam();
    } else {
      this.start();
    }
  },

  backToSetup() {
    clearInterval(this.timerInterval);
    this.timerInterval = null;
    this.deadlineAt = null;
    this.isComprehensiveExam = false;
    this.attemptId = null;
    document.getElementById("quizResults").classList.add("hidden");
    document.getElementById("quizPlay").classList.add("hidden");
    document.getElementById("quizSetup").classList.remove("hidden");
    this.selectedTopic = null;
    document.querySelectorAll(".quiz-topic-card").forEach(c => c.classList.remove("selected"));
  },

  quit() {
    clearInterval(this.timerInterval);
    this.backToSetup();
  }
};
