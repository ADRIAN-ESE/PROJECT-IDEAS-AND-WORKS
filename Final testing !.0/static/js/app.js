/**
 * CyberAware — Core App Router & Global State
 */

const App = {
  currentSection: "home",
  topics: [],

  async init() {
    // Load topics
    try {
      const res = await fetch("/api/topics");
      this.topics = await res.json();
    } catch (e) {
      console.warn("Could not load topics from API, using fallback");
      this.topics = [
        { id: "phishing", name: "Phishing", description: "Recognize phishing", icon: "🎣", color: "hsl(0, 85%, 60%)" },
        { id: "passwords", name: "Passwords", description: "Strong passwords", icon: "🔐", color: "hsl(170, 80%, 50%)" },
        { id: "social-engineering", name: "Social Engineering", description: "Manipulation tactics", icon: "🎭", color: "hsl(280, 90%, 65%)" },
        { id: "data-protection", name: "Data Protection", description: "Keep data safe", icon: "🛡️", color: "hsl(45, 100%, 60%)" },
        { id: "safe-browsing", name: "Safe Browsing", description: "Browse securely", icon: "🌐", color: "hsl(200, 90%, 55%)" },
        { id: "wifi-security", name: "Wi-Fi Security", description: "Secure wireless", icon: "📶", color: "hsl(320, 80%, 60%)" },
        { id: "device-security", name: "Device Security", description: "Protect devices", icon: "💻", color: "hsl(190, 80%, 55%)" },
        { id: "incident-response", name: "Incident Response", description: "Respond to incidents", icon: "🚨", color: "hsl(25, 90%, 60%)" },
        { id: "cyber-law", name: "Cyber Law", description: "Legal duties and responsible security conduct", icon: "⚖️", color: "hsl(210, 75%, 55%)" },
        { id: "governance", name: "Cyber Governance", description: "Cyber risk, accountability, and oversight", icon: "🏛️", color: "hsl(145, 65%, 45%)" }
      ];
    }

    this.setupNavigation();
    this.renderLearnTopics();
    this.handleHash();

    // Mobile nav toggle
    const toggle = document.getElementById("navToggle");
    const links = document.getElementById("navLinks");
    if (toggle) {
      toggle.addEventListener("click", () => links.classList.toggle("open"));
    }

    // Close mobile menu on link click
    document.querySelectorAll(".nav-link").forEach(link => {
      link.addEventListener("click", () => links.classList.remove("open"));
    });

    // Initialize account state before modules that save user progress.
    if (typeof Auth !== "undefined") await Auth.init();

    // Initialize feature modules
    if (typeof Quiz !== "undefined") Quiz.init();
    if (typeof Phishing !== "undefined") Phishing.init();
    if (typeof PasswordChecker !== "undefined") PasswordChecker.init();
    if (typeof Dashboard !== "undefined") Dashboard.init();

    document.getElementById("appLoader")?.classList.add("is-hidden");

    window.addEventListener("hashchange", () => this.handleHash());
  },

  setupNavigation() {
    document.querySelectorAll(".nav-link").forEach(link => {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        const section = link.dataset.section;
        this.navigate(section);
      });
    });
  },

  navigate(section) {
    window.location.hash = section;
  },

  handleHash() {
    const hash = window.location.hash.slice(1) || "home";
    this.showSection(hash);
  },

  showSection(id) {
    if (["learn", "quiz", "phishing", "password"].includes(id)
      && typeof Auth !== "undefined" && Auth.user
      && !Auth.canAccessTraining()) {
      id = "dashboard";
    }

    document.querySelectorAll(".section").forEach(s => s.classList.remove("active"));
    const target = document.getElementById(id);
    if (target) {
      target.classList.add("active");
      this.currentSection = id;
    }

    document.querySelectorAll(".nav-link").forEach(link => {
      link.classList.toggle("active", link.dataset.section === id);
    });

    // Refresh dashboard when navigating to it
    if (id === "dashboard" && typeof Dashboard !== "undefined") {
      Dashboard.render();
    }
    if (id === "admin" && typeof Admin !== "undefined") {
      Admin.render();
    }
  },

  async loadTopicResources(topicId) {
    try {
      const res = await fetch(`/api/learning?topic=${encodeURIComponent(topicId)}`);
      if (!res.ok) return [];
      const data = await res.json();
      return Array.isArray(data.resources) ? data.resources : [];
    } catch (error) {
      console.warn("Could not load learning resources", error);
      return [];
    }
  },

  renderLearnTopics() {
    const grid = document.getElementById("topicsGrid");
    if (!grid) return;

    const content = {
      phishing: {
        intro: "Phishing is one of the most common cyber attacks. Attackers impersonate trusted entities to steal credentials, money, or data.",
        tips: [
          "Hover over links before clicking to inspect the real URL",
          "Be suspicious of urgent or threatening language",
          "Never enter credentials after clicking an email link — go to the site directly",
          "Check the sender domain carefully for lookalikes (paypa1.com vs paypal.com)",
          "Enable multi-factor authentication so a stolen password alone is not enough"
        ],
        fact: "According to industry reports, phishing is involved in over 80% of security breaches."
      },
      passwords: {
        intro: "Passwords remain a primary authentication factor. Weak or reused passwords are a leading cause of account compromise.",
        tips: [
          "Use a unique password for every important account",
          "Prefer long passphrases (12–20+ characters) over short complex strings",
          "Use a reputable password manager",
          "Enable MFA / 2FA wherever available",
          "Change passwords only when compromise is suspected — forced rotation often reduces strength"
        ],
        fact: "Credential stuffing attacks reuse leaked username/password pairs across many sites. Unique passwords stop this cold."
      },
      "social-engineering": {
        intro: "Social engineering exploits human psychology rather than software vulnerabilities. Awareness is the best defense.",
        tips: [
          "Verify unexpected requests through a known independent channel",
          "Be wary of urgency, authority, and secrecy pressure tactics",
          "Never share passwords or MFA codes — even with 'IT support'",
          "Follow physical security procedures (no tailgating)",
          "Report suspected social engineering attempts promptly"
        ],
        fact: "Many of the largest breaches in history began with a single successful social engineering call or email."
      },
      "data-protection": {
        intro: "Protecting personal and organizational data reduces the impact of breaches and supports privacy regulations.",
        tips: [
          "Follow the 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite",
          "Encrypt sensitive data at rest and in transit",
          "Practice data minimization — collect and keep only what you need",
          "Securely wipe devices before disposal or resale",
          "Review app permissions regularly on mobile devices"
        ],
        fact: "The average cost of a data breach continues to rise year over year, making prevention far cheaper than recovery."
      },
      "safe-browsing": {
        intro: "Safe browsing habits dramatically reduce exposure to malware, phishing, and tracking.",
        tips: [
          "Look for HTTPS (padlock) — but remember it only means encryption, not trustworthiness",
          "Download software only from official sources",
          "Keep browsers and extensions up to date",
          "Be cautious with browser extensions — review their permissions",
          "Use private/incognito mode on shared computers and clear data afterward"
        ],
        fact: "Drive-by downloads can install malware simply by visiting a compromised page — keeping software updated is critical."
      },
      "wifi-security": {
        intro: "Wireless networks are convenient but expose traffic if not properly secured.",
        tips: [
          "Use WPA3 (or at least WPA2) encryption — never WEP",
          "Change the default router admin password",
          "Create a separate guest network for visitors",
          "Disable WPS if possible",
          "Use a VPN on public Wi-Fi"
        ],
        fact: "Open public Wi-Fi can allow attackers on the same network to intercept unencrypted traffic or perform man-in-the-middle attacks."
      },
      "device-security": {
        intro: "Every computer and mobile device is part of your security boundary. Small maintenance habits prevent common attacks and reduce the impact of loss.",
        tips: [
          "Install operating system and application updates promptly",
          "Use screen locks, device encryption, and remote-find tools",
          "Install software only from official sources",
          "Remove unused applications and review permissions",
          "Do not connect unknown USB devices"
        ],
        fact: "Device encryption protects data at rest if a laptop or phone is lost, but it does not replace strong account security."
      },
      "incident-response": {
        intro: "A calm, fast response limits damage. Learn what to report, what to preserve, and how to avoid making an incident worse.",
        tips: [
          "Report suspicious activity through the approved channel immediately",
          "Disconnect affected devices from networks when instructed",
          "Preserve messages, logs, and timestamps instead of deleting evidence",
          "Never investigate alone or publicly discuss an active incident",
          "Review lessons learned after recovery"
        ],
        fact: "Early reporting can turn a serious compromise into a contained event by helping responders isolate accounts and devices quickly."
      },
      "cyber-law": {
        intro: "Cyber and privacy laws differ by location, sector, and situation. Recognize when to stop, preserve information, and involve the right legal or privacy contact.",
        tips: [
          "Access only systems and records you are authorized to use",
          "Get written approval and scope before performing security tests",
          "Route breach and data requests through approved legal and privacy channels",
          "Preserve relevant records and follow legal-hold instructions",
          "Check applicable jurisdiction-specific requirements with qualified counsel"
        ],
        fact: "A reporting deadline or disclosure duty can depend on the law, the organization's role, the data involved, and the risks to affected people."
      },
      governance: {
        intro: "Cyber governance assigns accountability for risk decisions and ensures security work supports business priorities and obligations.",
        tips: [
          "Maintain an inventory of important systems, data, and suppliers",
          "Assign accountable owners to risks and security exceptions",
          "Set measurable outcomes and review them with leadership",
          "Assess supplier access and security commitments before adoption",
          "Use exercises and incidents to track improvements to closure"
        ],
        fact: "Governance frameworks help organizations define cybersecurity strategy, roles, policies, and oversight."
      }
    };

    grid.innerHTML = this.topics.map(t => `
      <div class="topic-card" style="--topic-color: ${t.color}" data-topic="${t.id}">
        <div class="topic-icon">${t.icon}</div>
        <h3>${t.name}</h3>
        <p>${t.description}</p>
      </div>
    `).join("");

    grid.querySelectorAll(".topic-card").forEach(card => {
      card.addEventListener("click", async () => {
        const id = card.dataset.topic;
        const topic = this.topics.find(t => t.id === id);
        const c = content[id] || { intro: "", tips: [], fact: "" };
        const detail = document.getElementById("lessonDetail");
        detail.classList.remove("hidden");
        detail.innerHTML = `
          <button class="back-link" onclick="document.getElementById('lessonDetail').classList.add('hidden')">← Back to topics</button>
          <h3>${topic.icon} ${topic.name}</h3>
          <p>${c.intro}</p>
          <div class="tips">
            <h4>Best Practices</h4>
            <ul>${c.tips.map(t => `<li>${t}</li>`).join("")}</ul>
          </div>
          <div class="did-you-know">
            <strong>Did you know?</strong> ${c.fact}
          </div>
          <div style="margin-top:1.5rem; display:flex; gap:0.75rem; flex-wrap:wrap;">
            <button class="btn btn-primary" onclick="navigate('quiz')">Take ${topic.name} Quiz</button>
          </div>
          <div class="resource-controls">
            <label for="resourceSource">Choose a learning source</label>
            <select id="resourceSource">
              <option value="all">All sources</option>
            </select>
          </div>
          <div class="resource-list" aria-live="polite">
            <p>Loading recommended learning resources…</p>
          </div>
        `;

        const resourceList = detail.querySelector(".resource-list");
        const resourceSource = detail.querySelector("#resourceSource");
        const resources = await this.loadTopicResources(id);
        if (!resources.length) {
          detail.querySelector(".resource-controls").remove();
          resourceList.innerHTML = "<p>No learning resources are available for this topic yet.</p>";
          detail.scrollIntoView({ behavior: "smooth", block: "start" });
          return;
        }

        const getResourceSource = resource => {
          if (resource.title.includes(" — ")) {
            return resource.title.split(" — ", 1)[0];
          }
          if (resource.title.startsWith("Google ")) return "Google";
          if (resource.title.startsWith("Firefox ")) return "Firefox";
          return resource.title;
        };
        const sources = [...new Set(resources.map(getResourceSource))].sort();
        resourceSource.innerHTML += sources.map(source => `
          <option value="${source}">${source}</option>
        `).join("");

        resourceList.innerHTML = resources.map(resource => `
          <article class="learning-resource">
            <div class="resource-topline">
              <span class="resource-type">${resource.type || "Resource"}</span>
              <span class="resource-level">${resource.difficulty || "Any level"}</span>
            </div>
            <h4>${resource.title}</h4>
            <p>${resource.description}</p>
            <a class="btn btn-secondary resource-link" href="${resource.url}" target="_blank" rel="noopener noreferrer">Open resource</a>
          </article>
        `).join("");

        resourceList.querySelectorAll(".learning-resource").forEach((card, index) => {
          card.dataset.source = getResourceSource(resources[index]);
        });
        resourceSource.addEventListener("change", () => {
          resourceList.querySelectorAll(".learning-resource").forEach(card => {
            card.hidden = resourceSource.value !== "all"
              && card.dataset.source !== resourceSource.value;
          });
        });

        detail.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }
};

// Global navigate helper used by onclick handlers
function navigate(section) {
  App.navigate(section);
}

document.addEventListener("DOMContentLoaded", () => App.init());
