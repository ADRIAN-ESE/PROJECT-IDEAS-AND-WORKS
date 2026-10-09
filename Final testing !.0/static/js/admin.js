/**
 * CyberAware — Administrator overview
 */

const Admin = {
  escape(value) {
    return String(value).replace(/[&<>"']/g, character => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    }[character]));
  },

  formatDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
  },

  async render() {
    if (!Auth?.user || Auth.user.role !== "admin") return;
    let data;
    try {
      const response = await fetch("/api/admin/summary");
      data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not load the administrator overview.");
    } catch (error) {
      console.error("Could not load administrator overview", error);
      Auth.showToast(error.message || "Could not load the administrator overview.", "error");
      return;
    }
    const stats = document.getElementById("adminStats");
    const users = document.getElementById("adminUsers");
    const rankings = document.getElementById("adminLeaderboard");
    const resetRequests = document.getElementById("adminResetRequests");
    const selectAll = document.getElementById("adminSelectAllUsers");
    const removeSelected = document.getElementById("adminRemoveSelectedUsers");

    if (selectAll && !selectAll.dataset.bound) {
      selectAll.addEventListener("change", () => {
        users?.querySelectorAll("[data-user-select]").forEach(checkbox => {
          checkbox.checked = selectAll.checked;
          checkbox.closest(".admin-user-row")?.classList.toggle("is-selected", checkbox.checked);
        });
        this.updateSelectionControls();
      });
      selectAll.dataset.bound = "true";
    }

    if (removeSelected && !removeSelected.dataset.bound) {
      removeSelected.addEventListener("click", () => this.removeSelectedUsers(removeSelected));
      removeSelected.dataset.bound = "true";
    }

    if (stats) {
      stats.innerHTML = `
        <div class="admin-stat"><span class="admin-stat-label">Registered users</span><strong>${data.users.length}</strong></div>
        <div class="admin-stat"><span class="admin-stat-label">Quiz attempts</span><strong>${data.quiz_attempts}</strong></div>
        <div class="admin-stat"><span class="admin-stat-label">Phishing practices</span><strong>${data.phishing_attempts}</strong></div>
        <div class="admin-stat"><span class="admin-stat-label">Avg. quiz score</span><strong>${data.average_score}%</strong></div>
        <div class="admin-stat"><span class="admin-stat-label">Active learners</span><strong>${data.active_users}</strong></div>
        <div class="admin-stat"><span class="admin-stat-label">Pending approvals</span><strong>${data.pending_approvals}</strong></div>
      `;
    }

    if (resetRequests) {
      if (!resetRequests.dataset.bound) {
        resetRequests.addEventListener("click", event => {
          const button = event.target.closest("[data-reset-action]");
          if (!button || !resetRequests.contains(button)) return;
          this.resolveProgressResetRequest(
            button.dataset.requestId,
            button.dataset.resetAction,
            button
          );
        });
        resetRequests.dataset.bound = "true";
      }

      const requests = Array.isArray(data.progress_reset_requests)
        ? data.progress_reset_requests
        : [];
      resetRequests.innerHTML = requests.length
        ? requests.map(resetRequest => `
            <article class="admin-reset-request">
              <div>
                <strong>${this.escape(resetRequest.username)}</strong>
                <small>${this.escape(resetRequest.email)} · Requested ${this.formatDate(resetRequest.requested_at)}</small>
              </div>
              <div class="admin-user-actions">
                <button class="btn btn-primary btn-sm" type="button" data-reset-action="approve" data-request-id="${resetRequest.id}">Approve reset</button>
                <button class="btn btn-ghost btn-sm" type="button" data-reset-action="reject" data-request-id="${resetRequest.id}">Reject</button>
              </div>
            </article>
          `).join("")
        : '<p class="admin-users-empty">No pending progress reset requests.</p>';
    }

    if (users) {
      if (!users.dataset.userActionsBound) {
        users.addEventListener("click", event => {
          const button = event.target.closest("[data-user-action]");
          if (!button || !users.contains(button)) return;
          if (button.dataset.userAction === "approve") {
            this.approveUser(button.dataset.userId, button.dataset.username, button);
          } else if (button.dataset.userAction === "remove") {
            this.removeUser(button.dataset.userId, button.dataset.username, button);
          }
        });
        users.addEventListener("change", event => {
          if (event.target.matches("[data-user-select]")) this.updateSelectionControls();
        });
        users.dataset.userActionsBound = "true";
      }

      users.innerHTML = data.users.map(user => `
        <div class="admin-user-row">
          <div class="admin-user-identity">
            ${user.role === "user" ? `<input type="checkbox" data-user-select value="${user.id}" aria-label="Select ${this.escape(user.username)}">` : ""}
            <div><strong>${this.escape(user.username)}</strong><small>${this.escape(user.email)}</small></div>
          </div>
          <span class="admin-role${user.role === "user" && !user.approved ? " is-pending" : ""}">
            ${user.role === "admin" ? "Administrator" : user.approved ? "Approved" : "Pending approval"}
          </span>
          <time datetime="${this.escape(user.created_at || "")}">${this.formatDate(user.created_at)}</time>
          <span class="admin-user-actions">
            ${user.role === "user" && !user.approved ? `<button class="btn btn-primary btn-sm" type="button" data-user-action="approve" data-user-id="${user.id}" data-username="${this.escape(user.username)}">Approve</button>` : ""}
            ${user.role === "user" ? `<button class="btn btn-threat btn-sm" type="button" data-user-action="remove" data-user-id="${user.id}" data-username="${this.escape(user.username)}" aria-label="Remove user ${this.escape(user.username)}">Remove</button>` : ""}
          </span>
        </div>
      `).join("") || '<p class="admin-users-empty">No user accounts to display.</p>';
      if (selectAll) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
      }
      this.updateSelectionControls();
    }

    if (rankings) {
      const entries = Array.isArray(data.leaderboard) ? data.leaderboard : [];
      rankings.innerHTML = entries.length
        ? entries.map((entry, index) => `
            <div class="leaderboard-row admin-leaderboard-row">
              <span class="rank">#${index + 1}</span>
              <span class="user">${this.escape(entry.username)}</span>
              <span class="score">${entry.points} pts</span>
            </div>
          `).join("")
        : '<p class="empty-state">No quiz data available yet.</p>';
    }
  },

  updateSelectionControls() {
    const users = document.getElementById("adminUsers");
    const selectAll = document.getElementById("adminSelectAllUsers");
    const removeSelected = document.getElementById("adminRemoveSelectedUsers");
    const selectionCount = document.getElementById("adminSelectionCount");
    if (!users || !removeSelected) return;

    const checkboxes = [...users.querySelectorAll("[data-user-select]")];
    const selectedCount = checkboxes.filter(checkbox => checkbox.checked).length;
    checkboxes.forEach(checkbox => {
      checkbox.closest(".admin-user-row")?.classList.toggle("is-selected", checkbox.checked);
    });
    removeSelected.disabled = selectedCount === 0;
    removeSelected.textContent = selectedCount
      ? `Delete selected users (${selectedCount})`
      : "Delete selected users";
    if (selectionCount) {
      selectionCount.textContent = selectedCount
        ? `${selectedCount} user${selectedCount === 1 ? "" : "s"} selected`
        : "No users selected";
    }
    if (selectAll) {
      selectAll.disabled = checkboxes.length === 0;
      selectAll.checked = checkboxes.length > 0 && selectedCount === checkboxes.length;
      selectAll.indeterminate = selectedCount > 0 && selectedCount < checkboxes.length;
    }
  },

  async approveUser(userId, username, button) {
    button.disabled = true;
    try {
      const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/approve`, {
        method: "POST"
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not approve user.");

      Auth.showToast(data.message || `${username} approved.`, "success");
      await this.render();
    } catch (error) {
      button.disabled = false;
      Auth.showToast(error.message || "Could not approve user.", "error");
    }
  },

  async resolveProgressResetRequest(requestId, action, button) {
    const approved = action === "approve";
    const message = approved
      ? "Approve this request and permanently clear the learner's quiz, phishing, and streak progress?"
      : "Reject this progress reset request?";
    if (!window.confirm(message)) return;

    button.disabled = true;
    try {
      const response = await fetch(
        `/api/admin/progress-reset-requests/${encodeURIComponent(requestId)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action })
        }
      );
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not resolve progress reset request.");

      Auth.showToast(data.message || "Progress reset request updated.", "success");
      await this.render();
    } catch (error) {
      button.disabled = false;
      Auth.showToast(error.message || "Could not resolve progress reset request.", "error");
    }
  },

  async removeSelectedUsers(button) {
    const users = document.getElementById("adminUsers");
    const selected = [...(users?.querySelectorAll("[data-user-select]:checked") || [])];
    if (!selected.length) return;

    const count = selected.length;
    const noun = count === 1 ? "account" : "accounts";
    if (!window.confirm(`Permanently remove ${count} selected user ${noun} and all associated training history? This cannot be undone.`)) return;

    button.disabled = true;
    try {
      const response = await fetch("/api/admin/users/batch", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_ids: selected.map(checkbox => Number(checkbox.value)) })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not remove selected users.");

      Auth.showToast(data.message || `${data.deleted_count} users removed.`, "success");
      await this.render();
    } catch (error) {
      button.disabled = false;
      Auth.showToast(error.message || "Could not remove selected users.", "error");
    }
  },

  async removeUser(userId, username, button) {
    if (!window.confirm(`Remove ${username} and all of their training progress? This cannot be undone.`)) return;

    button.disabled = true;
    try {
      const response = await fetch(`/api/admin/users/${encodeURIComponent(userId)}`, {
        method: "DELETE"
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not remove user.");

      Auth.showToast(data.message || "User removed.", "success");
      await this.render();
    } catch (error) {
      button.disabled = false;
      Auth.showToast(error.message || "Could not remove user.", "error");
    }
  }
};