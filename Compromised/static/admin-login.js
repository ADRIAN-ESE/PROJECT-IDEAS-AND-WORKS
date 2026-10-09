const form = document.getElementById('admin-login-form');
const errorBox = document.getElementById('login-error');
const submitButton = form.querySelector('button[type="submit"]');

function showError(message) {
  errorBox.hidden = false;
  errorBox.textContent = message;
}

async function checkExistingSession() {
  try {
    const response = await fetch('/api/admin/session', {
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    });
    if (!response.ok) return;
    const data = await response.json();
    if (data.authenticated) window.location.replace('/admin');
  } catch {
    // Keep the sign-in form usable when the session probe cannot complete.
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  submitButton.disabled = true;
  submitButton.textContent = 'Signing in…';

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;

  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || !data.ok) {
      showError(data.error || `Sign-in failed (${response.status}). Check your credentials and try again.`);
      return;
    }

    window.location.assign(data.redirect || '/admin');
  } catch {
    showError('Could not reach the PhishGuard server. Check that it is running and try again.');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = 'Access console';
  }
});

checkExistingSession();
