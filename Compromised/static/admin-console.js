const $ = (selector) => document.querySelector(selector);
const STATUS_STEPS = {
  new: { label: 'Acknowledge', next: 'acknowledged' },
  acknowledged: { label: 'Resolve', next: 'resolved' },
  resolved: { label: 'Resolved', next: null }
};

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json', ...options.headers },
    credentials: 'same-origin',
    ...options
  });
  const payload = await response.json().catch(() => ({}));

  if (response.status === 401 || response.status === 403) {
    window.location.assign('/admin/login');
    throw new Error('Your administrator session has expired.');
  }
  if (!response.ok) {
    throw new Error(payload.error || `Request failed (${response.status}).`);
  }
  return payload;
}

function setStatus(message, tone = 'ok') {
  const element = $('#status-pill');
  element.textContent = message;
  element.dataset.tone = tone;
}

function emptyState(message) {
  const row = document.createElement('div');
  row.className = 'empty-state';
  row.textContent = message;
  return row;
}

function renderSummary(target, entries, emptyMessage) {
  target.replaceChildren();
  const pairs = Object.entries(entries || {});
  if (!pairs.length) {
    target.append(emptyState(emptyMessage));
    return;
  }

  for (const [label, value] of pairs) {
    const row = document.createElement('div');
    row.className = 'summary-item';
    const name = document.createElement('span');
    name.className = 'summary-label';
    name.textContent = label.replaceAll('-', ' ');
    const count = document.createElement('span');
    count.className = 'summary-value';
    count.textContent = String(value);
    row.append(name, count);
    target.append(row);
  }
}

function formattedDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function addCell(row, value, className = '') {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  cell.textContent = value == null || value === '' ? '—' : String(value);
  row.append(cell);
  return cell;
}

function renderIncidents(incidents) {
  const target = $('#incidents-list');
  target.replaceChildren();
  $('#incidents-count').textContent = `${incidents.length} shown`;

  if (!incidents.length) {
    $('#incidents-state').hidden = false;
    $('#incidents-state').textContent = 'No incidents have been recorded yet.';
    return;
  }
  $('#incidents-state').hidden = true;

  for (const incident of incidents) {
    const row = document.createElement('tr');
    const identity = document.createElement('td');
    const title = document.createElement('strong');
    title.className = 'incident-title';
    title.textContent = incident.title || '(untitled incident)';
    const id = document.createElement('span');
    id.className = 'incident-id';
    id.textContent = incident.id || '';
    identity.append(title, id);
    row.append(identity);
    addCell(row, incident.kind);

    const verdict = addCell(row, incident.verdict, 'verdict-cell');
    verdict.dataset.verdict = (incident.verdict || '').toLowerCase();
    addCell(row, incident.score);
    addCell(row, incident.feedback === 'tp' ? 'True positive' : incident.feedback === 'fp' ? 'False positive' : 'Unreviewed');
    addCell(row, formattedDate(incident.created_at));
    target.append(row);
  }
}

function renderAlerts(alerts) {
  const target = $('#alerts-list');
  target.replaceChildren();
  $('#alerts-count').textContent = `${alerts.length} shown`;

  if (!alerts.length) {
    $('#alerts-state').hidden = false;
    $('#alerts-state').textContent = 'No alerts to review. New high-risk findings will appear here.';
    return;
  }
  $('#alerts-state').hidden = true;

  for (const alert of alerts) {
    const item = document.createElement('article');
    item.className = 'alert-item';

    const info = document.createElement('div');
    info.className = 'alert-info';
    const title = document.createElement('strong');
    title.className = 'alert-title';
    title.textContent = alert.title || '(untitled alert)';
    const details = document.createElement('span');
    details.className = 'alert-details';
    details.textContent = `${alert.severity || 'unknown'} severity · ${formattedDate(alert.created_at)} · Incident ${alert.incident_id || '—'}`;
    info.append(title, details);

    const actions = document.createElement('div');
    actions.className = 'alert-actions';
    const status = document.createElement('span');
    status.className = `alert-status status-${alert.status || 'unknown'}`;
    status.textContent = alert.status || 'unknown';
    actions.append(status);

    const step = STATUS_STEPS[alert.status];
    if (step?.next) {
      const button = document.createElement('button');
      button.className = 'small-button';
      button.type = 'button';
      button.dataset.alertId = String(alert.id);
      button.dataset.nextStatus = step.next;
      button.textContent = step.label;
      actions.append(button);
    }

    item.append(info, actions);
    target.append(item);
  }
}

async function refreshDashboard() {
  const refreshButton = $('#refresh-btn');
  refreshButton.disabled = true;
  refreshButton.textContent = 'Refreshing…';
  setStatus('Refreshing', 'loading');
  $('#alerts-state').hidden = false;
  $('#alerts-state').textContent = 'Loading alerts…';
  $('#incidents-state').hidden = false;
  $('#incidents-state').textContent = 'Loading incidents…';

  try {
    const [stats, alerts, incidents] = await Promise.all([
      requestJson('/api/stats'),
      requestJson('/api/alerts?limit=20'),
      requestJson('/api/incidents?limit=20')
    ]);

    $('#total-incidents').textContent = String(stats.total_incidents ?? 0);
    $('#open-alerts').textContent = String(stats.open_alerts ?? 0);
    $('#avg-score').textContent = String(stats.avg_score ?? 0);
    $('#accuracy').textContent = stats.feedback?.accuracy == null ? '—' : `${stats.feedback.accuracy}%`;
    renderSummary($('#verdict-summary'), stats.by_verdict, 'No email analyses recorded yet.');
    renderSummary($('#alert-summary'), stats.alert_counts, 'No alerts have been generated.');
    renderAlerts(alerts);
    renderIncidents(incidents);

    const updated = new Date();
    $('#refresh-note').textContent = `Last updated ${updated.toLocaleTimeString()}`;
    setStatus('Operational');
  } catch (error) {
    setStatus('Data unavailable', 'error');
    $('#alerts-state').hidden = false;
    $('#alerts-state').textContent = `Could not load dashboard data: ${error.message}`;
    $('#incidents-state').hidden = false;
    $('#incidents-state').textContent = 'Incident data may be incomplete. Refresh to try again.';
    console.error('Admin dashboard refresh failed:', error);
  } finally {
    refreshButton.disabled = false;
    refreshButton.textContent = 'Refresh data';
  }
}

$('#alerts-list').addEventListener('click', async (event) => {
  const button = event.target.closest('button[data-alert-id]');
  if (!button) return;

  button.disabled = true;
  const previousLabel = button.textContent;
  button.textContent = 'Saving…';
  try {
    await requestJson(`/api/alerts/${encodeURIComponent(button.dataset.alertId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: button.dataset.nextStatus })
    });
    await refreshDashboard();
  } catch (error) {
    button.disabled = false;
    button.textContent = previousLabel;
    setStatus('Action failed', 'error');
    console.error('Could not update alert:', error);
    window.alert(`Could not update alert: ${error.message}`);
  }
});

$('#refresh-btn').addEventListener('click', refreshDashboard);
$('#logout-btn').addEventListener('click', async () => {
  const button = $('#logout-btn');
  button.disabled = true;
  try {
    await requestJson('/api/admin/logout', { method: 'POST' });
  } finally {
    window.location.assign('/admin/login');
  }
});

refreshDashboard();
