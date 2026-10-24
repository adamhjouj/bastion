import { getJSON, subscribe } from './api.js';
import { mergeById, validateOverview } from './state.js';
import { $, node, renderOverview, renderDetail, renderLogs } from './render.js';

let overview = null, activeIncident = null, detailVersion = 0, detailUpdated = 0;
let logEntries = [], logCursor = 0, stopLogs = null, paused = false, logStatus = null, logTransport = 'connecting';

function notice(message) {
  $('notice').textContent = message || ''; $('notice').hidden = !message;
}

function overviewConnection(status) {
  $('connection').textContent = status === 'live' ? 'Live connection' : status;
  $('connection').className = `badge ${status === 'live' ? 'good' : 'warn'}`;
  if (status === 'unauthorized') notice('Authentication expired or was rejected. Reload to sign in again.');
  else if (['disconnected', 'reconnecting', 'invalid data'].includes(status)) notice('Connection interrupted. Displayed data may be stale; reconnecting automatically.');
  else notice(overview?.mode === 'observe' ? 'Observe mode: traffic is recorded, but automatic investigation is disabled.' : '');
}

async function openIncident(id, refresh = false) {
  activeIncident = id;
  const version = ++detailVersion;
  if (!refresh) {
    $('detail-title').textContent = `Incident #${id}`;
    $('detail-body').replaceChildren(node('p', 'Loading incident…', 'empty'));
    if (!$('incident-detail').open) $('incident-detail').showModal();
  }
  try {
    const value = await getJSON(`/incidents/${id}`);
    if (version === detailVersion && activeIncident === id) { renderDetail(value); detailUpdated = Date.now(); }
  } catch (error) {
    if (version === detailVersion) $('detail-body').replaceChildren(node('p', error.status === 404 ? 'Incident not found or removed by retention.' : 'Unable to load incident details.', 'empty'));
  }
}
$('close-detail').onclick = () => $('incident-detail').close();
$('incident-detail').addEventListener('close', () => { activeIncident = null; detailVersion++; });

const stopOverview = subscribe({
  stream: '/stream', event: 'snapshot', poll: '/overview', onState: overviewConnection,
  onData(value) {
    overview = validateOverview(value); renderOverview(overview, openIncident);
    if (activeIncident != null && Date.now() - detailUpdated > 5000) {
      detailUpdated = Date.now(); openIncident(activeIncident, true);
    }
  }
});

function logState() {
  $('log-state').textContent = `${logStatus?.status || 'waiting'} · ${paused ? 'display paused' : logTransport}`;
  const message = logStatus?.message || 'Waiting for the log collector';
  $('log-message').textContent = `${message}${logStatus?.updated ? ' · updated ' + logStatus.updated : ''}`;
}

function selectSource() {
  stopLogs?.(); logEntries = []; logCursor = 0; logStatus = null; logTransport = 'connecting';
  renderLogs([], false); logState();
  const source = $('log-source').value;
  stopLogs = subscribe({
    stream: () => `/logs/${encodeURIComponent(source)}/stream?after=${logCursor}`,
    event: 'logs', poll: () => `/logs/${encodeURIComponent(source)}?after=${logCursor}`,
    onState(status) { logTransport = status; logState(); },
    onData(value) {
      if (value.source !== source || !Array.isArray(value.entries)) throw new Error('Invalid log response');
      logEntries = mergeById(value.reset ? [] : logEntries, value.entries);
      logCursor = value.next_cursor; logStatus = value.status; logState();
      if (value.reset) $('log-message').textContent += ' · History was rotated/reset; showing available lines.';
      if (!paused) renderLogs(logEntries, $('follow-logs').checked);
    }
  });
}
$('log-source').onchange = selectSource;
$('pause-logs').onclick = () => {
  paused = !paused; $('pause-logs').textContent = paused ? 'Resume display' : 'Pause display';
  $('pause-logs').setAttribute('aria-pressed', String(paused));
  if (!paused) renderLogs(logEntries, $('follow-logs').checked);
  logState();
};
$('follow-logs').onchange = () => { if (!paused) renderLogs(logEntries, $('follow-logs').checked); };
selectSource();

const clock = setInterval(() => { $('clock').textContent = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'; }, 1000);
window.addEventListener('pagehide', () => { stopOverview(); stopLogs?.(); clearInterval(clock); }, { once: true });
