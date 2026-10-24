const ROOT = '/__api/v1';

export class ApiError extends Error {
  constructor(status) { super(`Request failed (${status})`); this.status = status; }
}

export async function getJSON(path, signal) {
  const response = await fetch(ROOT + path, { credentials: 'same-origin', cache: 'no-store', signal });
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
}

export async function postJSON(path, body) {
  const response = await fetch(ROOT + path, { method: 'POST', credentials: 'same-origin',
    cache: 'no-store', headers: { 'Content-Type': 'application/json' },
    body: body != null ? JSON.stringify(body) : undefined });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({}));
    throw Object.assign(new ApiError(response.status), { detail });
  }
  return response.json();
}

export function subscribe({ stream, event, poll, onData, onState }) {
  let active = true, source = null, retryTimer = null, pollTimer = null;
  let attempts = 0, revision = 0, streaming = false;
  const controller = new AbortController();
  const stop = () => {
    active = false; source?.close(); controller.abort();
    clearTimeout(retryTimer); clearTimeout(pollTimer);
  };
  async function refresh() {
    const started = revision;
    try {
      const value = await getJSON(typeof poll === 'function' ? poll() : poll, controller.signal);
      if (active && started === revision) { onData(value); onState('polling'); }
    } catch (error) {
      if (!active) return;
      if (error.status === 401 || error.status === 403) { onState('unauthorized'); stop(); }
      else onState('disconnected');
    }
  }
  function polling() {
    clearTimeout(pollTimer);
    if (!active || streaming) return;
    refresh().finally(() => { if (active && !streaming) pollTimer = setTimeout(polling, 5000); });
  }
  function connect() {
    if (!active) return;
    if (!globalThis.EventSource) { polling(); return; }
    try { source = new EventSource(ROOT + (typeof stream === 'function' ? stream() : stream)); }
    catch { polling(); retryTimer = setTimeout(connect, 5000); return; }
    const connection = source;
    connection.addEventListener(event, message => {
      if (!active || source !== connection) return;
      try {
        onData(JSON.parse(message.data)); revision++; attempts = 0; streaming = true;
        clearTimeout(pollTimer); onState('live');
      } catch { onState('invalid data'); }
    });
    connection.onerror = () => {
      if (!active || source !== connection) return;
      connection.close(); source = null; streaming = false; onState('reconnecting'); polling();
      retryTimer = setTimeout(connect, Math.min(30000, 1000 * 2 ** attempts++));
    };
  }
  refresh().finally(connect);
  return stop;
}
