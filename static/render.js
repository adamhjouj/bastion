import { actionStatus, componentStatus, verdictLabel } from './state.js';

export const $ = id => document.getElementById(id);
export function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text != null) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
const badge = (text, tone = '') => node('span', text, `badge ${tone}`);

export function reconcile(id, items, render, empty = 'No records yet') {
  const container = $(id), scroll = container.scrollTop;
  const existing = new Map([...container.children].map(child => [child.dataset.key, child]));
  const fragment = document.createDocumentFragment();
  for (const item of items) {
    const key = String(item.id), version = JSON.stringify(item);
    let element = existing.get(key);
    if (!element || element.dataset.version !== version) element = render(item);
    element.dataset.key = key; element.dataset.version = version; fragment.append(element);
  }
  if (!items.length) fragment.append(node('p', empty, 'empty'));
  container.replaceChildren(fragment); container.scrollTop = scroll;
}

export function renderOverview(data, openIncident) {
  const text = (id, value) => { $(id).textContent = String(value); };
  text('mode', data.mode || 'Unknown mode');
  text('s-req', data.events_total); text('s-blk', data.blocked_total); text('s-inc', data.incidents_total);
  text('s-ban', data.denylist.length); text('s-divert', data.honeypot.length);
  text('s-response', data.latest_containment ? `${data.latest_containment.seconds}s` : '—');
  text('p-evaluated', `${data.funnel.evaluated} evaluated`);
  text('p-flagged', `${data.funnel.flagged} Jev flags`);
  text('p-escalated', `${data.funnel.escalated} escalated`);
  text('p-tools', `${data.funnel.succeeded}/${data.funnel.actions} successful tool calls`);
  text('queue-count', `${(data.queue.pending || 0) + (data.queue.processing || 0)} queued / active · ${data.queue.dead || 0} failed`);
  const health = document.createDocumentFragment();
  for (const [key, label] of [['proxy', 'Proxy'], ['blue', 'Investigator worker'], ['classifier', 'Jev'], ['agent', 'LLM'], ['actuator', 'Actuator'], ['mail-worker', 'Mail worker']]) {
    const status = componentStatus(data.health[key]), row = node('div', null, 'health-item');
    row.append(node('strong', label), node('span', status.label, status.tone)); health.append(row);
  }
  $('health').replaceChildren(health);
  text('feed-count', `${data.events.length} shown`);
  reconcile('feed', data.events, event => {
    const row = node('div', null, `row request ${event.blocked ? 'stopped' : event.matched === 'diverted' ? 'diverted' : ''}`);
    row.title = `Request #${event.id} · ${event.ts || ''} · ${event.processing_status || ''}`;
    row.append(badge(event.status ?? 'pending', event.blocked ? 'good' : ''), node('span', event.ip, 'muted'),
      node('span', `${event.method} ${event.path}${event.query ? '?' + event.query : ''}`, 'payload'),
      node('span', event.status == null ? 'in flight' : event.matched || (event.blocked ? 'stopped' : 'forwarded'), 'muted'));
    return row;
  }, 'No request traffic yet');
  text('incident-count', `${data.incidents.length} shown`);
  reconcile('incidents', data.incidents, incident => {
    const row = node('div', null, 'row'), body = node('div', null, 'grow');
    body.append(node('strong', incident.attack_type || 'Incident'), node('div', incident.summary, 'event-description'),
      node('div', `${incident.source_ip || ''} · ${incident.ts || ''}`, 'muted small'));
    const button = node('button', 'Details'); button.type = 'button'; button.onclick = () => openIncident(incident.id);
    const tone = ['high', 'critical'].includes(incident.severity) ? 'bad' : 'warn';
    row.append(badge(incident.severity || 'unknown', tone), body, button); return row;
  }, 'No incidents recorded');
  const defenses = [
    ...data.denylist.map((item, index) => ({ ...item, id: `ban-${index}`, type: 'BAN', detail: item.expires ? `Expires ${item.expires}` : 'Permanent' })),
    ...data.honeypot.map((item, index) => ({ ...item, id: `divert-${index}`, type: 'DIVERT', detail: 'Routed to decoy' })),
    ...(data.enforced_security ? [{ id: 'security', type: 'APP', ip: data.enforced_security, detail: 'Enforced security level' }] : [])
  ];
  reconcile('defenses', defenses, item => {
    const row = node('div', null, 'row'), body = node('div', null, 'grow');
    body.append(node('code', item.ip), node('div', item.reason || item.detail, 'event-description'),
      node('div', item.detail, 'muted small'));
    row.append(badge(item.type), body); return row;
  }, 'No active defenses');
  text('action-count', `${data.actions.length} shown`);
  reconcile('actions', data.actions, action => {
    const status = actionStatus(action), row = node('div', null, 'row'), body = node('div', null, 'grow');
    body.append(node('strong', action.tool || (action.kind === 'triage' ? verdictLabel(action) : 'Processing error')),
      node('div', action.kind === 'triage' ? action.outcome : action.result || action.error || '', 'event-description'),
      node('div', `Case ${action.case_id || 'unlinked'} · ${action.ts || ''}`, 'muted small'));
    row.append(badge(status.label, status.tone), body); return row;
  }, 'No investigator activity yet');
  text('mail-count', `${data.mail.pending || 0} pending · ${data.mail.accepted || 0} accepted · ${data.mail.dead || 0} failed`);
  reconcile('notifications', data.notifications, renderNotification, 'No notifications queued');
  reconcile('outcomes', data.recent_outcomes, pair => {
    const row = node('div', null, 'row'), body = node('div', null, 'grow');
    body.append(node('code', `${pair.method} ${pair.path}`),
      node('div', `#${pair.before_id}: ${pair.before_status} forwarded · #${pair.after_id}: ${pair.after_status} stopped (${pair.reason})`, 'event-description'));
    row.append(body); return row;
  }, 'No repeated request outcome pairs in the recent feed');
}

export function renderNotification(item) {
  const row = node('div', null, 'row'), body = node('div', null, 'grow');
  body.append(node('span', `Case ${item.case_id || 'unlinked'} · ${item.attempts} attempt(s)`),
    node('div', item.error || item.provider_id || 'Waiting for the mail worker', 'event-description'));
  row.append(badge(item.status, item.status === 'accepted' ? 'good' : item.status === 'dead' ? 'bad' : 'warn'), body);
  return row;
}

export function renderDetail(data) {
  const sections = [
    ['Incident', data.incident], ['Contributing requests', data.requests],
    ['Investigation and actions', data.actions], ['Email status', data.notifications]
  ];
  const fragment = document.createDocumentFragment();
  for (const [title, content] of sections) {
    const section = node('section', null, 'detail-section');
    section.append(node('h3', title), node('pre', JSON.stringify(content, null, 2))); fragment.append(section);
  }
  $('detail-body').replaceChildren(fragment);
}

export function renderLogs(entries, follow) {
  const container = $('log-lines');
  const existing = new Map([...container.children].map(child => [child.dataset.key, child]));
  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    let line = existing.get(String(entry.id));
    if (!line || line.dataset.version !== JSON.stringify(entry)) {
      line = node('div', null, `log-line ${entry.stream === 'stderr' ? 'stderr' : ''}`); line.dataset.key = String(entry.id);
      line.dataset.version = JSON.stringify(entry);
      line.append(node('time', entry.ts), node('span', entry.stream, 'stream'),
        node('span', entry.text + (entry.truncated ? ' …[truncated]' : '')));
    }
    fragment.append(line);
  }
  if (!entries.length) fragment.append(node('p', 'No captured output for this source yet', 'empty'));
  const scroll = container.scrollTop;
  container.replaceChildren(fragment); container.scrollTop = follow ? container.scrollHeight : scroll;
}
