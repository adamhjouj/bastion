export function mergeById(existing, incoming, cap = 600) {
  const rows = new Map(existing.map(item => [item.id, item]));
  for (const item of incoming) rows.set(item.id, item);
  return [...rows.values()].sort((a, b) => a.id - b.id).slice(-cap);
}

export function validateOverview(value) {
  if (value?.schema_version !== 1 || !Array.isArray(value.events) || !Array.isArray(value.actions)
      || !Array.isArray(value.incidents) || !value.funnel || !value.health) throw new Error('Unsupported dashboard response');
  return value;
}

export function verdictLabel(record) {
  const verdict = record.jev;
  if (!verdict) return 'No Jev verdict';
  if (verdict.error || verdict.malicious == null) return 'Classifier unavailable';
  return verdict.malicious ? `Flagged: ${verdict.attack_type || 'unknown'}` : 'Classified benign';
}

export function actionStatus(record) {
  if (record.kind === 'error') return { label: record.status || 'error', tone: 'bad' };
  if (record.kind === 'triage') return { label: record.outcome || 'evaluated', tone: record.escalated ? 'warn' : 'muted' };
  if (record.outcome === 'ok') return { label: 'succeeded', tone: 'good' };
  return { label: record.outcome || 'unknown', tone: 'bad' };
}

export function componentStatus(component) {
  if (!component) return { label: 'Not reported', tone: 'muted' };
  if (component.stale) return { label: 'Stale heartbeat', tone: 'warn' };
  if (component.ready === false || component.available === false) return { label: component.error || 'Unavailable', tone: 'bad' };
  if (component.ready === true) return { label: 'Running', tone: 'good' };
  return { label: 'Last check successful', tone: 'good' };
}
