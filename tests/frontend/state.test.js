import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeById, validateOverview, actionStatus, componentStatus, verdictLabel } from '../../static/state.js';
import { getJSON, subscribe, ApiError } from '../../static/api.js';

const tick = () => new Promise(resolve => setImmediate(resolve));

test('stable database identities preserve identical messages and update existing records', () => {
  assert.deepEqual(mergeById([{ id: 1, text: 'old' }], [{ id: 1, text: 'updated' }, { id: 2, text: 'updated' }]),
    [{ id: 1, text: 'updated' }, { id: 2, text: 'updated' }]);
});
test('log display memory is bounded', () => {
  assert.equal(mergeById([], Array.from({ length: 1000 }, (_, id) => ({ id }))).length, 600);
});
test('classifier errors are not displayed as benign', () => {
  assert.equal(verdictLabel({ jev: { malicious: null, error: 'timeout' } }), 'Classifier unavailable');
});
test('failed and unknown actions are never labeled successful', () => {
  assert.equal(actionStatus({ kind: 'action', outcome: 'error' }).label, 'error');
  assert.equal(actionStatus({ kind: 'action' }).label, 'unknown');
});
test('stale worker heartbeat is distinct from a successful connection', () => {
  assert.equal(componentStatus({ ready: true, stale: true }).label, 'Stale heartbeat');
  assert.equal(componentStatus(null).label, 'Not reported');
});
test('unexpected API contracts are rejected', () => {
  assert.throws(() => validateOverview({ schema_version: 2 }));
});
test('HTTP authentication failures are not parsed as dashboard data', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  await assert.rejects(getJSON('/overview'), e => e instanceof ApiError && e.status === 401);
});
test('unauthorized initial fetch stops subscriptions without exposing credentials', async t => {
  const states = [];
  t.mock.method(globalThis, 'fetch', async () => new Response('{}', { status: 401 }));
  const stop = subscribe({ stream: '/stream', event: 'snapshot', poll: '/overview',
    onData: () => assert.fail('unauthorized response must not render'), onState: value => states.push(value) });
  await tick(); stop();
  assert.deepEqual(states, ['unauthorized']);
});
test('stopping a channel closes its source and suppresses late data', async t => {
  const sources = [], values = [];
  class Source {
    constructor(url) { this.url = url; sources.push(this); }
    addEventListener(_, fn) { this.receive = fn; }
    close() { this.closed = true; }
  }
  const previous = globalThis.EventSource;
  globalThis.EventSource = Source; t.after(() => { globalThis.EventSource = previous; });
  t.mock.method(globalThis, 'fetch', async () => new Response('{"id":1}'));
  const stop = subscribe({ stream: '/stream', event: 'snapshot', poll: '/overview', onData: value => values.push(value), onState() {} });
  await tick(); stop();
  sources[0].receive({ data: '{"id":2}' });
  assert.equal(values.length, 1); assert.equal(sources[0].closed, true);
});
