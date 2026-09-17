const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHash } = require('node:crypto');

const plain = (value) => JSON.parse(JSON.stringify(value));
const scope = (key) => createHash('sha256').update(`cli-proxy-api:caller-scope:v1\0${key}`).digest('hex');
const scopeA = scope('test-key-A');
const scopeB = scope('test-key-B');
const group = (id, allow = [], deny = []) => ({ id, name: id, allow_profiles: allow, deny_profiles: deny });
const policy = (groups = [group('team', ['A'])], policies = [{caller_scope: scopeA, group_ids: ['team']}]) => ({version: 3, access_control_enabled: true, default_deny: true, groups, policies});

function harness(initial = policy()) {
  const elements = new Map();
  const element = () => ({innerHTML: '', textContent: '', hidden: false, dataset: {}, children: [], listeners: {},
    classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, handler) { this.listeners[name] = handler; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    appendChild(child) { this.children.push(child); }, remove() {}});
  const document = {
    querySelector(selector) { if (!elements.has(selector)) elements.set(selector, element()); return elements.get(selector); },
    addEventListener() {}, createElement: element,
  };
  let stored = plain(initial);
  let revision = 1;
  let profiles = ['A', 'B', 'C'];
  let timeoutAfterSave = false;
  let codexAPIProfiles = [];
  const requests = [];
  const subjectNames = ['state', 'installRemoteData', 'serializablePolicy', 'keyAllowsProfile', 'policiesEquivalent', 'normalizePolicyDocument', 'renderKeyEditor', 'renderGroupEditor', 'createGroup', 'deleteGroup', 'setKeyMembership', 'updateProfiles', 'selectAllProfiles', 'toggleProfileRule', 'refreshData', 'reload', 'save', 'refreshProfileCatalog', 'connectFromCPAMC', 'finalizeEndedSession'];
  let source = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8');
  assert.match(source, /  initializeChrome\(\);\s+connectFromCPAMC\(\);/);
  source = source.replace(/  initializeChrome\(\);\s+connectFromCPAMC\(\);/, `  globalThis.subject = {${subjectNames.join(',')}};`);
  const context = vm.createContext({document, console, Uint8Array, TextEncoder, TextDecoder, DataView, AbortController,
    requestAnimationFrame() {},
    window: {crypto: webcrypto, addEventListener() {}, setTimeout() { return 1; }, clearTimeout() {}, confirm() {return true;}, prompt() {return 'new group';}},
    localStorage: {getItem(name) {return name === 'isLoggedIn' ? 'true' : name === 'cli-proxy-auth' ? JSON.stringify({state:{managementKey:'test-session'}}) : null;}, setItem() {throw Error('must not persist authorization in browser storage');}},
    async fetch(url, options) {
      requests.push({url, method: options.method, body: options.body});
      let data;
      if (url.endsWith('/status')) data = {persistent_updates: true, policy_file: 'test.toml', revision, schema_version: 2};
      else if (url.endsWith('/policies')) {
        if (options.method === 'PUT') {
          if (options.headers['If-Match'] !== `"rev-${revision}"`) return {ok:false,status:412,async json() {return {error:'policy changed'};}};
          stored = JSON.parse(options.body); revision++;
          if (timeoutAfterSave) { const error = Error('timeout'); error.name = 'AbortError'; throw error; }
        }
        data = {policy: plain(stored), revision, persistent: true};
      } else if (url.endsWith('/api-keys')) data = {'api-keys': ['test-key-A', 'test-key-B']};
      else if (url.endsWith('/auth-files')) data = {files: profiles.map(id => ({id, provider: 'codex', label: id}))};
      else if (url.endsWith('/codex-api-key')) data = {'codex-api-key': codexAPIProfiles};
      else data = {};
      return {ok: true, async json() {return data;}};
    },
  });
  vm.runInContext(source, context, {filename: 'settings.js'});
  const api = context.subject;
  const remote = () => ({status: {persistent_updates: true, schema_version: 2}, policies: {policy: plain(stored), revision}, keys: [scopeA, scopeB].map(s => ({scope: s, masked: 'test••••', fingerprint: s.slice(0, 8), group_ids: []})), catalog: {profiles: profiles.map(id => ({id, displayName: id, provider: 'codex'}))}});
  api.installRemoteData(remote(), scopeA);
  return {api, elements, requests, remote, stored: () => plain(stored), setCatalog(ids) {profiles = ids;}, timeoutAfterSave() {timeoutAfterSave = true;}, remoteEdit(doc) {stored = plain(doc); revision++;}, setCodexProfiles(entries) {codexAPIProfiles = entries;}};
}

test('single-account whitelist survives reload, catalog refresh and save', async () => {
  const h = harness();
  const before = plain(h.api.serializablePolicy());
  await h.api.refreshData();
  assert.deepEqual(plain(h.api.serializablePolicy()), before);
  assert.equal(h.api.state.dirty, false);
  await h.api.refreshProfileCatalog();
  assert.deepEqual(plain(h.api.serializablePolicy()), before);
  h.api.state.dirty = true;
  await h.api.save();
  await h.api.reload();
  assert.deepEqual(h.stored(), before);
  assert.deepEqual(plain(h.api.serializablePolicy()), before);
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[0], 'B'), false);
});

test('missing, returning, empty and new catalog entries never rewrite rules', async () => {
  const h = harness(policy([group('team', ['A'], ['B'])]));
  const before = plain(h.api.serializablePolicy());
  for (const ids of [['C'], [], ['A', 'B', 'C', 'NEW']]) {
    h.setCatalog(ids);
    await h.api.refreshProfileCatalog();
    assert.deepEqual(plain(h.api.serializablePolicy()), before);
    assert.equal(h.api.state.dirty, false);
  }
  h.api.state.selectedGroup = 'team';
  h.api.state.profiles = [{id: 'C'}];
  h.api.renderGroupEditor(h.api.state.groups[0]);
  assert.match(h.elements.get('#editor').innerHTML, /目录外/);
});

test('multi-group union, cross-group deny and empty allow groups', () => {
  const h = harness(policy([group('team', ['A', 'B']), group('second', ['C'], ['B']), group('empty')], [{caller_scope: scopeA, group_ids: ['team', 'second']}])).api;
  const key = h.state.keys[0];
  assert.equal(h.keyAllowsProfile(key, 'A'), true);
  assert.equal(h.keyAllowsProfile(key, 'C'), true);
  assert.equal(h.keyAllowsProfile(key, 'B'), false);
  assert.equal(h.keyAllowsProfile(key, 'NEW'), false);
  key.group_ids = ['empty'];
  assert.equal(h.keyAllowsProfile(key, 'A'), false);
});

test('default deny controls new keys; global bypass preserves configuration', async () => {
  const h = harness();
  const newKey = h.api.state.keys[1];
  assert.equal(h.api.keyAllowsProfile(newKey, 'A'), false);
  h.api.state.defaultDeny = false;
  assert.equal(h.api.keyAllowsProfile(newKey, 'A'), true);
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[0], 'B'), false);
  h.api.state.accessControlEnabled = false;
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[0], 'B'), true);
  h.api.state.dirty = true;
  await h.api.save();
  await h.api.refreshData();
  assert.equal(h.api.state.accessControlEnabled, false);
  assert.equal(h.api.state.defaultDeny, false);
  assert.deepEqual(plain(h.api.state.groups[0].allow_profiles), ['A']);
});

test('stale memberships, empty memberships and unassigned groups survive saving', () => {
  const doc = policy([group('team', ['A']), group('unused')], [{caller_scope: scopeA, group_ids: []}, {caller_scope: scope('deleted-key'), group_ids: ['unused']}]);
  const h = harness(doc).api;
  assert.deepEqual(plain(h.serializablePolicy()), doc);
});

test('key editor has multi-group membership only; upstream edits require group selection', () => {
  const h = harness();
  h.api.renderKeyEditor(h.api.state.keys[0], 0);
  const html = h.elements.get('#editor').innerHTML;
  assert.match(html, /data-key-group/);
  assert.doesNotMatch(html, /data-action="toggle-profile"/);
  h.api.updateProfiles('allow_profiles', () => ['C']);
  assert.deepEqual(plain(h.api.state.groups[0].allow_profiles), ['A']);
  h.api.state.selectedGroup = 'team';
  h.api.toggleProfileRule('allow_profiles', 'C');
  assert.deepEqual(plain(h.api.state.groups[0].allow_profiles), ['A', 'C']);
  assert.equal(h.api.state.dirty, true);
});

test('create/delete groups and change memberships without direct key rules', () => {
  const h = harness();
  h.api.createGroup();
  const groupID = h.api.state.selectedGroup;
  h.api.setKeyMembership(h.api.state.keys[0], groupID, true);
  h.api.setKeyMembership(h.api.state.keys[1], groupID, true);
  assert.equal(h.api.state.keys[0].group_ids.length, 2);
  h.api.deleteGroup();
  assert.deepEqual(plain(h.api.state.keys[0].group_ids), ['team']);
  assert.deepEqual(plain(h.api.state.keys[1].group_ids), []);
  for (const p of h.api.serializablePolicy().policies) {
    assert.deepEqual(Object.keys(p).sort(), ['caller_scope', 'group_ids']);
  }
});

test('normalization rejects direct per-key grants and unknown groups', () => {
  const h = harness().api;
  for (const mutation of [doc => {doc.policies[0].allow_profiles = [];}, doc => {doc.policies[0].group_ids = ['missing'];}, doc => {doc.groups.push(group('team'));}]) {
    const doc = policy(); mutation(doc);
    assert.throws(() => h.normalizePolicyDocument(doc));
  }
});

test('save timeout confirmation compares switches, groups and memberships', async () => {
  const h = harness();
  const a = policy();
  const b = plain(a); b.default_deny = false;
  assert.equal(h.api.policiesEquivalent(a, b), false);
  b.default_deny = true; b.groups[0].allow_profiles.push('B');
  assert.equal(h.api.policiesEquivalent(a, b), false);
  h.api.state.defaultDeny = false;
  h.api.state.dirty = true;
  h.timeoutAfterSave();
  await h.api.save();
  assert.equal(h.api.state.dirty, false);
  assert.equal(h.stored().default_deny, false);
});

test('restored session draft keeps its original revision and cannot overwrite revocations', async () => {
  const h = harness();
  h.api.state.defaultDeny = false;
  h.api.state.dirty = true;
  h.api.state.sessionEnded = true;
  h.api.finalizeEndedSession();
  assert.equal(h.api.state.pendingRevision, 1);
  const revoked = policy([group('team')]);
  h.remoteEdit(revoked);
  await h.api.connectFromCPAMC();
  assert.equal(h.api.state.revision, 1);
  assert.equal(h.api.state.dirty, true);
  assert.equal(h.api.state.defaultDeny, false);
  await h.api.save();
  assert.equal(h.api.state.dirty, true);
  assert.deepEqual(h.stored(), revoked);
});

test('legacy profile identity preview matches backend without rewriting saved grants', async () => {
  const kind = 'codex:apikey';
  const legacy = kind + ':' + createHash('sha256').update([kind, 'sample-key', 'https://example.invalid'].join('\0')).digest('hex').slice(0,12);
  const h = harness(policy([group('team', [legacy])]));
  h.setCodexProfiles([{'api-key':'sample-key', 'base-url':'https://example.invalid', prefix:'new-id-input'}]);
  await h.api.refreshProfileCatalog();
  const current = h.api.state.profiles.find(p => p.legacyID === legacy);
  assert.ok(current);
  assert.notEqual(current.id, legacy);
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[0], current.id), true);
  assert.deepEqual(plain(h.api.state.groups[0].allow_profiles), [legacy]);
  h.api.state.selectedGroup = 'team';
  h.api.renderGroupEditor(h.api.state.groups[0]);
  assert.doesNotMatch(h.elements.get('#editor').innerHTML, /<small>目录外<\/small>/);
  assert.doesNotMatch(h.elements.get('#editor').innerHTML, /sample-key|https:\/\/example\.invalid/);
  h.api.state.groups[0].allow_profiles = ['*'];
  h.api.state.groups[0].deny_profiles = [legacy];
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[0], current.id), false);
});
