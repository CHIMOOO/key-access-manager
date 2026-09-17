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
  const downloads = [];
  const blobs = new Map();
  const elements = new Map();
  const element = () => ({innerHTML: '', textContent: '', hidden: false, dataset: {}, children: [], listeners: {},
    classList: {add() {}, remove() {}, toggle() {}},
    addEventListener(name, handler) { this.listeners[name] = handler; },
    querySelector() { return null; }, querySelectorAll() { return []; },
    appendChild(child) { this.children.push(child); }, remove() {}, click() { if (this.download) downloads.push({name:this.download, blob:blobs.get(this.href)}); }});
  const document = {
    querySelector(selector) { if (!elements.has(selector)) elements.set(selector, element()); return elements.get(selector); },
    addEventListener() {}, createElement: element, body: element(),
  };
  let stored = plain(initial);
  let revision = 1;
  let profiles = ['A', 'B', 'C'];
  let timeoutAfterSave = false;
  let codexAPIProfiles = [];
  const requests = [];
  const subjectNames = ['state', 'installRemoteData', 'serializablePolicy', 'keyAllowsProfile', 'policiesEquivalent', 'normalizePolicyDocument', 'renderKeyEditor', 'renderGroupEditor', 'createGroup', 'deleteGroup', 'setKeyMembership', 'updateProfiles', 'selectAllProfiles', 'clearFilteredProfiles', 'profileCategory', 'profileMatchesPicker', 'toggleProfileRule', 'refreshData', 'reload', 'save', 'refreshProfileCatalog', 'connectFromCPAMC', 'finalizeEndedSession'];
  subjectNames.push('filteredMembers', 'updateFilteredMembers', 'keyGroupTags', 'renderNav', 'memberOptions');
  subjectNames.push('exportPolicyText', 'importPolicyText', 'importConfig', 'downloadConfig');
  let source = fs.readFileSync(path.join(__dirname, 'settings.js'), 'utf8');
  assert.match(source, /  initializeChrome\(\);\s+connectFromCPAMC\(\);/);
  source = source.replace(/  initializeChrome\(\);\s+connectFromCPAMC\(\);/, `  globalThis.subject = {${subjectNames.join(',')}};`);
  const context = vm.createContext({document, console, Uint8Array, TextEncoder, TextDecoder, DataView, AbortController, Blob,
    URL: {createObjectURL(blob) {const url = `blob:test-${blobs.size}`; blobs.set(url, blob); return url;}, revokeObjectURL(url) {blobs.delete(url);}},
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
  return {api, elements, requests, downloads, remote, stored: () => plain(stored), setCatalog(ids) {profiles = ids;}, timeoutAfterSave() {timeoutAfterSave = true;}, remoteEdit(doc) {stored = plain(doc); revision++;}, setCodexProfiles(entries) {codexAPIProfiles = entries;}};
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

test('fresh policy has enabled access control and opt-in default deny through save and reload', async () => {
  const initial = policy([], []);
  initial.default_deny = false;
  const h = harness(initial);
  assert.equal(h.api.state.accessControlEnabled, true);
  assert.equal(h.api.state.defaultDeny, false);
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[1], 'A'), true);
  h.api.state.defaultDeny = true;
  h.api.state.dirty = true;
  await h.api.save();
  await h.api.reload();
  assert.equal(h.api.state.accessControlEnabled, true);
  assert.equal(h.api.state.defaultDeny, true);
  assert.equal(h.api.keyAllowsProfile(h.api.state.keys[1], 'A'), false);
  for (const enabled of [true, false]) {
    for (const defaultDeny of [true, false]) {
      const explicit = policy();
      explicit.access_control_enabled = enabled;
      explicit.default_deny = defaultDeny;
      const result = h.api.normalizePolicyDocument(explicit);
      assert.equal(result.access_control_enabled, enabled);
      assert.equal(result.default_deny, defaultDeny);
    }
  }
  for (const key of ['access_control_enabled', 'default_deny']) {
    const invalid = policy();
    delete invalid[key];
    assert.throws(() => h.api.normalizePolicyDocument(invalid));
  }
});

const pickerProfiles = () => [
  {id: 'codex-primary', legacyID: 'codex-old', provider: 'codex', kind: 'apikey', displayName: 'Primary Team'},
  {id: 'codex-backup', provider: 'CODEX', kind: 'apikey', displayName: 'Backup Team'},
  {id: 'xai-primary', provider: 'xai', kind: 'apikey', displayName: 'Grok Team'},
  {id: 'oauth-primary', provider: 'codex', kind: 'oauth', displayName: 'Login Team'},
  {id: 'other-primary', provider: 'gemini', kind: 'apikey', displayName: 'Gemini Team'},
];

test('picker combines provider categories with case-insensitive name, id, provider and kind search', () => {
  const api = harness().api;
  const profiles = pickerProfiles();
  assert.equal(api.state.pickerCategory, 'codex');
  assert.deepEqual(profiles.map(profile => api.profileCategory(profile)), ['codex', 'codex', 'xai', 'oauth', 'other']);
  const matching = () => profiles.filter(profile => api.profileMatchesPicker(profile)).map(profile => profile.id);
  assert.deepEqual(matching(), ['codex-primary', 'codex-backup']);
  api.state.pickerQuery = '  PRIMARY TEAM  ';
  assert.deepEqual(matching(), ['codex-primary']);
  api.state.pickerQuery = '';
  api.state.pickerCategory = 'xai';
  assert.deepEqual(matching(), ['xai-primary']);
  api.state.pickerCategory = 'oauth';
  api.state.pickerQuery = 'CODEX';
  assert.deepEqual(matching(), ['oauth-primary']);
  api.state.pickerCategory = 'other';
  api.state.pickerQuery = 'APIKEY';
  assert.deepEqual(matching(), ['other-primary']);
  api.state.pickerCategory = 'all';
  api.state.pickerQuery = 'XAI-PRIMARY';
  assert.deepEqual(matching(), ['xai-primary']);
  api.state.pickerQuery = 'no-match';
  assert.deepEqual(matching(), []);
});

test('changing picker category and search never alters saved rules or dirty state', () => {
  const h = harness(policy([group('team', ['codex-primary', 'oauth-primary'], ['xai-primary'])]));
  h.api.state.selectedGroup = 'team';
  h.api.state.openPicker = 'allow_profiles';
  h.api.state.profiles = pickerProfiles();
  const before = plain(h.api.serializablePolicy());
  for (const category of ['codex', 'xai', 'oauth', 'other', 'all']) {
    h.api.state.pickerCategory = category;
    h.api.state.pickerQuery = category === 'all' ? 'missing' : 'TEAM';
    h.api.state.profiles.filter(profile => h.api.profileMatchesPicker(profile));
    h.api.renderGroupEditor(h.api.state.groups[0]);
    assert.equal(h.api.state.dirty, false);
    assert.deepEqual(plain(h.api.serializablePolicy()), before);
  }
});

test('bulk picker actions affect only current matches and retain off-filter and wildcard rules', () => {
  for (const kind of ['allow_profiles', 'deny_profiles']) {
    const h = harness();
    const api = h.api;
    api.state.selectedGroup = 'team';
    api.state.profiles = pickerProfiles();
    api.state.pickerCategory = 'codex';
    api.state.pickerQuery = 'primary';
    const rules = api.state.groups[0];
    rules[kind] = ['oauth-primary', 'xai-primary', 'codex-backup', 'missing-account', '*', 'codex-*'];
    const untouched = plain(rules[kind]);
    api.selectAllProfiles(kind);
    assert.deepEqual(plain(rules[kind]), [...untouched, 'codex-primary']);
    api.selectAllProfiles(kind);
    assert.deepEqual(plain(rules[kind]), [...untouched, 'codex-primary']);
    rules[kind].push('codex-old');
    api.clearFilteredProfiles(kind);
    assert.deepEqual(plain(rules[kind]), untouched);
    assert.equal(api.state.dirty, true);

    api.state.dirty = false;
    api.state.pickerQuery = 'no-match';
    api.selectAllProfiles(kind);
    api.clearFilteredProfiles(kind);
    assert.deepEqual(plain(rules[kind]), untouched);
    assert.equal(api.state.dirty, false);
  }
});

test('selected other tab stays reachable when its last provider disappears', () => {
  const h = harness();
  h.api.state.selectedGroup = 'team';
  h.api.state.openPicker = 'allow_profiles';
  h.api.state.pickerCategory = 'other';
  h.api.state.profiles = pickerProfiles().filter(profile => profile.provider !== 'gemini');
  h.api.renderGroupEditor(h.api.state.groups[0]);
  const html = h.elements.get('#editor').innerHTML;
  assert.match(html, /id="allow_profiles-tab-other"[^>]*aria-selected="true"[^>]*tabindex="0"/);
  assert.match(html, /aria-labelledby="allow_profiles-tab-other"/);
  assert.equal(h.api.state.dirty, false);
});

test('member search retains original key indexes and bulk edits only matching memberships', async () => {
  const h = harness(policy([group('team'), group('other')], [
    {caller_scope: scopeA, group_ids: ['team']},
    {caller_scope: scopeB, group_ids: ['other']},
  ]));
  const api = h.api;
  api.state.selectedGroup = 'team';
  api.state.memberQuery = '  key 02  ';
  assert.deepEqual(plain(api.filteredMembers().map(item => item.index)), [1]);
  assert.match(api.memberOptions(api.state.groups[0]), /data-group-key="1"/);
  assert.equal(api.state.dirty, false);
  api.updateFilteredMembers(true);
  assert.deepEqual(plain(api.state.keys.map(key => key.group_ids)), [['team'], ['other', 'team']]);
  api.updateFilteredMembers(false);
  assert.deepEqual(plain(api.state.keys.map(key => key.group_ids)), [['team'], ['other']]);
  api.state.memberQuery = api.state.keys[0].fingerprint.toUpperCase();
  assert.deepEqual(plain(api.filteredMembers().map(item => item.index)), [0]);
  api.state.memberQuery = 'TEST••••';
  assert.equal(api.filteredMembers().length, 2);
  api.state.memberQuery = 'no matching key';
  api.state.dirty = false;
  api.updateFilteredMembers(true);
  assert.equal(api.state.dirty, false);
  api.state.dirty = true;
  await api.save();
  await api.refreshData();
  assert.deepEqual(plain(api.state.keys.map(key => key.group_ids)), [['team'], ['other']]);
});

test('key group labels show all names, escape markup, and follow membership changes', () => {
  const h = harness(policy([group('team'), {...group('other'), name:'QA <review>'}], [{caller_scope:scopeA,group_ids:['team','other']}]));
  const api = h.api;
  let labels = api.keyGroupTags(api.state.keys[0]);
  assert.match(labels, /team/);
  assert.match(labels, /QA &lt;review&gt;/);
  api.state.groups[0].name = '开发组';
  api.renderNav();
  assert.match(h.elements.get('#policyNav').innerHTML, /key-group-tag[^>]*>开发组/);
  assert.match(api.keyGroupTags(api.state.keys[1]), /未分组/);
  api.setKeyMembership(api.state.keys[0], 'team', false);
  assert.doesNotMatch(api.keyGroupTags(api.state.keys[0]), /开发组/);
});

test('configuration export/import round-trips drafts, stale scopes and rules without credentials', async () => {
  const h = harness(policy([group('team', ['A', 'missing-profile'], ['B']), group('other', ['*'])], [
    {caller_scope: scopeA, group_ids:['team','other']},
    {caller_scope: scope('deleted-key'), group_ids:['other']},
  ]));
  h.api.state.defaultDeny = false;
  h.api.state.token = 'private-management-token';
  h.api.state.dirty = true;
  const backup = h.api.exportPolicyText();
  const expected = JSON.parse(backup);
  assert.doesNotMatch(backup, /private-management-token|test-key-A|test-key-B|masked|fingerprint|revision/);
  h.api.state.groups = [];
  h.api.importPolicyText('\uFEFF' + backup);
  assert.deepEqual(plain(h.api.serializablePolicy()), expected);
  assert.equal(h.api.state.dirty, true);
  assert.equal(h.requests.length, 0);
  await h.api.save();
  await h.api.refreshData();
  assert.deepEqual(plain(h.api.serializablePolicy()), expected);
});

test('invalid or oversized import leaves current draft untouched', async () => {
  const h = harness();
  const before = h.api.exportPolicyText();
  const invalidGroup = policy(); invalidGroup.policies[0].group_ids = ['unknown'];
  for (const content of ['not JSON', '{}', JSON.stringify({...policy(), version:2}), JSON.stringify(invalidGroup)]) {
    assert.throws(() => h.api.importPolicyText(content));
    assert.equal(h.api.exportPolicyText(), before);
    assert.equal(h.api.state.dirty, false);
  }
  await h.api.importConfig({size: 6 * 1024 * 1024, text() {throw Error('oversized file must not be read');}});
  assert.equal(h.api.exportPolicyText(), before);
  assert.equal(h.api.state.busy, false);
});

test('import preserves current revision and cannot overwrite concurrent server edits', async () => {
  const h = harness();
  const revision = h.api.state.revision;
  h.remoteEdit(policy([group('team', ['B'])]));
  const imported = policy([group('team', ['C'])]);
  h.api.importPolicyText(JSON.stringify(imported));
  assert.equal(h.api.state.revision, revision);
  await h.api.save();
  assert.deepEqual(h.stored().groups[0].allow_profiles, ['B']);
  assert.equal(h.api.state.dirty, true);
});

test('download generates a JSON file that the file importer accepts without saving remotely', async () => {
  const h = harness();
  h.api.downloadConfig();
  assert.equal(h.downloads.length, 1);
  const download = h.downloads[0];
  assert.match(download.name, /^key-access-manager-.*\.json$/);
  assert.equal(download.blob.type, 'application/json;charset=utf-8');
  const other = harness(policy([group('different')], []));
  await other.api.importConfig(download.blob);
  assert.deepEqual(plain(other.api.serializablePolicy()), JSON.parse(await download.blob.text()));
  assert.equal(other.api.state.dirty, true);
  assert.equal(other.api.state.busy, false);
  assert.equal(other.requests.length, 0);
  assert.equal(other.elements.get('#importConfigFile').value, '');
});
