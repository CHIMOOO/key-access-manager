# Key Access Manager

CLIProxyAPI plugin for group-based upstream access control. Forked from [GLGDLY/key-provider-access](https://github.com/GLGDLY/key-provider-access), originally based on `key-model-access`.

CLIProxyAPI 分组权限管理插件：Key 可加入多个组，只能通过分组绑定或排除上游配置；支持全局开关和新 Key 默认拒绝。

## 使用方式

1. 在 CPA 中安装并启用插件，然后打开设置页。
2. 创建分组，在**分组**中多选允许和拒绝的上游账号。
3. 为一个 Key 勾选多个分组，或在分组中批量选择成员 Key。
4. 点击**保存修改**。组规则、成员关系和全局开关一起保存。

上游选择器按 **Codex → xAI → OAuth** 展示筛选标签，默认显示 Codex API 配置；OAuth 账号统一位于 OAuth 标签中。其他供应商可在“其他”或“全部”中查看。搜索与分类同时生效，“全选筛选结果”和“清除筛选项”只操作当前筛选范围，不改动其他分类或通配符规则；`*` 在“全部”标签中单独选择。

**启用访问控制**默认开启。关闭它会暂停插件权限限制，CPA 自身的 API Key 认证仍然生效。**默认拒绝未分组 Key**默认关闭，未分组 Key 可使用 CPA 提供的上游；手动开启并保存后，新建 Key 和没有分组的现有 Key 在加入授权组之前不能使用任何上游。已保存的开关值在升级或刷新后保留。

同一个 Key 所有分组的允许列表取合集，任何组的拒绝规则优先。已分组但所有组的允许列表为空时，不授予访问权限。需要允许所有上游时，在组中明确选择 `*`。删除分组会解除相关成员关系，剩余组继续生效；完全未分组的 Key 由默认拒绝开关决定。

刷新页面、刷新目录、从文件重载，都不会自动增加或删除上游授权。暂时不在目录中的账号规则保留并显示“目录外”，账号重新出现时原规则仍生效。旧浏览器缓存不再恢复或扩大权限。已经错误保存的全选策略无法推断原始意图，请手动重新选择正确账号并保存。

## Authorization behavior

- CPA authenticates downstream keys and supplies `Metadata.caller_scope`; raw keys never belong in the policy document.
- A key may belong to multiple groups. Upstream allow/deny rules belong exclusively to groups.
- Allow lists are combined across groups; any matching deny rule wins.
- Empty group allow lists grant nothing. Use `*` for an explicit allow-all group; `?` matches one character.
- `access_control_enabled` defaults to `true`. Setting it to `false` bypasses plugin authorization and scheduling without disabling CPA authentication or erasing policies.
- `default_deny` defaults to `false`, allowing keys with no group memberships, including new keys. Setting it to `true` denies unassigned keys; assigned keys still follow their groups. Explicitly saved switch values are preserved on upgrade and reload.
- Missing/invalid caller identity fails closed when default-deny or assigned group policies require evaluation. Invalid initial policy state blocks access; an invalid reload preserves the last valid snapshot and reports the error.
- No matching allowed profile means denial. The plugin never adopts unrelated candidates when profile IDs change. Verified legacy API-key ID matching is retained for the same key/base URL.
- Scheduler and after-auth enforcement use the same group policy. Denied candidates never reach an upstream executor.

CPA offers only its currently eligible, highest-priority candidate tier. An allow list cannot promote a lower priority tier. CPA Home mode bypasses plugin schedulers; the after-auth check still prevents disallowed profiles but cannot reroute a request. Only the highest-priority enabled scheduler plugin is active, so set plugin priorities deliberately.

## Configuration and compatibility

The display name is **Key Access Manager**. For existing installations, the runtime plugin ID, binary name, configuration key, resource paths, and storage directory remain **`key-provider-access`**. Replace the old plugin; do not load both implementations with this ID. The GitHub repository metadata points to this fork.

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    key-provider-access:
      enabled: true
      priority: 100
      version: 3
      access_control_enabled: true
      default_deny: false
      groups: []
      policies: []
```

Settings page:

```text
/v0/resource/plugins/key-provider-access/settings
```

The page reuses the saved same-origin CPAMC management session. CPA keys appear only as head/tail masks and caller-scope fingerprints. Raw downstream keys and provider secrets are used transiently in memory, never written to policies, DOM, browser storage, or URLs.

On first use the page creates `plugins/key-provider-access/config.toml` and patches the plugin's `policy_file` setting. The file becomes the source of the complete policy, including both switches. Updates use revision ETags and atomic file replacement. Choosing items edits a draft; use **Save changes** to persist it.

## Policy schema v3

```toml
version = 3
access_control_enabled = true
default_deny = false

[[groups]]
id = "developers"
name = "开发组"
allow_profiles = ["oauth-profile-id", "codex:apikey:abc123def456"]
deny_profiles = ["*-retired"]

[[groups]]
id = "restricted"
name = "限制组"
allow_profiles = []
deny_profiles = ["private-*"]

[[policies]]
caller_scope = "f7291f3315e5ab0d3c02015a081879d748693f231d8370b43f38f57be991734a"
group_ids = ["developers", "restricted"]
```

Use the UI to derive caller scopes and choose actual profile IDs. Group IDs must be unique and every membership must reference an existing group. In v3, per-key `allow_profiles` and `deny_profiles` are rejected, including empty lists.

## Migration from v2

Existing v2 inline/file policies are accepted and converted into deterministic per-key groups on load. Existing allow/deny ranges are preserved; legacy empty allow lists become explicit `*` group grants. The management API and UI return v3, and the next save persists it. New API writes must use v3.

Unconfigured keys remain allowed unless `default_deny` is explicitly enabled. Strict unmatched-profile denial replaces the old automatic adoption behavior. Back up the old plugin binary and policy file before upgrading. Returning to the old plugin requires restoring its v2 file.

## Build and verification

Go 1.24+, a C compiler, and Node.js 18+ are required for the full checks.

```sh
make check
make build
```

`make check` runs Go formatting, vet, race tests and the dependency-free frontend regression tests. Frontend tests can also run with `node --test web/settings.test.cjs`.

The Linux amd64 output is `dist/key-provider-access.so`; install it under `plugins/linux/amd64/`. The Windows build produces `dist/key-provider-access.dll`. Web assets are embedded in the binary, so rebuild and reload/restart the plugin to apply UI changes.

## Management API

- `GET /v0/management/plugins/key-provider-access/status`
- `GET/PUT /v0/management/plugins/key-provider-access/policies`
- `POST /v0/management/plugins/key-provider-access/reload`
- `POST /v0/management/plugins/key-provider-access/initialize-storage`

All routes require CPA management authentication. Status includes effective global settings and group counts without exposing keys or caller scopes. Host plugin RPC remains schema 2; policy document version 3 is independent.
