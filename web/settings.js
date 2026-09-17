(() => {
  "use strict";

  const PATHS = {
    status: "/v0/management/plugins/key-provider-access/status",
    policies: "/v0/management/plugins/key-provider-access/policies",
    reload: "/v0/management/plugins/key-provider-access/reload",
    initializeStorage: "/v0/management/plugins/key-provider-access/initialize-storage",
    pluginList: "/v0/management/plugins",
    pluginConfig: "/v0/management/plugins/key-provider-access/config",
    apiKeys: "/v0/management/api-keys",
    authFiles: "/v0/management/auth-files",
    geminiKeys: "/v0/management/gemini-api-key",
    interactionsKeys: "/v0/management/interactions-api-key",
    claudeKeys: "/v0/management/claude-api-key",
    codexKeys: "/v0/management/codex-api-key",
    xaiKeys: "/v0/management/xai-api-key",
    openAICompatibility: "/v0/management/openai-compatibility",
    vertexKeys: "/v0/management/vertex-api-key"
  };

  const CPAMC_AUTH_KEY = "cli-proxy-auth";
  const CPAMC_THEME_KEY = "cli-proxy-theme";
  const CPAMC_LANGUAGE_KEY = "cli-proxy-language";
  const SUPPORTED_LANGUAGES = new Set(["en", "zh-CN", "zh-TW", "ru"]);
  const OBFUSCATION_PREFIX = "enc::v1::";
  const OBFUSCATION_SALT = "cli-proxy-api-webui::secure-storage";

  const icons = {
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/></svg>',
    overview: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M15 12v2"/></svg>',
    refresh: '<svg viewBox="0 0 24 24"><path d="M20 6v5h-5M4 18v-5h5"/><path d="M6.1 8.2A7 7 0 0 1 18.8 9M17.9 15.8A7 7 0 0 1 5.2 15"/></svg>',
    file: '<svg viewBox="0 0 24 24"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>',
    save: '<svg viewBox="0 0 24 24"><path d="M5 4h12l2 2v14H5z"/><path d="M8 4v6h8V4M8 20v-6h8v6"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m7 7 10 10M17 7 7 17"/></svg>',
    warning: '<svg viewBox="0 0 24 24"><path d="M12 3 2.8 19h18.4L12 3Z"/><path d="M12 9v4M12 16.5h.01"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    spinner: '<svg class="spinner" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-9 9"/><path d="M3 12a9 9 0 0 1 9-9" opacity=".35"/></svg>'
  };

  const state = {
    token: "",
    status: null,
    keys: [],
    profiles: [],
    profilesError: "",
    persistenceSetupError: "",
    stalePolicies: [],
    groups: [],
    accessControlEnabled: true,
    defaultDeny: false,
    selectedGroup: "",
    revision: 0,
    selectedIndex: -1,
    dirty: false,
    busy: false,
    profileBusy: false,
    sessionBusy: false,
    sessionEnded: false,
    pendingDraft: null,
    pendingRevision: null,
    pendingScope: "",
    pendingGroup: "",
    search: "",
    openPicker: "",
    pickerQuery: "",
    pickerCategory: "codex",
    pickerScroll: 0
  };

  let currentLanguage = "en";
  let localizing = false;

  // The host management UI stores its language preference under this key. The
  // plugin reads that preference (including CPAMC's obfuscated storage format)
  // and deliberately falls back to English instead of the browser's Chinese
  // locale. Chinese remains available for existing installations.
  const ENGLISH_REPLACEMENTS = [
    ["已开启", "On"],
    ["已关闭", "Off"],
    ["上游配置类型", "Provider category"],
    ["全选筛选结果", "Select filtered"],
    ["清除筛选项", "Clear filtered"],
    ["其他", "Other"],
    ["全部", "All"],
    ["Key 可加入多个权限分组；上游配置只能通过分组授权或排除。", "Keys may join multiple groups. Provider access is allowed or denied only through groups."],
    ["全局设置与访问统计", "Global settings and access counts"],
    ["按组管理 CPA Key 的访问权限", "Group-based access control for CPA keys"],
    ["保存访问策略", "Save access policy"],
    ["权限分组", "Access groups"],
    ["暂无分组，请先新建分组", "No groups yet. Create a group to get started."],
    ["新建分组", "New group"],
    ["全局设置", "Global settings"],
    ["修改后点击保存修改生效。", "Changes take effect after you save."],
    ["启用访问控制", "Enable access control"],
    ["关闭后所有已认证 Key 均可访问全部上游配置，分组规则仍会保留。", "When disabled, every authenticated key can use every provider. Group rules are preserved."],
    ["默认拒绝未分组 Key", "Deny ungrouped keys by default"],
    ["包含新建 Key 和没有分组的现有 Key；加入分组后按分组规则授权。", "Applies to new and existing keys without groups. Assigned keys follow their group rules."],
    ["访问控制已关闭：所有已认证 Key 均可访问全部上游配置。", "Access control is disabled: every authenticated key can use every provider."],
    ["已分组 Key", "Grouped keys"],
    ["支持多选分组", "Multiple groups per key"],
    ["未分组 Key", "Ungrouped keys"],
    ["默认拒绝全部", "Deny all by default"],
    ["默认允许全部", "Allow all by default"],
    ["允许合并，拒绝优先", "Allow union; deny takes priority"],
    ["统计当前草稿的有效权限；修改后点击保存修改生效。", "Shows effective permissions in the current draft. Save to apply your changes."],
    ["分组授权规则", "Group authorization rules"],
    ["多个分组的允许列表合并；任意分组的拒绝规则始终优先。分组允许列表为空时不授予访问权限。", "Allowed providers are combined across groups; a deny in any group takes priority. An empty group allow list grants no access."],
    ["新增或暂时不可用的上游配置不会自动改变已保存的分组规则。", "New or temporarily unavailable providers never automatically change saved group rules."],
    ["当前未分组，默认拒绝所有上游配置。", "This key has no groups and is denied access to every provider by default."],
    ["当前未分组，默认允许所有上游配置。", "This key has no groups and is allowed to use every provider by default."],
    ["多个分组的允许列表合并；任意分组的拒绝规则始终优先。", "Allowed providers are combined across groups; a deny in any group takes priority."],
    ["所属分组", "Group membership"],
    ["可多选分组；上游配置的允许与拒绝规则统一在分组中管理。", "Select one or more groups. Provider allow and deny rules are managed only in groups."],
    ["编辑分组", "Edit group"],
    ["清空分组", "Clear groups"],
    ["有效上游权限", "Effective provider access"],
    ["修改分组规则会影响所有已加入此分组的 Key。", "Changes to this group affect every key assigned to it."],
    ["重命名", "Rename"],
    ["删除分组", "Delete group"],
    ["分组上游配置规则", "Group provider rules"],
    ["允许列表为空时不授予访问权限；拒绝规则在所有分组间优先。", "An empty allow list grants no access. Deny rules take priority across all groups."],
    ["仅授予列表中的上游配置；空列表不授予权限", "Only these providers are allowed; an empty list grants no access"],
    ["分组成员", "Group members"],
    ["可多选 Key 加入当前分组，不影响这些 Key 的其他分组。", "Select multiple keys for this group without changing their other memberships."],
    ["选择全部当前 Key", "Select all current keys"],
    ["移除全部当前 Key", "Remove all current keys"],
    ["失效 Key 的分组成员关系仍保留。", "Memberships for missing keys are preserved."],
    ["输入分组名称（最多 128 个字符）：", "Enter a group name (up to 128 characters):"],
    ["分组名称不能为空、超过 128 个字符或与现有名称重复。", "Use a unique, non-empty group name of up to 128 characters."],
    ["删除分组并从所有 Key 中移除此分组？失去最后一个分组的 Key 将遵循全局默认策略。修改将在保存后生效。", "Delete this group and remove its membership from every key? Keys losing their final group will follow the global default policy. Changes take effect after saving."],
    ["由通配符匹配；移除通配符后可单独选择。", "Matched by a wildcard. Remove the wildcard to select individual providers."],
    ["插件返回了无效的 v3 策略文档。", "The plugin returned an invalid v3 policy document."],
    ["分组格式无效或名称重复。", "Invalid group format or duplicate group name."],
    ["分组的上游配置规则无效。", "Invalid provider rules in group."],
    ["Key 必须通过有效分组配置权限。", "Key permissions must reference valid groups."],
    ["策略已保存，但 CPA Key 列表在保存期间发生变化；新 Key 遵循全局默认策略，请检查分组。", "The policy was saved, but the CPA key list changed during saving. New keys follow the global default policy; review their groups."],
    ["允许", "Allowed"],
    ["拒绝", "Denied"],
    ["正在接入管理会话", "Connecting to management session"],
    ["正在只读获取 CPAMC 当前连接信息，无需再次输入 Management Key。", "Reading the current CPAMC connection in read-only mode. No second Management Key is required."],
    ["重新读取会话", "Read session again"],
    ["插件只读取 CPAMC 已保存的同源会话，不会复制或再次持久化 Management Key。", "The plugin only reads the saved same-origin CPAMC session; it never copies or persists the Management Key again."],
    ["上游配置权限", "Key Access Manager"],
    ["现有 Key 的上游配置访问策略", "Provider access policies for existing CPA keys"],
    ["策略导航", "Policy navigation"],
    ["只读来源", "Read-only source"],
    ["搜索 Key", "Search keys"],
    ["页面操作", "Page actions"],
    ["插件状态", "Plugin status"],
    ["正在连接", "Connecting"],
    ["刷新 CPA Key 与策略", "Refresh CPA keys and policies"],
    ["从策略文件重载", "Reload from policy file"],
    ["保存上游配置规则", "Save provider rules"],
    ["权限概览", "Access overview"],
    ["认证由 CPA 管理", "Authentication managed by CPA"],
    ["当前 CPA API Keys", "Current CPA API keys"],
    ["没有匹配的 Key", "No matching keys"],
    ["CPA 当前没有 API Key", "CPA has no API keys"],
    ["上游配置权限概览", "Provider access overview"],
    ["API Key 的创建、删除和生命周期完全由 CPA 管理；此页面只为现有 Key 配置上游配置规则。", "CPA manages API key creation, deletion, and lifecycle; this page configures provider rules for existing keys."],
    ["权限统计", "Access statistics"],
    ["当前 CPA Key", "Current CPA keys"],
    ["只读同步", "Read-only sync"],
    ["已配置", "Configured"],
    ["含 allow 或 deny", "Has allow or deny rules"],
    ["默认允许", "Default allow"],
    ["没有上游配置规则", "No provider rules"],
    ["失效策略", "Stale policies"],
    ["保存时仍保留", "Preserved when saving"],
    ["Provider 访问计数", "Provider access counts"],
    ["每个上游 Profile 单独统计，不会合并同一 Provider 类型的 OAuth/API 条目；每个 CPA Key 对每个 Profile 计一次。", "Each upstream profile is counted separately; OAuth and API entries of the same provider kind are not merged. Each CPA key contributes once per profile."],
    ["认证边界", "Authentication boundary"],
    ["Key 身份与上游配置授权相互分离。", "Key identity and provider authorization are kept separate."],
    ["认证由 CPA 内置 API Keys 管理", "Authentication is managed by CPA's built-in API keys"],
    ["运行状态", "Runtime status"],
    ["来自当前 CPA 插件实例。", "Reported by the current CPA plugin instance."],
    ["认证模式", "Authentication mode"],
    ["身份来源", "Identity source"],
    ["未配置 Key", "Unconfigured key"],
    ["允许全部上游配置", "Allow all providers"],
    ["后端策略数", "Backend policies"],
    ["策略版本", "Policy version"],
    ["策略来源", "Policy source"],
    ["最后更新", "Last updated"],
    ["上游配置规则", "Provider rules"],
    ["直接从 CPA 可用上游配置目录中选择；拒绝规则始终优先于允许规则。", "Select directly from CPA's available provider catalog; deny rules always take precedence over allow rules."],
    ["允许上游配置", "Allow providers"],
    ["设置后，仅允许列表中的上游配置", "When set, only providers in this list are allowed"],
    ["拒绝上游配置", "Deny providers"],
    ["命中后始终拒绝访问", "Matching providers are always denied"],
    ["通配符", "Wildcard"],
    ["目录外", "Outside catalog"],
    ["移除此上游配置规则", "Remove this provider rule"],
    ["尚未选择上游配置", "No providers selected yet"],
    ["全部上游配置", "All providers"],
    ["上游配置目录不可用", "Provider catalog unavailable"],
    ["没有匹配的上游配置", "No matching providers"],
    ["全选可用配置", "Select all available"],
    ["清空", "Clear"],
    ["重新加载", "Reload"],
    ["加载中", "Loading"],
    ["策略警告", "Policy warning"],
    ["最近的策略拒绝：", "Recent policy denial:"],
    ["未连接", "Disconnected"],
    ["插件运行正常", "Plugin is healthy"],
    ["最近一次被拒绝的请求没有匹配到该 Key 当前允许的上游配置。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。", "The most recent denied request matched no provider currently allowed for that key. If access is still failing, refresh the provider catalog and review that key's rules."],
    ["最近一次被拒绝的请求所选上游配置不在该 Key 的允许范围内。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。", "The provider selected for the most recent denied request was not allowed for that key. If access is still failing, refresh the provider catalog and review that key's rules."],
    ["检测到最近一次上游配置策略拒绝。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。", "A recent provider-policy denial was detected. If access is still failing, refresh the provider catalog and review that key's rules."],
    ["保存修改", "Save changes"],
    ["已保存", "Saved"],
    ["正在保存", "Saving"],
    ["正在重载", "Reloading"],
    ["策略自动保存到", "Policy is automatically saved to"],
    ["当前为内存模式；打开页面时会自动创建插件策略文件。", "Memory-only mode; the plugin policy file will be created when this page opens."],
    ["CPA 当前没有可统计的上游配置。", "CPA has no provider profiles to count."],
    ["没有可用上游配置目录。", "No provider catalog is available."],
    ["刷新会放弃尚未保存的上游配置规则。是否继续？", "Refreshing will discard unsaved provider rules. Continue?"],
    ["从策略文件重载会放弃尚未保存的上游配置规则。是否继续？", "Reloading from the policy file will discard unsaved provider rules. Continue?"],
    ["已刷新 CPA Key 与策略", "CPA keys and policies refreshed"],
    ["已从策略文件重载", "Reloaded from policy file"],
    ["策略已被其他管理员或配置重载修改。请刷新数据后再保存。", "The policy was changed by another administrator or a configuration reload. Refresh before saving."],
    ["策略已保存并持久化", "Policy saved and persisted"],
    ["策略已保存到内存", "Policy saved in memory"],
    ["刷新数据", "Refresh data"],
    ["CPA 响应超时，请检查服务状态。", "CPA response timed out; check the service status."],
    ["操作响应超时，提交结果尚未确认。", "The operation timed out; the submission result is not confirmed."],
    ["CPA 当前没有可用的 OAuth 或 API provider 配置。", "CPA has no usable OAuth or API provider profiles."],
    ["上游配置目录加载失败。", "Failed to load the provider catalog."],
    ["CPA 返回了无法识别的 API Key 列表。", "CPA returned an unrecognized API key list."],
    ["CPA 未返回有效的 plugins_dir。", "CPA did not return a valid plugins_dir."],
    ["插件未返回默认策略文件路径。", "The plugin did not return a default policy file path."],
    ["自动创建插件策略文件失败。", "Failed to create the plugin policy file automatically."],
    ["未找到可复用的 CPAMC 会话", "No reusable CPAMC session found"],
    ["自动接入要求 CPAMC 与 CPA 同源，并在登录时启用“记住密码”。请确认后返回此页面重试；插件不会要求你再次输入 Management Key。", "Automatic connection requires CPAMC and CPA to share an origin, with “remember password” enabled at login. Return here and retry; the plugin will not ask for the Management Key again."],
    ["CPAMC 保存的 Management Key 已失效。请返回 CPAMC 重新登录并启用“记住密码”。", "The saved CPAMC Management Key has expired. Return to CPAMC, sign in again, and enable “remember password”."],
    ["无法连接 CPA：", "Unable to connect to CPA: "],
    ["管理会话不可用", "Management session unavailable"],
    ["CPAMC 会话已结束", "CPAMC session ended"],
    ["未保存的策略草稿已保留在当前页面内存中。请重新登录；会话恢复后草稿会自动还原。", "The unsaved policy draft was kept in this page's memory. Sign in again; it will be restored when the session returns."],
    ["请先在 CPAMC 重新登录并启用“记住密码”，页面会自动重新接入。", "Sign in to CPAMC again with “remember password” enabled; this page will reconnect automatically."],
    ["策略已保存，但无法复核 CPA Key 列表：", "The policy was saved, but the CPA key list could not be verified: "],
    ["策略已保存，但状态刷新失败：", "The policy was saved, but status refresh failed: "],
    ["保存响应超时，但已重新读取并确认提交成功", "The save response timed out, but a reread confirmed the submission succeeded"],
    ["保存结果无法确认；本地修改已保留，请刷新后核对。", "The save result could not be confirmed; local changes were kept. Refresh and check."],
    ["策略已重载，但界面刷新失败：", "The policy reloaded, but the page could not refresh: "],
    ["CPA 已保存插件配置，但等待策略文件生效超时。", "CPA saved the plugin configuration, but the policy file did not become effective before the timeout."],
    ["正在验证 CPAMC 已保存的连接信息并加载上游配置策略…", "Validating the saved CPAMC connection and loading provider access policies…"],
    ["未配置 policy_file，无法从文件重载", "No policy_file is configured; reload from file is unavailable"],
    ["SHA-256 指纹", "SHA-256 fingerprint"],
    ["允许 / Enabled", "Allowed / Enabled"],
    ["拒绝 / Disabled", "Denied / Disabled"],
    ["最近一次配置存在问题：", "The most recent configuration has a problem:"],
    ["这些 caller scope 不对应 CPA 当前 Key。保存时会原样保留，不会静默删除；请在确认旧 Key 已永久移除后通过策略文件处理。", "These caller scopes do not correspond to current CPA keys. They are preserved when saving and are not silently deleted; remove them through the policy file only after confirming the old keys are permanently gone."],
    ["此 Key 将无法访问任何上游配置", "This key will not be able to access any provider"],
    ["自动包含未来新增上游配置", "Automatically includes future providers"],
    ["全部上游配置（*，包含未来新增）", "All providers (*, including future additions)"],
    ["* · 此 Key 将无法访问任何上游配置", "* · This key will not be able to access any provider"],
    ["* · 自动包含未来新增上游配置", "* · Automatically includes future providers"],
    ["当前仍在使用最后一个有效策略。", "The last valid policy is still in use."],
    ["Management Key 复用 CPAMC 已保存的同源会话；", "The Management Key reuses the saved same-origin CPAMC session; "],
    ["搜索上游配置…", "Search providers…"],
    ["全选可用配置", "Select all available"],
    ["CPA 已保存插件配置，但等待策略文件生效超时。", "CPA saved the plugin configuration, but the policy file did not become effective before the timeout."],
    ["策略已保存，但", "The policy was saved, but "],
    ["CPA API Key 列表已变化；为避免策略错配，保存已中止。请刷新数据后重新检查规则。", "The CPA API key list changed; saving was stopped to avoid mismatched policies. Refresh the data and review the rules."],
    ["CPA 内置 API Keys", "CPA built-in API keys"],
    ["搜索允许上游配置", "Search allowed providers"],
    ["搜索拒绝上游配置", "Search denied providers"],
    ["没有可用的上游配置目录。", "No provider catalog is available."],
    ["此 Key 将无法访问任何上游配置", "This key will not be able to access any provider"],
    ["自动包含未来新增上游配置", "Automatically includes future providers"],
    ["完整下游 CPA Key 仅在内存中用于计算 caller scope 和生成首尾脱敏显示，不会写入策略、DOM、浏览器存储或 URL。上游凭据仅在内存中用于复现 CPA profile ID，不会写入策略、DOM、浏览器存储或 URL。", "The complete downstream CPA key exists only in memory to calculate the caller scope and head/tail mask; it is never written to policy, the DOM, browser storage, or the URL. Upstream provider inputs are used only in memory to reproduce CPA profile IDs and are never written to policy, the DOM, browser storage, or the URL."]
  ];

  const ENGLISH_REPLACEMENTS_BY_SOURCE = [...ENGLISH_REPLACEMENTS].sort((left, right) => right[0].length - left[0].length);
  const ENGLISH_REPLACEMENTS_BY_TARGET = [...ENGLISH_REPLACEMENTS].sort((left, right) => right[1].length - left[1].length);

  function normalizeLanguage(value) {
    const language = String(value || "").trim().toLowerCase();
    if (language.startsWith("zh-tw") || language.startsWith("zh-hk") || language.startsWith("zh-mo") || language.startsWith("zh-hant")) return "zh-TW";
    if (language.startsWith("zh")) return "zh-CN";
    if (language.startsWith("ru")) return "ru";
    if (language.startsWith("en")) return "en";
    return "";
  }

  function readCPAMCLanguage() {
    const persisted = readStoredValue(CPAMC_LANGUAGE_KEY);
    const candidate = typeof persisted === "string"
      ? persisted
      : persisted?.state?.language ?? persisted?.language ?? "";
    const normalized = normalizeLanguage(candidate);
    return SUPPORTED_LANGUAGES.has(normalized) ? normalized : "en";
  }

  function translateText(value) {
    let text = String(value ?? "");
    if (currentLanguage === "zh-CN") {
      const exact = ENGLISH_REPLACEMENTS_BY_TARGET.find(([, to]) => text === to);
      if (exact) return exact[0];
      for (const [from, to] of ENGLISH_REPLACEMENTS_BY_TARGET) text = text.split(to).join(from);
      return text;
    }
    const exact = ENGLISH_REPLACEMENTS_BY_SOURCE.find(([from]) => text === from);
    if (exact) return exact[1];
    for (const [from, to] of ENGLISH_REPLACEMENTS_BY_SOURCE) text = text.split(from).join(to);
    text = text.replace(/^(\d+) 个当前 Key$/, "$1 current CPA keys")
      .replace(/^已匹配 (\d+) \/ (\d+) 个上游配置$/, "Matched $1 / $2 providers")
      .replace(/^从 (\d+) 个上游配置中选择$/, "Select from $1 providers")
      .replace(/^(\d+) 条规则$/, "$1 rules")
      .replace(/^已加载 (\d+) 个上游配置$/, "Loaded $1 providers")
      .replace(/^策略自动保存到 (.+)$/, "Policy is automatically saved to $1")
      .replace(/^自动持久化失败：(.+) 当前修改仅保存在内存中。$/, "Automatic persistence failed: $1 Changes are currently kept in memory only.")
      .replace(/^点击将清空(.+)规则$/, "Click to clear $1 rules")
      .replace(/^点击将从(.+)中移除冲突规则并取消此匹配$/, "Click to remove the conflicting rule from $1 and cancel this match")
      .replace(/^点击将从(.+)中移除冲突规则$/, "Click to remove the conflicting rule from $1")
      .replace(/^点击将取消(.+)匹配$/, "Click to cancel the $1 match")
      .replace(/^当前匹配 (\d+) 个上游配置，并覆盖未来同前缀上游配置$/, "Matches $1 providers and future providers with the same prefix")
      .replace(/^已保留 (\d+) 条现有规则$/, "$1 existing rules retained")
      .replace(/^已匹配 (\d+) \/ (\d+)$/, "Matched $1 / $2")
      .replace(/^(\d+) 条失效策略：$/, "$1 stale policies:")
      .replace(/^搜索(.+)$/, "Search $1")
      .replace(/^策略 (\d+) 格式无效。$/, "Policy $1 has an invalid format.")
      .replace(/^策略 (\d+) 的 caller scope 无效。$/, "Policy $1 has an invalid caller scope.")
      .replace(/^策略 (\d+) 的 caller scope 重复。$/, "Policy $1 has a duplicate caller scope.")
      .replace(/^策略 (\d+) 的 (allow_profiles|deny_profiles) 无效。$/, "Policy $1 has an invalid $2.")
      .replace(/^请求失败（HTTP (\d+)）。$/, "Request failed (HTTP $1).")
      .replace(/^已加载 (\d+) 个上游配置$/, "Loaded $1 providers")
      .replace(/^已匹配 (\d+) \/ (\d+) 个上游配置$/, "Matched $1 / $2 providers");
    return text;
  }

  function localizePage() {
    if (localizing) return;
    localizing = true;
    try {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      nodes.forEach((node) => {
        if (node.parentElement?.closest("[data-literal]")) return;
        const translated = translateText(node.nodeValue);
        if (translated !== node.nodeValue) node.nodeValue = translated;
      });
      document.querySelectorAll("[placeholder], [aria-label], [title]").forEach((element) => {
        if (element.closest("[data-literal]")) return;
        for (const attribute of ["placeholder", "aria-label", "title"]) {
          if (element.hasAttribute(attribute)) element.setAttribute(attribute, translateText(element.getAttribute(attribute)));
        }
      });
    } finally {
      localizing = false;
    }
  }

  function applyLanguage(language = readCPAMCLanguage()) {
    currentLanguage = SUPPORTED_LANGUAGES.has(language) ? language : "en";
    document.documentElement.lang = currentLanguage;
    const selector = $("#languageSelect");
    if (selector) selector.value = currentLanguage;
    localizePage();
  }

  const $ = (selector) => document.querySelector(selector);
  const authGate = $("#authGate");
  const app = $("#app");
  const editor = $("#editor");
  const nav = $("#policyNav");
  const saveButton = $("#saveButton");
  const reloadButton = $("#reloadButton");
  const refreshDataButton = $("#refreshDataButton");
  const healthBadge = $("#healthBadge");
  let navFrame = 0;

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>'"]/g, (character) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  }

  // Mirrors CPAMC secureStorage v1. This is reversible obfuscation for session
  // compatibility, not cryptography and not a new security boundary.
  function decodeStoredValue(raw) {
    if (!raw || !raw.startsWith(OBFUSCATION_PREFIX)) return raw;
    const encoded = atob(raw.slice(OBFUSCATION_PREFIX.length));
    const encrypted = Uint8Array.from(encoded, (character) => character.charCodeAt(0));
    const key = new TextEncoder().encode(`${OBFUSCATION_SALT}|${window.location.host}|${navigator.userAgent}`);
    const decoded = new Uint8Array(encrypted.length);
    for (let index = 0; index < encrypted.length; index += 1) decoded[index] = encrypted[index] ^ key[index % key.length];
    return new TextDecoder().decode(decoded);
  }

  function readStoredValue(name) {
    try {
      const raw = localStorage.getItem(name);
      if (raw === null) return null;
      const decoded = decodeStoredValue(raw);
      try { return JSON.parse(decoded); } catch (_) { return decoded; }
    } catch (_) {
      return null;
    }
  }

  function readCPAMCManagementKey() {
    try {
      if (localStorage.getItem("isLoggedIn") !== "true") return "";
      const persisted = readStoredValue(CPAMC_AUTH_KEY);
      const current = persisted && typeof persisted === "object" ? persisted.state?.managementKey : "";
      if (typeof current === "string" && current.trim()) return current.trim();
      const legacy = readStoredValue("managementKey");
      return typeof legacy === "string" ? legacy.trim() : "";
    } catch (_) {
      return "";
    }
  }

  function normalizeProfiles(value) {
    if (!Array.isArray(value)) return [];
    return [...new Set(value.map((profile) => String(profile).trim()).filter(Boolean))];
  }

  function profilePatternMatches(pattern, profile) {
    const source = String(pattern).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
    try { return new RegExp(`^${source}$`).test(profile); } catch (_) { return false; }
  }

  function profileRuleMatches(pattern, profile) {
    return profilePatternMatches(pattern, profile.id)
      || Boolean(profile.legacyID && profilePatternMatches(pattern, profile.legacyID));
  }

  function normalizePolicyDocument(raw) {
    if (!raw || typeof raw !== "object" || raw.version !== 3 || !Array.isArray(raw.policies) || !Array.isArray(raw.groups)
      || typeof raw.access_control_enabled !== "boolean" || typeof raw.default_deny !== "boolean") {
      throw new Error(translateText("插件返回了无效的 v3 策略文档。"));
    }
    const groupIDs = new Set();
    const groupNames = new Set();
    const groups = raw.groups.map((group) => {
      if (!group || typeof group.id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(group.id)
        || typeof group.name !== "string" || !group.name.trim() || [...group.name.trim()].length > 128
        || groupIDs.has(group.id) || groupNames.has(group.name.trim().toLowerCase())) {
        throw new Error(translateText("分组格式无效或名称重复。"));
      }
      groupIDs.add(group.id);
      groupNames.add(group.name.trim().toLowerCase());
      for (const field of ["allow_profiles", "deny_profiles"]) {
        if (!Array.isArray(group[field]) || group[field].some((profile) => typeof profile !== "string" || !profile.trim())) {
          throw new Error(translateText("分组的上游配置规则无效。"));
        }
      }
      return { id: group.id, name: group.name.trim(), allow_profiles: normalizeProfiles(group.allow_profiles), deny_profiles: normalizeProfiles(group.deny_profiles) };
    });
    const seen = new Set();
    const policies = raw.policies.map((item, index) => {
      if (!item || typeof item !== "object") throw new Error(`策略 ${index + 1} 格式无效。`);
      const scope = typeof item.caller_scope === "string" ? item.caller_scope.trim().toLowerCase() : "";
      if (!/^[0-9a-f]{64}$/.test(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 无效。`);
      if (seen.has(scope)) throw new Error(`策略 ${index + 1} 的 caller scope 重复。`);
      seen.add(scope);
      if (!Array.isArray(item.group_ids) || item.group_ids.some((id) => typeof id !== "string" || !groupIDs.has(id))
        || Object.hasOwn(item, "allow_profiles") || Object.hasOwn(item, "deny_profiles")) {
        throw new Error(translateText("Key 必须通过有效分组配置权限。"));
      }
      return {
        caller_scope: scope,
        group_ids: [...new Set(item.group_ids)]
      };
    });
    return { version: 3, access_control_enabled: raw.access_control_enabled, default_deny: raw.default_deny, groups, policies };
  }

  function shortFingerprint(scope) {
    return `${scope.slice(0, 10)}…${scope.slice(-6)}`;
  }

  function maskCPAKey(value) {
    const key = String(value ?? "").trim();
    if (!key) return "••••";
    if (key.length === 1) return "••••";
    if (key.length <= 4) return `${key.slice(0, 1)}••••${key.slice(-1)}`;
    const headLength = Math.min(6, Math.max(2, Math.floor(key.length / 3)));
    const tailLength = Math.min(4, Math.max(2, Math.floor(key.length / 4)));
    const hiddenLength = key.length - headLength - tailLength;
    if (hiddenLength <= 0) return `${key.slice(0, 1)}••••${key.slice(-1)}`;
    return `${key.slice(0, headLength)}${"•".repeat(Math.min(hiddenLength, 8))}${key.slice(-tailLength)}`;
  }

  function keyLabel(index) {
    return `CPA API Key ${String(index + 1).padStart(2, "0")}`;
  }

  async function api(path, options = {}) {
    const method = String(options.method || "GET").toUpperCase();
    const timeout = options.timeout || (method === "GET" ? 12000 : 20000);
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(path, {
        ...options,
        method,
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${state.token}`,
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.headers || {})
        },
        cache: "no-store"
      });
      let payload = null;
      try { payload = await response.json(); } catch (_) { payload = null; }
      if (!response.ok) {
        const detail = payload && (payload.error?.message || payload.error);
        const error = new Error(detail ? String(detail) : `请求失败（HTTP ${response.status}）`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } catch (error) {
      if (error.name === "AbortError") {
        const timeoutError = new Error(method === "GET" ? "CPA 响应超时，请检查服务状态。" : "操作响应超时，提交结果尚未确认。");
        timeoutError.code = "timeout";
        throw timeoutError;
      }
      throw error;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value);
    if (window.crypto?.subtle) {
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
    }
    // SubtleCrypto is unavailable on plain HTTP origins other than localhost.
    // Keep remote CPA panels functional without sending raw API keys elsewhere.
    return sha256FallbackHex(bytes);
  }

  function sha256FallbackHex(bytes) {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const stateWords = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const bitLength = bytes.length * 8;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const words = new Uint32Array(64);
    const rotateRight = (word, count) => (word >>> count) | (word << (32 - count));

    for (let offset = 0; offset < paddedLength; offset += 64) {
      for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4, false);
      for (let index = 16; index < 64; index += 1) {
        const left = words[index - 15];
        const right = words[index - 2];
        const sigma0 = rotateRight(left, 7) ^ rotateRight(left, 18) ^ (left >>> 3);
        const sigma1 = rotateRight(right, 17) ^ rotateRight(right, 19) ^ (right >>> 10);
        words[index] = (words[index - 16] + sigma0 + words[index - 7] + sigma1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = stateWords;
      for (let index = 0; index < 64; index += 1) {
        const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        const choose = (e & f) ^ (~e & g);
        const temp1 = (h + sum1 + choose + constants[index] + words[index]) >>> 0;
        const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (sum0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      stateWords[0] = (stateWords[0] + a) >>> 0;
      stateWords[1] = (stateWords[1] + b) >>> 0;
      stateWords[2] = (stateWords[2] + c) >>> 0;
      stateWords[3] = (stateWords[3] + d) >>> 0;
      stateWords[4] = (stateWords[4] + e) >>> 0;
      stateWords[5] = (stateWords[5] + f) >>> 0;
      stateWords[6] = (stateWords[6] + g) >>> 0;
      stateWords[7] = (stateWords[7] + h) >>> 0;
    }
    return stateWords.map((word) => word.toString(16).padStart(8, "0")).join("");
  }

  async function fetchProfileCatalog() {
    const endpoints = [
      [PATHS.authFiles, "files"],
      [PATHS.geminiKeys, "gemini-api-key"],
      [PATHS.interactionsKeys, "interactions-api-key"],
      [PATHS.claudeKeys, "claude-api-key"],
      [PATHS.codexKeys, "codex-api-key"],
      [PATHS.xaiKeys, "xai-api-key"],
      [PATHS.openAICompatibility, "openai-compatibility"],
      [PATHS.vertexKeys, "vertex-api-key"]
    ];
    try {
      const payloads = await Promise.all(endpoints.map(([path]) => api(path, { method: "GET" })));
      const lists = new Map(endpoints.map(([, field], index) => [field, Array.isArray(payloads[index]?.[field]) ? payloads[index][field] : []]));
      const profiles = [];
      const seen = new Set();
      const counters = new Map();
      const add = (id, provider, displayName, kind, legacyID = "") => {
        id = String(id || "").trim();
        if (!id || seen.has(id)) return;
        seen.add(id);
        profiles.push({ id, provider: String(provider || "").trim(), displayName: String(displayName || "").trim(), kind, ...(legacyID ? { legacyID } : {}) });
      };
      const nextID = async (kind, ...parts) => {
        const digest = await sha256Hex([kind, ...parts.map((part) => String(part || "").trim())].join("\0"));
        const base = `${kind}:${digest.slice(0, 12)}`;
        const count = counters.get(base) || 0;
        counters.set(base, count + 1);
        return count ? `${base}-${count}` : base;
      };

      for (const item of lists.get("files")) {
        if (item?.disabled === true || String(item?.status || "").toLowerCase() === "disabled") continue;
        const provider = String(item?.provider ?? item?.type ?? "").trim();
        const label = String(item?.label ?? item?.email ?? item?.account ?? item?.name ?? "OAuth profile").trim();
        add(item?.id, provider, `${label} · ${provider || "OAuth"}`, "oauth");
      }
      const formatSortedHeaders = (headers) => {
        if (!headers || typeof headers !== "object") return "";
        const keys = Object.keys(headers).sort();
        return keys.length ? `${keys.map((key) => `${key}\0${String(headers[key] ?? "")}`).join("\0")}\0` : "";
      };
      const addSimple = async (field, kind, provider) => {
        for (const item of lists.get(field)) {
          if (item?.disabled === true || String(item?.status || "").toLowerCase() === "disabled") continue;
          if (!String(item?.["api-key"] || "").trim()) continue;
          const id = await nextID(kind, item?.["api-key"], item?.["base-url"], item?.["proxy-url"], item?.prefix, formatSortedHeaders(item?.headers));
          // Match the backend's verified pre-v7.2.146 identity alias. Only the
          // digest is retained in this in-memory catalog; credentials and
          // aliases are never copied into the policy or browser storage.
          const digest = await sha256Hex([kind, String(item?.["api-key"] || "").trim(), String(item?.["base-url"] || "").trim()].join("\0"));
          add(id, provider, `${provider} API provider`, "api", `${kind}:${digest.slice(0, 12)}`);
        }
      };
      await addSimple("gemini-api-key", "gemini:apikey", "gemini");
      await addSimple("interactions-api-key", "gemini-interactions:apikey", "gemini-interactions");
      await addSimple("claude-api-key", "claude:apikey", "claude");
      await addSimple("codex-api-key", "codex:apikey", "codex");
      await addSimple("xai-api-key", "xai:apikey", "xai");

      for (const item of lists.get("openai-compatibility")) {
        if (item?.disabled) continue;
        const name = String(item?.name || "openai-compatibility").trim().toLowerCase();
        const provider = !name || name === "openai-compatibility" || name.startsWith("openai-compatible-") ? (name || "openai-compatibility") : `openai-compatible-${name}`;
        const kind = `openai-compatibility:${name || "openai-compatibility"}`;
        const entries = Array.isArray(item?.["api-key-entries"]) ? item["api-key-entries"] : [];
        if (entries.length) {
          for (const entry of entries) {
            const id = await nextID(kind, entry?.["api-key"], item?.["base-url"], entry?.["proxy-url"]);
            add(id, provider, `${item?.name || provider} API provider`, "api");
          }
        } else {
          const id = await nextID(kind, item?.["base-url"]);
          add(id, provider, `${item?.name || provider} API provider`, "api");
        }
      }
      for (const item of lists.get("vertex-api-key")) {
        const id = await nextID("vertex:apikey", item?.["api-key"], item?.["base-url"], item?.["proxy-url"]);
        add(id, "vertex", "vertex API provider", "api");
      }

      profiles.sort((left, right) => left.provider.localeCompare(right.provider) || left.id.localeCompare(right.id));
      return { profiles, error: profiles.length ? "" : "CPA 当前没有可用的 OAuth 或 API provider 配置。" };
    } catch (error) {
      return { profiles: [], error: error.message || "上游配置目录加载失败。" };
    }
  }

  async function fetchCurrentKeys(options = {}) {
    const payload = await api(PATHS.apiKeys, { method: "GET" });
    const values = Array.isArray(payload?.["api-keys"]) ? payload["api-keys"] : null;
    if (!values) throw new Error("CPA 返回了无法识别的 API Key 列表。");

    const temporaryValues = values.slice();
    const normalizedValues = temporaryValues.map((value) => String(value).trim()).filter(Boolean);
    try {
      const [scopes, catalog] = await Promise.all([
        Promise.all(normalizedValues.map((value) => sha256Hex(`cli-proxy-api:caller-scope:v1\0${value}`))),
        options.includeCatalog ? fetchProfileCatalog() : Promise.resolve(null)
      ]);
      const seen = new Set();
      const keys = scopes.map((scope, index) => ({
        scope,
        masked: maskCPAKey(normalizedValues[index]),
        group_ids: [],
        hasPolicy: false
      })).filter((key) => {
        if (seen.has(key.scope)) return false;
        seen.add(key.scope);
        return true;
      }).map((key) => ({
        ...key,
        fingerprint: shortFingerprint(key.scope)
      }));
      return options.includeCatalog ? { keys, catalog } : keys;
    } finally {
      normalizedValues.fill("");
      temporaryValues.fill("");
      values.fill("");
    }
  }

  async function waitForPersistentStatus(expectedPath) {
    let lastError = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (attempt > 0) await new Promise((resolve) => window.setTimeout(resolve, 250));
      try {
        const status = await api(PATHS.status, { method: "GET", timeout: 1500 });
        if (status?.persistent_updates && status.policy_file === expectedPath) return status;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("CPA 已保存插件配置，但等待策略文件生效超时。");
  }

  async function initializeDefaultPersistence() {
    const pluginList = await api(PATHS.pluginList, { method: "GET" });
    const pluginsDir = typeof pluginList?.plugins_dir === "string" ? pluginList.plugins_dir.trim() : "";
    if (!pluginsDir) throw new Error("CPA 未返回有效的 plugins_dir。");
    const initialized = await api(PATHS.initializeStorage, {
      method: "POST",
      body: JSON.stringify({ plugins_dir: pluginsDir })
    });
    const policyFile = typeof initialized?.policy_file === "string" ? initialized.policy_file.trim() : "";
    if (!policyFile) throw new Error("插件未返回默认策略文件路径。");
    await api(PATHS.pluginConfig, {
      method: "PATCH",
      body: JSON.stringify({ policy_file: policyFile })
    });
    return waitForPersistentStatus(policyFile);
  }

  async function fetchRemoteData() {
    // Verify Management authentication once before issuing the remaining reads.
    let status = await api(PATHS.status, { method: "GET" });
    let persistenceSetupError = "";
    if (!status?.persistent_updates) {
      try {
        status = await initializeDefaultPersistence();
      } catch (error) {
        persistenceSetupError = error.message || "自动创建插件策略文件失败。";
      }
    }
    const [policies, keyData] = await Promise.all([
      api(PATHS.policies, { method: "GET" }),
      fetchCurrentKeys({ includeCatalog: true })
    ]);
    return { status, policies, keys: keyData.keys, catalog: keyData.catalog, persistenceSetupError };
  }

  function applyPolicyDocument(rawDocument) {
    const documentValue = normalizePolicyDocument(rawDocument);
    const byScope = new Map(documentValue.policies.map((policy) => [policy.caller_scope, policy]));
    const currentScopes = new Set(state.keys.map((key) => key.scope));

    state.groups = documentValue.groups;
    state.accessControlEnabled = documentValue.access_control_enabled;
    state.defaultDeny = documentValue.default_deny;
    state.keys = state.keys.map((key) => {
      const policy = byScope.get(key.scope);
      return {
        ...key,
        group_ids: policy ? [...policy.group_ids] : [],
        hasPolicy: Boolean(policy)
      };
    });
    state.stalePolicies = documentValue.policies
      .filter((policy) => !currentScopes.has(policy.caller_scope))
      .map((policy) => ({ ...policy, group_ids: [...policy.group_ids] }));
  }

  function installRemoteData(remote, preferredScope = "") {
    state.status = remote.status;
    state.keys = remote.keys;
    state.profiles = remote.catalog?.profiles || [];
    state.profilesError = remote.catalog?.error || "";
    state.persistenceSetupError = remote.persistenceSetupError || "";
    applyPolicyDocument(remote.policies?.policy);
    state.dirty = false;
    state.revision = Number(remote.policies?.revision ?? remote.status?.revision ?? 0);
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    state.selectedIndex = preferredScope ? state.keys.findIndex((key) => key.scope === preferredScope) : -1;
    if (state.selectedIndex >= 0 || !state.groups.some((group) => group.id === state.selectedGroup)) state.selectedGroup = "";
  }

  function setSessionState(kind, title, message) {
    $("#authTitle").textContent = title;
    $("#authMessage").textContent = message;
    $("#sessionIcon").classList.toggle("error", kind === "error");
    $("#sessionIcon").innerHTML = kind === "loading" ? icons.spinner : kind === "error" ? icons.warning : icons.check;
    $("#retrySessionButton").hidden = kind !== "error";
  }

  async function connectFromCPAMC() {
    if (state.sessionBusy) return;
    const token = readCPAMCManagementKey();
    if (!token) {
      state.token = "";
      setSessionState("error", "未找到可复用的 CPAMC 会话", "自动接入要求 CPAMC 与 CPA 同源，并在登录时启用“记住密码”。请确认后返回此页面重试；插件不会要求你再次输入 Management Key。");
      return;
    }
    state.token = token;
    state.sessionBusy = true;
    setSessionState("loading", "正在接入管理会话", "正在验证 CPAMC 已保存的连接信息并加载上游配置策略…");
    try {
      const remote = await fetchRemoteData();
      const pendingDraft = state.pendingDraft;
      const pendingRevision = state.pendingRevision;
      const pendingScope = state.pendingScope;
      installRemoteData(remote, pendingScope);
      if (pendingDraft) {
        applyPolicyDocument(pendingDraft);
        // A restored draft is still based on its original revision. Keeping
        // that revision lets If-Match reject intervening remote changes.
        state.revision = pendingRevision ?? 0;
        state.dirty = true;
        state.pendingDraft = null;
        state.pendingRevision = null;
        state.pendingScope = "";
        state.selectedGroup = state.groups.some((group) => group.id === state.pendingGroup) ? state.pendingGroup : "";
        state.pendingGroup = "";
      }
      state.sessionEnded = false;
      authGate.hidden = true;
      app.hidden = false;
      renderAll();
    } catch (error) {
      state.token = "";
      const message = error.status === 401
        ? "CPAMC 保存的 Management Key 已失效。请返回 CPAMC 重新登录并启用“记住密码”。"
        : `无法连接 CPA：${error.message}`;
      setSessionState("error", "管理会话不可用", message);
    } finally {
      state.sessionBusy = false;
    }
  }

  function finalizeEndedSession() {
    if (!state.sessionEnded || state.busy || state.profileBusy) return;
    const hadDraft = state.dirty;
    if (hadDraft) {
      state.pendingDraft = serializablePolicy();
      state.pendingRevision = state.revision;
      state.pendingScope = selectedKey()?.scope || "";
      state.pendingGroup = state.selectedGroup;
    }
    state.token = "";
    state.status = null;
    state.keys = [];
    state.profiles = [];
    state.stalePolicies = [];
    state.groups = [];
    state.selectedGroup = "";
    state.dirty = false;
    state.sessionEnded = false;
    app.hidden = true;
    authGate.hidden = false;
    setSessionState("error", "CPAMC 会话已结束", hadDraft
      ? "未保存的策略草稿已保留在当前页面内存中。请重新登录；会话恢复后草稿会自动还原。"
      : "请先在 CPAMC 重新登录并启用“记住密码”，页面会自动重新接入。");
  }

  function setBusy(busy, action = "") {
    state.busy = busy;
    $("#workspace").inert = busy;
    refreshDataButton.disabled = busy || state.profileBusy;
    saveButton.disabled = busy || state.profileBusy || !state.dirty;
    reloadButton.disabled = busy || state.profileBusy || !state.status?.persistent_updates;
    saveButton.innerHTML = action === "save" && busy
      ? `${icons.spinner}<span class="label-long">正在保存</span>`
      : `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    reloadButton.innerHTML = action === "reload" && busy
      ? `${icons.spinner}<span class="label-long">正在重载</span>`
      : `${icons.file}<span class="label-long">从文件重载</span>`;
    refreshDataButton.innerHTML = action === "refresh" && busy
      ? icons.spinner
      : icons.refresh;
    if (!busy) finalizeEndedSession();
  }

  function markDirty() {
    state.dirty = true;
    syncHeader();
  }

  function renderAll() {
    renderNav();
    renderEditor();
    syncHeader();
    syncPersistence();
  }

  function syncHeader() {
    const healthy = state.status && !state.status.last_error;
    const warning = state.status?.last_error || state.status?.runtime_warning;
    healthBadge.innerHTML = `<span class="status-dot ${warning ? "warning" : healthy ? "" : "error"}"></span><span>${escapeHTML(warning ? "策略警告" : healthy ? `Schema v${state.status.schema_version || 3}` : "未连接")}</span>`;
    healthBadge.title = warning ? (state.status.last_error || runtimeWarningText(state.status.runtime_warning)) : "插件运行正常";
    saveButton.disabled = state.busy || state.profileBusy || !state.dirty;
    reloadButton.disabled = state.busy || state.profileBusy || !state.status?.persistent_updates;
    reloadButton.title = state.status?.persistent_updates ? "从策略文件重载" : "未配置 policy_file，无法从文件重载";
    saveButton.innerHTML = `${icons.save}<span class="label-long">${state.dirty ? "保存修改" : "已保存"}</span>`;
    $("#policyCount").textContent = `${state.keys.length} 个当前 Key`;
  }

  function syncPersistence() {
    const notice = $("#persistenceNotice");
    if (!state.status) return;
    if (state.status.persistent_updates) {
      notice.className = "persistence-notice";
      notice.textContent = `策略自动保存到 ${state.status.policy_file}`;
    } else {
      notice.className = "persistence-notice warning";
      notice.textContent = state.persistenceSetupError
        ? `自动持久化失败：${state.persistenceSetupError} 当前修改仅保存在内存中。`
        : "当前为内存模式；打开页面时会自动创建插件策略文件。";
    }
  }

  function scheduleNavRender() {
    if (navFrame) return;
    navFrame = requestAnimationFrame(() => {
      navFrame = 0;
      renderNav();
    });
  }

  function renderNav() {
    const query = state.search.trim().toLowerCase();
    const visible = state.keys.map((key, index) => ({ key, index })).filter(({ key, index }) =>
      !query || key.masked.toLowerCase().includes(query) || key.fingerprint.toLowerCase().includes(query) || keyLabel(index).toLowerCase().includes(query)
    );
    nav.innerHTML = `
      <button class="nav-item" type="button" data-select="overview" aria-current="${state.selectedIndex < 0 && !state.selectedGroup ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span><span class="nav-copy"><strong>权限概览</strong><span>全局设置与访问统计</span></span>
      </button>
      <div class="nav-group-heading"><p class="nav-group-label">权限分组</p><button class="nav-add" type="button" data-select="create-group" aria-label="新建分组">+</button></div>
      ${state.groups.map((group) => `<button class="nav-item" type="button" data-select="group" data-group="${escapeHTML(group.id)}" aria-current="${state.selectedGroup === group.id ? "page" : "false"}">
        <span class="nav-icon">${icons.overview}</span><span class="nav-copy"><strong data-literal>${escapeHTML(group.name)}</strong><span>${state.keys.filter((key) => key.group_ids.includes(group.id)).length} Key · ${group.allow_profiles.length} allow / ${group.deny_profiles.length} deny</span></span>
      </button>`).join("") || '<p class="empty-nav">暂无分组，请先新建分组</p>'}
      <p class="nav-group-label">当前 CPA API Keys</p>
      ${visible.length ? visible.map(({ key, index }) => `<button class="nav-item" type="button" data-select="key" data-index="${index}" aria-current="${state.selectedIndex === index ? "page" : "false"}" aria-label="${escapeHTML(keyLabel(index))}，${escapeHTML(key.masked)}，SHA-256 指纹 ${escapeHTML(key.fingerprint)}">
        <span class="nav-icon key">${icons.key}</span><span class="nav-copy"><strong>${escapeHTML(keyLabel(index))}</strong><span class="mono masked-key">${escapeHTML(key.masked)}</span><span>${key.group_ids.length} groups · SHA-256 ${escapeHTML(key.fingerprint)}</span></span>
      </button>`).join("") : `<p class="empty-nav">${query ? "没有匹配的 Key" : "CPA 当前没有 API Key"}</p>`}`;
  }

  function renderEditor() {
    const group = selectedGroup();
    if (group) { renderGroupEditor(group); return; }
    if (state.selectedIndex >= 0 && state.keys[state.selectedIndex]) {
      renderKeyEditor(state.keys[state.selectedIndex], state.selectedIndex);
      return;
    }
    state.selectedIndex = -1;
    state.selectedGroup = "";
    renderOverview();
  }

  function hasRules(key) {
    return key.group_ids.length > 0;
  }

  function keyAllowsProfile(key, profileID) {
    if (!state.accessControlEnabled) return true;
    if (!key.group_ids.length) return !state.defaultDeny;
    const profile = state.profiles.find((candidate) => candidate.id === profileID || candidate.legacyID === profileID) || { id: profileID };
    const groups = state.groups.filter((group) => key.group_ids.includes(group.id));
    if (groups.some((group) => group.deny_profiles.some((rule) => profileRuleMatches(rule, profile)))) return false;
    return groups.some((group) => group.allow_profiles.some((rule) => profileRuleMatches(rule, profile)));
  }

  function providerAccessCounts() {
    const rows = [];
    for (const profile of state.profiles) {
      const provider = String(profile.provider || "unknown").trim() || "unknown";
      const profileID = String(profile.id || "").trim();
      if (!profileID) continue;
      const counts = {
        provider,
        profile: String(profile.displayName || profileID).trim() || profileID,
        profileID,
        kind: profile.kind === "oauth" ? "OAuth" : "API",
        enabled: 0,
        disabled: 0
      };
      for (const key of state.keys) {
        if (keyAllowsProfile(key, profile.id)) counts.enabled += 1;
        else counts.disabled += 1;
      }
      rows.push(counts);
    }
    return rows.sort((left, right) => left.provider.localeCompare(right.provider) || left.profile.localeCompare(right.profile) || left.profileID.localeCompare(right.profileID));
  }

  function providerAccessTable(counts) {
    if (!counts.length) {
      return `<p class="provider-empty">${escapeHTML(state.profilesError || "CPA 当前没有可统计的上游配置。")}</p>`;
    }
    return `<div class="provider-table-wrap"><table class="provider-table">
      <thead><tr><th scope="col">Provider / Profile</th><th scope="col">Type</th><th scope="col">允许 / Enabled</th><th scope="col">拒绝 / Disabled</th></tr></thead>
      <tbody>${counts.map((item) => `<tr>
        <th scope="row"><span class="provider-name" data-literal>${escapeHTML(item.provider)}</span><small class="provider-profile" data-literal>${escapeHTML(item.profile)} · ${escapeHTML(item.profileID)}</small></th>
        <td>${escapeHTML(item.kind)}</td>
        <td><strong class="provider-count enabled">${item.enabled}</strong></td>
        <td><strong class="provider-count disabled">${item.disabled}</strong></td>
      </tr>`).join("")}</tbody>
    </table></div>`;
  }

  function runtimeWarningText(code) {
    switch (String(code || "").trim()) {
      case "profile_match_failed":
        return "最近一次被拒绝的请求没有匹配到该 Key 当前允许的上游配置。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。";
      case "selected_profile_denied":
        return "最近一次被拒绝的请求所选上游配置不在该 Key 的允许范围内。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。";
      default:
        return "检测到最近一次上游配置策略拒绝。如果访问仍然失败，请刷新上游配置目录并检查该 Key 的规则。";
    }
  }

  function renderOverview() {
    const configured = state.keys.filter(hasRules).length;
    const staleCount = state.stalePolicies.length;
    const statusWarning = state.status?.last_error
      ? `<div class="notice">${icons.warning}<span><strong>最近一次配置存在问题：</strong> ${escapeHTML(state.status.last_error)}。当前仍在使用最后一个有效策略。</span></div>` : "";
    const runtimeWarning = state.status?.runtime_warning
      ? `<div class="notice">${icons.warning}<span><strong>最近的策略拒绝：</strong> ${escapeHTML(runtimeWarningText(state.status.runtime_warning))}</span></div>` : "";
    const staleWarning = staleCount
      ? `<div class="notice">${icons.warning}<span><strong>${staleCount} 条失效策略：</strong>这些 caller scope 不对应 CPA 当前 Key。保存时会原样保留，不会静默删除；请在确认旧 Key 已永久移除后通过策略文件处理。</span></div>` : "";
    editor.innerHTML = `
      <header class="editor-head"><div class="editor-title-wrap"><p class="editor-kicker">Key Access Manager</p><h1>上游配置权限概览</h1><p class="editor-subtitle">Key 可加入多个权限分组；上游配置只能通过分组授权或排除。</p></div><button class="button secondary" type="button" data-action="create-group">新建分组</button></header>
      ${statusWarning}${runtimeWarning}${staleWarning}
      <section class="card">
        <div class="card-head"><h2>全局设置</h2><p>修改后点击保存修改生效。</p></div>
        ${settingToggle("accessControlEnabled", "启用访问控制", "关闭后所有已认证 Key 均可访问全部上游配置，分组规则仍会保留。")}
        ${settingToggle("defaultDeny", "默认拒绝未分组 Key", "包含新建 Key 和没有分组的现有 Key；加入分组后按分组规则授权。")}
      </section>
      ${!state.accessControlEnabled ? '<div class="notice">访问控制已关闭：所有已认证 Key 均可访问全部上游配置。</div>' : ""}
      <section class="overview-grid" aria-label="权限统计">
        ${statCard("当前 CPA Key", state.keys.length, "只读同步")}
        ${statCard("已分组 Key", configured, "支持多选分组")}
        ${statCard("未分组 Key", state.keys.length - configured, state.accessControlEnabled && state.defaultDeny ? "默认拒绝全部" : "默认允许全部")}
        ${statCard("权限分组", state.groups.length, "允许合并，拒绝优先")}
      </section>
      <section class="card"><div class="card-head"><h2>Provider 访问计数</h2><p>统计当前草稿的有效权限；修改后点击保存修改生效。</p></div>${providerAccessTable(providerAccessCounts())}</section>
      <section class="card"><div class="card-head"><h2>分组授权规则</h2><p>多个分组的允许列表合并；任意分组的拒绝规则始终优先。分组允许列表为空时不授予访问权限。</p></div>
        <div class="info-callout"><span class="callout-icon">${icons.key}</span><div><strong>认证由 CPA 内置 API Keys 管理</strong><p>新增或暂时不可用的上游配置不会自动改变已保存的分组规则。</p></div></div>
      </section>
      <section class="card"><div class="card-head"><h2>运行状态</h2><p>来自当前 CPA 插件实例。</p></div>
        ${statusRow("认证模式", displayAuthMode(state.status?.auth_mode))}
        ${statusRow("身份来源", state.status?.identity_source || "—")}
        ${statusRow("后端策略数", state.status?.policy_count ?? "—")}
        ${statusRow("策略版本", `rev-${state.revision}`)}
        ${statusRow("策略来源", state.status?.source || "—")}
        ${statusRow("最后更新", formatDate(state.status?.updated_at))}
      </section>`;
  }

  function settingToggle(name, title, description) {
    return `<label class="setting-row setting-toggle-row"><span class="setting-copy"><strong>${escapeHTML(title)}</strong><small>${escapeHTML(description)}</small></span><span class="setting-toggle-control"><span class="setting-toggle-state ${state[name] ? "enabled" : ""}" aria-hidden="true">${state[name] ? "已开启" : "已关闭"}</span><span class="setting-toggle"><input class="setting-switch" type="checkbox" role="switch" aria-label="${escapeHTML(title)}" data-setting="${name}" ${state[name] ? "checked" : ""}><span class="setting-track" aria-hidden="true"></span></span></span></label>`;
  }

  function statCard(label, value, note, warning = false) {
    return `<article class="stat-card ${warning ? "warning" : ""}"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong><small>${escapeHTML(note)}</small></article>`;
  }

  function displayAuthMode(value) {
    return value === "cpa_builtin_api_keys" ? "CPA 内置 API Keys" : value || "—";
  }

  function statusRow(label, value) {
    return `<div class="setting-row"><div class="setting-copy"><strong>${escapeHTML(label)}</strong></div><div class="setting-control mono">${escapeHTML(value)}</div></div>`;
  }

  function renderKeyEditor(key, index) {
    const message = !state.accessControlEnabled ? "访问控制已关闭：所有已认证 Key 均可访问全部上游配置。"
      : !hasRules(key) ? state.defaultDeny ? "当前未分组，默认拒绝所有上游配置。" : "当前未分组，默认允许所有上游配置。"
      : "多个分组的允许列表合并；任意分组的拒绝规则始终优先。";
    editor.innerHTML = `<header class="editor-head"><div class="editor-title-wrap"><p class="editor-kicker">CPA API Key</p><h1>${escapeHTML(keyLabel(index))}</h1><p class="editor-subtitle key-summary"><span class="mono masked-key">${escapeHTML(key.masked)}</span><span class="mono">SHA-256 ${escapeHTML(key.fingerprint)}</span></p></div></header>
      <div class="default-notice">${icons.key}<span>${message}</span></div>
      <section class="card"><div class="card-head"><h2>所属分组</h2><p>可多选分组；上游配置的允许与拒绝规则统一在分组中管理。</p></div>
        <div class="membership-list">${state.groups.map((group) => `<div class="membership-option"><label class="membership-choice"><input type="checkbox" data-key-group="${escapeHTML(group.id)}" ${key.group_ids.includes(group.id) ? "checked" : ""}><span><strong data-literal>${escapeHTML(group.name)}</strong><small>${group.allow_profiles.length} allow / ${group.deny_profiles.length} deny</small></span></label><button class="button secondary compact" type="button" data-action="open-group" data-group="${escapeHTML(group.id)}">编辑分组</button></div>`).join("") || '<p class="provider-empty">暂无分组，请先新建分组</p>'}</div>
        <div class="membership-toolbar"><button class="button secondary compact" type="button" data-action="create-group">新建分组</button><button class="button secondary compact" type="button" data-action="clear-key-groups" ${key.group_ids.length ? "" : "disabled"}>清空分组</button></div>
      </section>
      <section class="card"><div class="card-head"><h2>有效上游权限</h2><p>统计当前草稿的有效权限；修改后点击保存修改生效。</p></div><div class="effective-profiles">${state.profiles.map((profile) => `<span class="chip ${keyAllowsProfile(key, profile.id) ? "" : "deny"}"><span data-literal>${escapeHTML(profile.displayName || profile.id)}</span><small>${keyAllowsProfile(key, profile.id) ? "允许" : "拒绝"}</small></span>`).join("") || `<p class="provider-empty">${escapeHTML(state.profilesError || "没有可用的上游配置目录。")}</p>`}</div></section>
      <div class="privacy-note">Management Key 复用 CPAMC 已保存的同源会话；完整下游 CPA Key 仅在内存中用于计算 caller scope 和生成首尾脱敏显示，不会写入策略、DOM、浏览器存储或 URL。上游凭据仅在内存中用于复现 CPA profile ID，不会写入策略、DOM、浏览器存储或 URL。</div>`;
  }

  function renderGroupEditor(group) {
    const staleMembers = state.stalePolicies.filter((policy) => policy.group_ids.includes(group.id)).length;
    editor.innerHTML = `<header class="editor-head"><div class="editor-title-wrap"><p class="editor-kicker">Access group</p><h1 data-literal>${escapeHTML(group.name)}</h1><p class="editor-subtitle">修改分组规则会影响所有已加入此分组的 Key。</p></div><div class="group-actions"><button class="button secondary compact" type="button" data-action="rename-group">重命名</button><button class="button secondary compact danger-button" type="button" data-action="delete-group">删除分组</button></div></header>
      ${!state.accessControlEnabled ? '<div class="notice">访问控制已关闭：所有已认证 Key 均可访问全部上游配置。</div>' : ""}
      <section class="card rules-card"><div class="card-head"><h2>分组上游配置规则</h2><p>允许列表为空时不授予访问权限；拒绝规则在所有分组间优先。</p></div>
        ${profilePicker("allow_profiles", "允许上游配置", "仅授予列表中的上游配置；空列表不授予权限", group.allow_profiles, false)}
        ${profilePicker("deny_profiles", "拒绝上游配置", "命中后始终拒绝访问", group.deny_profiles, true)}
      </section>
      <section class="card"><div class="card-head"><h2>分组成员</h2><p>可多选 Key 加入当前分组，不影响这些 Key 的其他分组。</p></div>
        <div class="membership-toolbar"><button class="button secondary compact" type="button" data-action="all-group-keys">选择全部当前 Key</button><button class="button secondary compact" type="button" data-action="clear-group-keys">移除全部当前 Key</button></div>
        <div class="membership-list">${state.keys.map((key, index) => `<label class="membership-option"><input type="checkbox" data-group-key="${index}" ${key.group_ids.includes(group.id) ? "checked" : ""}><span><strong>${escapeHTML(keyLabel(index))}</strong><small class="mono">${escapeHTML(key.masked)} · ${escapeHTML(key.fingerprint)}</small></span></label>`).join("") || '<p class="provider-empty">CPA 当前没有 API Key</p>'}</div>
        ${staleMembers ? `<p class="membership-note">${staleMembers} caller scope · <span>失效 Key 的分组成员关系仍保留。</span></p>` : ""}
      </section>`;
  }

  function selectedGroup() {
    return state.groups.find((group) => group.id === state.selectedGroup) || null;
  }

  function openGroup(id) {
    state.selectedIndex = -1;
    state.selectedGroup = id;
    state.openPicker = "allow_profiles";
    state.pickerQuery = "";
    state.pickerCategory = "codex";
    state.pickerScroll = 0;
    renderAll();
  }

  function promptGroupName(current = "") {
    const entered = window.prompt(translateText("输入分组名称（最多 128 个字符）："), current);
    if (entered === null) return null;
    const name = entered.trim();
    if (!name || [...name].length > 128 || state.groups.some((group) => group.id !== (current ? state.selectedGroup : "") && group.name.toLowerCase() === name.toLowerCase())) {
      showToast("分组名称不能为空、超过 128 个字符或与现有名称重复。", "error");
      return null;
    }
    return name;
  }

  function createGroup() {
    const name = promptGroupName();
    if (!name) return;
    const random = new Uint8Array(16);
    window.crypto.getRandomValues(random);
    const id = `group-${Array.from(random, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    state.groups.push({ id, name, allow_profiles: [], deny_profiles: [] });
    markDirty();
    openGroup(id);
  }

  function deleteGroup() {
    const group = selectedGroup();
    if (!group || !window.confirm(translateText("删除分组并从所有 Key 中移除此分组？失去最后一个分组的 Key 将遵循全局默认策略。修改将在保存后生效。"))) return;
    state.groups = state.groups.filter((candidate) => candidate.id !== group.id);
    for (const key of state.keys) key.group_ids = key.group_ids.filter((id) => id !== group.id);
    for (const policy of state.stalePolicies) policy.group_ids = policy.group_ids.filter((id) => id !== group.id);
    state.selectedGroup = "";
    markDirty();
    renderAll();
  }

  function setKeyMembership(key, groupID, checked) {
    key.group_ids = checked ? [...new Set([...key.group_ids, groupID])] : key.group_ids.filter((id) => id !== groupID);
    key.hasPolicy = true;
  }

  function profileCategory(profile) {
    if (profile.kind === "oauth") return "oauth";
    const provider = String(profile.provider || "").trim().toLowerCase();
    return provider === "codex" || provider === "xai" ? provider : "other";
  }

  function profileSearchText(profile) {
    return `${profile.id || ""} ${profile.provider || ""} ${profile.displayName || ""} ${profile.kind || ""}`.toLowerCase();
  }

  function profileMatchesPicker(profile, query = state.pickerQuery) {
    return (state.pickerCategory === "all" || state.pickerCategory === profileCategory(profile))
      && profileSearchText(profile).includes(query.trim().toLowerCase());
  }

  function profileCategoryTabs(kind) {
    const categories = [["codex", "Codex"], ["xai", "xAI"], ["oauth", "OAuth"]];
    if (state.pickerCategory === "other" || state.profiles.some((profile) => profileCategory(profile) === "other")) categories.push(["other", "其他"]);
    categories.push(["all", "全部"]);
    return `<div class="profile-tabs" role="tablist" aria-label="上游配置类型">${categories.map(([id, label]) => {
      const count = state.profiles.filter((profile) => id === "all" || profileCategory(profile) === id).length;
      return `<button class="profile-tab" type="button" role="tab" id="${kind}-tab-${id}" aria-controls="${kind}-panel" aria-selected="${state.pickerCategory === id}" tabindex="${state.pickerCategory === id ? 0 : -1}" data-action="filter-profile-category" data-kind="${kind}" data-category="${id}"><span>${label}</span><span class="profile-tab-count">${count}</span></button>`;
    }).join("")}</div>`;
  }

  function profilePicker(kind, title, description, selectedProfiles, deny) {
    const selected = new Set(selectedProfiles);
    const matchedCount = state.profiles.filter((profile) => selectedProfiles.some((rule) => profileRuleMatches(rule, profile))).length;
    const isOpen = state.openPicker === kind;
    const summary = selected.has("*") ? "全部上游配置（*，包含未来新增）"
      : state.profiles.length ? `已匹配 ${matchedCount} / ${state.profiles.length} 个上游配置`
      : selectedProfiles.length ? `已保留 ${selectedProfiles.length} 条现有规则` : "上游配置目录不可用";
    const chips = selectedProfiles.map((rule) => {
      const wildcard = rule.includes("*") || rule.includes("?");
      const outsideCatalog = !wildcard && !state.profiles.some((profile) => profileRuleMatches(rule, profile));
      return `<span class="chip ${deny ? "deny" : ""}"><span data-literal>${escapeHTML(rule)}</span>${wildcard ? '<small>通配符</small>' : outsideCatalog ? '<small>目录外</small>' : ""}<button class="chip-remove" type="button" data-action="remove-profile" data-kind="${kind}" data-profile="${escapeHTML(rule)}" aria-label="移除此上游配置规则">${icons.close}</button></span>`;
    }).join("") || '<span class="empty-chips">尚未选择上游配置</span>';
    const wildcardSearch = "全部上游配置 all providers wildcard *";
    const wildcardVisible = state.pickerCategory === "all" && wildcardSearch.includes(state.pickerQuery.trim().toLowerCase());
    const visibleCount = state.profiles.filter((profile) => profileMatchesPicker(profile)).length;
    const wildcardRow = `<button class="profile-option wildcard-option ${selected.has("*") ? "selected" : ""}" type="button" role="option" aria-selected="${selected.has("*")}" data-action="toggle-profile" data-kind="${kind}" data-profile="*" data-category="all" data-search="${wildcardSearch}" ${wildcardVisible ? "" : "hidden"}><span class="profile-checkbox" aria-hidden="true">${selected.has("*") ? icons.check : ""}</span><span class="profile-option-copy"><strong>全部上游配置</strong><small>* · 自动包含未来新增上游配置</small></span><span class="profile-badge">通配符</span></button>`;
    const rows = state.profiles.map((profile) => {
      const explicitRule = selected.has(profile.id) ? profile.id : profile.legacyID && selected.has(profile.legacyID) ? profile.legacyID : "";
      const explicit = Boolean(explicitRule);
      const matchedRule = explicit ? "" : selectedProfiles.find((rule) => profileRuleMatches(rule, profile));
      const checked = explicit || Boolean(matchedRule);
      return `<button class="profile-option ${checked ? "selected" : ""} ${matchedRule ? "derived" : ""}" type="button" role="option" aria-selected="${checked}" ${matchedRule ? 'disabled title="由通配符匹配；移除通配符后可单独选择。"' : ""} data-action="toggle-profile" data-kind="${kind}" data-profile="${escapeHTML(explicitRule || profile.id)}" data-category="${profileCategory(profile)}" data-search="${escapeHTML(profileSearchText(profile))}" ${profileMatchesPicker(profile) ? "" : "hidden"}><span class="profile-checkbox" aria-hidden="true">${checked ? icons.check : ""}</span><span class="profile-option-copy"><strong data-literal>${escapeHTML(profile.displayName || profile.id)}</strong><small>${escapeHTML(profile.id)}</small>${matchedRule ? `<small>${escapeHTML(matchedRule)}</small>` : ""}</span><span class="profile-badge">${escapeHTML(profile.kind === "oauth" ? "OAuth" : profile.provider || "API")}</span></button>`;
    }).join("");
    return `<div class="profile-editor ${deny ? "deny" : ""}"><div class="tag-head"><div><strong>${escapeHTML(title)}</strong><span>${escapeHTML(description)}</span></div><span class="selection-count">${selectedProfiles.length} 条规则</span></div>
      <button class="profile-trigger ${isOpen ? "open" : ""}" type="button" data-action="toggle-picker" data-kind="${kind}" aria-expanded="${isOpen}"><span>${escapeHTML(summary)}</span><span class="picker-chevron" aria-hidden="true">⌄</span>${state.profiles.length ? `<progress class="selection-meter" max="${state.profiles.length}" value="${matchedCount}" aria-label="已匹配 ${matchedCount} / ${state.profiles.length} 个上游配置"></progress>` : ""}</button>
      ${isOpen ? `<div class="profile-panel">${profileCategoryTabs(kind)}<div id="${kind}-panel" role="tabpanel" aria-labelledby="${kind}-tab-${state.pickerCategory}"><div class="profile-search"><span>${icons.search}</span><input type="search" data-profile-search="${kind}" value="${escapeHTML(state.pickerQuery)}" autocomplete="off" placeholder="搜索上游配置…" aria-label="搜索${escapeHTML(title)}"></div><div class="profile-list" role="listbox" aria-label="${escapeHTML(title)}" aria-multiselectable="true">${wildcardRow}${rows}<p class="profile-empty" ${visibleCount || wildcardVisible ? "hidden" : ""}>没有匹配的上游配置</p></div><div class="profile-panel-footer"><span>已匹配 ${matchedCount} / ${state.profiles.length}</span><div><button type="button" data-action="select-all-profiles" data-kind="${kind}" ${visibleCount ? "" : "disabled"}>全选筛选结果</button><button type="button" data-action="clear-profiles" data-kind="${kind}" ${visibleCount ? "" : "disabled"}>清除筛选项</button></div></div></div>${state.profilesError ? `<div class="catalog-notice"><span>${escapeHTML(state.profilesError)}</span><button type="button" data-action="refresh-profiles">重新加载</button></div>` : ""}</div>` : ""}
      <div class="chips">${chips}</div></div>`;
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    const locale = currentLanguage === "zh-CN" ? "zh-CN" : currentLanguage === "zh-TW" ? "zh-TW" : currentLanguage === "ru" ? "ru-RU" : "en-US";
    return new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function selectedKey() {
    return state.selectedIndex >= 0 ? state.keys[state.selectedIndex] : null;
  }

  function validProfileKind(kind) {
    return kind === "allow_profiles" || kind === "deny_profiles";
  }

  function restorePickerView(kind, focusSearch = false) {
    requestAnimationFrame(() => {
      const input = editor.querySelector(`[data-profile-search="${kind}"]`);
      const list = input?.closest(".profile-panel")?.querySelector(".profile-list");
      if (input) filterProfilePicker(input);
      if (list) list.scrollTop = state.pickerScroll;
      if (focusSearch) input?.focus({ preventScroll: true });
    });
  }

  function updateProfiles(kind, updater) {
    if (state.busy || !validProfileKind(kind)) return;
    const key = selectedGroup();
    if (!key) return;
    const currentList = editor.querySelector(`[data-profile-search="${kind}"]`)?.closest(".profile-panel")?.querySelector(".profile-list");
    state.pickerScroll = currentList?.scrollTop || 0;
    const nextProfiles = normalizeProfiles(updater([...key[kind]]));
    if (nextProfiles.length === key[kind].length && nextProfiles.every((profile, index) => profile === key[kind][index])) return;
    key[kind] = nextProfiles;
    markDirty();
    scheduleNavRender();
    renderEditor();
    if (state.openPicker === kind) restorePickerView(kind, true);
  }

  function toggleProfileRule(kind, profileID) {
    if (!profileID) return;
    // Allow and deny lists remain independent. An explicit deny takes priority,
    // including when the allow list contains a wildcard.
    updateProfiles(kind, (rules) => rules.includes(profileID) ? rules.filter((rule) => rule !== profileID) : [...rules, profileID]);
  }

  function selectAllProfiles(kind) {
    updateProfiles(kind, (rules) => [...rules, ...state.profiles.filter((profile) => profileMatchesPicker(profile)).map((profile) => profile.id)]);
  }

  function clearFilteredProfiles(kind) {
    const ids = new Set(state.profiles.filter((profile) => profileMatchesPicker(profile)).flatMap((profile) => [profile.id, profile.legacyID].filter(Boolean)));
    updateProfiles(kind, (rules) => rules.filter((rule) => !ids.has(rule)));
  }

  function filterProfilePicker(input) {
    const query = input.value.trim().toLowerCase();
    state.pickerQuery = input.value;
    const panel = input.closest(".profile-panel");
    if (!panel) return;
    let visible = 0;
    panel.querySelectorAll(".profile-option").forEach((option) => {
      const matches = (state.pickerCategory === "all" || option.dataset.category === state.pickerCategory)
        && option.dataset.search.includes(query);
      option.hidden = !matches;
      if (matches) visible += 1;
    });
    const empty = panel.querySelector(".profile-empty");
    if (empty) empty.hidden = visible > 0;
    const hasProfiles = state.profiles.some((profile) => profileMatchesPicker(profile));
    panel.querySelectorAll('[data-action="select-all-profiles"], [data-action="clear-profiles"]').forEach((button) => { button.disabled = !hasProfiles; });
  }

  function setProfileBusy(busy) {
    state.profileBusy = busy;
    refreshDataButton.disabled = busy || state.busy;
    saveButton.disabled = busy || state.busy || !state.dirty;
    reloadButton.disabled = busy || state.busy || !state.status?.persistent_updates;
    if (!busy) finalizeEndedSession();
  }

  async function refreshProfileCatalog() {
    if (state.busy || state.profileBusy) return;
    setProfileBusy(true);
    const retryButton = editor.querySelector('[data-action="refresh-profiles"]');
    if (retryButton) { retryButton.disabled = true; retryButton.innerHTML = `${icons.spinner}<span>加载中</span>`; }
    try {
      const result = await fetchCurrentKeys({ includeCatalog: true });
      state.profiles = result.catalog?.profiles || [];
      state.profilesError = result.catalog?.error || "";
      renderEditor();
      showToast(state.profiles.length ? `已加载 ${state.profiles.length} 个上游配置` : state.profilesError, state.profiles.length ? "success" : "error");
    } finally {
      setProfileBusy(false);
      syncHeader();
    }
  }

  function serializablePolicy() {
    const active = state.keys.filter((key) => key.hasPolicy || hasRules(key)).map((key) => ({ caller_scope: key.scope, group_ids: [...key.group_ids] }));
    const stale = state.stalePolicies.map((policy) => ({ caller_scope: policy.caller_scope, group_ids: [...policy.group_ids] }));
    return {
      version: 3,
      access_control_enabled: state.accessControlEnabled,
      default_deny: state.defaultDeny,
      groups: state.groups.map((group) => ({ id: group.id, name: group.name, allow_profiles: [...group.allow_profiles], deny_profiles: [...group.deny_profiles] })),
      policies: [...active, ...stale]
    };
  }

  function scopeSet(keys) {
    return new Set(keys.map((key) => key.scope));
  }

  function setsEqual(left, right) {
    if (left.size !== right.size) return false;
    for (const value of left) if (!right.has(value)) return false;
    return true;
  }

  async function save() {
    if (!state.dirty || state.busy || state.profileBusy) return;
    const expectedRevision = state.revision;
    const submittedPolicy = serializablePolicy();
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "save");
    try {
      const latestKeys = await fetchCurrentKeys();
      if (!setsEqual(scopeSet(state.keys), scopeSet(latestKeys))) {
        const changed = new Error("CPA API Key 列表已变化；为避免策略错配，保存已中止。请刷新数据后重新检查规则。");
        changed.code = "key_set_changed";
        throw changed;
      }

      const response = await api(PATHS.policies, {
        method: "PUT",
        headers: { "If-Match": `"rev-${expectedRevision}"` },
        body: JSON.stringify(submittedPolicy)
      });
      let keySetChangedAfterSave = false;
      let postSaveCheckError = null;
      try {
        const keysAfterSave = await fetchCurrentKeys();
        keySetChangedAfterSave = !setsEqual(scopeSet(state.keys), scopeSet(keysAfterSave));
        if (keySetChangedAfterSave) {
          state.keys = keysAfterSave;
          state.selectedIndex = preferredScope ? state.keys.findIndex((key) => key.scope === preferredScope) : -1;
        }
      } catch (verificationError) {
        postSaveCheckError = verificationError;
      }
      applyPolicyDocument(response?.policy || submittedPolicy);
      state.revision = Number(response?.revision ?? expectedRevision + 1);
      state.dirty = false;
      renderAll();
      if (keySetChangedAfterSave) {
        showToast("策略已保存，但 CPA Key 列表在保存期间发生变化；新 Key 遵循全局默认策略，请检查分组。", "error");
      } else if (postSaveCheckError) {
        showToast(`策略已保存，但无法复核 CPA Key 列表：${postSaveCheckError.message}`, "error");
      } else {
        showToast(response?.persistent ? "策略已保存并持久化" : "策略已保存到内存", "success");
      }
      try {
        state.status = await api(PATHS.status, { method: "GET" });
        syncHeader();
        syncPersistence();
      } catch (refreshError) {
        showToast(`策略已保存，但状态刷新失败：${refreshError.message}`, "error");
      }
    } catch (error) {
      if (error.code === "timeout") {
        const confirmed = await confirmTimedOutSave(submittedPolicy, expectedRevision);
        showToast(confirmed ? "保存响应超时，但已重新读取并确认提交成功" : "保存结果无法确认；本地修改已保留，请刷新后核对。", confirmed ? "success" : "error");
      } else if (error.code === "key_set_changed") {
        showToast(error.message, "error", "刷新数据", refreshData);
      } else if (error.status === 412) {
        showToast("策略已被其他管理员或配置重载修改。请刷新数据后再保存。", "error", "刷新数据", refreshData);
      } else {
        showToast(error.message, "error");
      }
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function confirmTimedOutSave(submittedPolicy, expectedRevision) {
    try {
      const policies = await api(PATHS.policies, { method: "GET" });
      const remoteRevision = Number(policies?.revision ?? 0);
      if (remoteRevision <= expectedRevision || !policiesEquivalent(submittedPolicy, policies?.policy)) return false;
      applyPolicyDocument(policies.policy);
      state.revision = remoteRevision;
      state.dirty = false;
      try { state.status = await api(PATHS.status, { method: "GET" }); } catch (_) { /* policy confirmation is sufficient */ }
      renderAll();
      return true;
    } catch (_) {
      return false;
    }
  }

  function policiesEquivalent(leftRaw, rightRaw) {
    const canonical = (raw) => {
      const doc = normalizePolicyDocument(raw);
      return {
        ...doc,
        groups: doc.groups.map((group) => ({ ...group, allow_profiles: [...group.allow_profiles].sort(), deny_profiles: [...group.deny_profiles].sort() })).sort((left, right) => left.id.localeCompare(right.id)),
        policies: doc.policies.map((policy) => ({ caller_scope: policy.caller_scope, group_ids: [...policy.group_ids].sort() })).sort((left, right) => left.caller_scope.localeCompare(right.caller_scope))
      };
    };
    return JSON.stringify(canonical(leftRaw)) === JSON.stringify(canonical(rightRaw));
  }

  async function refreshData() {
    if (state.busy) return;
    if (state.dirty && !window.confirm("刷新会放弃尚未保存的上游配置规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "refresh");
    try {
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已刷新 CPA Key 与策略", "success");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  async function reload() {
    if (state.busy || !state.status?.persistent_updates) return;
    if (state.dirty && !window.confirm("从策略文件重载会放弃尚未保存的上游配置规则。是否继续？")) return;
    const preferredScope = selectedKey()?.scope || "";
    setBusy(true, "reload");
    let reloaded = false;
    try {
      await api(PATHS.reload, { method: "POST" });
      reloaded = true;
      const remote = await fetchRemoteData();
      installRemoteData(remote, preferredScope);
      renderAll();
      showToast("已从策略文件重载", "success");
    } catch (error) {
      showToast(reloaded ? `策略已重载，但界面刷新失败：${error.message}` : error.message, "error");
    } finally {
      setBusy(false);
      syncHeader();
    }
  }

  function showToast(message, type = "success", actionLabel = "", action = null) {
    const toast = document.createElement("div");
    toast.className = `toast ${type} enter`;
    toast.innerHTML = `${type === "error" ? icons.warning : icons.check}<span>${escapeHTML(message)}</span>${actionLabel ? `<button type="button">${escapeHTML(actionLabel)}</button>` : ""}`;
    $("#toastRegion").appendChild(toast);
    const button = toast.querySelector("button");
    let timer = window.setTimeout(remove, actionLabel ? 7000 : 3600);
    if (button) button.addEventListener("click", () => { window.clearTimeout(timer); action?.(); remove(); });
    requestAnimationFrame(() => toast.classList.remove("enter"));
    function remove() {
      if (!toast.isConnected) return;
      toast.classList.add("exit");
      window.setTimeout(() => toast.remove(), 190);
    }
  }

  function resolveCPAMCTheme() {
    try {
      if (window.self !== window.top) {
        const parentTheme = window.parent.document.documentElement.getAttribute("data-theme");
        return parentTheme === "dark" || parentTheme === "white" ? parentTheme : "light";
      }
    } catch (_) { /* same-origin storage remains the fallback */ }
    try {
      const persisted = JSON.parse(localStorage.getItem(CPAMC_THEME_KEY) || "null");
      const theme = persisted?.state?.theme;
      if (theme === "dark" || theme === "white" || theme === "light") return theme;
      if (theme === "auto") return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
    } catch (_) { /* use system preference */ }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "white";
  }

  function syncTheme() {
    const theme = resolveCPAMCTheme();
    if (theme === "light") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
  }

  function initializeChrome() {
    document.documentElement.classList.toggle("is-embedded", window.self !== window.top);
    $("#searchIcon").innerHTML = icons.search;
    refreshDataButton.innerHTML = icons.refresh;
    reloadButton.innerHTML = `${icons.file}<span class="label-long">Reload from policy file</span>`;
    saveButton.innerHTML = `${icons.save}<span class="label-long">Saved</span>`;
    applyLanguage();
    const languageSelect = $("#languageSelect");
    if (languageSelect) languageSelect.addEventListener("change", (event) => {
      const language = normalizeLanguage(event.target.value) || "en";
      try { localStorage.setItem(CPAMC_LANGUAGE_KEY, JSON.stringify({ state: { language } })); } catch (_) { /* preference is optional */ }
      applyLanguage(language);
    });
    new MutationObserver(() => localizePage()).observe(document.body, { childList: true, subtree: true, characterData: true });
    syncTheme();
    try {
      if (window.self !== window.top) {
        new MutationObserver(syncTheme).observe(window.parent.document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
      }
    } catch (_) { /* cross-origin embedding is unsupported for session reuse */ }
  }

  $("#retrySessionButton").addEventListener("click", connectFromCPAMC);
  window.addEventListener("storage", (event) => {
    if (event.key === CPAMC_THEME_KEY) syncTheme();
    if (event.key === CPAMC_LANGUAGE_KEY) applyLanguage();
    if (event.key !== CPAMC_AUTH_KEY && event.key !== "isLoggedIn") return;
    if (app.hidden) {
      connectFromCPAMC();
      return;
    }
    if (!readCPAMCManagementKey()) {
      state.sessionEnded = true;
      finalizeEndedSession();
    }
  });

  refreshDataButton.addEventListener("click", refreshData);
  saveButton.addEventListener("click", save);
  reloadButton.addEventListener("click", reload);
  $("#searchInput").addEventListener("input", (event) => { state.search = event.target.value; scheduleNavRender(); });

  nav.addEventListener("click", (event) => {
    if (state.busy) return;
    const item = event.target.closest("[data-select]");
    if (!item) return;
    if (item.dataset.select === "create-group") { createGroup(); return; }
    if (item.dataset.select === "group") { openGroup(item.dataset.group); return; }
    state.selectedGroup = "";
    state.selectedIndex = item.dataset.select === "overview" ? -1 : Number(item.dataset.index);
    state.openPicker = "";
    state.pickerQuery = "";
    state.pickerScroll = 0;
    renderNav();
    renderEditor();
  });

  editor.addEventListener("click", (event) => {
    if (state.busy) return;
    const target = event.target.closest("button");
    if (!target) return;
    const action = target.dataset.action;
    const kind = target.dataset.kind;
    if (action === "create-group") {
      createGroup();
    } else if (action === "open-group") {
      openGroup(target.dataset.group);
    } else if (action === "rename-group") {
      const group = selectedGroup();
      if (!group) return;
      const name = promptGroupName(group.name);
      if (name && name !== group.name) { group.name = name; markDirty(); renderAll(); }
    } else if (action === "delete-group") {
      deleteGroup();
    } else if (action === "clear-key-groups") {
      const key = selectedKey();
      if (!key) return;
      key.group_ids = []; key.hasPolicy = true;
      markDirty(); renderAll();
    } else if (action === "all-group-keys" || action === "clear-group-keys") {
      const group = selectedGroup();
      if (!group) return;
      for (const key of state.keys) setKeyMembership(key, group.id, action === "all-group-keys");
      markDirty(); renderAll();
    } else if (action === "toggle-picker" && validProfileKind(kind)) {
      const opening = state.openPicker !== kind;
      state.openPicker = opening ? kind : "";
      if (opening) { state.pickerQuery = ""; state.pickerCategory = "codex"; state.pickerScroll = 0; }
      renderEditor();
      if (opening) restorePickerView(kind, true);
    } else if (action === "filter-profile-category" && validProfileKind(kind)) {
      const category = target.dataset.category;
      if (!["codex", "xai", "oauth", "other", "all"].includes(category)) return;
      state.pickerCategory = category;
      state.pickerScroll = 0;
      renderEditor();
      editor.querySelector(`[data-kind="${kind}"][data-category="${category}"][role="tab"]`)?.focus({ preventScroll: true });
    } else if (action === "toggle-profile") {
      toggleProfileRule(kind, target.dataset.profile, target.dataset.derived === "true");
    } else if (action === "remove-profile") {
      updateProfiles(kind, (profiles) => profiles.filter((profile) => profile !== target.dataset.profile));
    } else if (action === "select-all-profiles") {
      selectAllProfiles(kind);
    } else if (action === "clear-profiles") {
      clearFilteredProfiles(kind);
    } else if (action === "refresh-profiles") {
      refreshProfileCatalog().catch((error) => showToast(error.message, "error"));
    }
  });

  editor.addEventListener("keydown", (event) => {
    if (!event.target.matches('[role="tab"]')) return;
    const tabs = [...event.target.closest('[role="tablist"]').querySelectorAll('[role="tab"]')];
    const index = tabs.indexOf(event.target);
    let next;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    tabs[next].click();
  });

  editor.addEventListener("change", (event) => {
    if (state.busy) return;
    const input = event.target;
    const listScroll = input.closest(".membership-list")?.scrollTop || 0;
    let focusSelector = "";
    if (input.matches("[data-setting]")) {
      const setting = input.dataset.setting;
      if (setting !== "accessControlEnabled" && setting !== "defaultDeny") return;
      state[setting] = input.checked;
      focusSelector = `[data-setting="${setting}"]`;
    } else if (input.matches("[data-key-group]")) {
      const key = selectedKey();
      if (!key || !state.groups.some((group) => group.id === input.dataset.keyGroup)) return;
      setKeyMembership(key, input.dataset.keyGroup, input.checked);
      focusSelector = `[data-key-group="${input.dataset.keyGroup}"]`;
    } else if (input.matches("[data-group-key]")) {
      const group = selectedGroup();
      const key = state.keys[Number(input.dataset.groupKey)];
      if (!group || !key) return;
      setKeyMembership(key, group.id, input.checked);
      focusSelector = `[data-group-key="${input.dataset.groupKey}"]`;
    } else return;
    markDirty();
    renderAll();
    const replacement = editor.querySelector(focusSelector);
    const list = replacement?.closest(".membership-list");
    if (list) list.scrollTop = listScroll;
    replacement?.focus({ preventScroll: true });
  });

  editor.addEventListener("input", (event) => {
    if (event.target.matches("[data-profile-search]")) filterProfilePicker(event.target);
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s" && !app.hidden) {
      event.preventDefault();
      save();
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (!state.dirty) return;
    event.preventDefault();
    event.returnValue = "";
  });

  initializeChrome();
  connectFromCPAMC();
})();
