package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

const maxPolicyFileSize = 2 << 20

type pluginConfig struct {
	Enabled              *bool          `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Priority             int            `json:"priority,omitempty" yaml:"priority,omitempty"`
	Store                any            `json:"store,omitempty" yaml:"store,omitempty"`
	PolicyFile           string         `json:"policy_file,omitempty" yaml:"policy_file,omitempty"`
	Version              int            `json:"version,omitempty" yaml:"version,omitempty"`
	AccessControlEnabled *bool          `json:"access_control_enabled,omitempty" yaml:"access_control_enabled,omitempty"`
	DefaultDeny          *bool          `json:"default_deny,omitempty" yaml:"default_deny,omitempty"`
	Groups               []groupConfig  `json:"groups,omitempty" yaml:"groups,omitempty"`
	Policies             []policyConfig `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type policyDocument struct {
	Version              int            `json:"version" yaml:"version" toml:"version"`
	AccessControlEnabled *bool          `json:"access_control_enabled" yaml:"access_control_enabled" toml:"access_control_enabled"`
	DefaultDeny          *bool          `json:"default_deny" yaml:"default_deny" toml:"default_deny"`
	Groups               []groupConfig  `json:"groups" yaml:"groups" toml:"groups"`
	Policies             []policyConfig `json:"policies" yaml:"policies" toml:"policies"`
}

type policyConfig struct {
	CallerScope string   `json:"caller_scope" yaml:"caller_scope" toml:"caller_scope"`
	GroupIDs    []string `json:"group_ids" yaml:"group_ids" toml:"group_ids"`
	// These fields are accepted only while migrating existing v2 documents.
	AllowProfiles []string `json:"allow_profiles,omitempty" yaml:"allow_profiles,omitempty" toml:"allow_profiles,omitempty"`
	DenyProfiles  []string `json:"deny_profiles,omitempty" yaml:"deny_profiles,omitempty" toml:"deny_profiles,omitempty"`
}

type groupConfig struct {
	ID            string   `json:"id" yaml:"id" toml:"id"`
	Name          string   `json:"name" yaml:"name" toml:"name"`
	AllowProfiles []string `json:"allow_profiles" yaml:"allow_profiles" toml:"allow_profiles"`
	DenyProfiles  []string `json:"deny_profiles" yaml:"deny_profiles" toml:"deny_profiles"`
}

type runtimePolicy struct {
	AllowProfiles []string
	DenyProfiles  []string
}

type policySnapshot struct {
	ByCallerScope        map[string]runtimePolicy
	AccessControlEnabled bool
	DefaultDeny          bool
	BlockAll             bool
}

type state struct {
	mu             sync.RWMutex
	config         pluginConfig
	snapshot       policySnapshot
	source         string
	updatedAt      time.Time
	hostSchema     uint32
	hasValidPolicy bool
	lastError      string
	runtimeWarning string
	revision       uint64
	pickCursor     map[string]uint64
	legacyAliases  map[string]map[string]string
}

var (
	globalState = state{snapshot: failClosedSnapshot(), pickCursor: make(map[string]uint64), legacyAliases: make(map[string]map[string]string)}
	mutationMu  sync.Mutex
)

func failClosedSnapshot() policySnapshot {
	return policySnapshot{ByCallerScope: make(map[string]runtimePolicy), AccessControlEnabled: true, DefaultDeny: true, BlockAll: true}
}

func (s *state) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pluginConfig{}
	s.snapshot = failClosedSnapshot()
	s.source = ""
	s.updatedAt = time.Time{}
	s.hostSchema = 0
	s.hasValidPolicy = false
	s.lastError = ""
	s.runtimeWarning = ""
	s.revision = 0
	s.pickCursor = make(map[string]uint64)
	s.legacyAliases = make(map[string]map[string]string)
}

func (s *state) current() (pluginConfig, policySnapshot, string, time.Time, uint32, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError
}

func (s *state) currentWithRevision() (pluginConfig, policySnapshot, string, time.Time, uint32, string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError, s.revision
}

func (s *state) replace(cfg pluginConfig, snapshot policySnapshot, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	s.snapshot = snapshot
	s.source = source
	s.updatedAt = time.Now().UTC()
	s.hasValidPolicy = true
	s.lastError = ""
	s.runtimeWarning = ""
	s.revision++
	s.legacyAliases = make(map[string]map[string]string)
}

func (s *state) policyRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *state) rememberLegacyAlias(scope, current, legacy string) {
	scope = strings.TrimSpace(scope)
	current = strings.TrimSpace(current)
	legacy = strings.TrimSpace(legacy)
	if scope == "" || current == "" || legacy == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.legacyAliases == nil {
		s.legacyAliases = make(map[string]map[string]string)
	}
	if s.legacyAliases[scope] == nil {
		s.legacyAliases[scope] = make(map[string]string)
	}
	s.legacyAliases[scope][current] = legacy
}

func (s *state) legacyAlias(scope, current string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.legacyAliases[strings.TrimSpace(scope)][strings.TrimSpace(current)]
}

func (s *state) setHostSchema(schema uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
}

func (s *state) recordPolicyError(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = cause.Error()
}

func (s *state) recordRuntimeWarning(message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtimeWarning = message
}

func (s *state) clearRuntimeWarning() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.runtimeWarning = ""
}

func (s *state) failClosedOrPreserve(cfg pluginConfig, schema uint32, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
	s.lastError = cause.Error()
	if s.hasValidPolicy {
		return
	}
	s.config = cfg
	s.snapshot = failClosedSnapshot()
	s.source = "fail-closed: " + cause.Error()
	s.updatedAt = time.Now().UTC()
	s.revision++
}

func configure(raw []byte) error {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	var req lifecycleRequest
	if err := decodeJSON(raw, &req); err != nil {
		return err
	}
	cfg := pluginConfig{Version: policyVersion}
	if req.SchemaVersion < schemaVersion {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("%s requires CPA plugin RPC schema 2 or newer (CPA v7.2.103+)", pluginID))
		return nil
	}
	if len(req.ConfigYAML) > 0 {
		if err := decodeStrictYAML(req.ConfigYAML, &cfg); err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("decode plugin config: %w", err))
			return nil
		}
	}
	cfg.PolicyFile = strings.TrimSpace(cfg.PolicyFile)

	document := documentFromConfig(cfg)
	source := "inline config"
	if cfg.PolicyFile != "" {
		loaded, err := readPolicyFile(cfg.PolicyFile)
		if err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
			return nil
		}
		document = loaded
		source = cfg.PolicyFile
	}

	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
		return nil
	}
	applyDocumentToConfig(&cfg, sanitized)
	globalState.setHostSchema(req.SchemaVersion)
	globalState.replace(cfg, snapshot, source)
	return nil
}

func documentFromConfig(cfg pluginConfig) policyDocument {
	return policyDocument{Version: cfg.Version, AccessControlEnabled: cloneBool(cfg.AccessControlEnabled), DefaultDeny: cloneBool(cfg.DefaultDeny), Groups: cloneGroupConfigs(cfg.Groups), Policies: clonePolicyConfigs(cfg.Policies)}
}

func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func applyDocumentToConfig(cfg *pluginConfig, document policyDocument) {
	cfg.Version = document.Version
	cfg.AccessControlEnabled = cloneBool(document.AccessControlEnabled)
	cfg.DefaultDeny = cloneBool(document.DefaultDeny)
	cfg.Groups = cloneGroupConfigs(document.Groups)
	cfg.Policies = clonePolicyConfigs(document.Policies)
}

func cloneGroupConfigs(groups []groupConfig) []groupConfig {
	cloned := make([]groupConfig, len(groups))
	for index, group := range groups {
		cloned[index] = groupConfig{ID: group.ID, Name: group.Name, AllowProfiles: append([]string{}, group.AllowProfiles...), DenyProfiles: append([]string{}, group.DenyProfiles...)}
	}
	return cloned
}

func clonePolicyConfigs(policies []policyConfig) []policyConfig {
	cloned := make([]policyConfig, len(policies))
	for index, policy := range policies {
		cloned[index] = policyConfig{
			CallerScope: policy.CallerScope,
			GroupIDs:    append([]string{}, policy.GroupIDs...),
		}
		if policy.AllowProfiles != nil {
			cloned[index].AllowProfiles = append([]string{}, policy.AllowProfiles...)
		}
		if policy.DenyProfiles != nil {
			cloned[index].DenyProfiles = append([]string{}, policy.DenyProfiles...)
		}
	}
	return cloned
}

func readPolicyFile(path string) (policyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return policyDocument{}, fmt.Errorf("open policy file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return policyDocument{}, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return policyDocument{}, fmt.Errorf("policy file %q is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return policyDocument{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > maxPolicyFileSize {
		return policyDocument{}, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	var document policyDocument
	var errDecode error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		errDecode = decodeStrictTOML(raw, &document)
	} else {
		errDecode = decodeStrictYAML(raw, &document)
	}
	if errDecode != nil {
		return policyDocument{}, fmt.Errorf("decode policy file %q: %w", path, errDecode)
	}
	return document, nil
}

func decodeStrictTOML(raw []byte, target any) error {
	metadata, errDecode := toml.Decode(string(raw), target)
	if errDecode != nil {
		return errDecode
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return fmt.Errorf("unknown TOML fields: %s", strings.Join(keys, ", "))
	}
	return nil
}

func decodeStrictYAML(raw []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not allowed")
}

func compileDocument(document policyDocument) (policySnapshot, policyDocument, error) {
	if document.Version != 2 && document.Version != policyVersion {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("unsupported policy version %d; only versions 2 and 3 are supported", document.Version)
	}
	// Own all slices before normalization, so failed validation cannot mutate the
	// last valid config or a caller's draft through shared backing arrays.
	document.Policies = clonePolicyConfigs(document.Policies)
	document.Groups = cloneGroupConfigs(document.Groups)
	if document.Version == 2 {
		var err error
		document, err = migrateV2Document(document)
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
	}
	enabled := boolValue(document.AccessControlEnabled, true)
	defaultDeny := boolValue(document.DefaultDeny, false)
	document.AccessControlEnabled = &enabled
	document.DefaultDeny = &defaultDeny
	groups := make(map[string]groupConfig, len(document.Groups))
	names := make(map[string]struct{}, len(document.Groups))
	for index := range document.Groups {
		group := &document.Groups[index]
		group.ID = strings.TrimSpace(group.ID)
		group.Name = strings.TrimSpace(group.Name)
		if !validGroupID(group.ID) {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("groups[%d].id must contain 1 to 128 ASCII letters, digits, underscores or hyphens", index)
		}
		if _, exists := groups[group.ID]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate group id at groups[%d]", index)
		}
		if group.Name == "" || utf8.RuneCountInString(group.Name) > 128 {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("groups[%d].name must contain 1 to 128 characters", index)
		}
		name := strings.ToLower(group.Name)
		if _, exists := names[name]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate group name at groups[%d]", index)
		}
		names[name] = struct{}{}
		var err error
		group.AllowProfiles, err = normalizePatterns(group.AllowProfiles, fmt.Sprintf("groups[%d].allow_profiles", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		group.DenyProfiles, err = normalizePatterns(group.DenyProfiles, fmt.Sprintf("groups[%d].deny_profiles", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		groups[group.ID] = *group
	}

	snapshot := policySnapshot{ByCallerScope: make(map[string]runtimePolicy), AccessControlEnabled: enabled, DefaultDeny: defaultDeny}
	seenScopes := make(map[string]struct{}, len(document.Policies))
	for index := range document.Policies {
		item := &document.Policies[index]
		item.CallerScope = strings.ToLower(strings.TrimSpace(item.CallerScope))
		if !validSHA256(item.CallerScope) {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("policies[%d].caller_scope must be 64 hexadecimal characters", index)
		}
		if _, exists := seenScopes[item.CallerScope]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate caller_scope at policies[%d]", index)
		}
		seenScopes[item.CallerScope] = struct{}{}
		if item.AllowProfiles != nil || item.DenyProfiles != nil {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("policies[%d] must use group_ids; profile rules belong to groups", index)
		}
		policy := runtimePolicy{}
		seenGroups := make(map[string]struct{}, len(item.GroupIDs))
		for groupIndex := range item.GroupIDs {
			id := strings.TrimSpace(item.GroupIDs[groupIndex])
			group, exists := groups[id]
			if !exists {
				return policySnapshot{}, policyDocument{}, fmt.Errorf("policies[%d].group_ids[%d] references an unknown group", index, groupIndex)
			}
			if _, duplicate := seenGroups[id]; duplicate {
				return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate group reference at policies[%d].group_ids[%d]", index, groupIndex)
			}
			seenGroups[id] = struct{}{}
			item.GroupIDs[groupIndex] = id
			policy.AllowProfiles = append(policy.AllowProfiles, group.AllowProfiles...)
			policy.DenyProfiles = append(policy.DenyProfiles, group.DenyProfiles...)
		}
		sort.Strings(item.GroupIDs)
		// No memberships is the unassigned/new-key state. Referencing an empty
		// group is different: it is an explicit whitelist with no grants.
		if len(item.GroupIDs) > 0 {
			snapshot.ByCallerScope[item.CallerScope] = policy
		}
	}
	return snapshot, document, nil
}

func validGroupID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func migrateV2Document(document policyDocument) (policyDocument, error) {
	if len(document.Groups) > 0 {
		return policyDocument{}, fmt.Errorf("version 2 cannot define groups; use version 3")
	}
	document.Version = policyVersion
	seen := make(map[string]struct{}, len(document.Policies))
	for index := range document.Policies {
		policy := &document.Policies[index]
		if len(policy.GroupIDs) > 0 {
			return policyDocument{}, fmt.Errorf("version 2 policies cannot define group_ids; use version 3")
		}
		scope := strings.ToLower(strings.TrimSpace(policy.CallerScope))
		if !validSHA256(scope) {
			return policyDocument{}, fmt.Errorf("policies[%d].caller_scope must be 64 hexadecimal characters", index)
		}
		if _, exists := seen[scope]; exists {
			return policyDocument{}, fmt.Errorf("duplicate caller_scope at policies[%d]", index)
		}
		seen[scope] = struct{}{}
		allow, err := normalizePatterns(policy.AllowProfiles, fmt.Sprintf("policies[%d].allow_profiles", index))
		if err != nil {
			return policyDocument{}, err
		}
		deny, err := normalizePatterns(policy.DenyProfiles, fmt.Sprintf("policies[%d].deny_profiles", index))
		if err != nil {
			return policyDocument{}, err
		}
		// V2's empty allow list meant all profiles. Preserve that existing grant
		// explicitly while new v3 groups use an empty, restrictive whitelist.
		if len(allow) == 0 {
			allow = []string{"*"}
		}
		id := "migrated-" + scope
		document.Groups = append(document.Groups, groupConfig{ID: id, Name: "Migrated " + scope, AllowProfiles: allow, DenyProfiles: deny})
		policy.CallerScope = scope
		policy.GroupIDs = []string{id}
		policy.AllowProfiles = nil
		policy.DenyProfiles = nil
	}
	return document, nil
}

func normalizePatterns(patterns []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for index, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("%s[%d] must not be empty", field, index)
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// callerScope mirrors CPA's built-in API-key identity derivation. It is kept
// here for fixed-vector tests and operator tooling; raw keys are never accepted
// by the policy schema or Management API.
func callerScope(rawKey string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}

func policyAllows(policy runtimePolicy, profile string) bool {
	return policyAllowsCandidate(policy, profile, "")
}

func policyAllowsCandidate(policy runtimePolicy, profile, provider string) bool {
	return policyAllowsCandidateWithLegacies(policy, profile, provider, nil)
}

func policyAllowsSchedulerCandidate(policy runtimePolicy, candidate schedulerAuthCandidate) bool {
	return policyAllowsCandidateWithLegacies(policy, candidate.ID, candidate.Provider, []string{legacyAPIKeyProfileID(candidate)})
}

func policyAllowsCandidateWithLegacy(policy runtimePolicy, profile, provider, legacyProfile string) bool {
	return policyAllowsCandidateWithLegacies(policy, profile, provider, []string{legacyProfile})
}

func policyAllowsCandidateWithLegacies(policy runtimePolicy, profile, provider string, legacyProfiles []string) bool {
	profile = strings.TrimSpace(profile)
	_ = provider
	matches := func(pattern string) bool {
		if wildcardMatch(pattern, profile) {
			return true
		}
		for _, legacyProfile := range legacyProfiles {
			if legacyProfile != "" && wildcardMatch(pattern, strings.TrimSpace(legacyProfile)) {
				return true
			}
		}
		return false
	}
	for _, pattern := range policy.DenyProfiles {
		if matches(pattern) {
			return false
		}
	}
	for _, pattern := range policy.AllowProfiles {
		if matches(pattern) {
			return true
		}
	}
	return false
}

// legacyAPIKeyProfileID reproduces the key+base-url ID format used before
// CPA v7.2.146 for every built-in API-key profile whose identity inputs were
// expanded in that release. Candidate credentials remain transient and are
// never persisted or logged.
func legacyAPIKeyProfileID(candidate schedulerAuthCandidate) string {
	profile := strings.TrimSpace(candidate.ID)
	separator := strings.LastIndex(profile, ":")
	if separator <= 0 {
		return ""
	}
	kind := profile[:separator]
	switch kind {
	case "gemini:apikey", "gemini-interactions:apikey", "claude:apikey", "codex:apikey", "xai:apikey":
	default:
		return ""
	}
	key := strings.TrimSpace(candidate.Attributes["api_key"])
	base := strings.TrimSpace(candidate.Attributes["base_url"])
	if key == "" && base == "" {
		return ""
	}
	hasher := sha256.New()
	hasher.Write([]byte(kind))
	hasher.Write([]byte{0})
	hasher.Write([]byte(key))
	hasher.Write([]byte{0})
	hasher.Write([]byte(base))
	digest := hex.EncodeToString(hasher.Sum(nil))
	return kind + ":" + digest[:12]
}

func (s *state) nextProfile(scope, provider, model string, candidates []schedulerAuthCandidate) string {
	if len(candidates) == 0 {
		return ""
	}
	key := scope + "\x00" + strings.ToLower(strings.TrimSpace(provider)) + "\x00" + strings.TrimSpace(model)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pickCursor == nil {
		s.pickCursor = make(map[string]uint64)
	}
	cursor := s.pickCursor[key]
	s.pickCursor[key] = cursor + 1
	return candidates[cursor%uint64(len(candidates))].ID
}

// wildcardMatch supports shell-style '*' and '?' while allowing '*' to cross '/'.
func wildcardMatch(pattern, value string) bool {
	patternRunes, valueRunes := []rune(pattern), []rune(value)
	p, v, star, checkpoint := 0, 0, -1, 0
	for v < len(valueRunes) {
		if p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == valueRunes[v]) {
			p++
			v++
			continue
		}
		if p < len(patternRunes) && patternRunes[p] == '*' {
			star = p
			p++
			checkpoint = v
			continue
		}
		if star >= 0 {
			p = star + 1
			checkpoint++
			v = checkpoint
			continue
		}
		return false
	}
	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}
	return p == len(patternRunes)
}

func writePolicyFile(path string, document policyDocument) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("policy_file is not configured")
	}
	var raw []byte
	var err error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		raw, err = toml.Marshal(document)
	} else {
		raw, err = yaml.Marshal(document)
	}
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create policy directory: %w", err)
		}
	}
	temporary, err := os.CreateTemp(dir, ".key-provider-access-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary policy file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary policy file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open policy directory for sync: %w", err)
		}
		errSync := directory.Sync()
		errClose := directory.Close()
		if errSync != nil {
			return fmt.Errorf("sync policy directory: %w", errSync)
		}
		if errClose != nil {
			return fmt.Errorf("close policy directory: %w", errClose)
		}
	}
	return nil
}
