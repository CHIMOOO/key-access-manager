package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func groupTestBool(value bool) *bool { return &value }

func groupTestDocument() policyDocument {
	return policyDocument{
		Version: policyVersion,
		Groups: []groupConfig{
			{ID: "team-a", Name: "Team A", AllowProfiles: []string{"account-a", "shared"}},
			{ID: "team-b", Name: "Team B", AllowProfiles: []string{"account-b"}, DenyProfiles: []string{"shared"}},
			{ID: "empty", Name: "Empty"},
		},
		Policies: []policyConfig{{CallerScope: scopeA, GroupIDs: []string{"team-a", "team-b"}}},
	}
}

func TestGroupMembershipUnionsGrantsAndDenyOverridesAcrossGroups(t *testing.T) {
	snapshot, sanitized, err := compileDocument(groupTestDocument())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.AccessControlEnabled || !snapshot.DefaultDeny || !*sanitized.AccessControlEnabled || !*sanitized.DefaultDeny {
		t.Fatal("secure defaults were not applied")
	}
	for profile, allowed := range map[string]bool{"account-a": true, "account-b": true, "shared": false, "account-c": false} {
		if got := policyAllows(snapshot.ByCallerScope[scopeA], profile); got != allowed {
			t.Errorf("access to %s = %v, want %v", profile, got, allowed)
		}
	}
	if policyAllows(runtimePolicy{}, "anything") {
		t.Fatal("empty group whitelist allowed access")
	}
}

func TestGroupDocumentRejectsDirectRulesAndInvalidMemberships(t *testing.T) {
	for name, mutate := range map[string]func(*policyDocument){
		"direct allow":         func(d *policyDocument) { d.Policies[0].AllowProfiles = []string{"*"} },
		"empty direct allow":   func(d *policyDocument) { d.Policies[0].AllowProfiles = []string{} },
		"direct deny":          func(d *policyDocument) { d.Policies[0].DenyProfiles = []string{"*"} },
		"unknown group":        func(d *policyDocument) { d.Policies[0].GroupIDs = []string{"missing"} },
		"duplicate membership": func(d *policyDocument) { d.Policies[0].GroupIDs = []string{"team-a", " team-a "} },
		"duplicate id":         func(d *policyDocument) { d.Groups[1].ID = "team-a" },
		"duplicate name":       func(d *policyDocument) { d.Groups[1].Name = " TEAM a " },
		"invalid id":           func(d *policyDocument) { d.Groups[0].ID = "../team" },
		"blank name":           func(d *policyDocument) { d.Groups[0].Name = " " },
		"long name":            func(d *policyDocument) { d.Groups[0].Name = strings.Repeat("组", 129) },
		"blank profile":        func(d *policyDocument) { d.Groups[0].AllowProfiles = []string{" "} },
		"duplicate scope":      func(d *policyDocument) { d.Policies = append(d.Policies, d.Policies[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			document := groupTestDocument()
			mutate(&document)
			if _, _, err := compileDocument(document); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestV2MigrationPreservesExistingRulesAsStableGroups(t *testing.T) {
	legacy := policyDocument{Version: 2, Policies: []policyConfig{
		{CallerScope: scopeA, AllowProfiles: []string{"account-a"}},
		{CallerScope: scopeB, DenyProfiles: []string{"private-*"}},
	}}
	first, migrated, err := compileDocument(legacy)
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := compileDocument(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(migrated, again) || migrated.Version != policyVersion || len(migrated.Groups) != 2 {
		t.Fatalf("migration is not deterministic: %#v", migrated)
	}
	for _, membership := range migrated.Policies {
		if len(membership.GroupIDs) != 1 || membership.AllowProfiles != nil || membership.DenyProfiles != nil {
			t.Fatalf("migration retained per-key grants: %#v", membership)
		}
	}
	if !policyAllows(first.ByCallerScope[scopeB], "public") || policyAllows(first.ByCallerScope[scopeB], "private-a") {
		t.Fatal("migration changed the v2 deny-list policy")
	}
	if !first.DefaultDeny {
		t.Fatal("migration did not deny new unassigned keys")
	}
	second, _, err := compileDocument(migrated)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("v3 recompilation changed migration grants")
	}
}

func TestGlobalSwitchAndDefaultDenyEnforcedByAllHooks(t *testing.T) {
	for _, test := range []struct {
		name     string
		document policyDocument
		scope    string
		profile  string
		denied   bool
		handled  bool
	}{
		{name: "new key secure default", document: policyDocument{Version: policyVersion}, scope: scopeB, profile: "account-a", denied: true},
		{name: "unassigned key optional allow", document: policyDocument{Version: policyVersion, DefaultDeny: groupTestBool(false)}, scope: scopeB, profile: "account-a"},
		{name: "global disabled no identity", document: policyDocument{Version: policyVersion, AccessControlEnabled: groupTestBool(false)}, profile: "account-a"},
		{name: "membership allowed", document: groupTestDocument(), scope: scopeA, profile: "account-a", handled: true},
		{name: "membership denied", document: groupTestDocument(), scope: scopeA, profile: "shared", denied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			installTestPolicy(t, test.document)
			metadata := map[string]any{"selected_auth_id": test.profile}
			if test.scope != "" {
				metadata["caller_scope"] = test.scope
			}
			request, _ := json.Marshal(requestInterceptRequest{Metadata: metadata})
			for _, after := range []bool{false, true} {
				raw, err := interceptRequest(request, after)
				if err != nil {
					t.Fatal(err)
				}
				var response requestInterceptResponse
				unwrapEnvelope(t, raw, &response)
				// Before selection, only unassigned keys are rejected; profile rules
				// are enforced by the scheduler and the after-auth guard.
				wantDenied := test.denied && (after || test.name == "new key secure default")
				if response.Terminate != wantDenied {
					t.Fatalf("after=%v response=%#v", after, response)
				}
			}
			pickRequest, _ := json.Marshal(schedulerPickRequest{Options: schedulerOptions{Metadata: metadata}, Candidates: []schedulerAuthCandidate{{ID: test.profile}}})
			raw, err := pickProfile(pickRequest)
			if err != nil {
				t.Fatal(err)
			}
			var wrapped envelope
			if err := json.Unmarshal(raw, &wrapped); err != nil {
				t.Fatal(err)
			}
			if wrapped.OK == test.denied {
				t.Fatalf("scheduler denial=%v: %s", test.denied, raw)
			}
			if test.denied {
				if wrapped.Error == nil || wrapped.Error.HTTPStatus != http.StatusForbidden {
					t.Fatalf("bad denial: %s", raw)
				}
			} else {
				var selected schedulerPickResponse
				unwrapEnvelope(t, raw, &selected)
				if selected.Handled != test.handled {
					t.Fatalf("unexpected selected=%#v", selected)
				}
			}
		})
	}
}

func TestEmptyMembershipUsesDefaultWhileEmptyGroupDenies(t *testing.T) {
	document := groupTestDocument()
	document.DefaultDeny = groupTestBool(false)
	document.Policies = []policyConfig{{CallerScope: scopeA, GroupIDs: []string{}}, {CallerScope: scopeB, GroupIDs: []string{"empty"}}}
	installTestPolicy(t, document)
	if got := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "anything"}}); got.Terminate {
		t.Fatal("unassigned key ignored default_deny=false")
	}
	if got := callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeB, "selected_auth_id": "anything"}}); !got.Terminate {
		t.Fatal("empty referenced group did not deny access")
	}
}

func TestGlobalDisablePreservesGroupsAndReenableRestoresRestrictions(t *testing.T) {
	document := groupTestDocument()
	document.AccessControlEnabled = groupTestBool(false)
	installTestPolicy(t, document)
	request := requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "shared"}}
	if callIntercept(t, request).Terminate {
		t.Fatal("disabled ACL blocked profile")
	}
	cfg, _, _, _, _, _ := globalState.current()
	document = documentFromConfig(cfg)
	document.AccessControlEnabled = groupTestBool(true)
	body, _ := json.Marshal(document)
	raw, err := managementReplacePolicies(body, etagForRevision(globalState.policyRevision()))
	if err != nil {
		t.Fatal(err)
	}
	if response := decodeManagementResponse(t, raw); response.StatusCode != http.StatusOK {
		t.Fatalf("enable failed: %s", response.Body)
	}
	if !callIntercept(t, request).Terminate {
		t.Fatal("reenabling did not restore group deny rule")
	}
}

func TestManagementV3RoundTripRetainsGroupsSettingsAndMissingProfiles(t *testing.T) {
	for _, extension := range []string{".toml", ".yaml"} {
		t.Run(extension, func(t *testing.T) {
			installTestPolicy(t, policyDocument{Version: policyVersion})
			cfg, snapshot, _, _, _, _ := globalState.current()
			cfg.PolicyFile = filepath.Join(t.TempDir(), "policy"+extension)
			globalState.replace(cfg, snapshot, "test")
			document := groupTestDocument()
			document.AccessControlEnabled = groupTestBool(false)
			document.DefaultDeny = groupTestBool(false)
			document.Groups[0].AllowProfiles = []string{"temporarily-missing-profile"}
			body, _ := json.Marshal(document)
			raw, err := managementReplacePolicies(body, etagForRevision(globalState.policyRevision()))
			if err != nil {
				t.Fatal(err)
			}
			if response := decodeManagementResponse(t, raw); response.StatusCode != http.StatusOK {
				t.Fatalf("save failed: %s", response.Body)
			}
			loaded, err := readPolicyFile(cfg.PolicyFile)
			if err != nil {
				t.Fatal(err)
			}
			_, expected, err := compileDocument(document)
			if err != nil {
				t.Fatal(err)
			}
			_, actual, err := compileDocument(loaded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("disk lost policy data: %#v", actual)
			}
			if _, err := managementReload(); err != nil {
				t.Fatal(err)
			}
			raw, err = managementPolicies()
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Policy policyDocument `json:"policy"`
			}
			if err := json.Unmarshal(decodeManagementResponse(t, raw).Body, &payload); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(payload.Policy, expected) {
				t.Fatalf("reload/GET lost policy data: %#v", payload.Policy)
			}
		})
	}
}

func TestManagementRejectsInvalidGroupWriteWithoutChangingDiskOrRuntime(t *testing.T) {
	document := groupTestDocument()
	installTestPolicy(t, document)
	cfg, snapshot, _, _, _, _ := globalState.current()
	cfg.PolicyFile = filepath.Join(t.TempDir(), "policy.toml")
	if err := writePolicyFile(cfg.PolicyFile, documentFromConfig(cfg)); err != nil {
		t.Fatal(err)
	}
	globalState.replace(cfg, snapshot, "test")
	before, err := os.ReadFile(cfg.PolicyFile)
	if err != nil {
		t.Fatal(err)
	}
	revision := globalState.policyRevision()
	for _, body := range [][]byte{
		[]byte(`{"version":2,"policies":[]}`),
		[]byte(`{"version":3,"groups":[],"policies":[{"caller_scope":"` + scopeA + `","group_ids":["missing"]}]}`),
		[]byte(`{"version":3,"groups":[],"policies":[{"caller_scope":"` + scopeA + `","allow_profiles":[]}]}`),
	} {
		raw, err := managementReplacePolicies(body, etagForRevision(revision))
		if err != nil {
			t.Fatal(err)
		}
		if response := decodeManagementResponse(t, raw); response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("invalid write response: %s", response.Body)
		}
		if globalState.policyRevision() != revision {
			t.Fatal("invalid write changed revision")
		}
		after, err := os.ReadFile(cfg.PolicyFile)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("invalid write changed disk")
		}
		if !callIntercept(t, requestInterceptRequest{Metadata: map[string]any{"caller_scope": scopeA, "selected_auth_id": "shared"}}).Terminate {
			t.Fatal("invalid write replaced the active deny rule")
		}
	}
}
