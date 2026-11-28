package directory

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func mappedFixture() Mapping {
	return Mapping{
		UsersBaseDN: "ou=People," + fixtureBase, GroupsBaseDN: "ou=Roles," + fixtureBase,
		UserObjectClass: "inetOrgPerson", GroupObjectClass: "groupOfNames",
		UserID: "entryUUID", GroupID: "entryUUID", UserRDN: "uid", GroupRDN: "cn",
		DeviceMAC: "macAddress", GroupName: "cn", DeviceActive: "employeeType", ActiveValue: "enabled", InactiveValue: "disabled",
		GroupMember: "member", GroupPolicy: "description",
	}
}

func mappedEntries(m Mapping) (group, device *ldap.Entry) {
	dn := "uid=Printer," + m.UsersBaseDN
	group = ldap.NewEntry("CN=guest-printers,"+m.GroupsBaseDN, map[string][]string{
		"objectClass": {"top", "groupOfNames"}, "entryUUID": {"role-uuid"}, "cn": {"guest-printers"}, "member": {dn},
		"description": {`{"schema_version":1,"kind":"placement","vlan_role":"untrusted"}`},
	})
	device = ldap.NewEntry(dn, map[string][]string{
		"objectClass": {"inetOrgPerson"}, "entryUUID": {"device-uuid"}, "uid": {"Printer"},
		"macAddress": {fixtureMAC}, "employeeType": {"enabled"},
	})
	return group, device
}

func TestMappedDirectoryUsesAuthoritativeFieldsAndOriginalMemberships(t *testing.T) {
	for _, test := range []struct {
		name       string
		change     func(*Mapping, *ldap.Entry, *ldap.Entry)
		wantError  bool
		wantDevice bool
		wantActive bool
		wantGroup  bool
	}{
		{name: "group holds direct membership", wantDevice: true, wantActive: true, wantGroup: true},
		{name: "withdrawn forward membership", change: func(_ *Mapping, g, _ *ldap.Entry) { attribute(g, "member").Values = nil }, wantDevice: true, wantActive: true},
		{name: "explicitly disabled", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "employeeType").Values = []string{"disabled"} }, wantDevice: true, wantGroup: true},
		{name: "missing active", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "employeeType").Values = nil }, wantError: true},
		{name: "unknown activation value", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "employeeType").Values = []string{"Enabled"} }, wantError: true},
		{name: "missing MAC on ordinary user", change: func(_ *Mapping, _, d *ldap.Entry) {
			d.Attributes = slices.DeleteFunc(d.Attributes, func(a *ldap.EntryAttribute) bool { return a.Name == "macAddress" })
		}},
		{name: "malformed dedicated MAC", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "macAddress").Values = []string{"unassigned"} }, wantError: true},
		{name: "different case sensitive principal", change: func(_ *Mapping, g, _ *ldap.Entry) {
			attribute(g, "member").Values[0] = strings.Replace(attribute(g, "member").Values[0], "Printer", "printer", 1)
		}, wantError: true},
		{name: "mismatched account RDN", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "uid").Values = []string{"other"} }, wantError: true},
		{name: "wrong object class", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "objectClass").Values = []string{"groupOfNames"} }, wantError: true},
		{name: "backlink required", change: func(m *Mapping, _, _ *ldap.Entry) { m.MemberOf = "memberOf" }, wantError: true},
		{name: "corroborated backlink", change: func(m *Mapping, g, d *ldap.Entry) {
			m.MemberOf = "memberOf"
			d.Attributes = append(d.Attributes, &ldap.EntryAttribute{Name: "memberOf", Values: []string{g.DN}})
		}, wantDevice: true, wantActive: true, wantGroup: true},
		{name: "grant cannot come from backlink alone", change: func(m *Mapping, g, d *ldap.Entry) {
			m.MemberOf = "memberOf"
			attribute(g, "member").Values = nil
			d.Attributes = append(d.Attributes, &ldap.EntryAttribute{Name: "memberOf", Values: []string{g.DN}})
		}, wantError: true},
		{name: "dangling member", change: func(m *Mapping, g, _ *ldap.Entry) {
			attribute(g, "member").Values = []string{"uid=Unknown," + m.UsersBaseDN}
		}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := mappedFixture()
			group, device := mappedEntries(m)
			if test.change != nil {
				test.change(&m, group, device)
			}
			config := fixtureConfig()
			config.SearchMode = "unpaged"
			config.Mapping = &m
			reader, err := New(config, fixtureReader(t).credentials)
			if err != nil {
				t.Fatal(err)
			}
			reply := searchFunc(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				if len(req.Controls) != 0 || !req.EnforceSizeLimit || req.SizeLimit != 17 || req.Scope != ldap.ScopeSingleLevel {
					t.Fatal("expected bounded ordinary read")
				}
				if req.BaseDN == m.GroupsBaseDN && req.Filter == "(objectClass=groupOfNames)" && slices.Contains(req.Attributes, "description") {
					return &ldap.SearchResult{Entries: []*ldap.Entry{group}}, nil
				}
				if req.BaseDN != m.UsersBaseDN || req.Filter != "(objectClass=inetOrgPerson)" || slices.Contains(req.Attributes, "description") {
					t.Fatalf("incorrect projected search: %s", req.Filter)
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{device}}, nil
			})
			snapshot, err := reader.collect(t.Context(), reply, fixtureTime)
			if test.wantError {
				if !errors.Is(err, ErrRead) || snapshot.Complete {
					t.Fatal("incomplete directory accepted")
				}
				return
			}
			if err != nil || !snapshot.Complete || len(snapshot.Groups) != 1 || snapshot.Groups[0].ID != "role-uuid" || snapshot.Groups[0].Policy == nil || (len(snapshot.Devices) == 1) != test.wantDevice {
				t.Fatalf("unexpected snapshot: %+v, %v", snapshot, err)
			}
			if test.wantDevice {
				got := snapshot.Devices[0]
				if got.ID != "device-uuid" || got.MAC != fixtureMAC || got.Active != test.wantActive || slices.Contains(got.GroupIDs, "role-uuid") != test.wantGroup {
					t.Fatalf("incorrect device: %+v", got)
				}
			}
		})
	}
}

func TestMappingValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Mapping)
		ok     bool
	}{
		{"ordinary mapping", nil, true},
		{"DN outside configured base", func(m *Mapping) { m.UsersBaseDN = "ou=people,dc=elsewhere" }, false},
		{"case-specific parent", func(m *Mapping) { m.UsersBaseDN = "ou=People,dc=Example,dc=test" }, false},
		{"one base distinct object classes", func(m *Mapping) { m.UsersBaseDN = m.GroupsBaseDN }, true},
		{"one base identical classes", func(m *Mapping) { m.UsersBaseDN = m.GroupsBaseDN; m.UserObjectClass = m.GroupObjectClass }, false},
		{"aliased policy and membership", func(m *Mapping) { m.GroupMember = "Description" }, false},
		{"aliased active and identity", func(m *Mapping) { m.DeviceActive = "UID" }, false},
		{"aliased member and backlink", func(m *Mapping) { m.MemberOf = "member" }, false},
		{"naming data can identify a device", func(m *Mapping) { m.UserID = m.UserRDN; m.DeviceMAC = m.UserID }, true},
		{"no active-state distinction", func(m *Mapping) { m.InactiveValue = m.ActiveValue }, false},
		{"unknown special selector", func(m *Mapping) { m.GroupPolicy = "*" }, false},
		{"entry options", func(m *Mapping) { m.UserID = "uid;binary" }, false},
		{"numeric attribute identifiers", func(m *Mapping) { m.UserID = "1.3.6.1.1.16.4" }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := mappedFixture()
			if test.change != nil {
				test.change(&m)
			}
			c := fixtureConfig()
			c.Mapping = &m
			_, err := New(c, fixtureReader(t).credentials)
			if (err == nil) != test.ok {
				t.Fatal("unexpected mapping validation", err)
			}
		})
	}
	m := mappedFixture()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(data), "user_id", "USER_ID", 1), strings.Replace(string(data), "}", `,"member_of":""}`, 1), strings.Replace(string(data), "}", `,"active_value":"yes"}`, 1)} {
		var decoded Mapping
		if err := json.Unmarshal([]byte(bad), &decoded); err == nil {
			t.Fatal("ambiguous mapping accepted")
		}
	}
	m.MemberOf = "isMemberOf"
	encoded, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Mapping
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || roundTrip != m {
		t.Fatalf("mapping did not round-trip: %v", err)
	}
	if !validCredentials(Credentials{BindDN: "uid=Lookup,ou=Services," + fixtureBase, Password: "fixture"}, fixtureBase, true) ||
		validCredentials(Credentials{BindDN: "uid=Lookup,dc=foreign", Password: "fixture"}, fixtureBase, true) {
		t.Fatal("incorrect generic bind scope")
	}
}

func TestAutoSearchRestartsBothNamespacesOnlyOnSizeLimit(t *testing.T) {
	groups, users := fixtureEntries()
	for _, test := range []struct {
		name            string
		ordinaryCode    uint16
		paginationFails bool
		wantCalls       int
		complete        bool
	}{
		{"standard search success", ldap.LDAPResultSuccess, false, 2, true},
		{"discard partial search and re-read both namespaces", ldap.LDAPResultSizeLimitExceeded, false, 4, true},
		{"missing paged control after retry", ldap.LDAPResultSizeLimitExceeded, true, 3, false},
		{"administrative limit", ldap.LDAPResultAdminLimitExceeded, false, 2, false},
		{"time limit", ldap.LDAPResultTimeLimitExceeded, false, 2, false},
		{"referral", ldap.LDAPResultReferral, false, 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := fixtureConfig()
			c.SearchMode = ""
			r, err := New(c, fixtureReader(t).credentials)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			f := searchFunc(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				calls++
				if calls == 1 {
					if len(req.Controls) != 0 || req.BaseDN != "ou=groups,"+fixtureBase {
						t.Fatal("not an ordinary group search")
					}
					if test.ordinaryCode == ldap.LDAPResultSuccess {
						return &ldap.SearchResult{Entries: groups}, nil
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=discarded,ou=groups,"+fixtureBase, nil)}}, nil
				}
				if calls == 2 {
					if len(req.Controls) != 0 || req.BaseDN != "ou=users,"+fixtureBase {
						t.Fatal("not an ordinary user search")
					}
					if test.ordinaryCode == ldap.LDAPResultSuccess {
						return &ldap.SearchResult{Entries: users}, nil
					}
					return &ldap.SearchResult{Entries: []*ldap.Entry{ldap.NewEntry("cn=discarded,ou=users,"+fixtureBase, nil)}, ResultCode: test.ordinaryCode}, ldap.NewError(test.ordinaryCode, errors.New("synthetic"))
				}
				if calls == 3 && test.paginationFails {
					return &ldap.SearchResult{Entries: groups}, nil
				}
				return fixtureSearch(t, groups, users)(req)
			})
			snapshot, err := r.collect(t.Context(), f, time.Now())
			if (err == nil) != test.complete || snapshot.Complete != test.complete || calls != test.wantCalls || test.complete && len(snapshot.Devices) != 1 {
				t.Fatalf("calls=%d complete=%v err=%v", calls, snapshot.Complete, err)
			}
		})
	}
}

func flaggedEntries(flags string) (Mapping, *ldap.Entry, *ldap.Entry) {
	m := mappedFixture()
	m.UserScope, m.GroupScope = "subtree", "subtree"
	m.UserID, m.GroupID = "objectGUID", "objectGUID"
	m.UserIDEncoding, m.GroupIDEncoding = "hex", "hex"
	m.DeviceActive, m.DisabledBit = "userAccountControl", 2
	m.ActiveValue, m.InactiveValue = "", ""
	g, d := mappedEntries(m)
	d.DN = "uid=Printer,ou=Floor," + m.UsersBaseDN
	g.DN = "cn=guest-printers,ou=Site," + m.GroupsBaseDN
	attribute(g, "member").Values = []string{d.DN}
	for i, entry := range []*ldap.Entry{g, d} {
		attr := attribute(entry, "entryUUID")
		attr.Name = "objectGUID"
		attr.Values = []string{string([]byte{0, 0x80, byte(i + 1), 0xff})}
	}
	state := attribute(d, "employeeType")
	state.Name = "userAccountControl"
	state.Values = []string{flags}
	return m, g, d
}

func TestMappedSubtreeBinaryIdentityAndDisabledBit(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  string
		change func(*Mapping, *ldap.Entry, *ldap.Entry)
		bad    bool
		active bool
	}{
		{name: "enabled with other flags", value: "512", active: true},
		{name: "zero flags", value: "0", active: true},
		{name: "disabled bit", value: "514"},
		{name: "maximum unsigned flags", value: "4294967295"},
		{name: "noncanonical decimal", value: "0512", bad: true},
		{name: "larger than unsigned flags", value: "4294967296", bad: true},
		{name: "negative flags", value: "-1", bad: true},
		{name: "missing flags", value: "", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "userAccountControl").Values = nil }, bad: true},
		{name: "wrong namespace despite subtree", value: "512", change: func(_ *Mapping, g, d *ldap.Entry) {
			d.DN = strings.Replace(d.DN, "ou=People", "ou=Retired", 1)
			attribute(g, "member").Values = []string{d.DN}
		}, bad: true},
		{name: "one-level rejects nested entry", value: "512", change: func(m *Mapping, _, _ *ldap.Entry) { m.UserScope = "one" }, bad: true},
		{name: "wrong leaf in subtree", value: "512", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "uid").Values = []string{"different"} }, bad: true},
		{name: "binary remains bounded", value: "512", change: func(_ *Mapping, _, d *ldap.Entry) {
			attribute(d, "objectGUID").Values = []string{strings.Repeat("x", 65)}
		}, bad: true},
		{name: "binary remains single-valued", value: "512", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "objectGUID").Values = []string{"a", "b"} }, bad: true},
		{name: "other attributes remain UTF-8", value: "512", change: func(_ *Mapping, _, d *ldap.Entry) { attribute(d, "uid").Values = []string{string([]byte{0xff})} }, bad: true},
		{name: "text ID rejects binary", value: "512", change: func(m *Mapping, _, _ *ldap.Entry) { m.UserIDEncoding = "text" }, bad: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, g, d := flaggedEntries(test.value)
			if test.change != nil {
				test.change(&m, g, d)
			}
			cfg := fixtureConfig()
			cfg.Mapping = &m
			cfg.SearchMode = "unpaged"
			r, err := New(cfg, fixtureReader(t).credentials)
			if err != nil {
				t.Fatal(err)
			}
			f := searchFunc(func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				wantScope := ldap.ScopeWholeSubtree
				if req.BaseDN == m.UsersBaseDN && m.UserScope == "one" {
					wantScope = ldap.ScopeSingleLevel
				}
				if req.Scope != wantScope {
					t.Fatal("wrong requested scope")
				}
				entry := d
				if req.BaseDN == m.GroupsBaseDN {
					entry = g
				}
				return &ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil
			})
			got, err := r.collect(t.Context(), f, fixtureTime)
			if test.bad {
				if !errors.Is(err, ErrRead) || got.Complete {
					t.Fatal("invalid directory state accepted")
				}
				return
			}
			if err != nil || len(got.Groups) != 1 || len(got.Devices) != 1 || got.Groups[0].ID != "008001ff" ||
				got.Devices[0].ID != "008002ff" || got.Devices[0].Active != test.active || !slices.Equal(got.Devices[0].GroupIDs, []string{got.Groups[0].ID}) {
				t.Fatalf("unexpected collection: %+v, %v", got, err)
			}
		})
	}
}

func TestActivationSelection(t *testing.T) {
	m := mappedFixture()
	m.ActiveValue, m.InactiveValue = "", ""
	m.DisabledBit = 2
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Mapping
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != m {
		t.Fatal("bit configuration round trip", err)
	}
	for _, replacement := range []string{`"disabled_bit":0`, `"active_value":"enabled","disabled_bit":2`, `"disabled_bit":4294967296`, `"disabled_bit":1.5`, `"disabled_bit":null`, `"disabled_bit":-1`, `"disabled_bit":2,"user_scope":""`} {
		encoded := strings.Replace(string(data), `"disabled_bit":2`, replacement, 1)
		if err := json.Unmarshal([]byte(encoded), &decoded); err == nil {
			t.Fatal("ambiguous state rule accepted")
		}
	}
	for _, change := range []func(*Mapping){
		func(m *Mapping) { m.DisabledBit = 3 }, func(m *Mapping) { m.UserScope = "all" }, func(m *Mapping) { m.GroupScope = "base" },
		func(m *Mapping) { m.UserIDEncoding = "base64" }, func(m *Mapping) { m.UserIDEncoding = "hex"; m.UserID = m.DeviceMAC },
		func(m *Mapping) { m.GroupIDEncoding = "hex"; m.GroupID = m.GroupName },
	} {
		invalid := m
		change(&invalid)
		cfg := fixtureConfig()
		cfg.Mapping = &invalid
		if _, err := New(cfg, fixtureReader(t).credentials); err == nil {
			t.Fatal("invalid mapping accepted")
		}
	}
}
