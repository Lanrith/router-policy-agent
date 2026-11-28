package directory

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

// Mapping describes the original LDAP entries which supply policy evidence.
// Member values are DNs. The optional memberOf attribute corroborates forward
// edges; when absent, the complete group search is the membership authority.
type Mapping struct {
	UsersBaseDN      string `json:"users_base_dn"`
	GroupsBaseDN     string `json:"groups_base_dn"`
	UserObjectClass  string `json:"user_object_class"`
	GroupObjectClass string `json:"group_object_class"`
	UserID           string `json:"user_id"`
	GroupID          string `json:"group_id"`
	UserRDN          string `json:"user_rdn"`
	GroupRDN         string `json:"group_rdn"`
	DeviceMAC        string `json:"device_mac"`
	GroupName        string `json:"group_name"`
	DeviceActive     string `json:"device_active"`
	ActiveValue      string `json:"active_value,omitempty"`
	InactiveValue    string `json:"inactive_value,omitempty"`
	GroupMember      string `json:"group_member"`
	GroupPolicy      string `json:"group_policy"`
	MemberOf         string `json:"member_of,omitempty"`
	UserScope        string `json:"user_scope,omitempty"`
	GroupScope       string `json:"group_scope,omitempty"`
	UserIDEncoding   string `json:"user_id_encoding,omitempty"`
	GroupIDEncoding  string `json:"group_id_encoding,omitempty"`
	DisabledBit      uint32 `json:"disabled_bit,omitempty"`
}

// UnmarshalJSON rejects misspellings, ambiguous fields and incomplete mappings
// before a configuration can change the meaning of group or account records.
func (m *Mapping) UnmarshalJSON(data []byte) error {
	var keys map[string]json.RawMessage
	if err := strictjson.Decode(data, &keys, 16<<10); err != nil {
		return ErrRead
	}
	required := []string{"users_base_dn", "groups_base_dn", "user_object_class", "group_object_class",
		"user_id", "group_id", "user_rdn", "group_rdn", "device_mac", "group_name", "device_active", "group_member", "group_policy"}
	_, bitMode := keys["disabled_bit"]
	if bitMode {
		required = append(required, "disabled_bit")
	} else {
		required = append(required, "active_value", "inactive_value")
	}
	optional := []string{"member_of", "user_scope", "group_scope", "user_id_encoding", "group_id_encoding"}
	if err := strictjson.Object(data, required, optional, 16<<10); err != nil {
		return ErrRead
	}
	type fields Mapping
	var decoded fields
	if err := json.Unmarshal(data, &decoded); err != nil || bitMode && decoded.DisabledBit == 0 {
		return ErrRead
	}
	for _, key := range optional {
		if raw, present := keys[key]; present && string(raw) == `""` {
			return ErrRead
		}
	}
	*m = Mapping(decoded)
	return nil
}

var ldapName = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_-]*|[0-9]+(?:\.[0-9]+)+)$`)

func defaultMapping(base string) Mapping {
	return Mapping{
		UsersBaseDN: "ou=users," + base, GroupsBaseDN: "ou=groups," + base,
		UserObjectClass: "goauthentik.io/ldap/user", GroupObjectClass: "goauthentik.io/ldap/group",
		UserID: "uid", GroupID: "uid", UserRDN: "cn", GroupRDN: "cn",
		DeviceMAC: "cn", GroupName: "cn", DeviceActive: "ak-active", ActiveValue: "true", InactiveValue: "false",
		GroupMember: "member", MemberOf: "memberOf", GroupPolicy: policy.Attribute,
	}
}

func validLDAPName(name string) bool { return len(name) <= 127 && ldapName.MatchString(name) }

func scopedBase(raw string, base *ldap.DN) (*ldap.DN, bool) {
	if raw == "" || len(raw) > 1024 || !utf8.ValidString(raw) || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return nil, false
	}
	dn, err := ldap.ParseDN(raw)
	return dn, err == nil && dn != nil && len(dn.RDNs) > 0 && (base.Equal(dn) || base.AncestorOf(dn))
}

func attributesDistinct(ordinary, authority []string) bool {
	seen := map[string]bool{"objectclass": true}
	for _, field := range ordinary {
		key := strings.ToLower(field)
		if !validLDAPName(field) || key == "objectclass" {
			return false
		}
		seen[key] = true
	}
	for _, field := range authority {
		key := strings.ToLower(field)
		if !validLDAPName(field) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (m Mapping) valid(base *ldap.DN) bool {
	users, uOK := scopedBase(m.UsersBaseDN, base)
	groups, gOK := scopedBase(m.GroupsBaseDN, base)
	if !uOK || !gOK || users.Equal(groups) && strings.EqualFold(m.UserObjectClass, m.GroupObjectClass) {
		return false
	}
	if !validLDAPName(m.UserObjectClass) && m.UserObjectClass != "goauthentik.io/ldap/user" ||
		!validLDAPName(m.GroupObjectClass) && m.GroupObjectClass != "goauthentik.io/ldap/group" ||
		!m.validActivation() || !validScope(m.UserScope) || !validScope(m.GroupScope) ||
		!validIDEncoding(m.UserIDEncoding, m.UserID, m.UserRDN, m.DeviceMAC) ||
		!validIDEncoding(m.GroupIDEncoding, m.GroupID, m.GroupRDN, m.GroupName) {
		return false
	}
	userAuthority := []string{m.DeviceActive}
	groupAuthority := []string{m.GroupMember, m.GroupPolicy}
	if m.MemberOf != "" {
		userAuthority = append(userAuthority, m.MemberOf)
		groupAuthority = append(groupAuthority, m.MemberOf)
	}
	return attributesDistinct([]string{m.UserID, m.UserRDN, m.DeviceMAC}, userAuthority) &&
		attributesDistinct([]string{m.GroupID, m.GroupRDN, m.GroupName}, groupAuthority)
}

func (m Mapping) validActivation() bool {
	if m.DisabledBit != 0 {
		return m.DisabledBit&(m.DisabledBit-1) == 0 && m.ActiveValue == "" && m.InactiveValue == ""
	}
	return validName(m.ActiveValue) && validName(m.InactiveValue) && m.ActiveValue != m.InactiveValue
}

func validScope(scope string) bool { return scope == "" || scope == "one" || scope == "subtree" }

func validIDEncoding(encoding, id, rdn, name string) bool {
	switch encoding {
	case "", "text":
		return true
	case "hex":
		return !strings.EqualFold(id, rdn) && !strings.EqualFold(id, name)
	default:
		return false
	}
}

type searchSpec struct {
	base       string
	scope      int
	filter     string
	attributes []string
}

func (r *Reader) searchSpec(unit string) searchSpec {
	m := r.mapping
	spec := searchSpec{base: m.UsersBaseDN, filter: "(objectClass=" + ldap.EscapeFilter(m.UserObjectClass) + ")",
		attributes: []string{m.UserID, m.UserRDN, m.DeviceMAC, m.DeviceActive, "objectClass", m.MemberOf}}
	if unit == "groups" {
		spec = searchSpec{base: m.GroupsBaseDN, filter: "(objectClass=" + ldap.EscapeFilter(m.GroupObjectClass) + ")",
			attributes: []string{m.GroupID, m.GroupRDN, m.GroupName, "objectClass", m.GroupMember, m.GroupPolicy, m.MemberOf}}
	}
	spec.scope = ldap.ScopeSingleLevel
	if unit == "groups" && m.GroupScope == "subtree" || unit == "users" && m.UserScope == "subtree" {
		spec.scope = ldap.ScopeWholeSubtree
	}
	if r.config.Mapping == nil {
		spec.filter = "(objectClass=*)"
	}
	projection := make([]string, 0, len(spec.attributes))
	for _, attr := range spec.attributes {
		if attr != "" && !slices.ContainsFunc(projection, func(s string) bool { return strings.EqualFold(s, attr) }) {
			projection = append(projection, attr)
		}
	}
	spec.attributes = projection
	return spec
}
