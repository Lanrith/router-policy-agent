package directory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

var stableID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type groupEntry struct {
	group   policy.Group
	dn      string
	members map[string]bool
	parents map[string]bool
}

func (r *Reader) collect(ctx context.Context, client searcher, observed time.Time) (policy.DirectorySnapshot, error) {
	// A size-limited ordinary search never contributes entries to a paged
	// collection. Both namespaces restart on the same bound connection and
	// share the original deadline and byte budget.
	paged := r.config.SearchMode == "paged"
	groups, users, err := r.namespaces(ctx, client, paged)
	if r.config.SearchMode == "auto" && errors.Is(err, errSizeLimit) {
		groups, users, err = r.namespaces(ctx, client, true)
	}
	if err != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	snapshot := policy.DirectorySnapshot{
		ObservedAt: observed, Complete: true,
		Groups: []policy.Group{}, Devices: []policy.Device{},
	}
	byDN := map[string]groupEntry{}
	groupIDs := map[string]bool{}
	for _, entry := range groups {
		group, err := r.group(entry)
		if err != nil || groupIDs[group.group.ID] {
			return policy.DirectorySnapshot{}, ErrRead
		}
		byDN[group.dn], groupIDs[group.group.ID] = group, true
		snapshot.Groups = append(snapshot.Groups, group.group)
	}
	memberships, err := r.directMemberships(byDN, users)
	if err != nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	deviceIDs, macs := map[string]bool{}, map[string]bool{}
	for _, entry := range users {
		if err := ctx.Err(); err != nil {
			return policy.DirectorySnapshot{}, readError(ctx)
		}
		attributes, attrErr := checkedAttributes(entry, r.mapping.UserID, r.mapping.UserIDEncoding)
		id, idOK := single(attributes, r.mapping.UserID)
		if attrErr != nil || !idOK || deviceIDs[id] || !stableID.MatchString(id) {
			return policy.DirectorySnapshot{}, ErrRead
		}
		deviceIDs[id] = true
		device, isDevice, err := r.device(entry, attributes, byDN, memberships)
		if err != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		if !isDevice {
			continue
		}
		if macs[device.MAC] {
			return policy.DirectorySnapshot{}, ErrRead
		}
		macs[device.MAC] = true
		snapshot.Devices = append(snapshot.Devices, device)
	}
	slices.SortFunc(snapshot.Groups, func(a, b policy.Group) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(snapshot.Devices, func(a, b policy.Device) int { return strings.Compare(a.ID, b.ID) })
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 16<<20 || ctx.Err() != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	return snapshot, nil
}

// errSizeLimit is returned only after the server reports an LDAP size limit.
// The client-side bound is always a rejected observation and cannot trigger a retry.
var errSizeLimit = errors.New("directory: LDAP search size limit")

func (r *Reader) namespaces(ctx context.Context, client searcher, paged bool) ([]*ldap.Entry, []*ldap.Entry, error) {
	groups, err := r.search(ctx, client, "groups", r.config.MaximumGroups, paged)
	if err != nil {
		return nil, nil, err
	}
	users, err := r.search(ctx, client, "users", r.config.MaximumDevices, paged)
	return groups, users, err
}

func (r *Reader) search(ctx context.Context, client searcher, unit string, maximum int, paged bool) ([]*ldap.Entry, error) {
	spec := r.searchSpec(unit)
	entries := []*ldap.Entry{}
	seenEntries, cookies := map[string]bool{}, map[string]bool{}
	page := ldap.NewControlPaging(r.config.PageSize)
	populatedPages := 0
	for pageIndex := range maximum + 1 {
		if ctx.Err() != nil {
			return nil, readError(ctx)
		}
		var controls []ldap.Control
		if paged {
			controls = []ldap.Control{criticalPage(page)}
		}
		request := ldap.NewSearchRequest(spec.base, spec.scope, ldap.NeverDerefAliases, maximum+1,
			max(1, int(r.config.Timeout/time.Second)), false, spec.filter, spec.attributes, controls)
		request.EnforceSizeLimit = true
		response, err := safeSearch(client, request)
		if !paged && ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) &&
			response != nil && response.ResultCode == ldap.LDAPResultSizeLimitExceeded && len(response.Referrals) == 0 && len(response.Controls) == 0 && len(response.Entries) <= maximum {
			return nil, errSizeLimit
		}
		if err != nil || response == nil || response.ResultCode != ldap.LDAPResultSuccess || len(response.Referrals) != 0 || len(response.Entries) > maximum-len(entries) ||
			paged && r.checkPages != ordinaryRead && len(response.Entries) > int(r.config.PageSize) {
			return nil, ErrRead
		}
		if len(response.Entries) != 0 {
			populatedPages++
		}
		for _, entry := range response.Entries {
			if entry == nil {
				return nil, ErrRead
			}
			dn, err := r.canonicalDN(entry.DN)
			if err != nil || seenEntries[dn] {
				return nil, ErrRead
			}
			seenEntries[dn] = true
			entries = append(entries, entry)
		}
		if !paged {
			if len(response.Controls) != 0 || r.checkPages == ordinaryFixture && len(entries) < 2 {
				return nil, ErrRead
			}
			return entries, nil
		}
		if len(response.Controls) != 1 {
			return nil, ErrRead
		}
		returned, ok := response.Controls[0].(*ldap.ControlPaging)
		if !ok || returned == nil || len(returned.Cookie) > 4096 {
			return nil, ErrRead
		}
		if len(returned.Cookie) == 0 {
			if r.checkPages == multiplePopulatedPages && populatedPages < 2 ||
				r.checkPages == onePopulatedPage && (pageIndex != 0 || populatedPages != 1) {
				return nil, ErrRead
			}
			return entries, nil
		}
		cookie := string(returned.Cookie)
		if cookies[cookie] {
			return nil, ErrRead
		}
		cookies[cookie] = true
		page.SetCookie(slices.Clone(returned.Cookie))
	}
	return nil, ErrRead
}

// criticalPage retains the library's paging encoding but requires the server
// to reject an unsupported control rather than silently return an unpaged view.
func criticalPage(page *ldap.ControlPaging) ldap.Control {
	encoded := page.Encode()
	return ldap.NewControlString(ldap.ControlTypePaging, true, encoded.Children[1].Data.String())
}

func (r *Reader) group(entry *ldap.Entry) (groupEntry, error) {
	attributes, err := checkedAttributes(entry, r.mapping.GroupID, r.mapping.GroupIDEncoding)
	if err != nil || !hasClass(attributes, r.mapping.GroupObjectClass) {
		return groupEntry{}, ErrRead
	}
	id, idOK := single(attributes, r.mapping.GroupID)
	name, nameOK := single(attributes, r.mapping.GroupName)
	rdn, rdnOK := single(attributes, r.mapping.GroupRDN)
	dn, err := r.entryDN(entry.DN, r.mapping.GroupsBaseDN, r.mapping.GroupRDN, rdn, r.mapping.GroupScope)
	if err != nil || !rdnOK || !validName(rdn) || !idOK || !nameOK || !stableID.MatchString(id) || !validName(name) {
		return groupEntry{}, ErrRead
	}
	group := policy.Group{ID: id, Name: name, IsNetwork: networkName(name)}
	if values, exists := attributes[strings.ToLower(r.mapping.GroupPolicy)]; exists {
		if len(values) != 1 || len(values[0]) > policy.AttributeLimit || !utf8.ValidString(values[0]) {
			return groupEntry{}, ErrRead
		}
		group.Policy, group.IsNetwork = &values[0], true
	}
	members := map[string]bool{}
	for _, raw := range attributes[strings.ToLower(r.mapping.GroupMember)] {
		member, err := r.canonicalDN(raw)
		if err != nil || members[member] {
			return groupEntry{}, ErrRead
		}
		members[member] = true
	}
	parents := map[string]bool{}
	for _, raw := range attributes[strings.ToLower(r.mapping.MemberOf)] {
		parent, err := r.canonicalDN(raw)
		if err != nil || parents[parent] {
			return groupEntry{}, ErrRead
		}
		parents[parent] = true
	}
	return groupEntry{group: group, dn: dn, members: members, parents: parents}, nil
}

// directMemberships indexes each user's original group edges once. Nested
// groups are validated separately and never supply inherited device permissions.
func (r *Reader) directMemberships(groups map[string]groupEntry, users []*ldap.Entry) (map[string][]string, error) {
	direct := map[string][]string{}
	userEntries := map[string]bool{}
	for _, entry := range users {
		if entry == nil {
			return nil, ErrRead
		}
		dn, err := r.canonicalDN(entry.DN)
		if err != nil || userEntries[dn] {
			return nil, ErrRead
		}
		if _, overlap := groups[dn]; overlap {
			return nil, ErrRead
		}
		userEntries[dn] = true
	}
	for dn, group := range groups {
		for parentDN := range group.parents {
			parent, ok := groups[parentDN]
			if !ok || !parent.members[dn] {
				return nil, ErrRead
			}
		}
		for memberDN := range group.members {
			if child, ok := groups[memberDN]; ok {
				if r.mapping.MemberOf != "" && !child.parents[dn] {
					return nil, ErrRead
				}
				continue
			}
			if !userEntries[memberDN] {
				return nil, ErrRead
			}
			direct[memberDN] = append(direct[memberDN], dn)
		}
	}
	return direct, nil
}

func (r *Reader) device(entry *ldap.Entry, attributes map[string][]string, groups map[string]groupEntry, direct map[string][]string) (policy.Device, bool, error) {
	if !hasClass(attributes, r.mapping.UserObjectClass) {
		return policy.Device{}, false, ErrRead
	}
	id, idOK := single(attributes, r.mapping.UserID)
	name, nameOK := single(attributes, r.mapping.UserRDN)
	dn, err := r.entryDN(entry.DN, r.mapping.UsersBaseDN, r.mapping.UserRDN, name, r.mapping.UserScope)
	if err != nil || !idOK || !nameOK || !stableID.MatchString(id) || !validName(name) {
		return policy.Device{}, false, ErrRead
	}
	macValues, exists := attributes[strings.ToLower(r.mapping.DeviceMAC)]
	if !exists {
		return policy.Device{}, false, nil
	}
	if len(macValues) != 1 {
		return policy.Device{}, false, ErrRead
	}
	mac, isDevice := macSubject(macValues[0])
	if !isDevice {
		// A naming or identity field may also contain ordinary human accounts.
		if strings.EqualFold(r.mapping.DeviceMAC, r.mapping.UserRDN) ||
			strings.EqualFold(r.mapping.DeviceMAC, r.mapping.UserID) {
			return policy.Device{}, false, nil
		}
		return policy.Device{}, false, ErrRead
	}
	value, present := single(attributes, r.mapping.DeviceActive)
	active, ok := r.accountActive(value)
	if !present || !ok {
		return policy.Device{}, false, ErrRead
	}
	device := policy.Device{ID: id, MAC: mac, Active: active, GroupIDs: []string{}}
	memberships := map[string]bool{}
	for _, raw := range attributes[strings.ToLower(r.mapping.MemberOf)] {
		membership, err := r.canonicalDN(raw)
		if err != nil || memberships[membership] {
			return policy.Device{}, false, ErrRead
		}
		memberships[membership] = true
		if r.config.Mapping == nil {
			if _, err := r.entryDN(raw, "ou=virtual-groups,"+r.config.BaseDN, "cn", name, "one"); err == nil {
				continue
			}
		}
		group, exists := groups[membership]
		if !exists || !group.members[dn] {
			// Inherited parent membership is not a direct policy contribution.
			return policy.Device{}, false, ErrRead
		}
	}
	for _, groupDN := range direct[dn] {
		if r.mapping.MemberOf != "" && !memberships[groupDN] {
			return policy.Device{}, false, ErrRead
		}
		device.GroupIDs = append(device.GroupIDs, groups[groupDN].group.ID)
	}
	slices.Sort(device.GroupIDs)
	return device, true, nil
}

func (r *Reader) accountActive(value string) (bool, bool) {
	if r.mapping.DisabledBit != 0 {
		number, err := strconv.ParseUint(value, 10, 32)
		if err != nil || strconv.FormatUint(number, 10) != value {
			return false, false
		}
		return number&uint64(r.mapping.DisabledBit) == 0, true
	}
	// Authentik emits LDAP BOOLEAN on the wire. Keep the historical
	// lower-case spellings without changing exact matches in explicit mappings.
	if r.config.Mapping == nil {
		switch value {
		case "TRUE":
			return true, true
		case "FALSE":
			return false, true
		}
	}
	return value == r.mapping.ActiveValue, value == r.mapping.ActiveValue || value == r.mapping.InactiveValue
}

func macSubject(name string) (string, bool) {
	mac, err := policy.CanonicalMAC(name)
	return mac, err == nil
}

func (r *Reader) entryDN(raw, base, attr, value, scope string) (string, error) {
	canonical, err := r.canonicalDN(raw)
	if err != nil {
		return "", ErrRead
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) == 0 {
		return "", ErrRead
	}
	if r.config.Mapping == nil {
		expected, err := ldap.ParseDN(attr + "=" + ldap.EscapeDN(value) + "," + base)
		if err != nil || !expected.EqualFold(dn) {
			return "", ErrRead
		}
		return canonical, nil
	}
	// LDAP attribute types compare without case. Preserve the configured
	// naming values because their matching rules belong to the directory.
	leaf := dn.RDNs[0].Attributes
	if len(leaf) != 1 || !strings.EqualFold(leaf[0].Type, attr) || leaf[0].Value != value {
		return "", ErrRead
	}
	parent, err := ldap.ParseDN(base)
	if err != nil || !parent.Equal(dn) && !parent.AncestorOf(dn) {
		return "", ErrRead
	}
	if scope != "subtree" && len(dn.RDNs) != len(parent.RDNs)+1 {
		return "", ErrRead
	}
	return canonical, nil
}

func hasClass(attributes map[string][]string, class string) bool {
	return slices.ContainsFunc(attributes["objectclass"], func(value string) bool { return strings.EqualFold(value, class) })
}

func checkedAttributes(entry *ldap.Entry, idAttribute, idEncoding string) (map[string][]string, error) {
	if entry == nil || len(entry.Attributes) > 16 {
		return nil, ErrRead
	}
	result := map[string][]string{}
	total := 0
	for _, attribute := range entry.Attributes {
		if attribute == nil || len(attribute.Name) > 128 || len(attribute.Values) > 12288 {
			return nil, ErrRead
		}
		name := strings.ToLower(attribute.Name)
		if _, exists := result[name]; exists || name == "" || strings.Contains(name, ";") {
			return nil, ErrRead
		}
		if idEncoding == "hex" && strings.EqualFold(attribute.Name, idAttribute) {
			if len(attribute.Values) != 1 || len(attribute.Values[0]) == 0 || len(attribute.Values[0]) > 64 {
				return nil, ErrRead
			}
			value := attribute.Values[0]
			total += len(value)
			if total > 1<<20 {
				return nil, ErrRead
			}
			result[name] = []string{hex.EncodeToString([]byte(value))}
			continue
		}
		for _, value := range attribute.Values {
			total += len(value)
			if len(value) > policy.AttributeLimit || !utf8.ValidString(value) || total > 1<<20 {
				return nil, ErrRead
			}
		}
		result[name] = attribute.Values
	}
	return result, nil
}

func single(attributes map[string][]string, name string) (string, bool) {
	values := attributes[strings.ToLower(name)]
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func validName(name string) bool {
	return name != "" && len(name) <= 128 && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsControl) < 0
}

func networkName(name string) bool {
	for _, prefix := range []string{"vlan-", "trusted-", "guest-", "untrusted-", "infrastructure-", "security-", "assessment-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
