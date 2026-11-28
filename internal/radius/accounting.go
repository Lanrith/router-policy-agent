// Package radius correlates authenticated accounting history without granting
// firewall authority. Accounting alone lacks actual VLAN/source ownership;
// optional host-placement checks still produce only shadow binding proposals.
package radius

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lanrith/router-policy-agent/internal/policy"
	"github.com/lanrith/router-policy-agent/internal/strictjson"
)

const (
	marker          = "radius-policy-accounting-v1 "
	maximumHistory  = 16 << 20
	maximumEntry    = 32 << 10
	maximumEvents   = 16384
	maximumSessions = 4096
	clockTolerance  = 5 * time.Second
	// Freshness bounds session evidence; rereading the journal cannot renew it.
	Freshness = 90 * time.Second
)

// Scope pins the current boot and authenticated local RADIUS service identity.
// NASPrefixes admit authenticated NAS sources, not device addresses or VLANs.
type Scope struct {
	BootID      string
	ServiceUID  uint32
	NASPrefixes []netip.Prefix
}

// Observation contains only unambiguous, fresh sessions from one replay.
// Withheld counts MACs with conflicting current sessions, including roaming.
// ObservedAt is the caller's collection time, not a session heartbeat.
type Observation struct {
	ObservedAt     time.Time
	Sessions       []Session
	Withheld       int
	DuplicateClaim bool
}

// Session retains original accounting times and an opaque boot-scoped identity.
// ReportedVLAN is a NAS claim, not independently verified physical placement.
// IPv6Reported does not qualify any native IPv6 or privacy address.
type Session struct {
	MAC           string     `json:"mac"`
	NAS           netip.Addr `json:"nas"`
	AssociationID string     `json:"association_id"`
	StartedAt     time.Time  `json:"started_at"`
	ObservedAt    time.Time  `json:"observed_at"`
	ValidUntil    time.Time  `json:"valid_until"`
	IPv4          netip.Addr `json:"ipv4"`
	ReportedVLAN  uint16     `json:"reported_vlan"`
	IPv6Reported  bool       `json:"ipv6_reported"`
}

type accountingEvent struct {
	ReceivedAt      int64  `json:"received_at"`
	MAC             string `json:"mac"`
	NASSource       string `json:"nas_source"`
	NASReportedIPv4 string `json:"nas_reported_ipv4"`
	NASPort         string `json:"nas_port"`
	NASPortType     string `json:"nas_port_type"`
	NASPortIDHex    string `json:"nas_port_id_hex"`
	SessionIDHex    string `json:"session_id_hex"`
	Status          string `json:"status"`
	EventTime       string `json:"event_time"`
	DelaySeconds    string `json:"delay_seconds"`
	SessionSeconds  string `json:"session_seconds"`
	IPv4            string `json:"ipv4"`
	IPv6Addresses   string `json:"ipv6_addresses"`
	IPv6Prefixes    string `json:"ipv6_prefixes"`
	InterfaceID     string `json:"interface_id"`
	VLANReportedHex string `json:"vlan_reported_hex"`
}

type event struct {
	UnknownAge   bool
	WallOriginal time.Time
	MAC          string
	NAS          netip.Addr
	Key          string
	Status       string
	Original     time.Time
	JournalAt    time.Time
	Duration     uint64
	IP           netip.Addr
	VLAN         uint16
	Port         string
	IPv6         bool
}

type sessionState struct {
	Uncertain event
	Negative  map[netip.Addr]time.Time
	First     event
	Last      event
	Started   bool
	Closed    bool
	Conflict  bool
}

// Replay consumes a bounded, chronological journal JSON capture, preserving
// Stop tombstones and original Start/session-duration anchors. The caller must
// authenticate the journal source and supply complete current-boot history;
// JSON metadata alone cannot authenticate arbitrary input or prove completeness.
// Do not use a tail, reverse-order capture or previously filtered active list.
// Missing Starts, reused IDs and overlapping sessions withhold candidates.
// Malformed, oversized, wrong-source or out-of-order input returns no result.
// This is a correlation core, not an installed collector or enforcement feed.
func Replay(data []byte, scope Scope, now time.Time) (Observation, error) {
	if !validScope(scope) || now.IsZero() || len(data) > maximumHistory ||
		(len(data) != 0 && data[len(data)-1] != '\n') {
		return Observation{}, errors.New("radius: invalid scope or incomplete history")
	}
	states := make(map[string]*sessionState)
	previous := time.Time{}
	count := 0
	for line := range bytes.Lines(data) {
		count++
		if count > maximumEvents {
			return Observation{}, errors.New("radius: event limit exceeded")
		}
		item, err := decodeEntry(bytes.TrimSuffix(line, []byte{'\n'}), scope, now)
		if err != nil {
			return Observation{}, err
		}
		if item.JournalAt.Before(previous) {
			return Observation{}, errors.New("radius: journal clock or order conflict")
		}
		previous = item.JournalAt
		if err := accumulate(states, item); err != nil {
			return Observation{}, err
		}
	}
	return current(states, now), nil
}

func accumulate(states map[string]*sessionState, item event) error {
	state, exists := states[item.Key]
	if !exists {
		if len(states) >= maximumSessions {
			return errors.New("radius: session limit exceeded")
		}
		state = &sessionState{First: item, Last: item}
		states[item.Key] = state
	}
	if state.First.MAC != item.MAC {
		return errors.New("radius: session identity has conflicting owners")
	}
	return state.apply(item)
}

func validScope(scope Scope) bool {
	boot, err := hex.DecodeString(scope.BootID)
	if err != nil || len(boot) != 16 || len(scope.NASPrefixes) == 0 || len(scope.NASPrefixes) > 64 {
		return false
	}
	for _, prefix := range scope.NASPrefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return false
		}
	}
	return true
}

func decodeEntry(data []byte, scope Scope, now time.Time) (event, error) {
	entry := make(map[string]json.RawMessage)
	if err := strictjson.Decode(data, &entry, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid journal entry")
	}
	fields := []string{"MESSAGE", "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_BOOT_ID", "_UID", "__REALTIME_TIMESTAMP"}
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		var value string
		if err := json.Unmarshal(entry[field], &value); err != nil || value == "" {
			return event{}, errors.New("radius: missing journal provenance")
		}
		values[field] = value
	}
	if values["_SYSTEMD_UNIT"] != "freeradius.service" || values["SYSLOG_IDENTIFIER"] != "freeradius" ||
		values["_BOOT_ID"] != scope.BootID || values["_UID"] != strconv.FormatUint(uint64(scope.ServiceUID), 10) ||
		!strings.HasPrefix(values["MESSAGE"], marker) {
		return event{}, errors.New("radius: journal source or boot mismatch")
	}
	micros, err := unsigned(values["__REALTIME_TIMESTAMP"], 9999999999999999)
	if err != nil || micros > math.MaxInt64 {
		return event{}, errors.New("radius: invalid journal timestamp")
	}
	journalAt := time.UnixMicro(int64(micros)).UTC()
	payload := []byte(strings.TrimPrefix(values["MESSAGE"], marker))
	required := []string{"received_at", "mac", "nas_source", "nas_reported_ipv4", "nas_port", "nas_port_type",
		"nas_port_id_hex", "session_id_hex", "status", "event_time", "delay_seconds", "session_seconds",
		"ipv4", "ipv6_addresses", "ipv6_prefixes", "interface_id", "vlan_reported_hex"}
	if err := strictjson.Object(payload, required, nil, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid accounting schema")
	}
	var raw accountingEvent
	if err := strictjson.Decode(payload, &raw, maximumEntry); err != nil {
		return event{}, errors.New("radius: invalid accounting fields")
	}
	item, err := normalize(raw, scope, now)
	if err != nil {
		return event{}, err
	}
	receipt := time.Unix(raw.ReceivedAt, 0).UTC()
	if journalAt.Before(receipt) || journalAt.After(receipt.Add(10*time.Second)) || journalAt.After(now) {
		return event{}, errors.New("radius: journal receipt clock conflict")
	}
	item.JournalAt = journalAt
	return item, nil
}

func normalize(raw accountingEvent, scope Scope, now time.Time) (event, error) {
	stringsToCheck := []string{raw.MAC, raw.NASSource, raw.NASReportedIPv4, raw.NASPort, raw.NASPortType,
		raw.NASPortIDHex, raw.SessionIDHex, raw.Status, raw.EventTime, raw.DelaySeconds, raw.SessionSeconds,
		raw.IPv4, raw.IPv6Addresses, raw.IPv6Prefixes, raw.InterfaceID, raw.VLANReportedHex}
	for _, value := range stringsToCheck {
		if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
			return event{}, errors.New("radius: invalid accounting field")
		}
	}
	mac, macErr := policy.CanonicalMAC(raw.MAC)
	nas, nasErr := netip.ParseAddr(raw.NASSource)
	if macErr != nil || nasErr != nil || nas.Is4In6() || nas.Zone() != "" || !nas.IsGlobalUnicast() ||
		!slices.ContainsFunc(scope.NASPrefixes, func(prefix netip.Prefix) bool { return prefix.Contains(nas) }) ||
		(raw.NASReportedIPv4 != "" && raw.NASReportedIPv4 != nas.String()) {
		return event{}, errors.New("radius: invalid identity or unapproved NAS")
	}
	sessionID, err := hex.DecodeString(raw.SessionIDHex)
	if err != nil || len(sessionID) == 0 || len(sessionID) > 128 {
		return event{}, errors.New("radius: invalid session identity")
	}
	portID, err := hex.DecodeString(raw.NASPortIDHex)
	if err != nil || len(portID) > 128 {
		return event{}, errors.New("radius: invalid port identity")
	}
	if raw.Status != "Start" && raw.Status != "Stop" && raw.Status != "Alive" && raw.Status != "Interim-Update" {
		return event{}, errors.New("radius: unsupported accounting status")
	}
	delayText := raw.DelaySeconds
	if delayText == "" {
		delayText = "0"
	} // Used only for the conservative denial window.
	delay, err := unsigned(delayText, 0xffffffff)
	if err != nil {
		return event{}, err
	}
	durationText := raw.SessionSeconds
	if durationText == "" {
		durationText = "0"
	}
	duration, err := unsigned(durationText, 0xffffffff)
	if err != nil {
		return event{}, err
	}
	if raw.ReceivedAt <= 0 || raw.ReceivedAt > now.Unix() || delay > math.MaxInt64 || delay >= uint64(raw.ReceivedAt) {
		return event{}, errors.New("radius: invalid accounting receipt or delay")
	}
	original := time.Unix(raw.ReceivedAt-int64(delay), 0).UTC() // delay < positive int64 receipt.
	if raw.EventTime != "" && raw.DelaySeconds != "" {
		stamp, err := eventTime(raw.EventTime)
		if err != nil || stamp.After(time.Unix(raw.ReceivedAt, 0)) || !near(stamp, original) {
			return event{}, errors.New("radius: inconsistent event timestamp")
		}
		if stamp.Before(original) {
			original = stamp
		}
	}
	var ip netip.Addr
	if raw.IPv4 != "" {
		ip, err = netip.ParseAddr(raw.IPv4)
		if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
			return event{}, errors.New("radius: invalid reported IPv4")
		}
	}
	vlan, err := reportedVLAN(raw.VLANReportedHex)
	if err != nil {
		return event{}, err
	}
	return event{
		UnknownAge:   raw.DelaySeconds == "" || raw.SessionSeconds == "" && raw.Status != "Start",
		WallOriginal: original, MAC: mac, NAS: nas,
		Key:    digest(scope.BootID, nas.String(), hex.EncodeToString(sessionID)),
		Status: raw.Status, Original: original, Duration: duration, IP: ip, VLAN: vlan,
		Port: digest(raw.NASPort, raw.NASPortType, hex.EncodeToString(portID)),
		IPv6: raw.IPv6Addresses != "" || raw.IPv6Prefixes != "" || raw.InterfaceID != "",
	}, nil
}

// apply never removes a tombstone. Newer durations remain anchored to the
// original Start, so a delayed duplicate cannot become a new heartbeat.
func (state *sessionState) apply(item event) error {
	state.applyEvent(item)
	if state.Closed || !state.Conflict && state.Uncertain.Original.IsZero() {
		state.Negative = nil
		return nil
	}
	for address, until := range state.Negative {
		if !item.Original.Before(until) {
			delete(state.Negative, address)
		}
	}
	if item.IP.IsValid() {
		if state.Negative == nil {
			state.Negative = make(map[netip.Addr]time.Time)
		}
		until := item.Original.Add(Freshness)
		if until.After(state.Negative[item.IP]) {
			state.Negative[item.IP] = until
		}
	}
	if len(state.Negative) > 16 {
		return errBudget
	}
	return nil
}

func (state *sessionState) applyEvent(item event) {
	if item.Status == "Stop" {
		state.Closed = true
		return
	}
	if state.Closed {
		return
	}
	if item.UnknownAge {
		state.Uncertain = item
		return
	}
	if item.Status == "Start" {
		switch {
		case item.Duration != 0:
			state.Conflict = true
		case !state.Started:
			state.First, state.Last, state.Started = item, item, true
			if !state.Uncertain.Original.After(item.Original) {
				state.Uncertain = event{}
			}
		case !item.WallOriginal.Equal(state.First.WallOriginal) || !near(item.Original, state.First.Original) || !samePlacement(item, state.First):
			state.Conflict = true
		}
		return
	}
	if !state.Started {
		state.Conflict = true
		state.Last = item
		return
	}
	if item.Duration < state.Last.Duration {
		return
	}
	if item.Duration == state.Last.Duration {
		if !samePlacement(item, state.Last) {
			state.Conflict = true
		}
		return
	}
	if item.Duration > uint64(math.MaxInt64/int64(time.Second)) {
		state.Conflict = true
		return
	}
	anchored := state.First.Original.Add(time.Duration(item.Duration) * time.Second)
	if !near(anchored, item.Original) || item.Port != state.First.Port || item.VLAN != state.Last.VLAN {
		state.Conflict = true
		return
	}
	if anchored.Before(item.Original) {
		item.Original = anchored
	}
	state.Last = item
	if !state.Uncertain.Original.After(item.Original) {
		state.Uncertain = event{}
	}
}

func current(states map[string]*sessionState, now time.Time) Observation {
	byMAC := make(map[string][]*sessionState)
	claims := make(map[netip.Addr]string)
	conflicted := make(map[netip.Addr]bool)
	claim := func(address netip.Addr, mac string) {
		if owner, seen := claims[address]; seen && owner != mac {
			conflicted[address] = true
		}
		claims[address] = mac
	}
	for _, state := range states {
		if state.Closed {
			continue
		}
		if evidence := state.Last; evidence.IP.IsValid() && now.Before(evidence.Original.Add(Freshness)) {
			claim(evidence.IP, evidence.MAC)
		}
		negative := false
		for address, until := range state.Negative {
			if now.Before(until) {
				claim(address, state.First.MAC)
				negative = true
			}
		}
		if negative || now.Before(state.Uncertain.Original.Add(Freshness)) {
			byMAC[state.First.MAC] = append(byMAC[state.First.MAC], state)
			continue
		}
		if !state.Last.Original.After(now) && now.Before(state.Last.Original.Add(Freshness)) {
			byMAC[state.First.MAC] = append(byMAC[state.First.MAC], state)
		}
	}
	result := Observation{ObservedAt: now, Sessions: []Session{}, DuplicateClaim: len(conflicted) > 0}
	for mac, active := range byMAC {
		if len(active) != 1 || active[0].Conflict || !active[0].Started || conflicted[active[0].Last.IP] ||
			now.Before(active[0].Uncertain.Original.Add(Freshness)) {
			result.Withheld++
			continue
		}
		state := active[0]
		result.Sessions = append(result.Sessions, Session{
			MAC: mac, NAS: state.Last.NAS,
			AssociationID: digest(state.First.Key, strconv.FormatInt(state.First.Original.Unix(), 10)),
			StartedAt:     state.First.Original, ObservedAt: state.Last.Original,
			ValidUntil: state.Last.Original.Add(Freshness), IPv4: state.Last.IP,
			ReportedVLAN: state.Last.VLAN, IPv6Reported: state.Last.IPv6,
		})
	}
	slices.SortFunc(result.Sessions, func(a, b Session) int { return strings.Compare(a.MAC, b.MAC) })
	return result
}

func samePlacement(a, b event) bool {
	return a.IP == b.IP && a.VLAN == b.VLAN && a.Port == b.Port && a.IPv6 == b.IPv6
}

func unsigned(value string, maximum uint64) (uint64, error) {
	if len(value) == 0 || len(value) > 20 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, errors.New("radius: invalid unsigned field")
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > maximum {
		return 0, errors.New("radius: unsigned field out of range")
	}
	return parsed, nil
}

func eventTime(value string) (time.Time, error) {
	if seconds, err := unsigned(value, 9999999999); err == nil && seconds != 0 && seconds <= math.MaxInt64 {
		return time.Unix(int64(seconds), 0).UTC(), nil
	}
	stamp, err := time.Parse("Jan _2 2006 15:04:05 MST", value)
	if err != nil || !strings.HasSuffix(value, " UTC") || stamp.Unix() <= 0 {
		return time.Time{}, errors.New("radius: unqualified timestamp format")
	}
	return stamp.UTC(), nil
}

func reportedVLAN(value string) (uint16, error) {
	if value == "" {
		return 0, nil
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) > 4 {
		return 0, errors.New("radius: invalid reported VLAN")
	}
	number, err := unsigned(string(decoded), 4094)
	if err != nil || number == 0 || number > math.MaxUint16 {
		return 0, errors.New("radius: invalid reported VLAN")
	}
	return uint16(number), nil // Bounded to the VLAN range above.
}

func near(a, b time.Time) bool {
	return !a.Before(b.Add(-clockTolerance)) && !a.After(b.Add(clockTolerance))
}

func digest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		// Length framing avoids concatenation collisions without retaining raw IDs.
		_, _ = fmt.Fprintf(hash, "%d:%s", len(part), part)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
